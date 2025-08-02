//! Module de journalisation sécurisée ERDPS
//!
//! Système de logs sécurisé avec:
//! - Hachage cryptographique pour l'intégrité
//! - Chiffrement des données sensibles
//! - Rotation automatique des fichiers
//! - Protection contre la falsification
//! - Audit trail complet
//! - Compression et archivage

use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter, BufReader, BufRead};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, Duration};
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context, bail};
use chrono::{DateTime, Utc, Local};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};
use rand::{RngCore, rngs::OsRng};
use flate2::write::GzEncoder;
use flate2::Compression;
use ring::hmac;

use crate::config::LoggingConfig;
use crate::detection::{ThreatContext, ThreatType, ThreatSeverity};

/// Logger sécurisé ERDPS
pub struct SecureLogger {
    config: LoggingConfig,
    log_writers: Arc<RwLock<Vec<LogWriter>>>,
    log_queue: Arc<RwLock<Vec<LogEntry>>>,
    integrity_chain: Arc<RwLock<IntegrityChain>>,
    encryption_key: Option<Key<Aes256Gcm>>,
    hmac_key: hmac::Key,
    is_running: Arc<RwLock<bool>>,
    sequence_number: Arc<RwLock<u64>>,
}

/// Writer de logs
struct LogWriter {
    file_path: PathBuf,
    writer: BufWriter<File>,
    current_size: u64,
    max_size: u64,
    log_level: LogLevel,
    encrypted: bool,
}

/// Entrée de log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub category: LogCategory,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub source: String,
    pub thread_id: Option<u32>,
    pub process_id: u32,
    pub user_id: Option<String>,
    pub session_id: Option<Uuid>,
    pub sequence_number: u64,
    pub hash: Option<String>,
    pub previous_hash: Option<String>,
}

/// Niveau de log
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5,
}

/// Catégorie de log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogCategory {
    System,
    Security,
    Threat,
    Network,
    File,
    Process,
    Registry,
    Authentication,
    Configuration,
    Performance,
    Audit,
    Error,
}

/// Chaîne d'intégrité
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntegrityChain {
    entries: Vec<IntegrityEntry>,
    last_hash: String,
    chain_start: DateTime<Utc>,
    total_entries: u64,
}

/// Entrée d'intégrité
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntegrityEntry {
    sequence: u64,
    timestamp: DateTime<Utc>,
    log_hash: String,
    previous_hash: String,
    cumulative_hash: String,
}

/// Événement de sécurité
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: Uuid,
    pub event_type: SecurityEventType,
    pub severity: ThreatSeverity,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub target: Option<String>,
    pub description: String,
    pub evidence: Vec<String>,
    pub mitigation: Option<String>,
    pub user_context: Option<UserContext>,
    pub network_context: Option<NetworkContext>,
    pub file_context: Option<FileContext>,
}

/// Type d'événement de sécurité
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    ThreatDetected,
    MalwareFound,
    SuspiciousActivity,
    UnauthorizedAccess,
    DataExfiltration,
    SystemCompromise,
    ConfigurationChange,
    PolicyViolation,
    AuthenticationFailure,
    PrivilegeEscalation,
    NetworkIntrusion,
    FileIntegrityViolation,
}

/// Contexte utilisateur
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    pub user_id: String,
    pub username: String,
    pub domain: Option<String>,
    pub privileges: Vec<String>,
    pub session_id: Option<String>,
    pub logon_time: Option<DateTime<Utc>>,
}

/// Contexte réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: String,
    pub bytes_transferred: u64,
    pub connection_duration: Option<Duration>,
}

/// Contexte fichier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContext {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub file_hash: String,
    pub file_type: String,
    pub creation_time: DateTime<Utc>,
    pub modification_time: DateTime<Utc>,
    pub access_time: DateTime<Utc>,
    pub permissions: String,
    pub owner: String,
}

/// Statistiques de logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingStats {
    pub total_entries: u64,
    pub entries_by_level: std::collections::HashMap<LogLevel, u64>,
    pub entries_by_category: std::collections::HashMap<String, u64>,
    pub total_size: u64,
    pub files_count: u32,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
    pub integrity_violations: u32,
    pub encryption_errors: u32,
}

impl SecureLogger {
    /// Crée un nouveau logger sécurisé
    pub fn new(config: LoggingConfig) -> Result<Self> {
        // Générer les clés cryptographiques
        let mut encryption_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut encryption_key_bytes);
        let encryption_key = Some(*Key::<Aes256Gcm>::from_slice(&encryption_key_bytes));
        
        let mut hmac_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut hmac_key_bytes);
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
        
        // Créer le répertoire de logs
        std::fs::create_dir_all(&config.log_directory)
            .context("Création du répertoire de logs")?;
        
        Ok(Self {
            config,
            log_writers: Arc::new(RwLock::new(Vec::new())),
            log_queue: Arc::new(RwLock::new(Vec::new())),
            integrity_chain: Arc::new(RwLock::new(IntegrityChain {
                entries: Vec::new(),
                last_hash: "genesis".to_string(),
                chain_start: Utc::now(),
                total_entries: 0,
            })),
            encryption_key,
            hmac_key,
            is_running: Arc::new(RwLock::new(false)),
            sequence_number: Arc::new(RwLock::new(0)),
        })
    }
    
    /// Démarre le système de logging
    pub async fn start(&mut self) -> Result<()> {
        info!("📝 Démarrage du système de logging sécurisé...");
        
        let mut is_running = self.is_running.write().await;
        if *is_running {
            warn!("⚠️ Le système de logging est déjà actif");
            return Ok(());
        }
        
        // Initialiser les writers
        self.initialize_writers().await?;
        
        // Charger la chaîne d'intégrité existante
        self.load_integrity_chain().await?;
        
        *is_running = true;
        
        // Démarrer les tâches de maintenance
        self.start_background_tasks().await?;
        
        info!("✅ Système de logging sécurisé démarré");
        Ok(())
    }
    
    /// Arrête le système de logging
    pub async fn stop(&mut self) -> Result<()> {
        info!("🛑 Arrêt du système de logging...");
        
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        
        // Vider la file d'attente
        self.flush_queue().await?;
        
        // Sauvegarder la chaîne d'intégrité
        self.save_integrity_chain().await?;
        
        // Fermer les writers
        let mut writers = self.log_writers.write().await;
        writers.clear();
        
        info!("✅ Système de logging arrêté");
        Ok(())
    }
    
    /// Initialise les writers de logs
    async fn initialize_writers(&self) -> Result<()> {
        let mut writers = self.log_writers.write().await;
        
        // Writer principal (tous les niveaux)
        let main_log_path = self.config.log_directory.join("erdps-agent.log");
        let main_writer = self.create_log_writer(&main_log_path, LogLevel::Trace, false)?;
        writers.push(main_writer);
        
        // Writer de sécurité (chiffré)
        let security_log_path = self.config.log_directory.join("erdps-security.log");
        let security_writer = self.create_log_writer(&security_log_path, LogLevel::Warn, true)?;
        writers.push(security_writer);
        
        // Writer d'audit
        let audit_log_path = self.config.log_directory.join("erdps-audit.log");
        let audit_writer = self.create_log_writer(&audit_log_path, LogLevel::Info, false)?;
        writers.push(audit_writer);
        
        info!("📁 Writers de logs initialisés: {}", writers.len());
        Ok(())
    }
    
    /// Crée un writer de log
    fn create_log_writer(
        &self,
        file_path: &Path,
        log_level: LogLevel,
        encrypted: bool,
    ) -> Result<LogWriter> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .with_context(|| format!("Ouverture du fichier de log: {:?}", file_path))?;
        
        let current_size = file.metadata()
            .context("Lecture des métadonnées du fichier")?.
            len();
        
        Ok(LogWriter {
            file_path: file_path.to_path_buf(),
            writer: BufWriter::new(file),
            current_size,
            max_size: self.config.max_file_size,
            log_level,
            encrypted,
        })
    }
    
    /// Démarre les tâches de maintenance
    async fn start_background_tasks(&self) -> Result<()> {
        // Tâche de traitement de la file d'attente
        let log_queue = self.log_queue.clone();
        let log_writers = self.log_writers.clone();
        let integrity_chain = self.integrity_chain.clone();
        let is_running = self.is_running.clone();
        let encryption_key = self.encryption_key;
        let hmac_key = self.hmac_key.clone();
        
        tokio::spawn(async move {
            Self::queue_processing_task(
                log_queue,
                log_writers,
                integrity_chain,
                is_running,
                encryption_key,
                hmac_key,
            ).await;
        });
        
        // Tâche de rotation des logs
        let log_writers = self.log_writers.clone();
        let config = self.config.clone();
        let is_running = self.is_running.clone();
        
        tokio::spawn(async move {
            Self::log_rotation_task(log_writers, config, is_running).await;
        });
        
        // Tâche d'archivage
        let config = self.config.clone();
        let is_running = self.is_running.clone();
        
        tokio::spawn(async move {
            Self::archiving_task(config, is_running).await;
        });
        
        Ok(())
    }
    
    /// Tâche de traitement de la file d'attente
    async fn queue_processing_task(
        log_queue: Arc<RwLock<Vec<LogEntry>>>,
        log_writers: Arc<RwLock<Vec<LogWriter>>>,
        integrity_chain: Arc<RwLock<IntegrityChain>>,
        is_running: Arc<RwLock<bool>>,
        encryption_key: Option<Key<Aes256Gcm>>,
        hmac_key: hmac::Key,
    ) {
        let mut interval = interval(Duration::from_millis(100));
        
        while *is_running.read().await {
            interval.tick().await;
            
            let mut queue = log_queue.write().await;
            if queue.is_empty() {
                continue;
            }
            
            // Traiter tous les logs en attente
            let entries_to_process: Vec<LogEntry> = queue.drain(..).collect();
            drop(queue);
            
            for mut entry in entries_to_process {
                // Calculer le hash de l'entrée
                entry.hash = Some(Self::calculate_entry_hash(&entry, &hmac_key));
                
                // Mettre à jour la chaîne d'intégrité
                Self::update_integrity_chain(&entry, &integrity_chain).await;
                
                // Écrire dans les fichiers appropriés
                Self::write_to_files(&entry, &log_writers, encryption_key).await;
            }
        }
    }
    
    /// Tâche de rotation des logs
    async fn log_rotation_task(
        log_writers: Arc<RwLock<Vec<LogWriter>>>,
        config: LoggingConfig,
        is_running: Arc<RwLock<bool>>,
    ) {
        let mut interval = interval(Duration::from_secs(3600)); // Vérifier chaque heure
        
        while *is_running.read().await {
            interval.tick().await;
            
            let mut writers = log_writers.write().await;
            
            for writer in writers.iter_mut() {
                if writer.current_size >= writer.max_size {
                    if let Err(e) = Self::rotate_log_file(writer, &config).await {
                        error!("❌ Erreur lors de la rotation: {}", e);
                    }
                }
            }
        }
    }
    
    /// Tâche d'archivage
    async fn archiving_task(
        config: LoggingConfig,
        is_running: Arc<RwLock<bool>>,
    ) {
        let mut interval = interval(Duration::from_secs(86400)); // Vérifier chaque jour
        
        while *is_running.read().await {
            interval.tick().await;
            
            if let Err(e) = Self::archive_old_logs(&config).await {
                error!("❌ Erreur lors de l'archivage: {}", e);
            }
        }
    }
    
    /// Log une entrée
    pub async fn log(&self, entry: LogEntry) -> Result<()> {
        let mut queue = self.log_queue.write().await;
        queue.push(entry);
        Ok(())
    }
    
    /// Log un message simple
    pub async fn log_message(
        &self,
        level: LogLevel,
        category: LogCategory,
        message: &str,
        details: Option<serde_json::Value>,
    ) -> Result<()> {
        let mut sequence = self.sequence_number.write().await;
        *sequence += 1;
        let seq_num = *sequence;
        drop(sequence);
        
        let entry = LogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level,
            category,
            message: message.to_string(),
            details,
            source: "erdps-agent".to_string(),
            thread_id: Self::get_current_thread_id(),
            process_id: std::process::id(),
            user_id: Self::get_current_user(),
            session_id: None,
            sequence_number: seq_num,
            hash: None,
            previous_hash: None,
        };
        
        self.log(entry).await
    }
    
    /// Log un événement de sécurité
    pub async fn log_security_event(&self, event: &SecurityEvent) -> Result<()> {
        let details = serde_json::to_value(event)
            .context("Sérialisation de l'événement de sécurité")?;
        
        let level = match event.severity {
            ThreatSeverity::Critical => LogLevel::Critical,
            ThreatSeverity::High => LogLevel::Error,
            ThreatSeverity::Medium => LogLevel::Warn,
            ThreatSeverity::Low => LogLevel::Info,
        };
        
        self.log_message(
            level,
            LogCategory::Security,
            &format!("Événement de sécurité: {:?}", event.event_type),
            Some(details),
        ).await
    }
    
    /// Calcule le hash d'une entrée
    fn calculate_entry_hash(entry: &LogEntry, hmac_key: &hmac::Key) -> String {
        let data = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            entry.id,
            entry.timestamp.timestamp_nanos(),
            entry.level as u8,
            entry.message,
            entry.source,
            entry.sequence_number,
            entry.previous_hash.as_deref().unwrap_or("")
        );
        
        let signature = hmac::sign(hmac_key, data.as_bytes());
        hex::encode(signature.as_ref())
    }
    
    /// Met à jour la chaîne d'intégrité
    async fn update_integrity_chain(
        entry: &LogEntry,
        integrity_chain: Arc<RwLock<IntegrityChain>>,
    ) {
        let mut chain = integrity_chain.write().await;
        
        let integrity_entry = IntegrityEntry {
            sequence: entry.sequence_number,
            timestamp: entry.timestamp,
            log_hash: entry.hash.clone().unwrap_or_default(),
            previous_hash: chain.last_hash.clone(),
            cumulative_hash: Self::calculate_cumulative_hash(
                &chain.last_hash,
                &entry.hash.clone().unwrap_or_default(),
            ),
        };
        
        chain.last_hash = integrity_entry.cumulative_hash.clone();
        chain.entries.push(integrity_entry);
        chain.total_entries += 1;
        
        // Limiter la taille de la chaîne en mémoire
        if chain.entries.len() > 10000 {
            chain.entries.drain(0..5000);
        }
    }
    
    /// Calcule le hash cumulatif
    fn calculate_cumulative_hash(previous_hash: &str, current_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(previous_hash.as_bytes());
        hasher.update(current_hash.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Écrit dans les fichiers de logs
    async fn write_to_files(
        entry: &LogEntry,
        log_writers: &Arc<RwLock<Vec<LogWriter>>>,
        encryption_key: Option<Key<Aes256Gcm>>,
    ) {
        let mut writers = log_writers.write().await;
        
        for writer in writers.iter_mut() {
            if entry.level >= writer.log_level {
                if let Err(e) = Self::write_entry_to_file(entry, writer, encryption_key).await {
                    error!("❌ Erreur d'écriture dans {}: {}", 
                           writer.file_path.display(), e);
                }
            }
        }
    }
    
    /// Écrit une entrée dans un fichier
    async fn write_entry_to_file(
        entry: &LogEntry,
        writer: &mut LogWriter,
        encryption_key: Option<Key<Aes256Gcm>>,
    ) -> Result<()> {
        let json_entry = serde_json::to_string(entry)
            .context("Sérialisation de l'entrée de log")?;
        
        let data_to_write = if writer.encrypted {
            Self::encrypt_log_data(&json_entry, encryption_key)?
        } else {
            json_entry.into_bytes()
        };
        
        writer.writer.write_all(&data_to_write)
            .context("Écriture dans le fichier de log")?;
        writer.writer.write_all(b"\n")
            .context("Écriture du saut de ligne")?;
        writer.writer.flush()
            .context("Flush du buffer")?;
        
        writer.current_size += data_to_write.len() as u64 + 1;
        
        Ok(())
    }
    
    /// Chiffre les données de log
    fn encrypt_log_data(
        data: &str,
        encryption_key: Option<Key<Aes256Gcm>>,
    ) -> Result<Vec<u8>> {
        let key = encryption_key
            .context("Clé de chiffrement non disponible")?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let cipher = Aes256Gcm::new(&key);
        let ciphertext = cipher.encrypt(nonce, data.as_bytes())
            .map_err(|e| anyhow::anyhow!("Échec du chiffrement: {}", e))?;
        
        // Encoder en base64 pour stockage texte
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(base64::encode(&result).into_bytes())
    }
    
    /// Effectue la rotation d'un fichier de log
    async fn rotate_log_file(
        writer: &mut LogWriter,
        config: &LoggingConfig,
    ) -> Result<()> {
        info!("🔄 Rotation du fichier: {:?}", writer.file_path);
        
        // Fermer le writer actuel
        writer.writer.flush()
            .context("Flush avant rotation")?;
        
        // Renommer le fichier actuel
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let rotated_path = writer.file_path.with_extension(
            format!("log.{}", timestamp)
        );
        
        std::fs::rename(&writer.file_path, &rotated_path)
            .context("Renommage du fichier pour rotation")?;
        
        // Créer un nouveau fichier
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&writer.file_path)
            .context("Création du nouveau fichier de log")?;
        
        writer.writer = BufWriter::new(new_file);
        writer.current_size = 0;
        
        // Compresser l'ancien fichier si configuré
        if config.compress_rotated {
            tokio::spawn(async move {
                if let Err(e) = Self::compress_log_file(&rotated_path).await {
                    error!("❌ Erreur de compression: {}", e);
                }
            });
        }
        
        info!("✅ Rotation terminée: {:?}", rotated_path);
        Ok(())
    }
    
    /// Compresse un fichier de log
    async fn compress_log_file(file_path: &Path) -> Result<()> {
        let compressed_path = file_path.with_extension("log.gz");
        
        let input_file = File::open(file_path)
            .context("Ouverture du fichier à compresser")?;
        let output_file = File::create(&compressed_path)
            .context("Création du fichier compressé")?;
        
        let mut reader = BufReader::new(input_file);
        let mut encoder = GzEncoder::new(output_file, Compression::default());
        
        std::io::copy(&mut reader, &mut encoder)
            .context("Compression du fichier")?;
        
        encoder.finish()
            .context("Finalisation de la compression")?;
        
        // Supprimer le fichier original
        std::fs::remove_file(file_path)
            .context("Suppression du fichier original")?;
        
        info!("📦 Fichier compressé: {:?}", compressed_path);
        Ok(())
    }
    
    /// Archive les anciens logs
    async fn archive_old_logs(config: &LoggingConfig) -> Result<()> {
        let retention_days = config.retention_days;
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);
        
        let log_dir = std::fs::read_dir(&config.log_directory)
            .context("Lecture du répertoire de logs")?;
        
        for entry in log_dir {
            let entry = entry.context("Lecture de l'entrée du répertoire")?;
            let path = entry.path();
            
            if path.is_file() {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        let modified_datetime: DateTime<Utc> = modified.into();
                        
                        if modified_datetime < cutoff_date {
                            info!("🗑️ Suppression de l'ancien log: {:?}", path);
                            if let Err(e) = std::fs::remove_file(&path) {
                                error!("❌ Erreur de suppression: {}", e);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Charge la chaîne d'intégrité
    async fn load_integrity_chain(&self) -> Result<()> {
        let chain_file = self.config.log_directory.join("integrity_chain.json");
        
        if chain_file.exists() {
            let data = tokio::fs::read_to_string(&chain_file).await
                .context("Lecture de la chaîne d'intégrité")?;
            
            let loaded_chain: IntegrityChain = serde_json::from_str(&data)
                .context("Désérialisation de la chaîne d'intégrité")?;
            
            let mut chain = self.integrity_chain.write().await;
            *chain = loaded_chain;
            
            info!("📋 Chaîne d'intégrité chargée: {} entrées", chain.entries.len());
        }
        
        Ok(())
    }
    
    /// Sauvegarde la chaîne d'intégrité
    async fn save_integrity_chain(&self) -> Result<()> {
        let chain_file = self.config.log_directory.join("integrity_chain.json");
        
        let chain = self.integrity_chain.read().await;
        let data = serde_json::to_string_pretty(&*chain)
            .context("Sérialisation de la chaîne d'intégrité")?;
        
        tokio::fs::write(&chain_file, data).await
            .context("Écriture de la chaîne d'intégrité")?;
        
        info!("💾 Chaîne d'intégrité sauvegardée");
        Ok(())
    }
    
    /// Vide la file d'attente
    async fn flush_queue(&self) -> Result<()> {
        let queue_size = {
            let queue = self.log_queue.read().await;
            queue.len()
        };
        
        if queue_size > 0 {
            info!("🔄 Vidage de la file d'attente: {} entrées", queue_size);
            
            // Attendre que la file soit vide
            let mut attempts = 0;
            while attempts < 50 {
                let queue = self.log_queue.read().await;
                if queue.is_empty() {
                    break;
                }
                drop(queue);
                
                tokio::time::sleep(Duration::from_millis(100)).await;
                attempts += 1;
            }
        }
        
        Ok(())
    }
    
    /// Obtient l'ID du thread actuel
    fn get_current_thread_id() -> Option<u32> {
        // Implémentation Windows pour obtenir l'ID du thread
        None
    }
    
    /// Obtient l'utilisateur actuel
    fn get_current_user() -> Option<String> {
        std::env::var("USERNAME").ok()
    }
    
    /// Obtient les statistiques de logging
    pub async fn get_stats(&self) -> LoggingStats {
        let chain = self.integrity_chain.read().await;
        
        LoggingStats {
            total_entries: chain.total_entries,
            entries_by_level: std::collections::HashMap::new(), // À implémenter
            entries_by_category: std::collections::HashMap::new(), // À implémenter
            total_size: 0, // À calculer
            files_count: 0, // À calculer
            oldest_entry: None, // À calculer
            newest_entry: None, // À calculer
            integrity_violations: 0, // À implémenter
            encryption_errors: 0, // À implémenter
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    fn create_test_config() -> LoggingConfig {
        let temp_dir = tempdir().unwrap();
        
        LoggingConfig {
            enabled: true,
            log_directory: temp_dir.path().to_path_buf(),
            log_level: LogLevel::Debug,
            max_file_size: 1024 * 1024, // 1MB
            max_files: 10,
            compress_rotated: true,
            retention_days: 30,
            secure_logging: true,
            remote_logging: false,
            remote_endpoint: None,
        }
    }
    
    #[tokio::test]
    async fn test_logger_creation() {
        let config = create_test_config();
        let logger = SecureLogger::new(config);
        assert!(logger.is_ok());
    }
    
    #[tokio::test]
    async fn test_log_entry_creation() {
        let entry = LogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level: LogLevel::Info,
            category: LogCategory::System,
            message: "Test message".to_string(),
            details: None,
            source: "test".to_string(),
            thread_id: None,
            process_id: 1234,
            user_id: Some("test_user".to_string()),
            session_id: None,
            sequence_number: 1,
            hash: None,
            previous_hash: None,
        };
        
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "Test message");
    }
    
    #[test]
    fn test_hash_calculation() {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        
        let entry = LogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level: LogLevel::Info,
            category: LogCategory::System,
            message: "Test".to_string(),
            details: None,
            source: "test".to_string(),
            thread_id: None,
            process_id: 1234,
            user_id: None,
            session_id: None,
            sequence_number: 1,
            hash: None,
            previous_hash: None,
        };
        
        let hash = SecureLogger::calculate_entry_hash(&entry, &hmac_key);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 hex = 64 caractères
    }
}