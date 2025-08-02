//! Module de surveillance temps réel ERDPS
//!
//! Surveillance multi-couches pour la détection proactive:
//! - Surveillance des fichiers (création, modification, suppression)
//! - Surveillance des processus (démarrage, injection, comportement)
//! - Surveillance réseau (connexions, trafic suspect)
//! - Surveillance du registre (modifications critiques)

use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context};
use notify::{Watcher, RecursiveMode, Event, EventKind};
use sysinfo::{System, SystemExt, ProcessExt, Pid};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::detection::{ThreatDetector, ThreatContext, ProcessInfo, NetworkIndicator};

/// Moniteur de fichiers en temps réel
pub struct FileMonitor {
    watcher: Option<notify::RecommendedWatcher>,
    monitored_paths: Vec<PathBuf>,
    excluded_paths: Vec<PathBuf>,
    threat_detector: Arc<ThreatDetector>,
    event_sender: mpsc::UnboundedSender<FileEvent>,
    event_receiver: Option<mpsc::UnboundedReceiver<FileEvent>>,
    is_running: Arc<RwLock<bool>>,
    file_operations: Arc<RwLock<HashMap<PathBuf, FileOperationHistory>>>,
}

/// Moniteur de processus
pub struct ProcessMonitor {
    system: System,
    threat_detector: Arc<ThreatDetector>,
    monitored_processes: Arc<RwLock<HashMap<u32, MonitoredProcess>>>,
    process_whitelist: Vec<String>,
    process_blacklist: Vec<String>,
    is_running: Arc<RwLock<bool>>,
    scan_interval: tokio::time::Duration,
}

/// Moniteur réseau
pub struct NetworkMonitor {
    threat_detector: Arc<ThreatDetector>,
    active_connections: Arc<RwLock<HashMap<String, NetworkConnection>>>,
    suspicious_domains: Vec<String>,
    monitored_ports: Vec<u16>,
    is_running: Arc<RwLock<bool>>,
    scan_interval: tokio::time::Duration,
}

/// Événement de fichier
#[derive(Debug, Clone)]
pub struct FileEvent {
    pub event_id: Uuid,
    pub event_type: FileEventType,
    pub file_path: PathBuf,
    pub timestamp: DateTime<Utc>,
    pub process_id: Option<u32>,
    pub file_size: Option<u64>,
    pub file_hash: Option<String>,
    pub entropy: Option<f64>,
}

/// Type d'événement de fichier
#[derive(Debug, Clone, PartialEq)]
pub enum FileEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
    Moved,
    AttributeChanged,
}

/// Historique des opérations sur fichier
#[derive(Debug, Clone)]
struct FileOperationHistory {
    operations: Vec<FileEvent>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    operation_count: u32,
    suspicious_score: f64,
}

/// Processus surveillé
#[derive(Debug, Clone)]
struct MonitoredProcess {
    info: ProcessInfo,
    start_time: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    file_operations: u32,
    network_connections: u32,
    child_processes: Vec<u32>,
    dll_injections: Vec<DllInjection>,
    memory_allocations: Vec<MemoryAllocation>,
    suspicious_score: f64,
}

/// Injection de DLL détectée
#[derive(Debug, Clone)]
struct DllInjection {
    target_process: u32,
    dll_path: PathBuf,
    injection_method: InjectionMethod,
    timestamp: DateTime<Utc>,
}

/// Méthode d'injection
#[derive(Debug, Clone)]
enum InjectionMethod {
    SetWindowsHookEx,
    CreateRemoteThread,
    NtCreateThreadEx,
    ManualDllMapping,
    ProcessHollowing,
    AtomBombing,
}

/// Allocation mémoire suspecte
#[derive(Debug, Clone)]
struct MemoryAllocation {
    address: u64,
    size: usize,
    protection: u32,
    allocation_type: u32,
    timestamp: DateTime<Utc>,
}

/// Connexion réseau
#[derive(Debug, Clone)]
struct NetworkConnection {
    connection_id: String,
    local_address: String,
    remote_address: String,
    local_port: u16,
    remote_port: u16,
    protocol: NetworkProtocol,
    state: ConnectionState,
    process_id: u32,
    start_time: DateTime<Utc>,
    bytes_sent: u64,
    bytes_received: u64,
    is_suspicious: bool,
}

/// Protocole réseau
#[derive(Debug, Clone)]
enum NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    Other(String),
}

/// État de connexion
#[derive(Debug, Clone)]
enum ConnectionState {
    Established,
    Listen,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

impl FileMonitor {
    /// Crée un nouveau moniteur de fichiers
    pub fn new(
        monitored_paths: &[PathBuf],
        threat_detector: Arc<ThreatDetector>,
    ) -> Result<Self> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        Ok(Self {
            watcher: None,
            monitored_paths: monitored_paths.to_vec(),
            excluded_paths: vec![
                PathBuf::from("C:\\Windows\\System32"),
                PathBuf::from("C:\\Program Files\\ERDPS"),
                PathBuf::from("C:\\$Recycle.Bin"),
            ],
            threat_detector,
            event_sender,
            event_receiver: Some(event_receiver),
            is_running: Arc::new(RwLock::new(false)),
            file_operations: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Démarre la surveillance des fichiers
    pub async fn start(&mut self) -> Result<()> {
        info!("🔍 Démarrage de la surveillance des fichiers...");
        
        let mut is_running = self.is_running.write().await;
        if *is_running {
            warn!("⚠️ La surveillance des fichiers est déjà active");
            return Ok(());
        }
        
        // Configuration du watcher
        let event_sender = self.event_sender.clone();
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if let Err(e) = Self::handle_notify_event(event, &event_sender) {
                        error!("❌ Erreur lors du traitement de l'événement: {}", e);
                    }
                },
                Err(e) => error!("❌ Erreur du watcher: {}", e),
            }
        })
        .context("Échec de la création du watcher de fichiers")?;
        
        // Ajout des chemins à surveiller
        for path in &self.monitored_paths {
            if path.exists() {
                watcher.watch(path, RecursiveMode::Recursive)
                    .with_context(|| format!("Échec de la surveillance du chemin: {:?}", path))?;
                info!("📁 Surveillance active: {:?}", path);
            } else {
                warn!("⚠️ Chemin inexistant ignoré: {:?}", path);
            }
        }
        
        self.watcher = Some(watcher);
        *is_running = true;
        
        // Démarrage du processeur d'événements
        if let Some(event_receiver) = self.event_receiver.take() {
            let threat_detector = self.threat_detector.clone();
            let file_operations = self.file_operations.clone();
            let excluded_paths = self.excluded_paths.clone();
            let is_running_clone = self.is_running.clone();
            
            tokio::spawn(async move {
                Self::process_file_events(
                    event_receiver,
                    threat_detector,
                    file_operations,
                    excluded_paths,
                    is_running_clone,
                ).await;
            });
        }
        
        info!("✅ Surveillance des fichiers démarrée");
        Ok(())
    }
    
    /// Arrête la surveillance des fichiers
    pub async fn stop(&mut self) -> Result<()> {
        info!("🛑 Arrêt de la surveillance des fichiers...");
        
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        
        if let Some(watcher) = self.watcher.take() {
            drop(watcher);
        }
        
        info!("✅ Surveillance des fichiers arrêtée");
        Ok(())
    }
    
    /// Traite un événement notify
    fn handle_notify_event(
        event: Event,
        sender: &mpsc::UnboundedSender<FileEvent>,
    ) -> Result<()> {
        let event_type = match event.kind {
            EventKind::Create(_) => FileEventType::Created,
            EventKind::Modify(_) => FileEventType::Modified,
            EventKind::Remove(_) => FileEventType::Deleted,
            _ => return Ok(()), // Ignorer les autres types
        };
        
        for path in event.paths {
            let file_event = FileEvent {
                event_id: Uuid::new_v4(),
                event_type: event_type.clone(),
                file_path: path,
                timestamp: Utc::now(),
                process_id: Self::get_current_process_id(),
                file_size: None, // Sera calculé plus tard
                file_hash: None, // Sera calculé plus tard
                entropy: None,   // Sera calculé plus tard
            };
            
            sender.send(file_event)
                .context("Échec de l'envoi de l'événement de fichier")?;
        }
        
        Ok(())
    }
    
    /// Processeur d'événements de fichiers
    async fn process_file_events(
        mut receiver: mpsc::UnboundedReceiver<FileEvent>,
        mut threat_detector: Arc<ThreatDetector>,
        file_operations: Arc<RwLock<HashMap<PathBuf, FileOperationHistory>>>,
        excluded_paths: Vec<PathBuf>,
        is_running: Arc<RwLock<bool>>,
    ) {
        while *is_running.read().await {
            if let Some(mut event) = receiver.recv().await {
                // Vérifier si le fichier est exclu
                if Self::is_path_excluded(&event.file_path, &excluded_paths) {
                    continue;
                }
                
                // Enrichir l'événement avec des métadonnées
                Self::enrich_file_event(&mut event).await;
                
                // Mettre à jour l'historique
                Self::update_file_history(&event, &file_operations).await;
                
                // Analyser la menace
                if let Ok(Some(threat)) = threat_detector.analyze_file(&event.file_path).await {
                    warn!("🚨 Menace détectée: {:?} - {:?}", threat.threat_type, event.file_path);
                    // Ici, on déclencherait les actions de mitigation
                }
                
                debug!("📄 Événement de fichier traité: {:?}", event);
            }
        }
    }
    
    /// Enrichit un événement de fichier avec des métadonnées
    async fn enrich_file_event(event: &mut FileEvent) {
        // Calculer la taille du fichier
        if let Ok(metadata) = tokio::fs::metadata(&event.file_path).await {
            event.file_size = Some(metadata.len());
        }
        
        // Calculer le hash SHA-256
        if event.file_path.is_file() {
            event.file_hash = Self::calculate_file_hash(&event.file_path).await;
        }
        
        // Calculer l'entropie (indicateur de chiffrement)
        if event.file_path.is_file() {
            event.entropy = Self::calculate_file_entropy(&event.file_path).await;
        }
    }
    
    /// Calcule le hash SHA-256 d'un fichier
    async fn calculate_file_hash(file_path: &Path) -> Option<String> {
        use sha2::{Sha256, Digest};
        use tokio::io::AsyncReadExt;
        
        match tokio::fs::File::open(file_path).await {
            Ok(mut file) => {
                let mut hasher = Sha256::new();
                let mut buffer = [0; 8192];
                
                loop {
                    match file.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => hasher.update(&buffer[..n]),
                        Err(_) => return None,
                    }
                }
                
                Some(format!("{:x}", hasher.finalize()))
            },
            Err(_) => None,
        }
    }
    
    /// Calcule l'entropie d'un fichier
    async fn calculate_file_entropy(file_path: &Path) -> Option<f64> {
        use tokio::io::AsyncReadExt;
        
        match tokio::fs::File::open(file_path).await {
            Ok(mut file) => {
                let mut buffer = vec![0u8; 8192];
                let mut byte_counts = [0u32; 256];
                let mut total_bytes = 0u32;
                
                loop {
                    match file.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => {
                            for &byte in &buffer[..n] {
                                byte_counts[byte as usize] += 1;
                                total_bytes += 1;
                            }
                        },
                        Err(_) => return None,
                    }
                }
                
                if total_bytes == 0 {
                    return Some(0.0);
                }
                
                // Calcul de l'entropie de Shannon
                let mut entropy = 0.0;
                for &count in &byte_counts {
                    if count > 0 {
                        let probability = count as f64 / total_bytes as f64;
                        entropy -= probability * probability.log2();
                    }
                }
                
                Some(entropy)
            },
            Err(_) => None,
        }
    }
    
    /// Met à jour l'historique des opérations sur fichier
    async fn update_file_history(
        event: &FileEvent,
        file_operations: &Arc<RwLock<HashMap<PathBuf, FileOperationHistory>>>,
    ) {
        let mut operations = file_operations.write().await;
        
        let history = operations.entry(event.file_path.clone())
            .or_insert_with(|| FileOperationHistory {
                operations: Vec::new(),
                first_seen: event.timestamp,
                last_seen: event.timestamp,
                operation_count: 0,
                suspicious_score: 0.0,
            });
        
        history.operations.push(event.clone());
        history.last_seen = event.timestamp;
        history.operation_count += 1;
        
        // Calcul du score de suspicion
        history.suspicious_score = Self::calculate_suspicion_score(&history.operations);
    }
    
    /// Calcule un score de suspicion basé sur les opérations
    fn calculate_suspicion_score(operations: &[FileEvent]) -> f64 {
        let mut score = 0.0;
        
        // Facteurs de suspicion:
        // - Nombre d'opérations en peu de temps
        // - Changements d'entropie (chiffrement)
        // - Extensions suspectes
        // - Taille des fichiers
        
        if operations.len() > 10 {
            score += 0.3; // Beaucoup d'opérations
        }
        
        // Vérifier les changements d'entropie
        for window in operations.windows(2) {
            if let (Some(entropy1), Some(entropy2)) = (window[0].entropy, window[1].entropy) {
                if entropy2 > entropy1 + 2.0 {
                    score += 0.4; // Augmentation significative de l'entropie
                }
            }
        }
        
        // Vérifier les extensions suspectes
        for op in operations {
            if let Some(ext) = op.file_path.extension() {
                if ext == "encrypted" || ext == "locked" || ext == "crypto" {
                    score += 0.5;
                }
            }
        }
        
        score.min(1.0) // Limiter à 1.0
    }
    
    /// Vérifie si un chemin est exclu
    fn is_path_excluded(path: &Path, excluded_paths: &[PathBuf]) -> bool {
        excluded_paths.iter().any(|excluded| path.starts_with(excluded))
    }
    
    /// Obtient l'ID du processus actuel
    fn get_current_process_id() -> Option<u32> {
        // Implémentation Windows pour obtenir le PID du processus qui a modifié le fichier
        // Ceci nécessiterait l'utilisation d'APIs Windows avancées
        None
    }
}

impl ProcessMonitor {
    /// Crée un nouveau moniteur de processus
    pub fn new(threat_detector: Arc<ThreatDetector>) -> Result<Self> {
        Ok(Self {
            system: System::new_all(),
            threat_detector,
            monitored_processes: Arc::new(RwLock::new(HashMap::new())),
            process_whitelist: vec![
                "explorer.exe".to_string(),
                "svchost.exe".to_string(),
                "erdps-agent.exe".to_string(),
                "winlogon.exe".to_string(),
                "csrss.exe".to_string(),
            ],
            process_blacklist: vec![
                "mimikatz.exe".to_string(),
                "psexec.exe".to_string(),
                "nc.exe".to_string(),
                "netcat.exe".to_string(),
            ],
            is_running: Arc::new(RwLock::new(false)),
            scan_interval: tokio::time::Duration::from_secs(5),
        })
    }
    
    /// Démarre la surveillance des processus
    pub async fn start(&mut self) -> Result<()> {
        info!("🔍 Démarrage de la surveillance des processus...");
        
        let mut is_running = self.is_running.write().await;
        if *is_running {
            warn!("⚠️ La surveillance des processus est déjà active");
            return Ok(());
        }
        
        *is_running = true;
        
        // Démarrage de la boucle de surveillance
        let threat_detector = self.threat_detector.clone();
        let monitored_processes = self.monitored_processes.clone();
        let process_whitelist = self.process_whitelist.clone();
        let process_blacklist = self.process_blacklist.clone();
        let is_running_clone = self.is_running.clone();
        let scan_interval = self.scan_interval;
        
        tokio::spawn(async move {
            Self::process_monitoring_loop(
                threat_detector,
                monitored_processes,
                process_whitelist,
                process_blacklist,
                is_running_clone,
                scan_interval,
            ).await;
        });
        
        info!("✅ Surveillance des processus démarrée");
        Ok(())
    }
    
    /// Arrête la surveillance des processus
    pub async fn stop(&mut self) -> Result<()> {
        info!("🛑 Arrêt de la surveillance des processus...");
        
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        
        info!("✅ Surveillance des processus arrêtée");
        Ok(())
    }
    
    /// Boucle principale de surveillance des processus
    async fn process_monitoring_loop(
        mut threat_detector: Arc<ThreatDetector>,
        monitored_processes: Arc<RwLock<HashMap<u32, MonitoredProcess>>>,
        process_whitelist: Vec<String>,
        process_blacklist: Vec<String>,
        is_running: Arc<RwLock<bool>>,
        scan_interval: tokio::time::Duration,
    ) {
        let mut interval = tokio::time::interval(scan_interval);
        let mut system = System::new_all();
        
        while *is_running.read().await {
            interval.tick().await;
            
            // Rafraîchir les informations système
            system.refresh_all();
            
            // Analyser tous les processus
            for (pid, process) in system.processes() {
                let process_name = process.name();
                
                // Vérifier la liste noire
                if process_blacklist.iter().any(|name| process_name.contains(name)) {
                    warn!("🚨 Processus en liste noire détecté: {} (PID: {})", process_name, pid);
                    // Déclencher une alerte immédiate
                }
                
                // Ignorer les processus en liste blanche
                if process_whitelist.iter().any(|name| process_name.contains(name)) {
                    continue;
                }
                
                // Créer les informations du processus
                let process_info = ProcessInfo {
                    pid: pid.as_u32(),
                    name: process_name.to_string(),
                    path: process.exe().unwrap_or(Path::new("")).to_path_buf(),
                    command_line: process.cmd().join(" "),
                    parent_pid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                    user: process.user_id().map(|u| u.to_string()).unwrap_or_default(),
                    start_time: Utc::now(), // Approximation
                    hash: None, // Sera calculé si nécessaire
                };
                
                // Analyser le processus pour détecter des menaces
                if let Ok(Some(threat)) = threat_detector.analyze_process(&process_info).await {
                    warn!("🚨 Menace détectée dans le processus: {} - {:?}", 
                          process_name, threat.threat_type);
                }
                
                // Mettre à jour le processus surveillé
                Self::update_monitored_process(pid.as_u32(), &process_info, &monitored_processes).await;
            }
        }
    }
    
    /// Met à jour un processus surveillé
    async fn update_monitored_process(
        pid: u32,
        process_info: &ProcessInfo,
        monitored_processes: &Arc<RwLock<HashMap<u32, MonitoredProcess>>>,
    ) {
        let mut processes = monitored_processes.write().await;
        
        let monitored = processes.entry(pid)
            .or_insert_with(|| MonitoredProcess {
                info: process_info.clone(),
                start_time: Utc::now(),
                last_seen: Utc::now(),
                file_operations: 0,
                network_connections: 0,
                child_processes: Vec::new(),
                dll_injections: Vec::new(),
                memory_allocations: Vec::new(),
                suspicious_score: 0.0,
            });
        
        monitored.last_seen = Utc::now();
        // Mettre à jour d'autres métriques selon les besoins
    }
}

impl NetworkMonitor {
    /// Crée un nouveau moniteur réseau
    pub fn new(threat_detector: Arc<ThreatDetector>) -> Result<Self> {
        Ok(Self {
            threat_detector,
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            suspicious_domains: vec![
                "tor2web.org".to_string(),
                "onion.to".to_string(),
                "bit.ly".to_string(), // Raccourcisseurs d'URL suspects
            ],
            monitored_ports: vec![80, 443, 21, 22, 23, 25, 53, 135, 139, 445, 3389],
            is_running: Arc::new(RwLock::new(false)),
            scan_interval: tokio::time::Duration::from_secs(10),
        })
    }
    
    /// Démarre la surveillance réseau
    pub async fn start(&mut self) -> Result<()> {
        info!("🔍 Démarrage de la surveillance réseau...");
        
        let mut is_running = self.is_running.write().await;
        if *is_running {
            warn!("⚠️ La surveillance réseau est déjà active");
            return Ok(());
        }
        
        *is_running = true;
        
        // Démarrage de la boucle de surveillance
        let threat_detector = self.threat_detector.clone();
        let active_connections = self.active_connections.clone();
        let suspicious_domains = self.suspicious_domains.clone();
        let monitored_ports = self.monitored_ports.clone();
        let is_running_clone = self.is_running.clone();
        let scan_interval = self.scan_interval;
        
        tokio::spawn(async move {
            Self::network_monitoring_loop(
                threat_detector,
                active_connections,
                suspicious_domains,
                monitored_ports,
                is_running_clone,
                scan_interval,
            ).await;
        });
        
        info!("✅ Surveillance réseau démarrée");
        Ok(())
    }
    
    /// Arrête la surveillance réseau
    pub async fn stop(&mut self) -> Result<()> {
        info!("🛑 Arrêt de la surveillance réseau...");
        
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        
        info!("✅ Surveillance réseau arrêtée");
        Ok(())
    }
    
    /// Boucle principale de surveillance réseau
    async fn network_monitoring_loop(
        mut threat_detector: Arc<ThreatDetector>,
        active_connections: Arc<RwLock<HashMap<String, NetworkConnection>>>,
        suspicious_domains: Vec<String>,
        monitored_ports: Vec<u16>,
        is_running: Arc<RwLock<bool>>,
        scan_interval: tokio::time::Duration,
    ) {
        let mut interval = tokio::time::interval(scan_interval);
        
        while *is_running.read().await {
            interval.tick().await;
            
            // Analyser les connexions réseau actives
            // Implémentation simplifiée - nécessiterait l'utilisation d'APIs Windows
            // pour obtenir les vraies connexions réseau
            
            debug!("🌐 Scan des connexions réseau...");
            
            // Ici, on utiliserait des APIs comme GetTcpTable2, GetUdpTable, etc.
            // pour obtenir les vraies connexions réseau
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_file_monitor_creation() {
        let temp_dir = tempdir().unwrap();
        let paths = vec![temp_dir.path().to_path_buf()];
        
        // Mock threat detector
        let config = crate::config::DetectionConfig {
            yara_enabled: false,
            yara_rules_path: PathBuf::from("test"),
            behavioral_detection: true,
            detection_threshold: 0.8,
            heuristics: crate::config::HeuristicsConfig {
                detect_mass_encryption: true,
                encryption_threshold: 10,
                time_window: 300,
                detect_extension_changes: true,
                detect_ransom_notes: true,
                ransom_note_patterns: vec![],
            },
            auto_actions: crate::config::AutoActionsConfig {
                auto_isolate: false,
                auto_kill_processes: false,
                auto_backup: false,
                backup_path: PathBuf::from("test"),
                immediate_notification: true,
            },
        };
        
        let threat_detector = Arc::new(
            crate::detection::ThreatDetector::new(&config).await.unwrap()
        );
        
        let monitor = FileMonitor::new(&paths, threat_detector);
        assert!(monitor.is_ok());
    }
    
    #[test]
    fn test_file_event_creation() {
        let event = FileEvent {
            event_id: Uuid::new_v4(),
            event_type: FileEventType::Created,
            file_path: PathBuf::from("test.txt"),
            timestamp: Utc::now(),
            process_id: Some(1234),
            file_size: Some(1024),
            file_hash: Some("abc123".to_string()),
            entropy: Some(7.5),
        };
        
        assert_eq!(event.event_type, FileEventType::Created);
        assert_eq!(event.file_path, PathBuf::from("test.txt"));
    }
}