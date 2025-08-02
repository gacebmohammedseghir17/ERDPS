//! Moteur de détection YARA pour ERDPS
//! 
//! Ce module implémente le moteur de détection basé sur les règles YARA
//! pour identifier les signatures de ransomware et autres malwares.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use log::{debug, error, info, warn};

/// Configuration du moteur YARA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraConfig {
    /// Répertoire des règles YARA
    pub rules_directory: PathBuf,
    /// Intervalle de mise à jour des règles (en secondes)
    pub update_interval: u64,
    /// Timeout pour l'analyse d'un fichier (en millisecondes)
    pub scan_timeout: u64,
    /// Taille maximale de fichier à analyser (en bytes)
    pub max_file_size: u64,
    /// Extensions de fichiers à analyser
    pub file_extensions: Vec<String>,
    /// Répertoires à exclure de l'analyse
    pub excluded_directories: Vec<PathBuf>,
    /// Activer l'analyse en temps réel
    pub real_time_scanning: bool,
    /// Nombre maximum de threads pour l'analyse
    pub max_threads: usize,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            rules_directory: PathBuf::from("./rules"),
            update_interval: 300, // 5 minutes
            scan_timeout: 30000,  // 30 secondes
            max_file_size: 100 * 1024 * 1024, // 100 MB
            file_extensions: vec![
                ".exe".to_string(), ".dll".to_string(), ".bat".to_string(),
                ".cmd".to_string(), ".ps1".to_string(), ".vbs".to_string(),
                ".js".to_string(), ".jar".to_string(), ".scr".to_string()
            ],
            excluded_directories: vec![
                PathBuf::from("C:\\Windows\\System32"),
                PathBuf::from("C:\\Windows\\SysWOW64"),
                PathBuf::from("C:\\Program Files\\Windows Defender")
            ],
            real_time_scanning: true,
            max_threads: 4,
        }
    }
}

/// Résultat d'une détection YARA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// ID unique de la détection
    pub id: String,
    /// Nom de la règle qui a matché
    pub rule_name: String,
    /// Namespace de la règle
    pub namespace: String,
    /// Tags associés à la règle
    pub tags: Vec<String>,
    /// Métadonnées de la règle
    pub metadata: HashMap<String, String>,
    /// Chemin du fichier analysé
    pub file_path: PathBuf,
    /// Taille du fichier
    pub file_size: u64,
    /// Hash MD5 du fichier
    pub file_hash: String,
    /// Timestamp de la détection
    pub timestamp: u64,
    /// Niveau de criticité (1-10)
    pub severity: u8,
    /// Strings qui ont matché
    pub matched_strings: Vec<MatchedString>,
    /// Temps d'analyse en millisecondes
    pub scan_duration: u64,
}

/// String qui a matché dans une règle YARA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedString {
    /// Identifiant de la string
    pub identifier: String,
    /// Offset dans le fichier
    pub offset: u64,
    /// Longueur de la string
    pub length: u32,
    /// Données matchées (tronquées si trop longues)
    pub data: Vec<u8>,
}

/// Statistiques du moteur YARA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStats {
    /// Nombre total de fichiers analysés
    pub files_scanned: u64,
    /// Nombre total de détections
    pub total_detections: u64,
    /// Nombre de règles chargées
    pub rules_loaded: u32,
    /// Dernière mise à jour des règles
    pub last_rules_update: u64,
    /// Temps moyen d'analyse par fichier (ms)
    pub avg_scan_time: f64,
    /// Nombre d'erreurs d'analyse
    pub scan_errors: u64,
    /// Taille totale des fichiers analysés
    pub total_bytes_scanned: u64,
    /// Détections par niveau de criticité
    pub detections_by_severity: HashMap<u8, u64>,
}

impl Default for YaraStats {
    fn default() -> Self {
        Self {
            files_scanned: 0,
            total_detections: 0,
            rules_loaded: 0,
            last_rules_update: 0,
            avg_scan_time: 0.0,
            scan_errors: 0,
            total_bytes_scanned: 0,
            detections_by_severity: HashMap::new(),
        }
    }
}

/// État du moteur YARA
#[derive(Debug, Clone, PartialEq)]
pub enum YaraEngineState {
    Stopped,
    Starting,
    Running,
    Updating,
    Error(String),
}

/// Moteur de détection YARA
pub struct YaraEngine {
    config: YaraConfig,
    state: Arc<RwLock<YaraEngineState>>,
    stats: Arc<RwLock<YaraStats>>,
    rules_version: Arc<RwLock<String>>,
    detection_sender: Option<mpsc::UnboundedSender<YaraMatch>>,
    shutdown_sender: Option<mpsc::Sender<()>>,
}

impl YaraEngine {
    /// Crée une nouvelle instance du moteur YARA
    pub fn new(config: YaraConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(YaraEngineState::Stopped)),
            stats: Arc::new(RwLock::new(YaraStats::default())),
            rules_version: Arc::new(RwLock::new(String::new())),
            detection_sender: None,
            shutdown_sender: None,
        }
    }

    /// Démarre le moteur YARA
    pub async fn start(&mut self, detection_sender: mpsc::UnboundedSender<YaraMatch>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting YARA engine...");
        
        {
            let mut state = self.state.write().unwrap();
            *state = YaraEngineState::Starting;
        }

        // Charger les règles initiales
        self.load_rules().await?;

        self.detection_sender = Some(detection_sender);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_sender = Some(shutdown_tx);

        // Démarrer la tâche de mise à jour des règles
        let config = self.config.clone();
        let state = Arc::clone(&self.state);
        let stats = Arc::clone(&self.stats);
        let rules_version = Arc::clone(&self.rules_version);
        
        tokio::spawn(async move {
            let mut update_interval = interval(Duration::from_secs(config.update_interval));
            
            loop {
                tokio::select! {
                    _ = update_interval.tick() => {
                        if let Err(e) = Self::update_rules_task(&config, &state, &stats, &rules_version).await {
                            error!("Failed to update YARA rules: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("YARA engine update task shutting down");
                        break;
                    }
                }
            }
        });

        {
            let mut state = self.state.write().unwrap();
            *state = YaraEngineState::Running;
        }

        info!("YARA engine started successfully");
        Ok(())
    }

    /// Arrête le moteur YARA
    pub async fn stop(&mut self) {
        info!("Stopping YARA engine...");
        
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(()).await;
        }

        {
            let mut state = self.state.write().unwrap();
            *state = YaraEngineState::Stopped;
        }

        info!("YARA engine stopped");
    }

    /// Analyse un fichier avec les règles YARA
    pub async fn scan_file(&self, file_path: &Path) -> Result<Vec<YaraMatch>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        // Vérifier si le fichier doit être analysé
        if !self.should_scan_file(file_path) {
            return Ok(vec![]);
        }

        debug!("Scanning file: {:?}", file_path);

        // Simuler l'analyse YARA (dans une vraie implémentation, utiliser la librairie YARA)
        let matches = self.simulate_yara_scan(file_path).await?;
        
        let scan_duration = start_time.elapsed().as_millis() as u64;
        
        // Mettre à jour les statistiques
        self.update_scan_stats(file_path, scan_duration, matches.len()).await;
        
        // Envoyer les détections
        if !matches.is_empty() {
            for detection in &matches {
                if let Some(sender) = &self.detection_sender {
                    let _ = sender.send(detection.clone());
                }
            }
        }

        Ok(matches)
    }

    /// Vérifie si un fichier doit être analysé
    fn should_scan_file(&self, file_path: &Path) -> bool {
        // Vérifier l'extension
        if let Some(extension) = file_path.extension() {
            let ext_str = format!(".{}", extension.to_string_lossy().to_lowercase());
            if !self.config.file_extensions.contains(&ext_str) {
                return false;
            }
        } else {
            return false;
        }

        // Vérifier les répertoires exclus
        for excluded_dir in &self.config.excluded_directories {
            if file_path.starts_with(excluded_dir) {
                return false;
            }
        }

        // Vérifier la taille du fichier
        if let Ok(metadata) = std::fs::metadata(file_path) {
            if metadata.len() > self.config.max_file_size {
                return false;
            }
        }

        true
    }

    /// Simule une analyse YARA (à remplacer par la vraie implémentation)
    async fn simulate_yara_scan(&self, file_path: &Path) -> Result<Vec<YaraMatch>, Box<dyn std::error::Error + Send + Sync>> {
        // Simuler un délai d'analyse
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        let mut matches = Vec::new();
        
        // Simuler des détections basées sur le nom du fichier
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
            
        if file_name.contains("ransom") || file_name.contains("crypt") || file_name.contains("lock") {
            let file_size = std::fs::metadata(file_path)?.len();
            let file_hash = format!("{:x}", md5::compute(file_path.to_string_lossy().as_bytes()));
            
            let yara_match = YaraMatch {
                id: Uuid::new_v4().to_string(),
                rule_name: "ransomware_detection".to_string(),
                namespace: "erdps".to_string(),
                tags: vec!["ransomware".to_string(), "malware".to_string()],
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("author".to_string(), "ERDPS Team".to_string());
                    meta.insert("description".to_string(), "Potential ransomware detected".to_string());
                    meta
                },
                file_path: file_path.to_path_buf(),
                file_size,
                file_hash,
                timestamp: chrono::Utc::now().timestamp() as u64,
                severity: 9,
                matched_strings: vec![
                    MatchedString {
                        identifier: "$ransom_string".to_string(),
                        offset: 0,
                        length: file_name.len() as u32,
                        data: file_name.as_bytes().to_vec(),
                    }
                ],
                scan_duration: 10,
            };
            
            matches.push(yara_match);
        }
        
        Ok(matches)
    }

    /// Charge les règles YARA depuis le répertoire
    async fn load_rules(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Loading YARA rules from: {:?}", self.config.rules_directory);
        
        {
            let mut state = self.state.write().unwrap();
            *state = YaraEngineState::Updating;
        }

        // Simuler le chargement des règles
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let rules_count = 42; // Simuler 42 règles chargées
        let version = format!("v{}", chrono::Utc::now().timestamp());
        
        {
            let mut stats = self.stats.write().unwrap();
            stats.rules_loaded = rules_count;
            stats.last_rules_update = chrono::Utc::now().timestamp() as u64;
        }
        
        {
            let mut rules_version = self.rules_version.write().unwrap();
            *rules_version = version.clone();
        }
        
        {
            let mut state = self.state.write().unwrap();
            *state = YaraEngineState::Running;
        }
        
        info!("Loaded {} YARA rules, version: {}", rules_count, version);
        Ok(())
    }

    /// Tâche de mise à jour des règles
    async fn update_rules_task(
        config: &YaraConfig,
        state: &Arc<RwLock<YaraEngineState>>,
        stats: &Arc<RwLock<YaraStats>>,
        rules_version: &Arc<RwLock<String>>
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Checking for YARA rules updates...");
        
        // Simuler la vérification de mise à jour
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        // Dans une vraie implémentation, vérifier si de nouvelles règles sont disponibles
        // et les télécharger/compiler si nécessaire
        
        Ok(())
    }

    /// Met à jour les statistiques d'analyse
    async fn update_scan_stats(&self, file_path: &Path, scan_duration: u64, detections_count: usize) {
        let mut stats = self.stats.write().unwrap();
        
        stats.files_scanned += 1;
        stats.total_detections += detections_count as u64;
        
        if let Ok(metadata) = std::fs::metadata(file_path) {
            stats.total_bytes_scanned += metadata.len();
        }
        
        // Calculer le temps moyen d'analyse
        let total_time = stats.avg_scan_time * (stats.files_scanned - 1) as f64 + scan_duration as f64;
        stats.avg_scan_time = total_time / stats.files_scanned as f64;
    }

    /// Récupère l'état actuel du moteur
    pub fn get_state(&self) -> YaraEngineState {
        self.state.read().unwrap().clone()
    }

    /// Récupère les statistiques du moteur
    pub fn get_stats(&self) -> YaraStats {
        self.stats.read().unwrap().clone()
    }

    /// Récupère la version des règles
    pub fn get_rules_version(&self) -> String {
        self.rules_version.read().unwrap().clone()
    }

    /// Force une mise à jour des règles
    pub async fn force_rules_update(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Forcing YARA rules update...");
        self.load_rules().await
    }

    /// Vérifie si le moteur est en cours d'exécution
    pub fn is_running(&self) -> bool {
        matches!(*self.state.read().unwrap(), YaraEngineState::Running)
    }

    /// Récupère la configuration actuelle
    pub fn get_config(&self) -> &YaraConfig {
        &self.config
    }

    /// Met à jour la configuration
    pub fn update_config(&mut self, new_config: YaraConfig) {
        self.config = new_config;
        info!("YARA engine configuration updated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[tokio::test]
    async fn test_yara_engine_creation() {
        let config = YaraConfig::default();
        let engine = YaraEngine::new(config);
        
        assert_eq!(engine.get_state(), YaraEngineState::Stopped);
        assert!(!engine.is_running());
    }

    #[tokio::test]
    async fn test_should_scan_file() {
        let config = YaraConfig::default();
        let engine = YaraEngine::new(config);
        
        // Test avec une extension valide
        let exe_path = Path::new("test.exe");
        assert!(engine.should_scan_file(exe_path));
        
        // Test avec une extension invalide
        let txt_path = Path::new("test.txt");
        assert!(!engine.should_scan_file(txt_path));
    }

    #[tokio::test]
    async fn test_simulate_yara_scan() {
        let config = YaraConfig::default();
        let engine = YaraEngine::new(config);
        
        // Créer un fichier temporaire avec un nom suspect
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("ransomware.exe");
        fs::write(&file_path, b"test content").unwrap();
        
        let matches = engine.simulate_yara_scan(&file_path).await.unwrap();
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_name, "ransomware_detection");
        assert_eq!(matches[0].severity, 9);
    }

    #[tokio::test]
    async fn test_stats_update() {
        let config = YaraConfig::default();
        let engine = YaraEngine::new(config);
        
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.exe");
        fs::write(&file_path, b"test content").unwrap();
        
        engine.update_scan_stats(&file_path, 100, 1).await;
        
        let stats = engine.get_stats();
        assert_eq!(stats.files_scanned, 1);
        assert_eq!(stats.total_detections, 1);
        assert_eq!(stats.avg_scan_time, 100.0);
    }
}