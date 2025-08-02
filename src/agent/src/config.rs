//! Configuration management for ERDPS Agent
//!
//! Gestion de la configuration de l'agent ERDPS
//! Support pour fichiers TOML, variables d'environnement et arguments CLI
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

/// Configuration principale de l'agent ERDPS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Informations de base de l'agent
    pub agent: AgentInfo,
    
    /// Configuration du serveur ERDPS
    pub server: ServerConfig,
    
    /// Configuration de la surveillance
    pub monitoring: MonitoringConfig,
    
    /// Configuration de la détection
    pub detection: DetectionConfig,
    
    /// Configuration de la sécurité
    pub security: SecurityConfig,
    
    /// Configuration du logging
    pub logging: LoggingConfig,
    
    /// Configuration de performance
    pub performance: PerformanceConfig,
    
    /// Configuration des exclusions
    pub exclusions: ExclusionConfig,
}

/// Informations de base de l'agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Identifiant unique de l'agent
    pub id: String,
    
    /// Nom de l'agent
    pub name: String,
    
    /// Version de l'agent
    pub version: String,
    
    /// Groupe d'agents (pour l'organisation)
    pub group: String,
    
    /// Tags personnalisés
    pub tags: HashMap<String, String>,
    
    /// Description de l'agent
    pub description: String,
}

/// Configuration du serveur ERDPS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Endpoint du serveur ERDPS
    pub endpoint: String,
    
    /// Port du serveur
    pub port: u16,
    
    /// Utilisation de TLS
    pub use_tls: bool,
    
    /// Chemin vers le certificat client
    pub client_cert_path: Option<PathBuf>,
    
    /// Chemin vers la clé privée client
    pub client_key_path: Option<PathBuf>,
    
    /// Chemin vers le certificat CA
    pub ca_cert_path: Option<PathBuf>,
    
    /// Vérification du certificat serveur
    pub verify_server_cert: bool,
    
    /// Timeout de connexion (secondes)
    pub connection_timeout_seconds: u64,
    
    /// Timeout de requête (secondes)
    pub request_timeout_seconds: u64,
    
    /// Nombre de tentatives de reconnexion
    pub max_retry_attempts: u32,
    
    /// Délai entre les tentatives (secondes)
    pub retry_delay_seconds: u64,
    
    /// Intervalle de heartbeat (secondes)
    pub heartbeat_interval_seconds: u64,
    
    /// Intervalle de rapport (secondes)
    pub reporting_interval_seconds: u64,
}

/// Configuration de la surveillance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Surveillance des fichiers activée
    pub enable_file_monitoring: bool,
    
    /// Surveillance des processus activée
    pub enable_process_monitoring: bool,
    
    /// Surveillance du réseau activée
    pub enable_network_monitoring: bool,
    
    /// Surveillance du registre activée
    pub enable_registry_monitoring: bool,
    
    /// Configuration de surveillance des fichiers
    pub file_monitoring: FileMonitoringConfig,
    
    /// Configuration de surveillance des processus
    pub process_monitoring: ProcessMonitoringConfig,
    
    /// Configuration de surveillance du réseau
    pub network_monitoring: NetworkMonitoringConfig,
    
    /// Configuration de surveillance du registre
    pub registry_monitoring: RegistryMonitoringConfig,
}

/// Configuration de surveillance des fichiers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitoringConfig {
    /// Répertoires à surveiller
    pub monitored_directories: Vec<PathBuf>,
    
    /// Extensions de fichiers à surveiller
    pub monitored_extensions: Vec<String>,
    
    /// Extensions suspectes
    pub suspicious_extensions: Vec<String>,
    
    /// Taille maximale de fichier à analyser (bytes)
    pub max_file_size_bytes: u64,
    
    /// Calcul d'entropie activé
    pub enable_entropy_calculation: bool,
    
    /// Seuil d'entropie pour détection
    pub entropy_threshold: f64,
    
    /// Surveillance des répertoires protégés
    pub monitor_protected_directories: bool,
    
    /// Répertoires protégés
    pub protected_directories: Vec<PathBuf>,
    
    /// Détection de renommage en masse
    pub detect_mass_rename: bool,
    
    /// Seuil de renommage en masse
    pub mass_rename_threshold: u32,
    
    /// Fenêtre de temps pour détection (secondes)
    pub mass_rename_time_window_seconds: u64,
}

/// Configuration de surveillance des processus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitoringConfig {
    /// Surveillance de création de processus
    pub monitor_process_creation: bool,
    
    /// Surveillance de terminaison de processus
    pub monitor_process_termination: bool,
    
    /// Détection d'injection de processus
    pub detect_process_injection: bool,
    
    /// Détection de process hollowing
    pub detect_process_hollowing: bool,
    
    /// Surveillance des modifications mémoire
    pub monitor_memory_modifications: bool,
    
    /// Processus à surveiller spécifiquement
    pub monitored_processes: Vec<String>,
    
    /// Processus de confiance (whitelist)
    pub trusted_processes: Vec<String>,
    
    /// Surveillance des processus système
    pub monitor_system_processes: bool,
    
    /// Détection de privilège escalation
    pub detect_privilege_escalation: bool,
}

/// Configuration de surveillance du réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitoringConfig {
    /// Surveillance des connexions TCP
    pub monitor_tcp_connections: bool,
    
    /// Surveillance des connexions UDP
    pub monitor_udp_connections: bool,
    
    /// Détection de communication C2
    pub detect_c2_communication: bool,
    
    /// Détection d'exfiltration de données
    pub detect_data_exfiltration: bool,
    
    /// Surveillance du trafic DNS
    pub monitor_dns_traffic: bool,
    
    /// Ports suspects à surveiller
    pub suspicious_ports: Vec<u16>,
    
    /// Domaines suspects
    pub suspicious_domains: Vec<String>,
    
    /// IPs suspectes
    pub suspicious_ips: Vec<String>,
    
    /// Seuil de trafic pour alerte (bytes/sec)
    pub traffic_threshold_bytes_per_sec: u64,
    
    /// Surveillance des connexions sortantes
    pub monitor_outbound_connections: bool,
    
    /// Surveillance des connexions entrantes
    pub monitor_inbound_connections: bool,
}

/// Configuration de surveillance du registre
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryMonitoringConfig {
    /// Surveillance des clés de démarrage
    pub monitor_startup_keys: bool,
    
    /// Surveillance des clés de sécurité
    pub monitor_security_keys: bool,
    
    /// Surveillance des clés système
    pub monitor_system_keys: bool,
    
    /// Clés spécifiques à surveiller
    pub monitored_keys: Vec<String>,
    
    /// Clés critiques (haute priorité)
    pub critical_keys: Vec<String>,
    
    /// Détection de persistance malveillante
    pub detect_malicious_persistence: bool,
    
    /// Surveillance des modifications de politique
    pub monitor_policy_changes: bool,
}

/// Configuration de la détection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Moteur de détection comportementale activé
    pub enable_behavioral_detection: bool,
    
    /// Intégration YARA activée
    pub enable_yara_integration: bool,
    
    /// Chemin vers les règles YARA
    pub yara_rules_path: PathBuf,
    
    /// Mise à jour automatique des règles YARA
    pub auto_update_yara_rules: bool,
    
    /// Configuration du scoring de risque
    pub risk_scoring: RiskScoringConfig,
    
    /// Configuration des heuristiques
    pub heuristics: HeuristicsConfig,
    
    /// Seuils de détection
    pub detection_thresholds: DetectionThresholds,
}

/// Configuration du scoring de risque
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoringConfig {
    /// Score maximum
    pub max_score: u32,
    
    /// Seuil pour alerte faible
    pub low_risk_threshold: u32,
    
    /// Seuil pour alerte moyenne
    pub medium_risk_threshold: u32,
    
    /// Seuil pour alerte élevée
    pub high_risk_threshold: u32,
    
    /// Seuil pour alerte critique
    pub critical_risk_threshold: u32,
    
    /// Décroissance du score dans le temps
    pub score_decay_rate: f64,
    
    /// Fenêtre de temps pour le scoring (secondes)
    pub scoring_time_window_seconds: u64,
}

/// Configuration des heuristiques
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicsConfig {
    /// Détection de chiffrement en masse
    pub detect_mass_encryption: bool,
    
    /// Seuil de fichiers chiffrés
    pub mass_encryption_threshold: u32,
    
    /// Détection de suppression de shadow copies
    pub detect_shadow_copy_deletion: bool,
    
    /// Détection de modification de boot record
    pub detect_boot_record_modification: bool,
    
    /// Détection de désactivation de sécurité
    pub detect_security_software_tampering: bool,
    
    /// Détection de création de notes de rançon
    pub detect_ransom_note_creation: bool,
    
    /// Patterns de notes de rançon
    pub ransom_note_patterns: Vec<String>,
}

/// Seuils de détection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionThresholds {
    /// Seuil d'entropie pour fichiers suspects
    pub entropy_threshold: f64,
    
    /// Nombre de fichiers pour détection de masse
    pub mass_file_threshold: u32,
    
    /// Fenêtre de temps pour détection (secondes)
    pub detection_time_window_seconds: u64,
    
    /// Seuil de processus suspects
    pub suspicious_process_threshold: u32,
    
    /// Seuil de connexions réseau suspectes
    pub suspicious_network_threshold: u32,
}

/// Configuration de la sécurité
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Chiffrement des communications activé
    pub enable_encryption: bool,
    
    /// Algorithme de chiffrement
    pub encryption_algorithm: String,
    
    /// Taille de clé de chiffrement
    pub encryption_key_size: u32,
    
    /// Authentification mutuelle activée
    pub enable_mutual_authentication: bool,
    
    /// Validation de certificat activée
    pub enable_certificate_validation: bool,
    
    /// Rotation automatique des clés
    pub enable_key_rotation: bool,
    
    /// Intervalle de rotation des clés (heures)
    pub key_rotation_interval_hours: u64,
    
    /// Protection contre le tampering
    pub enable_tamper_protection: bool,
    
    /// Auto-protection de l'agent
    pub enable_self_protection: bool,
}

/// Configuration du logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Niveau de log
    pub level: String,
    
    /// Logging vers fichier activé
    pub enable_file_logging: bool,
    
    /// Chemin du fichier de log
    pub log_file_path: PathBuf,
    
    /// Taille maximale du fichier de log (MB)
    pub max_log_file_size_mb: u64,
    
    /// Nombre de fichiers de log à conserver
    pub max_log_files: u32,
    
    /// Logging vers console activé
    pub enable_console_logging: bool,
    
    /// Logging vers serveur activé
    pub enable_remote_logging: bool,
    
    /// Format des logs
    pub log_format: String,
    
    /// Inclusion des informations de thread
    pub include_thread_info: bool,
    
    /// Inclusion du timestamp
    pub include_timestamp: bool,
}

/// Configuration de performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Nombre de threads de travail
    pub worker_threads: u32,
    
    /// Taille du buffer d'événements
    pub event_buffer_size: u32,
    
    /// Taille de la queue de traitement
    pub processing_queue_size: u32,
    
    /// Limite d'utilisation CPU (%)
    pub cpu_usage_limit_percent: u32,
    
    /// Limite d'utilisation mémoire (MB)
    pub memory_usage_limit_mb: u64,
    
    /// Intervalle de nettoyage (secondes)
    pub cleanup_interval_seconds: u64,
    
    /// Optimisation pour SSD
    pub optimize_for_ssd: bool,
    
    /// Cache des métadonnées de fichiers
    pub enable_file_metadata_cache: bool,
    
    /// Taille du cache (entrées)
    pub cache_size: u32,
}

/// Configuration des exclusions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionConfig {
    /// Répertoires exclus de la surveillance
    pub excluded_directories: Vec<PathBuf>,
    
    /// Fichiers exclus de la surveillance
    pub excluded_files: Vec<PathBuf>,
    
    /// Extensions exclues
    pub excluded_extensions: Vec<String>,
    
    /// Processus exclus
    pub excluded_processes: Vec<String>,
    
    /// IPs exclues
    pub excluded_ips: Vec<String>,
    
    /// Domaines exclus
    pub excluded_domains: Vec<String>,
    
    /// Clés de registre exclues
    pub excluded_registry_keys: Vec<String>,
    
    /// Patterns d'exclusion (regex)
    pub exclusion_patterns: Vec<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent: AgentInfo::default(),
            server: ServerConfig::default(),
            monitoring: MonitoringConfig::default(),
            detection: DetectionConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            performance: PerformanceConfig::default(),
            exclusions: ExclusionConfig::default(),
        }
    }
}

impl Default for AgentInfo {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: format!("ERDPS-Agent-{}", hostname::get().unwrap_or_default().to_string_lossy()),
            version: "1.0.0".to_string(),
            group: "default".to_string(),
            tags: HashMap::new(),
            description: "ERDPS Agent for ransomware detection and prevention".to_string(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://erdps-server.local".to_string(),
            port: 8443,
            use_tls: true,
            client_cert_path: Some(PathBuf::from("certs/client.crt")),
            client_key_path: Some(PathBuf::from("certs/client.key")),
            ca_cert_path: Some(PathBuf::from("certs/ca.crt")),
            verify_server_cert: true,
            connection_timeout_seconds: 30,
            request_timeout_seconds: 60,
            max_retry_attempts: 3,
            retry_delay_seconds: 5,
            heartbeat_interval_seconds: 60,
            reporting_interval_seconds: 300,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enable_file_monitoring: true,
            enable_process_monitoring: true,
            enable_network_monitoring: true,
            enable_registry_monitoring: true,
            file_monitoring: FileMonitoringConfig::default(),
            process_monitoring: ProcessMonitoringConfig::default(),
            network_monitoring: NetworkMonitoringConfig::default(),
            registry_monitoring: RegistryMonitoringConfig::default(),
        }
    }
}

impl Default for FileMonitoringConfig {
    fn default() -> Self {
        Self {
            monitored_directories: vec![
                PathBuf::from("C:\\Users"),
                PathBuf::from("C:\\Documents and Settings"),
                PathBuf::from("D:\\"),
                PathBuf::from("E:\\"),
            ],
            monitored_extensions: vec![
                ".doc".to_string(), ".docx".to_string(), ".xls".to_string(), ".xlsx".to_string(),
                ".ppt".to_string(), ".pptx".to_string(), ".pdf".to_string(), ".txt".to_string(),
                ".jpg".to_string(), ".jpeg".to_string(), ".png".to_string(), ".gif".to_string(),
                ".mp4".to_string(), ".avi".to_string(), ".mp3".to_string(), ".wav".to_string(),
            ],
            suspicious_extensions: vec![
                ".encrypted".to_string(), ".locked".to_string(), ".crypto".to_string(),
                ".crypt".to_string(), ".enc".to_string(), ".vault".to_string(),
            ],
            max_file_size_bytes: 100 * 1024 * 1024, // 100 MB
            enable_entropy_calculation: true,
            entropy_threshold: 7.5,
            monitor_protected_directories: true,
            protected_directories: vec![
                PathBuf::from("C:\\Windows\\System32"),
                PathBuf::from("C:\\Program Files"),
                PathBuf::from("C:\\Program Files (x86)"),
            ],
            detect_mass_rename: true,
            mass_rename_threshold: 50,
            mass_rename_time_window_seconds: 300,
        }
    }
}

impl Default for ProcessMonitoringConfig {
    fn default() -> Self {
        Self {
            monitor_process_creation: true,
            monitor_process_termination: true,
            detect_process_injection: true,
            detect_process_hollowing: true,
            monitor_memory_modifications: true,
            monitored_processes: vec![
                "powershell.exe".to_string(),
                "cmd.exe".to_string(),
                "wscript.exe".to_string(),
                "cscript.exe".to_string(),
            ],
            trusted_processes: vec![
                "explorer.exe".to_string(),
                "winlogon.exe".to_string(),
                "csrss.exe".to_string(),
            ],
            monitor_system_processes: true,
            detect_privilege_escalation: true,
        }
    }
}

impl Default for NetworkMonitoringConfig {
    fn default() -> Self {
        Self {
            monitor_tcp_connections: true,
            monitor_udp_connections: true,
            detect_c2_communication: true,
            detect_data_exfiltration: true,
            monitor_dns_traffic: true,
            suspicious_ports: vec![4444, 5555, 6666, 7777, 8888, 9999],
            suspicious_domains: vec![
                "tor2web.org".to_string(),
                "onion.to".to_string(),
            ],
            suspicious_ips: vec![],
            traffic_threshold_bytes_per_sec: 10 * 1024 * 1024, // 10 MB/s
            monitor_outbound_connections: true,
            monitor_inbound_connections: false,
        }
    }
}

impl Default for RegistryMonitoringConfig {
    fn default() -> Self {
        Self {
            monitor_startup_keys: true,
            monitor_security_keys: true,
            monitor_system_keys: true,
            monitored_keys: vec![
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services".to_string(),
            ],
            critical_keys: vec![
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot".to_string(),
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies".to_string(),
            ],
            detect_malicious_persistence: true,
            monitor_policy_changes: true,
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enable_behavioral_detection: true,
            enable_yara_integration: true,
            yara_rules_path: PathBuf::from("rules/yara"),
            auto_update_yara_rules: true,
            risk_scoring: RiskScoringConfig::default(),
            heuristics: HeuristicsConfig::default(),
            detection_thresholds: DetectionThresholds::default(),
        }
    }
}

impl Default for RiskScoringConfig {
    fn default() -> Self {
        Self {
            max_score: 1000,
            low_risk_threshold: 100,
            medium_risk_threshold: 300,
            high_risk_threshold: 600,
            critical_risk_threshold: 800,
            score_decay_rate: 0.1,
            scoring_time_window_seconds: 3600, // 1 hour
        }
    }
}

impl Default for HeuristicsConfig {
    fn default() -> Self {
        Self {
            detect_mass_encryption: true,
            mass_encryption_threshold: 100,
            detect_shadow_copy_deletion: true,
            detect_boot_record_modification: true,
            detect_security_software_tampering: true,
            detect_ransom_note_creation: true,
            ransom_note_patterns: vec![
                "README".to_string(),
                "DECRYPT".to_string(),
                "RANSOM".to_string(),
                "PAYMENT".to_string(),
                "BITCOIN".to_string(),
            ],
        }
    }
}

impl Default for DetectionThresholds {
    fn default() -> Self {
        Self {
            entropy_threshold: 7.5,
            mass_file_threshold: 50,
            detection_time_window_seconds: 300,
            suspicious_process_threshold: 10,
            suspicious_network_threshold: 20,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_encryption: true,
            encryption_algorithm: "AES-256-GCM".to_string(),
            encryption_key_size: 256,
            enable_mutual_authentication: true,
            enable_certificate_validation: true,
            enable_key_rotation: true,
            key_rotation_interval_hours: 24,
            enable_tamper_protection: true,
            enable_self_protection: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "INFO".to_string(),
            enable_file_logging: true,
            log_file_path: PathBuf::from("logs/erdps-agent.log"),
            max_log_file_size_mb: 100,
            max_log_files: 10,
            enable_console_logging: true,
            enable_remote_logging: true,
            log_format: "json".to_string(),
            include_thread_info: true,
            include_timestamp: true,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get() as u32,
            event_buffer_size: 10000,
            processing_queue_size: 5000,
            cpu_usage_limit_percent: 25,
            memory_usage_limit_mb: 512,
            cleanup_interval_seconds: 3600,
            optimize_for_ssd: true,
            enable_file_metadata_cache: true,
            cache_size: 10000,
        }
    }
}

impl Default for ExclusionConfig {
    fn default() -> Self {
        Self {
            excluded_directories: vec![
                PathBuf::from("C:\\Windows\\Temp"),
                PathBuf::from("C:\\Temp"),
                PathBuf::from("C:\\$Recycle.Bin"),
                PathBuf::from("C:\\System Volume Information"),
            ],
            excluded_files: vec![
                PathBuf::from("pagefile.sys"),
                PathBuf::from("hiberfil.sys"),
                PathBuf::from("swapfile.sys"),
            ],
            excluded_extensions: vec![
                ".tmp".to_string(),
                ".temp".to_string(),
                ".log".to_string(),
                ".cache".to_string(),
            ],
            excluded_processes: vec![
                "System".to_string(),
                "Registry".to_string(),
                "smss.exe".to_string(),
            ],
            excluded_ips: vec![
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
            excluded_domains: vec![
                "localhost".to_string(),
                "microsoft.com".to_string(),
                "windows.com".to_string(),
            ],
            excluded_registry_keys: vec![
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer".to_string(),
            ],
            exclusion_patterns: vec![],
        }
    }
}

/// Utilitaires pour la configuration
impl AgentConfig {
    /// Charge la configuration depuis un fichier TOML
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: AgentConfig = toml::from_str(&content)?;
        Ok(config)
    }
    
    /// Sauvegarde la configuration dans un fichier TOML
    pub fn to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    /// Valide la configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validation de l'agent
        if self.agent.id.is_empty() {
            return Err("Agent ID cannot be empty".to_string());
        }
        
        if self.agent.name.is_empty() {
            return Err("Agent name cannot be empty".to_string());
        }
        
        // Validation du serveur
        if self.server.endpoint.is_empty() {
            return Err("Server endpoint cannot be empty".to_string());
        }
        
        if self.server.port == 0 {
            return Err("Server port cannot be 0".to_string());
        }
        
        // Validation des intervalles
        if self.server.heartbeat_interval_seconds == 0 {
            return Err("Heartbeat interval must be greater than 0".to_string());
        }
        
        if self.server.reporting_interval_seconds == 0 {
            return Err("Reporting interval must be greater than 0".to_string());
        }
        
        // Validation du monitoring
        if !self.monitoring.enable_file_monitoring &&
           !self.monitoring.enable_process_monitoring &&
           !self.monitoring.enable_network_monitoring &&
           !self.monitoring.enable_registry_monitoring {
            return Err("At least one monitoring module must be enabled".to_string());
        }
        
        // Validation du niveau de log
        match self.logging.level.to_uppercase().as_str() {
            "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR" => {},
            _ => return Err(format!("Invalid log level: {}", self.logging.level)),
        }
        
        // Validation des seuils de performance
        if self.performance.cpu_usage_limit_percent > 100 {
            return Err("CPU usage limit cannot exceed 100%".to_string());
        }
        
        if self.performance.worker_threads == 0 {
            return Err("Worker threads must be greater than 0".to_string());
        }
        
        Ok(())
    }
    
    /// Applique les variables d'environnement
    pub fn apply_env_overrides(&mut self) {
        if let Ok(endpoint) = std::env::var("ERDPS_SERVER_ENDPOINT") {
            self.server.endpoint = endpoint;
        }
        
        if let Ok(port) = std::env::var("ERDPS_SERVER_PORT") {
            if let Ok(port_num) = port.parse::<u16>() {
                self.server.port = port_num;
            }
        }
        
        if let Ok(log_level) = std::env::var("ERDPS_LOG_LEVEL") {
            self.logging.level = log_level;
        }
        
        if let Ok(agent_id) = std::env::var("ERDPS_AGENT_ID") {
            self.agent.id = agent_id;
        }
        
        if let Ok(use_tls) = std::env::var("ERDPS_USE_TLS") {
            self.server.use_tls = use_tls.to_lowercase() == "true";
        }
    }
    
    /// Retourne la durée de heartbeat
    pub fn heartbeat_duration(&self) -> Duration {
        Duration::from_secs(self.server.heartbeat_interval_seconds)
    }
    
    /// Retourne la durée de rapport
    pub fn reporting_duration(&self) -> Duration {
        Duration::from_secs(self.server.reporting_interval_seconds)
    }
    
    /// Retourne la durée de timeout de connexion
    pub fn connection_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.server.connection_timeout_seconds)
    }
    
    /// Retourne la durée de timeout de requête
    pub fn request_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.server.request_timeout_seconds)
    }
}

// Tests unitaires
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    
    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert!(config.validate().is_ok());
        assert!(!config.agent.id.is_empty());
        assert!(!config.agent.name.is_empty());
        assert!(config.monitoring.enable_file_monitoring);
    }
    
    #[test]
    fn test_config_serialization() {
        let config = AgentConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: AgentConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.agent.version, deserialized.agent.version);
    }
    
    #[test]
    fn test_config_file_operations() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_config.toml");
        
        let config = AgentConfig::default();
        config.to_file(&file_path).unwrap();
        
        let loaded_config = AgentConfig::from_file(&file_path).unwrap();
        assert_eq!(config.agent.version, loaded_config.agent.version);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = AgentConfig::default();
        assert!(config.validate().is_ok());
        
        // Test avec agent_id vide
        config.agent.id = String::new();
        assert!(config.validate().is_err());
        
        // Test avec endpoint vide
        config.agent.id = "test".to_string();
        config.server.endpoint = String::new();
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_env_overrides() {
        std::env::set_var("ERDPS_SERVER_ENDPOINT", "https://test.example.com");
        std::env::set_var("ERDPS_SERVER_PORT", "9443");
        std::env::set_var("ERDPS_LOG_LEVEL", "DEBUG");
        
        let mut config = AgentConfig::default();
        config.apply_env_overrides();
        
        assert_eq!(config.server.endpoint, "https://test.example.com");
        assert_eq!(config.server.port, 9443);
        assert_eq!(config.logging.level, "DEBUG");
        
        // Nettoyage
        std::env::remove_var("ERDPS_SERVER_ENDPOINT");
        std::env::remove_var("ERDPS_SERVER_PORT");
        std::env::remove_var("ERDPS_LOG_LEVEL");
    }
    
    #[test]
    fn test_duration_helpers() {
        let config = AgentConfig::default();
        
        assert_eq!(config.heartbeat_duration(), Duration::from_secs(60));
        assert_eq!(config.reporting_duration(), Duration::from_secs(300));
        assert_eq!(config.connection_timeout_duration(), Duration::from_secs(30));
        assert_eq!(config.request_timeout_duration(), Duration::from_secs(60));
    }
}