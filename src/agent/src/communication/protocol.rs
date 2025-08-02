//! Protocol definitions for ERDPS Agent communication
//!
//! Définitions du protocole de communication entre l'agent et le serveur ERDPS
//! Structures de données pour gRPC et sérialisation JSON
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Requête d'enregistrement de l'agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistrationRequest {
    /// Identifiant unique de l'agent
    pub agent_id: String,
    
    /// Nom de l'agent
    pub agent_name: String,
    
    /// Version de l'agent
    pub agent_version: String,
    
    /// Nom d'hôte de la machine
    pub hostname: String,
    
    /// Informations du système d'exploitation
    pub os_info: String,
    
    /// Capacités de l'agent
    pub capabilities: Vec<String>,
}

/// Réponse d'enregistrement de l'agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistrationResponse {
    /// Succès de l'enregistrement
    pub success: bool,
    
    /// Message de réponse
    pub message: String,
    
    /// Configuration assignée
    pub assigned_config: Option<String>,
    
    /// Certificats de sécurité
    pub security_certificates: Option<SecurityCertificates>,
}

/// Certificats de sécurité
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCertificates {
    /// Certificat client
    pub client_cert: String,
    
    /// Clé privée client
    pub client_key: String,
    
    /// Certificat CA
    pub ca_cert: String,
}

/// Événement de fichier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    /// Identifiant de l'événement
    pub event_id: String,
    
    /// Identifiant de l'agent
    pub agent_id: String,
    
    /// Timestamp de l'événement
    pub timestamp: DateTime<Utc>,
    
    /// Type d'événement
    pub event_type: FileEventType,
    
    /// Chemin du fichier
    pub file_path: String,
    
    /// Ancien chemin (pour les renommages)
    pub old_path: Option<String>,
    
    /// Taille du fichier
    pub file_size: Option<u64>,
    
    /// Hash du fichier
    pub file_hash: Option<String>,
    
    /// Entropie du fichier
    pub entropy: Option<f64>,
    
    /// Extension du fichier
    pub file_extension: Option<String>,
    
    /// Processus responsable
    pub process_id: Option<u32>,
    
    /// Nom du processus
    pub process_name: Option<String>,
    
    /// Utilisateur
    pub user: Option<String>,
    
    /// Métadonnées supplémentaires
    pub metadata: HashMap<String, String>,
}

/// Type d'événement de fichier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
    Accessed,
    PermissionChanged,
    AttributeChanged,
}

/// Événement de processus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Identifiant de l'événement
    pub event_id: String,
    
    /// Identifiant de l'agent
    pub agent_id: String,
    
    /// Timestamp de l'événement
    pub timestamp: DateTime<Utc>,
    
    /// Type d'événement
    pub event_type: ProcessEventType,
    
    /// ID du processus
    pub process_id: u32,
    
    /// Nom du processus
    pub process_name: String,
    
    /// Chemin de l'exécutable
    pub executable_path: String,
    
    /// Ligne de commande
    pub command_line: Option<String>,
    
    /// ID du processus parent
    pub parent_process_id: Option<u32>,
    
    /// Nom du processus parent
    pub parent_process_name: Option<String>,
    
    /// Utilisateur
    pub user: Option<String>,
    
    /// Hash de l'exécutable
    pub executable_hash: Option<String>,
    
    /// Signature numérique
    pub digital_signature: Option<String>,
    
    /// Métadonnées supplémentaires
    pub metadata: HashMap<String, String>,
}

/// Type d'événement de processus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessEventType {
    Created,
    Terminated,
    InjectionDetected,
    HollowingDetected,
    MemoryModified,
    PrivilegeEscalation,
    SuspiciousBehavior,
}

/// Événement réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Identifiant de l'événement
    pub event_id: String,
    
    /// Identifiant de l'agent
    pub agent_id: String,
    
    /// Timestamp de l'événement
    pub timestamp: DateTime<Utc>,
    
    /// Type d'événement
    pub event_type: NetworkEventType,
    
    /// Protocole (TCP, UDP, etc.)
    pub protocol: String,
    
    /// Adresse IP source
    pub source_ip: String,
    
    /// Port source
    pub source_port: u16,
    
    /// Adresse IP destination
    pub destination_ip: String,
    
    /// Port destination
    pub destination_port: u16,
    
    /// Direction du trafic
    pub direction: NetworkDirection,
    
    /// Quantité de données transférées
    pub bytes_transferred: Option<u64>,
    
    /// ID du processus responsable
    pub process_id: Option<u32>,
    
    /// Nom du processus
    pub process_name: Option<String>,
    
    /// Métadonnées supplémentaires
    pub metadata: HashMap<String, String>,
}

/// Type d'événement réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEventType {
    ConnectionEstablished,
    ConnectionClosed,
    DataTransfer,
    SuspiciousTraffic,
    C2Communication,
    DataExfiltration,
    DnsQuery,
}

/// Direction du trafic réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

/// Événement de registre
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    /// Identifiant de l'événement
    pub event_id: String,
    
    /// Identifiant de l'agent
    pub agent_id: String,
    
    /// Timestamp de l'événement
    pub timestamp: DateTime<Utc>,
    
    /// Type d'événement
    pub event_type: RegistryEventType,
    
    /// Clé de registre
    pub registry_key: String,
    
    /// Nom de la valeur
    pub value_name: Option<String>,
    
    /// Ancienne valeur
    pub old_value: Option<String>,
    
    /// Nouvelle valeur
    pub new_value: Option<String>,
    
    /// Type de valeur
    pub value_type: Option<String>,
    
    /// ID du processus responsable
    pub process_id: Option<u32>,
    
    /// Nom du processus
    pub process_name: Option<String>,
    
    /// Utilisateur
    pub user: Option<String>,
    
    /// Métadonnées supplémentaires
    pub metadata: HashMap<String, String>,
}

/// Type d'événement de registre
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryEventType {
    KeyCreated,
    KeyDeleted,
    ValueSet,
    ValueDeleted,
    PermissionChanged,
    SuspiciousModification,
}

/// Alerte de menace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    /// Identifiant de l'alerte
    pub alert_id: String,
    
    /// Identifiant de l'agent
    pub agent_id: String,
    
    /// Timestamp de l'alerte
    pub timestamp: DateTime<Utc>,
    
    /// Type de menace
    pub threat_type: ThreatType,
    
    /// Niveau de sévérité
    pub severity: SeverityLevel,
    
    /// Score de risque
    pub risk_score: u32,
    
    /// Titre de l'alerte
    pub title: String,
    
    /// Description de la menace
    pub description: String,
    
    /// Événements associés
    pub related_events: Vec<String>,
    
    /// Processus impliqués
    pub involved_processes: Vec<ProcessInfo>,
    
    /// Fichiers impliqués
    pub involved_files: Vec<FileInfo>,
    
    /// Connexions réseau impliquées
    pub involved_network_connections: Vec<NetworkConnectionInfo>,
    
    /// Actions recommandées
    pub recommended_actions: Vec<String>,
    
    /// Indicateurs de compromission
    pub iocs: Vec<IndicatorOfCompromise>,
    
    /// Métadonnées supplémentaires
    pub metadata: HashMap<String, String>,
}

/// Type de menace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    Ransomware,
    Malware,
    SuspiciousBehavior,
    DataExfiltration,
    PrivilegeEscalation,
    ProcessInjection,
    NetworkAnomaly,
    RegistryTampering,
    FileSystemAnomaly,
    C2Communication,
}

/// Niveau de sévérité
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Informations de processus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub process_id: u32,
    pub process_name: String,
    pub executable_path: String,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub start_time: DateTime<Utc>,
}

/// Informations de fichier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub file_path: String,
    pub file_size: Option<u64>,
    pub file_hash: Option<String>,
    pub entropy: Option<f64>,
    pub creation_time: Option<DateTime<Utc>>,
    pub modification_time: Option<DateTime<Utc>>,
}

/// Informations de connexion réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionInfo {
    pub protocol: String,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub bytes_transferred: Option<u64>,
    pub connection_time: DateTime<Utc>,
}

/// Indicateur de compromission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorOfCompromise {
    pub ioc_type: IocType,
    pub value: String,
    pub description: String,
    pub confidence: f32,
}

/// Type d'indicateur de compromission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IocType {
    FileHash,
    IpAddress,
    Domain,
    Url,
    Email,
    RegistryKey,
    ProcessName,
    Mutex,
    Certificate,
}

/// Statut de l'agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    /// Identifiant de l'agent
    pub agent_id: String,
    
    /// Timestamp du statut
    pub timestamp: DateTime<Utc>,
    
    /// État de l'agent
    pub status: AgentState,
    
    /// Version de l'agent
    pub version: String,
    
    /// Uptime en secondes
    pub uptime_seconds: u64,
    
    /// Utilisation CPU (%)
    pub cpu_usage_percent: f32,
    
    /// Utilisation mémoire (MB)
    pub memory_usage_mb: u64,
    
    /// Espace disque disponible (GB)
    pub disk_space_available_gb: u64,
    
    /// Nombre d'événements traités
    pub events_processed: u64,
    
    /// Nombre d'alertes générées
    pub alerts_generated: u64,
    
    /// Dernière mise à jour des règles
    pub last_rules_update: Option<DateTime<Utc>>,
    
    /// Configuration active
    pub active_config_version: String,
    
    /// Modules actifs
    pub active_modules: Vec<String>,
    
    /// Erreurs récentes
    pub recent_errors: Vec<String>,
}

/// État de l'agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Error,
    Updating,
    Maintenance,
}

/// Commande pour l'agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCommand {
    /// Identifiant de la commande
    pub command_id: String,
    
    /// Type de commande
    pub command_type: CommandType,
    
    /// Paramètres de la commande
    pub parameters: HashMap<String, String>,
    
    /// Timestamp de création
    pub created_at: DateTime<Utc>,
    
    /// Timestamp d'expiration
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Priorité
    pub priority: CommandPriority,
}

/// Type de commande
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandType {
    UpdateConfig,
    UpdateRules,
    ScanFile,
    ScanDirectory,
    QuarantineFile,
    RestoreFile,
    KillProcess,
    BlockNetwork,
    UnblockNetwork,
    CollectLogs,
    RestartAgent,
    UpdateAgent,
    GetSystemInfo,
    RunDiagnostics,
}

/// Priorité de commande
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Requête de commandes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    pub agent_id: String,
}

/// Réponse de commandes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub commands: Vec<AgentCommand>,
}

/// Résultat d'exécution de commande
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    /// Identifiant de la commande
    pub command_id: String,
    
    /// Identifiant de l'agent
    pub agent_id: String,
    
    /// Timestamp d'exécution
    pub executed_at: DateTime<Utc>,
    
    /// Succès de l'exécution
    pub success: bool,
    
    /// Message de résultat
    pub message: String,
    
    /// Données de résultat
    pub result_data: Option<String>,
    
    /// Code d'erreur
    pub error_code: Option<String>,
}

/// Message de heartbeat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// Identifiant de l'agent
    pub agent_id: String,
    
    /// Timestamp du heartbeat
    pub timestamp: DateTime<Utc>,
    
    /// Statut de base
    pub status: AgentState,
    
    /// Métriques de performance
    pub performance_metrics: PerformanceMetrics,
}

/// Métriques de performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage_percent: f32,
    pub memory_usage_mb: u64,
    pub disk_io_read_mb: u64,
    pub disk_io_write_mb: u64,
    pub network_bytes_sent: u64,
    pub network_bytes_received: u64,
    pub events_per_second: f32,
}

/// Rapport périodique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodicReport {
    /// Identifiant de l'agent
    pub agent_id: String,
    
    /// Période du rapport
    pub report_period_start: DateTime<Utc>,
    pub report_period_end: DateTime<Utc>,
    
    /// Statistiques d'événements
    pub event_statistics: EventStatistics,
    
    /// Statistiques de menaces
    pub threat_statistics: ThreatStatistics,
    
    /// Métriques de performance
    pub performance_summary: PerformanceSummary,
    
    /// Erreurs et avertissements
    pub errors_and_warnings: Vec<String>,
}

/// Statistiques d'événements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStatistics {
    pub total_file_events: u64,
    pub total_process_events: u64,
    pub total_network_events: u64,
    pub total_registry_events: u64,
    pub events_by_type: HashMap<String, u64>,
}

/// Statistiques de menaces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStatistics {
    pub total_threats_detected: u64,
    pub threats_by_type: HashMap<String, u64>,
    pub threats_by_severity: HashMap<String, u64>,
    pub false_positives: u64,
    pub blocked_threats: u64,
}

/// Résumé de performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub average_cpu_usage: f32,
    pub peak_cpu_usage: f32,
    pub average_memory_usage: u64,
    pub peak_memory_usage: u64,
    pub total_disk_io: u64,
    pub total_network_io: u64,
    pub average_response_time_ms: f32,
}

// Implémentations utilitaires

impl Default for SeverityLevel {
    fn default() -> Self {
        SeverityLevel::Medium
    }
}

impl Default for AgentState {
    fn default() -> Self {
        AgentState::Starting
    }
}

impl Default for CommandPriority {
    fn default() -> Self {
        CommandPriority::Normal
    }
}

impl std::fmt::Display for SeverityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeverityLevel::Low => write!(f, "Low"),
            SeverityLevel::Medium => write!(f, "Medium"),
            SeverityLevel::High => write!(f, "High"),
            SeverityLevel::Critical => write!(f, "Critical"),
        }
    }
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::Ransomware => write!(f, "Ransomware"),
            ThreatType::Malware => write!(f, "Malware"),
            ThreatType::SuspiciousBehavior => write!(f, "Suspicious Behavior"),
            ThreatType::DataExfiltration => write!(f, "Data Exfiltration"),
            ThreatType::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            ThreatType::ProcessInjection => write!(f, "Process Injection"),
            ThreatType::NetworkAnomaly => write!(f, "Network Anomaly"),
            ThreatType::RegistryTampering => write!(f, "Registry Tampering"),
            ThreatType::FileSystemAnomaly => write!(f, "File System Anomaly"),
            ThreatType::C2Communication => write!(f, "C2 Communication"),
        }
    }
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentState::Starting => write!(f, "Starting"),
            AgentState::Running => write!(f, "Running"),
            AgentState::Stopping => write!(f, "Stopping"),
            AgentState::Stopped => write!(f, "Stopped"),
            AgentState::Error => write!(f, "Error"),
            AgentState::Updating => write!(f, "Updating"),
            AgentState::Maintenance => write!(f, "Maintenance"),
        }
    }
}

// Tests unitaires
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    
    #[test]
    fn test_agent_registration_request_serialization() {
        let request = AgentRegistrationRequest {
            agent_id: Uuid::new_v4().to_string(),
            agent_name: "Test Agent".to_string(),
            agent_version: "1.0.0".to_string(),
            hostname: "test-host".to_string(),
            os_info: "Windows 10".to_string(),
            capabilities: vec!["file_monitoring".to_string()],
        };
        
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: AgentRegistrationRequest = serde_json::from_str(&json).unwrap();
        
        assert_eq!(request.agent_name, deserialized.agent_name);
        assert_eq!(request.capabilities, deserialized.capabilities);
    }
    
    #[test]
    fn test_threat_alert_creation() {
        let alert = ThreatAlert {
            alert_id: Uuid::new_v4().to_string(),
            agent_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            threat_type: ThreatType::Ransomware,
            severity: SeverityLevel::Critical,
            risk_score: 950,
            title: "Ransomware Activity Detected".to_string(),
            description: "Mass file encryption detected".to_string(),
            related_events: vec![],
            involved_processes: vec![],
            involved_files: vec![],
            involved_network_connections: vec![],
            recommended_actions: vec!["Isolate system".to_string()],
            iocs: vec![],
            metadata: HashMap::new(),
        };
        
        assert_eq!(alert.severity, SeverityLevel::Critical);
        assert_eq!(alert.threat_type.to_string(), "Ransomware");
        assert!(alert.risk_score > 900);
    }
    
    #[test]
    fn test_file_event_creation() {
        let event = FileEvent {
            event_id: Uuid::new_v4().to_string(),
            agent_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: FileEventType::Modified,
            file_path: "C:\\test\\file.txt".to_string(),
            old_path: None,
            file_size: Some(1024),
            file_hash: Some("sha256hash".to_string()),
            entropy: Some(7.8),
            file_extension: Some(".txt".to_string()),
            process_id: Some(1234),
            process_name: Some("notepad.exe".to_string()),
            user: Some("DOMAIN\\user".to_string()),
            metadata: HashMap::new(),
        };
        
        assert_eq!(event.file_size, Some(1024));
        assert!(event.entropy.unwrap() > 7.0);
    }
}