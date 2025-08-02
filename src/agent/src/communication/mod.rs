//! Communication module for ERDPS Agent
//!
//! Module de communication sécurisée avec le serveur ERDPS
//! Support pour gRPC avec TLS 1.3 et authentification mutuelle
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

pub mod grpc_client;
pub mod protocol;
pub mod security;
pub mod heartbeat;
pub mod reporting;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::AgentConfig;

pub use grpc_client::GrpcClient;
pub use protocol::*;
pub use security::SecurityManager;
pub use heartbeat::HeartbeatManager;
pub use reporting::ReportingManager;

/// Gestionnaire principal de communication
#[derive(Debug)]
pub struct CommunicationManager {
    /// Client gRPC
    grpc_client: Arc<GrpcClient>,
    
    /// Gestionnaire de sécurité
    security_manager: Arc<SecurityManager>,
    
    /// Gestionnaire de heartbeat
    heartbeat_manager: Arc<HeartbeatManager>,
    
    /// Gestionnaire de rapports
    reporting_manager: Arc<ReportingManager>,
    
    /// Configuration
    config: Arc<RwLock<AgentConfig>>,
    
    /// État de connexion
    is_connected: Arc<RwLock<bool>>,
}

impl CommunicationManager {
    /// Crée un nouveau gestionnaire de communication
    pub async fn new(config: AgentConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing communication manager");
        
        let config = Arc::new(RwLock::new(config));
        let config_read = config.read().await;
        
        // Initialisation du gestionnaire de sécurité
        let security_manager = Arc::new(SecurityManager::new(&config_read.security).await?);
        
        // Initialisation du client gRPC
        let grpc_client = Arc::new(GrpcClient::new(
            &config_read.server,
            security_manager.clone(),
        ).await?);
        
        // Initialisation du gestionnaire de heartbeat
        let heartbeat_manager = Arc::new(HeartbeatManager::new(
            grpc_client.clone(),
            config_read.heartbeat_duration(),
        ));
        
        // Initialisation du gestionnaire de rapports
        let reporting_manager = Arc::new(ReportingManager::new(
            grpc_client.clone(),
            config_read.reporting_duration(),
        ));
        
        drop(config_read);
        
        Ok(Self {
            grpc_client,
            security_manager,
            heartbeat_manager,
            reporting_manager,
            config,
            is_connected: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Démarre la communication
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting communication manager");
        
        // Test de connexion initial
        if let Err(e) = self.test_connection().await {
            warn!("Initial connection test failed: {}", e);
        }
        
        // Démarrage du heartbeat
        self.heartbeat_manager.start().await?;
        
        // Démarrage du gestionnaire de rapports
        self.reporting_manager.start().await?;
        
        *self.is_connected.write().await = true;
        
        info!("Communication manager started successfully");
        Ok(())
    }
    
    /// Arrête la communication
    pub async fn stop(&self) {
        info!("Stopping communication manager");
        
        *self.is_connected.write().await = false;
        
        // Arrêt du heartbeat
        self.heartbeat_manager.stop().await;
        
        // Arrêt du gestionnaire de rapports
        self.reporting_manager.stop().await;
        
        info!("Communication manager stopped");
    }
    
    /// Teste la connexion avec le serveur
    pub async fn test_connection(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Testing connection to ERDPS server");
        
        let config = self.config.read().await;
        let request = AgentRegistrationRequest {
            agent_id: config.agent.id.clone(),
            agent_name: config.agent.name.clone(),
            agent_version: config.agent.version.clone(),
            hostname: hostname::get().unwrap_or_default().to_string_lossy().to_string(),
            os_info: get_os_info(),
            capabilities: get_agent_capabilities(&config),
        };
        drop(config);
        
        match self.grpc_client.register_agent(request).await {
            Ok(response) => {
                info!("Agent registered successfully: {}", response.message);
                Ok(())
            }
            Err(e) => {
                error!("Failed to register agent: {}", e);
                Err(e)
            }
        }
    }
    
    /// Envoie un événement de fichier
    pub async fn send_file_event(&self, event: FileEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !*self.is_connected.read().await {
            return Err("Communication manager not connected".into());
        }
        
        self.grpc_client.send_file_event(event).await
    }
    
    /// Envoie un événement de processus
    pub async fn send_process_event(&self, event: ProcessEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !*self.is_connected.read().await {
            return Err("Communication manager not connected".into());
        }
        
        self.grpc_client.send_process_event(event).await
    }
    
    /// Envoie un événement réseau
    pub async fn send_network_event(&self, event: NetworkEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !*self.is_connected.read().await {
            return Err("Communication manager not connected".into());
        }
        
        self.grpc_client.send_network_event(event).await
    }
    
    /// Envoie un événement de registre
    pub async fn send_registry_event(&self, event: RegistryEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !*self.is_connected.read().await {
            return Err("Communication manager not connected".into());
        }
        
        self.grpc_client.send_registry_event(event).await
    }
    
    /// Envoie une alerte de menace
    pub async fn send_threat_alert(&self, alert: ThreatAlert) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !*self.is_connected.read().await {
            return Err("Communication manager not connected".into());
        }
        
        self.grpc_client.send_threat_alert(alert).await
    }
    
    /// Récupère les commandes du serveur
    pub async fn get_commands(&self) -> Result<Vec<AgentCommand>, Box<dyn std::error::Error + Send + Sync>> {
        if !*self.is_connected.read().await {
            return Err("Communication manager not connected".into());
        }
        
        let config = self.config.read().await;
        let request = CommandRequest {
            agent_id: config.agent.id.clone(),
        };
        drop(config);
        
        self.grpc_client.get_commands(request).await
    }
    
    /// Envoie le statut de l'agent
    pub async fn send_agent_status(&self, status: AgentStatus) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !*self.is_connected.read().await {
            return Err("Communication manager not connected".into());
        }
        
        self.grpc_client.send_agent_status(status).await
    }
    
    /// Met à jour la configuration
    pub async fn update_config(&self, new_config: AgentConfig) {
        *self.config.write().await = new_config;
        info!("Configuration updated");
    }
    
    /// Vérifie l'état de connexion
    pub async fn is_connected(&self) -> bool {
        *self.is_connected.read().await
    }
    
    /// Obtient les statistiques de communication
    pub async fn get_stats(&self) -> CommunicationStats {
        CommunicationStats {
            is_connected: *self.is_connected.read().await,
            heartbeat_stats: self.heartbeat_manager.get_stats().await,
            reporting_stats: self.reporting_manager.get_stats().await,
            grpc_stats: self.grpc_client.get_stats().await,
        }
    }
}

/// Statistiques de communication
#[derive(Debug, Clone)]
pub struct CommunicationStats {
    pub is_connected: bool,
    pub heartbeat_stats: HeartbeatStats,
    pub reporting_stats: ReportingStats,
    pub grpc_stats: GrpcStats,
}

/// Statistiques de heartbeat
#[derive(Debug, Clone)]
pub struct HeartbeatStats {
    pub total_sent: u64,
    pub total_failed: u64,
    pub last_success: Option<chrono::DateTime<chrono::Utc>>,
    pub last_failure: Option<chrono::DateTime<chrono::Utc>>,
}

/// Statistiques de rapport
#[derive(Debug, Clone)]
pub struct ReportingStats {
    pub total_reports_sent: u64,
    pub total_events_sent: u64,
    pub total_alerts_sent: u64,
    pub last_report_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Statistiques gRPC
#[derive(Debug, Clone)]
pub struct GrpcStats {
    pub total_requests: u64,
    pub total_failures: u64,
    pub average_response_time_ms: f64,
    pub last_request_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Obtient les informations du système d'exploitation
fn get_os_info() -> String {
    #[cfg(windows)]
    {
        use winapi::um::sysinfoapi::{GetVersionExW, OSVERSIONINFOW};
        use std::mem;
        
        unsafe {
            let mut version_info: OSVERSIONINFOW = mem::zeroed();
            version_info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;
            
            if GetVersionExW(&mut version_info) != 0 {
                format!(
                    "Windows {}.{} Build {}",
                    version_info.dwMajorVersion,
                    version_info.dwMinorVersion,
                    version_info.dwBuildNumber
                )
            } else {
                "Windows (version unknown)".to_string()
            }
        }
    }
    
    #[cfg(not(windows))]
    {
        "Non-Windows OS".to_string()
    }
}

/// Obtient les capacités de l'agent
fn get_agent_capabilities(config: &AgentConfig) -> Vec<String> {
    let mut capabilities = Vec::new();
    
    if config.monitoring.enable_file_monitoring {
        capabilities.push("file_monitoring".to_string());
    }
    
    if config.monitoring.enable_process_monitoring {
        capabilities.push("process_monitoring".to_string());
    }
    
    if config.monitoring.enable_network_monitoring {
        capabilities.push("network_monitoring".to_string());
    }
    
    if config.monitoring.enable_registry_monitoring {
        capabilities.push("registry_monitoring".to_string());
    }
    
    if config.detection.enable_behavioral_detection {
        capabilities.push("behavioral_detection".to_string());
    }
    
    if config.detection.enable_yara_integration {
        capabilities.push("yara_integration".to_string());
    }
    
    capabilities.push("real_time_protection".to_string());
    capabilities.push("threat_response".to_string());
    capabilities.push("secure_communication".to_string());
    
    capabilities
}

// Tests unitaires
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_os_info() {
        let os_info = get_os_info();
        assert!(!os_info.is_empty());
        #[cfg(windows)]
        assert!(os_info.contains("Windows"));
    }
    
    #[test]
    fn test_get_agent_capabilities() {
        let config = AgentConfig::default();
        let capabilities = get_agent_capabilities(&config);
        
        assert!(!capabilities.is_empty());
        assert!(capabilities.contains(&"file_monitoring".to_string()));
        assert!(capabilities.contains(&"process_monitoring".to_string()));
        assert!(capabilities.contains(&"network_monitoring".to_string()));
        assert!(capabilities.contains(&"registry_monitoring".to_string()));
    }
    
    #[tokio::test]
    async fn test_communication_stats() {
        let stats = CommunicationStats {
            is_connected: true,
            heartbeat_stats: HeartbeatStats {
                total_sent: 10,
                total_failed: 0,
                last_success: Some(chrono::Utc::now()),
                last_failure: None,
            },
            reporting_stats: ReportingStats {
                total_reports_sent: 5,
                total_events_sent: 100,
                total_alerts_sent: 2,
                last_report_time: Some(chrono::Utc::now()),
            },
            grpc_stats: GrpcStats {
                total_requests: 115,
                total_failures: 0,
                average_response_time_ms: 50.0,
                last_request_time: Some(chrono::Utc::now()),
            },
        };
        
        assert!(stats.is_connected);
        assert_eq!(stats.heartbeat_stats.total_sent, 10);
        assert_eq!(stats.reporting_stats.total_events_sent, 100);
    }
}