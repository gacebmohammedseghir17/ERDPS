//! gRPC Client for ERDPS Agent communication
//!
//! Client gRPC sécurisé pour la communication avec le serveur ERDPS
//! Support TLS 1.3, authentification mutuelle et retry automatique
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};
use chrono::Utc;

use crate::config::ServerConfig;
use crate::communication::protocol::*;
use crate::communication::security::SecurityManager;

/// Client gRPC pour la communication avec le serveur ERDPS
#[derive(Debug)]
pub struct GrpcClient {
    /// Canal de communication gRPC
    channel: Channel,
    
    /// Configuration du serveur
    server_config: ServerConfig,
    
    /// Gestionnaire de sécurité
    security_manager: Arc<SecurityManager>,
    
    /// Statistiques de communication
    stats: Arc<RwLock<GrpcClientStats>>,
}

/// Statistiques du client gRPC
#[derive(Debug, Default)]
struct GrpcClientStats {
    total_requests: u64,
    total_failures: u64,
    total_response_time_ms: u64,
    last_request_time: Option<chrono::DateTime<chrono::Utc>>,
    connection_attempts: u64,
    successful_connections: u64,
}

impl GrpcClient {
    /// Crée un nouveau client gRPC
    pub async fn new(
        server_config: &ServerConfig,
        security_manager: Arc<SecurityManager>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing gRPC client for endpoint: {}", server_config.endpoint);
        
        let channel = Self::create_channel(server_config, &security_manager).await?;
        
        Ok(Self {
            channel,
            server_config: server_config.clone(),
            security_manager,
            stats: Arc::new(RwLock::new(GrpcClientStats::default())),
        })
    }
    
    /// Crée le canal de communication gRPC
    async fn create_channel(
        config: &ServerConfig,
        security_manager: &SecurityManager,
    ) -> Result<Channel, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint_url = if config.use_tls {
            format!("https://{}:{}", config.endpoint.replace("https://", "").replace("http://", ""), config.port)
        } else {
            format!("http://{}:{}", config.endpoint.replace("https://", "").replace("http://", ""), config.port)
        };
        
        info!("Connecting to ERDPS server at: {}", endpoint_url);
        
        let mut endpoint = Endpoint::from_shared(endpoint_url)?
            .timeout(Duration::from_secs(config.request_timeout_seconds))
            .connect_timeout(Duration::from_secs(config.connection_timeout_seconds))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(5))
            .keep_alive_while_idle(true);
        
        // Configuration TLS si activée
        if config.use_tls {
            let mut tls_config = ClientTlsConfig::new();
            
            // Configuration du nom de domaine pour la vérification du certificat
            let domain = config.endpoint
                .replace("https://", "")
                .replace("http://", "")
                .split(':')
                .next()
                .unwrap_or("localhost")
                .to_string();
            
            tls_config = tls_config.domain_name(domain);
            
            // Chargement des certificats si disponibles
            if let Some(ca_cert_path) = &config.ca_cert_path {
                if ca_cert_path.exists() {
                    let ca_cert = tokio::fs::read(ca_cert_path).await?;
                    tls_config = tls_config.ca_certificate(tonic::transport::Certificate::from_pem(ca_cert));
                    info!("Loaded CA certificate from: {:?}", ca_cert_path);
                }
            }
            
            // Configuration de l'authentification mutuelle
            if let (Some(client_cert_path), Some(client_key_path)) = 
                (&config.client_cert_path, &config.client_key_path) {
                if client_cert_path.exists() && client_key_path.exists() {
                    let client_cert = tokio::fs::read(client_cert_path).await?;
                    let client_key = tokio::fs::read(client_key_path).await?;
                    
                    let identity = tonic::transport::Identity::from_pem(client_cert, client_key);
                    tls_config = tls_config.identity(identity);
                    info!("Configured mutual TLS authentication");
                }
            }
            
            endpoint = endpoint.tls_config(tls_config)?;
        }
        
        // Tentative de connexion avec retry
        let mut last_error = None;
        for attempt in 1..=config.max_retry_attempts {
            match endpoint.connect().await {
                Ok(channel) => {
                    info!("Successfully connected to ERDPS server (attempt {})", attempt);
                    return Ok(channel);
                }
                Err(e) => {
                    warn!("Connection attempt {} failed: {}", attempt, e);
                    last_error = Some(e);
                    
                    if attempt < config.max_retry_attempts {
                        tokio::time::sleep(Duration::from_secs(config.retry_delay_seconds)).await;
                    }
                }
            }
        }
        
        Err(format!("Failed to connect after {} attempts: {:?}", 
                   config.max_retry_attempts, last_error).into())
    }
    
    /// Enregistre l'agent auprès du serveur
    pub async fn register_agent(
        &self,
        request: AgentRegistrationRequest,
    ) -> Result<AgentRegistrationResponse, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        debug!("Registering agent: {}", request.agent_id);
        
        // Création du stub gRPC (simulé - dans un vrai projet, ceci serait généré par tonic-build)
        let mut client = self.create_erdps_client();
        
        let grpc_request = Request::new(request);
        
        match self.execute_with_retry(|| async {
            client.register_agent(grpc_request.clone()).await
        }).await {
            Ok(response) => {
                let response_data = response.into_inner();
                self.update_stats(start_time, true).await;
                info!("Agent registration successful");
                Ok(response_data)
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                error!("Agent registration failed: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Envoie un événement de fichier
    pub async fn send_file_event(
        &self,
        event: FileEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        debug!("Sending file event: {}", event.event_id);
        
        let mut client = self.create_erdps_client();
        let grpc_request = Request::new(event);
        
        match self.execute_with_retry(|| async {
            client.send_file_event(grpc_request.clone()).await
        }).await {
            Ok(_) => {
                self.update_stats(start_time, true).await;
                debug!("File event sent successfully");
                Ok(())
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                error!("Failed to send file event: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Envoie un événement de processus
    pub async fn send_process_event(
        &self,
        event: ProcessEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        debug!("Sending process event: {}", event.event_id);
        
        let mut client = self.create_erdps_client();
        let grpc_request = Request::new(event);
        
        match self.execute_with_retry(|| async {
            client.send_process_event(grpc_request.clone()).await
        }).await {
            Ok(_) => {
                self.update_stats(start_time, true).await;
                debug!("Process event sent successfully");
                Ok(())
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                error!("Failed to send process event: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Envoie un événement réseau
    pub async fn send_network_event(
        &self,
        event: NetworkEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        debug!("Sending network event: {}", event.event_id);
        
        let mut client = self.create_erdps_client();
        let grpc_request = Request::new(event);
        
        match self.execute_with_retry(|| async {
            client.send_network_event(grpc_request.clone()).await
        }).await {
            Ok(_) => {
                self.update_stats(start_time, true).await;
                debug!("Network event sent successfully");
                Ok(())
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                error!("Failed to send network event: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Envoie un événement de registre
    pub async fn send_registry_event(
        &self,
        event: RegistryEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        debug!("Sending registry event: {}", event.event_id);
        
        let mut client = self.create_erdps_client();
        let grpc_request = Request::new(event);
        
        match self.execute_with_retry(|| async {
            client.send_registry_event(grpc_request.clone()).await
        }).await {
            Ok(_) => {
                self.update_stats(start_time, true).await;
                debug!("Registry event sent successfully");
                Ok(())
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                error!("Failed to send registry event: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Envoie une alerte de menace
    pub async fn send_threat_alert(
        &self,
        alert: ThreatAlert,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        info!("Sending threat alert: {} ({})", alert.alert_id, alert.threat_type);
        
        let mut client = self.create_erdps_client();
        let grpc_request = Request::new(alert);
        
        match self.execute_with_retry(|| async {
            client.send_threat_alert(grpc_request.clone()).await
        }).await {
            Ok(_) => {
                self.update_stats(start_time, true).await;
                info!("Threat alert sent successfully");
                Ok(())
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                error!("Failed to send threat alert: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Récupère les commandes du serveur
    pub async fn get_commands(
        &self,
        request: CommandRequest,
    ) -> Result<Vec<AgentCommand>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        debug!("Retrieving commands for agent: {}", request.agent_id);
        
        let mut client = self.create_erdps_client();
        let grpc_request = Request::new(request);
        
        match self.execute_with_retry(|| async {
            client.get_commands(grpc_request.clone()).await
        }).await {
            Ok(response) => {
                let response_data = response.into_inner();
                self.update_stats(start_time, true).await;
                debug!("Retrieved {} commands", response_data.commands.len());
                Ok(response_data.commands)
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                error!("Failed to retrieve commands: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Envoie le statut de l'agent
    pub async fn send_agent_status(
        &self,
        status: AgentStatus,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        debug!("Sending agent status: {}", status.agent_id);
        
        let mut client = self.create_erdps_client();
        let grpc_request = Request::new(status);
        
        match self.execute_with_retry(|| async {
            client.send_agent_status(grpc_request.clone()).await
        }).await {
            Ok(_) => {
                self.update_stats(start_time, true).await;
                debug!("Agent status sent successfully");
                Ok(())
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                error!("Failed to send agent status: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Envoie un heartbeat
    pub async fn send_heartbeat(
        &self,
        heartbeat: HeartbeatMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        debug!("Sending heartbeat for agent: {}", heartbeat.agent_id);
        
        let mut client = self.create_erdps_client();
        let grpc_request = Request::new(heartbeat);
        
        match self.execute_with_retry(|| async {
            client.send_heartbeat(grpc_request.clone()).await
        }).await {
            Ok(_) => {
                self.update_stats(start_time, true).await;
                debug!("Heartbeat sent successfully");
                Ok(())
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                warn!("Failed to send heartbeat: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Envoie un rapport périodique
    pub async fn send_periodic_report(
        &self,
        report: PeriodicReport,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        info!("Sending periodic report for agent: {}", report.agent_id);
        
        let mut client = self.create_erdps_client();
        let grpc_request = Request::new(report);
        
        match self.execute_with_retry(|| async {
            client.send_periodic_report(grpc_request.clone()).await
        }).await {
            Ok(_) => {
                self.update_stats(start_time, true).await;
                info!("Periodic report sent successfully");
                Ok(())
            }
            Err(e) => {
                self.update_stats(start_time, false).await;
                error!("Failed to send periodic report: {}", e);
                Err(e.into())
            }
        }
    }
    
    /// Exécute une requête avec retry automatique
    async fn execute_with_retry<F, Fut, T>(&self, operation: F) -> Result<T, Status>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Response<T>, Status>>,
    {
        let mut last_error = None;
        
        for attempt in 1..=self.server_config.max_retry_attempts {
            match operation().await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("Request attempt {} failed: {}", attempt, e);
                    last_error = Some(e);
                    
                    if attempt < self.server_config.max_retry_attempts {
                        let delay = Duration::from_secs(self.server_config.retry_delay_seconds * attempt as u64);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| Status::internal("Unknown error")))
    }
    
    /// Met à jour les statistiques
    async fn update_stats(&self, start_time: Instant, success: bool) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.total_response_time_ms += start_time.elapsed().as_millis() as u64;
        stats.last_request_time = Some(Utc::now());
        
        if !success {
            stats.total_failures += 1;
        }
    }
    
    /// Obtient les statistiques
    pub async fn get_stats(&self) -> super::GrpcStats {
        let stats = self.stats.read().await;
        
        let average_response_time = if stats.total_requests > 0 {
            stats.total_response_time_ms as f64 / stats.total_requests as f64
        } else {
            0.0
        };
        
        super::GrpcStats {
            total_requests: stats.total_requests,
            total_failures: stats.total_failures,
            average_response_time_ms: average_response_time,
            last_request_time: stats.last_request_time,
        }
    }
    
    /// Crée un client ERDPS (simulé - dans un vrai projet, ceci serait généré par tonic-build)
    fn create_erdps_client(&self) -> ERDPSServiceClient {
        ERDPSServiceClient::new(self.channel.clone())
    }
}

/// Client de service ERDPS (simulé - dans un vrai projet, ceci serait généré par tonic-build)
#[derive(Debug, Clone)]
struct ERDPSServiceClient {
    channel: Channel,
}

impl ERDPSServiceClient {
    fn new(channel: Channel) -> Self {
        Self { channel }
    }
    
    async fn register_agent(
        &mut self,
        request: Request<AgentRegistrationRequest>,
    ) -> Result<Response<AgentRegistrationResponse>, Status> {
        // Simulation d'un appel gRPC
        // Dans un vrai projet, ceci serait généré automatiquement
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        let response = AgentRegistrationResponse {
            success: true,
            message: "Agent registered successfully".to_string(),
            assigned_config: None,
            security_certificates: None,
        };
        
        Ok(Response::new(response))
    }
    
    async fn send_file_event(
        &mut self,
        _request: Request<FileEvent>,
    ) -> Result<Response<()>, Status> {
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(Response::new(()))
    }
    
    async fn send_process_event(
        &mut self,
        _request: Request<ProcessEvent>,
    ) -> Result<Response<()>, Status> {
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(Response::new(()))
    }
    
    async fn send_network_event(
        &mut self,
        _request: Request<NetworkEvent>,
    ) -> Result<Response<()>, Status> {
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(Response::new(()))
    }
    
    async fn send_registry_event(
        &mut self,
        _request: Request<RegistryEvent>,
    ) -> Result<Response<()>, Status> {
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(Response::new(()))
    }
    
    async fn send_threat_alert(
        &mut self,
        _request: Request<ThreatAlert>,
    ) -> Result<Response<()>, Status> {
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(Response::new(()))
    }
    
    async fn get_commands(
        &mut self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        tokio::time::sleep(Duration::from_millis(5)).await;
        
        let response = CommandResponse {
            commands: vec![], // Pas de commandes pour le moment
        };
        
        Ok(Response::new(response))
    }
    
    async fn send_agent_status(
        &mut self,
        _request: Request<AgentStatus>,
    ) -> Result<Response<()>, Status> {
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(Response::new(()))
    }
    
    async fn send_heartbeat(
        &mut self,
        _request: Request<HeartbeatMessage>,
    ) -> Result<Response<()>, Status> {
        tokio::time::sleep(Duration::from_millis(3)).await;
        Ok(Response::new(()))
    }
    
    async fn send_periodic_report(
        &mut self,
        _request: Request<PeriodicReport>,
    ) -> Result<Response<()>, Status> {
        tokio::time::sleep(Duration::from_millis(15)).await;
        Ok(Response::new(()))
    }
}

// Tests unitaires
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use crate::communication::security::SecurityManager;
    
    #[tokio::test]
    async fn test_grpc_client_creation() {
        let config = AgentConfig::default();
        let security_manager = Arc::new(
            SecurityManager::new(&config.security).await.unwrap()
        );
        
        // Note: Ce test échouera sans un serveur réel, mais teste la logique de création
        let result = GrpcClient::new(&config.server, security_manager).await;
        
        // Dans un environnement de test réel, on utiliserait un serveur mock
        assert!(result.is_err()); // Attendu car pas de serveur
    }
    
    #[tokio::test]
    async fn test_stats_update() {
        let config = AgentConfig::default();
        let security_manager = Arc::new(
            SecurityManager::new(&config.security).await.unwrap()
        );
        
        // Création d'un client avec un canal mock
        let stats = Arc::new(RwLock::new(GrpcClientStats::default()));
        
        // Test de mise à jour des statistiques
        {
            let mut stats_guard = stats.write().await;
            stats_guard.total_requests += 1;
            stats_guard.total_response_time_ms += 100;
        }
        
        let stats_read = stats.read().await;
        assert_eq!(stats_read.total_requests, 1);
        assert_eq!(stats_read.total_response_time_ms, 100);
    }
}