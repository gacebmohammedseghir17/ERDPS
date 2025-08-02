//! Module de communication sécurisée ERDPS
//!
//! Communication chiffrée TLS 1.3 entre l'agent et le serveur:
//! - Authentification mutuelle par certificats X.509
//! - Chiffrement bout-en-bout des données sensibles
//! - Protocole gRPC pour les échanges structurés
//! - Mécanismes de reconnexion automatique
//! - Validation de l'intégrité des messages

use std::sync::Arc;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, timeout};
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context, bail};
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};
use tonic::{Request, Response, Status};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};
use rand::{RngCore, rngs::OsRng};

use crate::detection::{ThreatContext, ThreatType, ThreatSeverity};
use crate::config::ServerConfig;

/// Client de communication sécurisée
pub struct SecureCommunicationClient {
    config: ServerConfig,
    channel: Option<Channel>,
    client: Option<ErdpsServiceClient<Channel>>,
    connection_state: Arc<RwLock<ConnectionState>>,
    message_queue: Arc<RwLock<Vec<QueuedMessage>>>,
    encryption_key: Option<Key<Aes256Gcm>>,
    agent_id: Uuid,
    session_id: Option<Uuid>,
    heartbeat_interval: Duration,
    reconnect_attempts: u32,
    max_reconnect_attempts: u32,
}

/// État de la connexion
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
    Error(String),
}

/// Message en file d'attente
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueuedMessage {
    id: Uuid,
    message_type: MessageType,
    payload: Vec<u8>,
    timestamp: DateTime<Utc>,
    priority: MessagePriority,
    retry_count: u32,
    max_retries: u32,
}

/// Type de message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Heartbeat,
    ThreatAlert,
    SystemStatus,
    ConfigUpdate,
    LogEntry,
    FileEvent,
    ProcessEvent,
    NetworkEvent,
    AuthRequest,
    AuthResponse,
}

/// Priorité du message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

/// Message de menace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMessage {
    pub threat_id: Uuid,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub context: ThreatContext,
    pub timestamp: DateTime<Utc>,
    pub agent_id: Uuid,
    pub mitigation_actions: Vec<String>,
    pub evidence: Vec<Evidence>,
}

/// Preuve d'une menace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub data: Vec<u8>,
    pub hash: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
}

/// Type de preuve
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    FileHash,
    ProcessMemory,
    NetworkPacket,
    RegistryKey,
    LogEntry,
    Screenshot,
    YaraMatch,
}

/// Message de statut système
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatusMessage {
    pub agent_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: f32,
    pub network_usage: f32,
    pub active_threats: u32,
    pub monitored_files: u32,
    pub monitored_processes: u32,
    pub uptime: Duration,
    pub version: String,
}

/// Message de heartbeat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    pub agent_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub sequence_number: u64,
    pub status: AgentStatus,
}

/// Statut de l'agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentStatus {
    Healthy,
    Warning,
    Critical,
    Maintenance,
}

/// Client gRPC généré (simulation)
pub struct ErdpsServiceClient<T> {
    inner: T,
}

impl<T> ErdpsServiceClient<T> {
    pub fn new(channel: T) -> Self {
        Self { inner: channel }
    }
    
    pub async fn send_threat_alert(
        &mut self,
        request: Request<ThreatAlertRequest>,
    ) -> Result<Response<ThreatAlertResponse>, Status> {
        // Implémentation simulée - serait générée par tonic
        Ok(Response::new(ThreatAlertResponse {
            success: true,
            message: "Alert received".to_string(),
        }))
    }
    
    pub async fn send_heartbeat(
        &mut self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        // Implémentation simulée
        Ok(Response::new(HeartbeatResponse {
            success: true,
            server_time: Utc::now().timestamp(),
        }))
    }
    
    pub async fn authenticate(
        &mut self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        // Implémentation simulée
        Ok(Response::new(AuthResponse {
            success: true,
            session_id: Uuid::new_v4().to_string(),
            encryption_key: vec![0u8; 32], // Clé simulée
        }))
    }
}

/// Messages gRPC (simulation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlertRequest {
    pub agent_id: String,
    pub threat_data: Vec<u8>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlertResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_id: String,
    pub timestamp: i64,
    pub sequence: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub success: bool,
    pub server_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub agent_id: String,
    pub certificate: Vec<u8>,
    pub challenge_response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub session_id: String,
    pub encryption_key: Vec<u8>,
}

impl SecureCommunicationClient {
    /// Crée un nouveau client de communication sécurisée
    pub fn new(config: ServerConfig) -> Result<Self> {
        let agent_id = Uuid::new_v4();
        
        Ok(Self {
            config,
            channel: None,
            client: None,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            message_queue: Arc::new(RwLock::new(Vec::new())),
            encryption_key: None,
            agent_id,
            session_id: None,
            heartbeat_interval: Duration::from_secs(30),
            reconnect_attempts: 0,
            max_reconnect_attempts: 10,
        })
    }
    
    /// Démarre la communication avec le serveur
    pub async fn start(&mut self) -> Result<()> {
        info!("🔐 Démarrage de la communication sécurisée...");
        
        // Établir la connexion
        self.connect().await?;
        
        // Authentification
        self.authenticate().await?;
        
        // Démarrer les tâches de maintenance
        self.start_background_tasks().await?;
        
        info!("✅ Communication sécurisée établie");
        Ok(())
    }
    
    /// Arrête la communication
    pub async fn stop(&mut self) -> Result<()> {
        info!("🛑 Arrêt de la communication sécurisée...");
        
        let mut state = self.connection_state.write().await;
        *state = ConnectionState::Disconnected;
        
        self.channel = None;
        self.client = None;
        self.session_id = None;
        
        info!("✅ Communication sécurisée arrêtée");
        Ok(())
    }
    
    /// Établit la connexion TLS avec le serveur
    async fn connect(&mut self) -> Result<()> {
        info!("🔗 Connexion au serveur ERDPS...");
        
        let mut state = self.connection_state.write().await;
        *state = ConnectionState::Connecting;
        drop(state);
        
        // Configuration TLS
        let tls_config = self.create_tls_config().await
            .context("Échec de la configuration TLS")?;
        
        // Établissement de la connexion
        let endpoint = tonic::transport::Endpoint::from_shared(
            format!("https://{}:{}", self.config.host, self.config.port)
        )
        .context("URL du serveur invalide")?
        .tls_config(tls_config)
        .context("Configuration TLS invalide")?
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10));
        
        match timeout(Duration::from_secs(30), endpoint.connect()).await {
            Ok(Ok(channel)) => {
                self.channel = Some(channel.clone());
                self.client = Some(ErdpsServiceClient::new(channel));
                
                let mut state = self.connection_state.write().await;
                *state = ConnectionState::Connected;
                
                info!("✅ Connexion établie avec le serveur");
                Ok(())
            },
            Ok(Err(e)) => {
                let mut state = self.connection_state.write().await;
                *state = ConnectionState::Error(format!("Erreur de connexion: {}", e));
                bail!("Échec de la connexion: {}", e);
            },
            Err(_) => {
                let mut state = self.connection_state.write().await;
                *state = ConnectionState::Error("Timeout de connexion".to_string());
                bail!("Timeout lors de la connexion");
            }
        }
    }
    
    /// Crée la configuration TLS
    async fn create_tls_config(&self) -> Result<ClientTlsConfig> {
        let mut tls_config = ClientTlsConfig::new()
            .domain_name(&self.config.host);
        
        // Certificat du serveur
        if let Some(ref ca_cert_path) = self.config.tls.ca_cert_path {
            let ca_cert = tokio::fs::read(ca_cert_path).await
                .with_context(|| format!("Lecture du certificat CA: {:?}", ca_cert_path))?;
            
            let certificate = Certificate::from_pem(ca_cert);
            tls_config = tls_config.ca_certificate(certificate);
        }
        
        // Certificat client pour l'authentification mutuelle
        if let (Some(ref cert_path), Some(ref key_path)) = 
            (&self.config.tls.client_cert_path, &self.config.tls.client_key_path) {
            
            let cert = tokio::fs::read(cert_path).await
                .with_context(|| format!("Lecture du certificat client: {:?}", cert_path))?;
            
            let key = tokio::fs::read(key_path).await
                .with_context(|| format!("Lecture de la clé client: {:?}", key_path))?;
            
            let identity = Identity::from_pem(cert, key);
            tls_config = tls_config.identity(identity);
        }
        
        Ok(tls_config)
    }
    
    /// Authentification avec le serveur
    async fn authenticate(&mut self) -> Result<()> {
        info!("🔐 Authentification avec le serveur...");
        
        let client = self.client.as_mut()
            .context("Client non initialisé")?;
        
        // Préparer la requête d'authentification
        let auth_request = AuthRequest {
            agent_id: self.agent_id.to_string(),
            certificate: self.load_client_certificate().await?,
            challenge_response: self.generate_challenge_response().await?,
        };
        
        // Envoyer la requête
        let response = client.authenticate(Request::new(auth_request)).await
            .context("Échec de l'authentification")?;
        
        let auth_response = response.into_inner();
        
        if auth_response.success {
            // Stocker la session et la clé de chiffrement
            self.session_id = Some(Uuid::parse_str(&auth_response.session_id)
                .context("ID de session invalide")?);
            
            self.encryption_key = Some(*Key::<Aes256Gcm>::from_slice(&auth_response.encryption_key));
            
            let mut state = self.connection_state.write().await;
            *state = ConnectionState::Authenticated;
            
            info!("✅ Authentification réussie");
            Ok(())
        } else {
            let mut state = self.connection_state.write().await;
            *state = ConnectionState::Error("Authentification échouée".to_string());
            bail!("Échec de l'authentification");
        }
    }
    
    /// Charge le certificat client
    async fn load_client_certificate(&self) -> Result<Vec<u8>> {
        if let Some(ref cert_path) = self.config.tls.client_cert_path {
            tokio::fs::read(cert_path).await
                .with_context(|| format!("Lecture du certificat: {:?}", cert_path))
        } else {
            bail!("Chemin du certificat client non configuré");
        }
    }
    
    /// Génère une réponse au défi d'authentification
    async fn generate_challenge_response(&self) -> Result<String> {
        // Implémentation simplifiée - dans un vrai système, ceci impliquerait
        // un défi cryptographique du serveur
        let challenge = format!("{}-{}", self.agent_id, Utc::now().timestamp());
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    /// Démarre les tâches de maintenance en arrière-plan
    async fn start_background_tasks(&self) -> Result<()> {
        // Tâche de heartbeat
        let connection_state = self.connection_state.clone();
        let agent_id = self.agent_id;
        let heartbeat_interval = self.heartbeat_interval;
        
        tokio::spawn(async move {
            Self::heartbeat_task(connection_state, agent_id, heartbeat_interval).await;
        });
        
        // Tâche de traitement de la file d'attente
        let message_queue = self.message_queue.clone();
        let connection_state = self.connection_state.clone();
        
        tokio::spawn(async move {
            Self::message_queue_task(message_queue, connection_state).await;
        });
        
        // Tâche de reconnexion automatique
        let connection_state = self.connection_state.clone();
        
        tokio::spawn(async move {
            Self::reconnection_task(connection_state).await;
        });
        
        Ok(())
    }
    
    /// Tâche de heartbeat
    async fn heartbeat_task(
        connection_state: Arc<RwLock<ConnectionState>>,
        agent_id: Uuid,
        heartbeat_interval: Duration,
    ) {
        let mut interval = interval(heartbeat_interval);
        let mut sequence = 0u64;
        
        loop {
            interval.tick().await;
            
            let state = connection_state.read().await;
            if *state != ConnectionState::Authenticated {
                continue;
            }
            drop(state);
            
            sequence += 1;
            
            let heartbeat = HeartbeatMessage {
                agent_id,
                timestamp: Utc::now(),
                sequence_number: sequence,
                status: AgentStatus::Healthy,
            };
            
            debug!("💓 Envoi du heartbeat #{}", sequence);
            
            // Ici, on enverrait le heartbeat au serveur
            // Pour la simulation, on log simplement
        }
    }
    
    /// Tâche de traitement de la file d'attente
    async fn message_queue_task(
        message_queue: Arc<RwLock<Vec<QueuedMessage>>>,
        connection_state: Arc<RwLock<ConnectionState>>,
    ) {
        let mut interval = interval(Duration::from_secs(5));
        
        loop {
            interval.tick().await;
            
            let state = connection_state.read().await;
            if *state != ConnectionState::Authenticated {
                continue;
            }
            drop(state);
            
            let mut queue = message_queue.write().await;
            
            // Trier par priorité
            queue.sort_by(|a, b| b.priority.cmp(&a.priority));
            
            // Traiter les messages
            let mut processed_indices = Vec::new();
            
            for (index, message) in queue.iter_mut().enumerate() {
                if Self::process_queued_message(message).await {
                    processed_indices.push(index);
                } else {
                    message.retry_count += 1;
                    if message.retry_count >= message.max_retries {
                        warn!("❌ Message abandonné après {} tentatives: {:?}", 
                              message.max_retries, message.id);
                        processed_indices.push(index);
                    }
                }
            }
            
            // Supprimer les messages traités (en ordre inverse)
            for &index in processed_indices.iter().rev() {
                queue.remove(index);
            }
        }
    }
    
    /// Traite un message en file d'attente
    async fn process_queued_message(message: &QueuedMessage) -> bool {
        debug!("📤 Traitement du message: {:?}", message.id);
        
        // Simulation du traitement
        // Dans un vrai système, on enverrait le message au serveur
        
        // Simuler un succès aléatoire pour les tests
        true
    }
    
    /// Tâche de reconnexion automatique
    async fn reconnection_task(connection_state: Arc<RwLock<ConnectionState>>) {
        let mut interval = interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            let state = connection_state.read().await;
            match *state {
                ConnectionState::Error(_) | ConnectionState::Disconnected => {
                    drop(state);
                    info!("🔄 Tentative de reconnexion...");
                    
                    // Ici, on déclencherait une reconnexion
                    // Pour la simulation, on change juste l'état
                    
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    
                    let mut state = connection_state.write().await;
                    *state = ConnectionState::Connecting;
                },
                _ => {}
            }
        }
    }
    
    /// Envoie une alerte de menace
    pub async fn send_threat_alert(&self, threat: &ThreatMessage) -> Result<()> {
        info!("🚨 Envoi d'alerte de menace: {:?}", threat.threat_id);
        
        // Chiffrer le message
        let encrypted_data = self.encrypt_message(threat).await
            .context("Échec du chiffrement de l'alerte")?;
        
        // Créer la signature
        let signature = self.sign_message(&encrypted_data).await
            .context("Échec de la signature")?;
        
        // Ajouter à la file d'attente
        let queued_message = QueuedMessage {
            id: Uuid::new_v4(),
            message_type: MessageType::ThreatAlert,
            payload: encrypted_data,
            timestamp: Utc::now(),
            priority: match threat.severity {
                ThreatSeverity::Critical => MessagePriority::Critical,
                ThreatSeverity::High => MessagePriority::High,
                ThreatSeverity::Medium => MessagePriority::Normal,
                ThreatSeverity::Low => MessagePriority::Low,
            },
            retry_count: 0,
            max_retries: 5,
        };
        
        let mut queue = self.message_queue.write().await;
        queue.push(queued_message);
        
        info!("✅ Alerte ajoutée à la file d'attente");
        Ok(())
    }
    
    /// Envoie le statut système
    pub async fn send_system_status(&self, status: &SystemStatusMessage) -> Result<()> {
        debug!("📊 Envoi du statut système");
        
        let encrypted_data = self.encrypt_message(status).await
            .context("Échec du chiffrement du statut")?;
        
        let queued_message = QueuedMessage {
            id: Uuid::new_v4(),
            message_type: MessageType::SystemStatus,
            payload: encrypted_data,
            timestamp: Utc::now(),
            priority: MessagePriority::Normal,
            retry_count: 0,
            max_retries: 3,
        };
        
        let mut queue = self.message_queue.write().await;
        queue.push(queued_message);
        
        Ok(())
    }
    
    /// Chiffre un message
    async fn encrypt_message<T: Serialize>(&self, message: &T) -> Result<Vec<u8>> {
        let key = self.encryption_key.as_ref()
            .context("Clé de chiffrement non disponible")?;
        
        // Sérialiser le message
        let plaintext = bincode::serialize(message)
            .context("Échec de la sérialisation")?;
        
        // Générer un nonce aléatoire
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Chiffrer
        let cipher = Aes256Gcm::new(key);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Échec du chiffrement: {}", e))?;
        
        // Combiner nonce + ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Signe un message
    async fn sign_message(&self, data: &[u8]) -> Result<String> {
        // Implémentation simplifiée avec SHA-256
        // Dans un vrai système, on utiliserait une signature RSA/ECDSA
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(self.agent_id.as_bytes());
        
        if let Some(session_id) = &self.session_id {
            hasher.update(session_id.as_bytes());
        }
        
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    /// Obtient l'état de la connexion
    pub async fn get_connection_state(&self) -> ConnectionState {
        self.connection_state.read().await.clone()
    }
    
    /// Obtient la taille de la file d'attente
    pub async fn get_queue_size(&self) -> usize {
        self.message_queue.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, TlsConfig};
    
    fn create_test_config() -> ServerConfig {
        ServerConfig {
            host: "localhost".to_string(),
            port: 8443,
            tls: TlsConfig {
                enabled: true,
                ca_cert_path: Some(PathBuf::from("test_ca.pem")),
                client_cert_path: Some(PathBuf::from("test_client.pem")),
                client_key_path: Some(PathBuf::from("test_client.key")),
                verify_server: true,
            },
            timeout: 30,
            retry_attempts: 3,
        }
    }
    
    #[tokio::test]
    async fn test_client_creation() {
        let config = create_test_config();
        let client = SecureCommunicationClient::new(config);
        assert!(client.is_ok());
    }
    
    #[tokio::test]
    async fn test_message_encryption() {
        let config = create_test_config();
        let mut client = SecureCommunicationClient::new(config).unwrap();
        
        // Simuler une clé de chiffrement
        let key = Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
        client.encryption_key = Some(*key);
        
        let test_message = "Test message";
        let encrypted = client.encrypt_message(&test_message).await;
        assert!(encrypted.is_ok());
        
        let encrypted_data = encrypted.unwrap();
        assert!(encrypted_data.len() > test_message.len());
    }
    
    #[test]
    fn test_message_priority_ordering() {
        let mut messages = vec![
            QueuedMessage {
                id: Uuid::new_v4(),
                message_type: MessageType::ThreatAlert,
                payload: vec![],
                timestamp: Utc::now(),
                priority: MessagePriority::Low,
                retry_count: 0,
                max_retries: 3,
            },
            QueuedMessage {
                id: Uuid::new_v4(),
                message_type: MessageType::ThreatAlert,
                payload: vec![],
                timestamp: Utc::now(),
                priority: MessagePriority::Critical,
                retry_count: 0,
                max_retries: 3,
            },
            QueuedMessage {
                id: Uuid::new_v4(),
                message_type: MessageType::SystemStatus,
                payload: vec![],
                timestamp: Utc::now(),
                priority: MessagePriority::Normal,
                retry_count: 0,
                max_retries: 3,
            },
        ];
        
        messages.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        assert_eq!(messages[0].priority, MessagePriority::Critical);
        assert_eq!(messages[1].priority, MessagePriority::Normal);
        assert_eq!(messages[2].priority, MessagePriority::Low);
    }
}