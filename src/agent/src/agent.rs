//! ERDPS Agent Principal
//!
//! Module principal de l'agent ERDPS qui coordonne tous les composants
//! de surveillance et de détection de ransomwares
//!
//! Fonctionnalités:
//! - Coordination des modules de surveillance
//! - Communication avec le serveur ERDPS
//! - Gestion de la configuration
//! - Logging et reporting
//! - Gestion du cycle de vie de l'agent
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::{sleep, interval};
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// Importation des modules de surveillance
use crate::monitoring::{
    file_monitor::{FileMonitor, FileMonitorConfig},
    process_monitor::{ProcessMonitor, ProcessMonitorConfig},
    network_monitor::{NetworkMonitor, NetworkMonitorConfig},
    registry_monitor::{RegistryMonitor, RegistryMonitorConfig},
};

// Importation du moteur de détection
use crate::detection::behavioral_engine::{
    BehavioralEngine,
    BehavioralEngineConfig,
    FileEvent,
    ProcessEvent,
    NetworkEvent,
    RegistryEvent,
    ThreatAlert,
};

// Importation de la communication
use crate::communication::{
    grpc_client::{GrpcClient, GrpcClientConfig},
    security::SecurityManager,
    heartbeat::{HeartbeatManager, HealthStatus},
    reporting::ReportingManager,
};
use crate::config::AgentConfig;
use crate::utils::crypto::CryptoManager;

// Configuration de l'agent

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ERDPSAgentConfig {
    pub agent_id: String,
    pub server_endpoint: String,
    pub enable_file_monitoring: bool,
    pub enable_process_monitoring: bool,
    pub enable_network_monitoring: bool,
    pub enable_registry_monitoring: bool,
    pub enable_behavioral_detection: bool,
    pub reporting_interval_seconds: u64,
    pub heartbeat_interval_seconds: u64,
    pub max_events_per_batch: usize,
    pub log_level: String,
    pub data_retention_hours: u64,
    pub enable_real_time_alerts: bool,
    pub quarantine_enabled: bool,
    pub auto_response_enabled: bool,
    pub file_monitor_config: FileMonitorConfig,
    pub process_monitor_config: ProcessMonitorConfig,
    pub network_monitor_config: NetworkMonitorConfig,
    pub registry_monitor_config: RegistryMonitorConfig,
    pub behavioral_engine_config: BehavioralEngineConfig,
    pub grpc_client_config: GrpcClientConfig,
}

impl Default for ERDPSAgentConfig {
    fn default() -> Self {
        Self {
            agent_id: Uuid::new_v4().to_string(),
            server_endpoint: "https://localhost:8443".to_string(),
            enable_file_monitoring: true,
            enable_process_monitoring: true,
            enable_network_monitoring: true,
            enable_registry_monitoring: true,
            enable_behavioral_detection: true,
            reporting_interval_seconds: 30,
            heartbeat_interval_seconds: 60,
            max_events_per_batch: 100,
            log_level: "INFO".to_string(),
            data_retention_hours: 24,
            enable_real_time_alerts: true,
            quarantine_enabled: true,
            auto_response_enabled: false,
            file_monitor_config: FileMonitorConfig::default(),
            process_monitor_config: ProcessMonitorConfig::default(),
            network_monitor_config: NetworkMonitorConfig::default(),
            registry_monitor_config: RegistryMonitorConfig::default(),
            behavioral_engine_config: BehavioralEngineConfig::default(),
            grpc_client_config: GrpcClientConfig::default(),
        }
    }
}

// Structures de données pour les événements

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AgentEventType,
    pub source_module: String,
    pub severity: EventSeverity,
    pub data: serde_json::Value,
    pub processed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentEventType {
    FileEvent,
    ProcessEvent,
    NetworkEvent,
    RegistryEvent,
    ThreatAlert,
    SystemEvent,
    ConfigurationChange,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum EventSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub agent_id: String,
    pub status: AgentState,
    pub last_heartbeat: DateTime<Utc>,
    pub uptime_seconds: u64,
    pub events_processed: u64,
    pub threats_detected: u64,
    pub active_monitors: Vec<String>,
    pub system_resources: SystemResources,
    pub configuration_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentState {
    Starting,
    Running,
    Paused,
    Stopping,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResources {
    pub cpu_usage_percent: f32,
    pub memory_usage_mb: u64,
    pub disk_usage_percent: f32,
    pub network_usage_kbps: u64,
}

// Agent principal ERDPS

pub struct ERDPSAgent {
    config: ERDPSAgentConfig,
    status: Arc<Mutex<AgentStatus>>,
    
    // Modules de surveillance
    file_monitor: Option<FileMonitor>,
    process_monitor: Option<ProcessMonitor>,
    network_monitor: Option<NetworkMonitor>,
    registry_monitor: Option<RegistryMonitor>,
    
    // Moteur de détection
    behavioral_engine: Option<BehavioralEngine>,
    
    // Communication
    grpc_client: Option<GrpcClient>,
    
    // Gestionnaires
    security_manager: Option<SecurityManager>,
    heartbeat_manager: Option<HeartbeatManager>,
    reporting_manager: Option<ReportingManager>,
    
    // Canaux de communication internes
    file_event_sender: mpsc::UnboundedSender<FileEvent>,
    file_event_receiver: Arc<Mutex<mpsc::UnboundedReceiver<FileEvent>>>,
    
    process_event_sender: mpsc::UnboundedSender<ProcessEvent>,
    process_event_receiver: Arc<Mutex<mpsc::UnboundedReceiver<ProcessEvent>>>,
    
    network_event_sender: mpsc::UnboundedSender<NetworkEvent>,
    network_event_receiver: Arc<Mutex<mpsc::UnboundedReceiver<NetworkEvent>>>,
    
    registry_event_sender: mpsc::UnboundedSender<RegistryEvent>,
    registry_event_receiver: Arc<Mutex<mpsc::UnboundedReceiver<RegistryEvent>>>,
    
    threat_alert_sender: mpsc::UnboundedSender<ThreatAlert>,
    threat_alert_receiver: Arc<Mutex<mpsc::UnboundedReceiver<ThreatAlert>>>,
    
    // Gestion des événements
    event_queue: Arc<Mutex<Vec<AgentEvent>>>,
    event_statistics: Arc<Mutex<HashMap<String, u64>>>,
    
    // Contrôle du cycle de vie
    shutdown_signal: Arc<Mutex<bool>>,
    start_time: SystemTime,
}

impl ERDPSAgent {
    /// Crée une nouvelle instance de l'agent ERDPS
    pub fn new(config: ERDPSAgentConfig) -> Self {
        // Création des canaux de communication
        let (file_event_sender, file_event_receiver) = mpsc::unbounded_channel();
        let (process_event_sender, process_event_receiver) = mpsc::unbounded_channel();
        let (network_event_sender, network_event_receiver) = mpsc::unbounded_channel();
        let (registry_event_sender, registry_event_receiver) = mpsc::unbounded_channel();
        let (threat_alert_sender, threat_alert_receiver) = mpsc::unbounded_channel();
        
        // Initialisation du statut
        let status = AgentStatus {
            agent_id: config.agent_id.clone(),
            status: AgentState::Starting,
            last_heartbeat: Utc::now(),
            uptime_seconds: 0,
            events_processed: 0,
            threats_detected: 0,
            active_monitors: Vec::new(),
            system_resources: SystemResources {
                cpu_usage_percent: 0.0,
                memory_usage_mb: 0,
                disk_usage_percent: 0.0,
                network_usage_kbps: 0,
            },
            configuration_version: "1.0.0".to_string(),
        };
        
        Self {
            config,
            status: Arc::new(Mutex::new(status)),
            file_monitor: None,
            process_monitor: None,
            network_monitor: None,
            registry_monitor: None,
            behavioral_engine: None,
            grpc_client: None,
            security_manager: None,
            heartbeat_manager: None,
            reporting_manager: None,
            file_event_sender,
            file_event_receiver: Arc::new(Mutex::new(file_event_receiver)),
            process_event_sender,
            process_event_receiver: Arc::new(Mutex::new(process_event_receiver)),
            network_event_sender,
            network_event_receiver: Arc::new(Mutex::new(network_event_receiver)),
            registry_event_sender,
            registry_event_receiver: Arc::new(Mutex::new(registry_event_receiver)),
            threat_alert_sender,
            threat_alert_receiver: Arc::new(Mutex::new(threat_alert_receiver)),
            event_queue: Arc::new(Mutex::new(Vec::new())),
            event_statistics: Arc::new(Mutex::new(HashMap::new())),
            shutdown_signal: Arc::new(Mutex::new(false)),
            start_time: SystemTime::now(),
        }
    }

    /// Démarre l'agent ERDPS
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting ERDPS Agent v1.0.0...");
        
        // Mise à jour du statut
        {
            let mut status = self.status.lock().unwrap();
            status.status = AgentState::Starting;
            status.last_heartbeat = Utc::now();
        }
        
        // Initialisation du client gRPC
        if let Err(e) = self.initialize_grpc_client().await {
            error!("Failed to initialize gRPC client: {}", e);
            return Err(e);
        }
        
        // Initialisation du moteur de détection comportementale
        if self.config.enable_behavioral_detection {
            if let Err(e) = self.initialize_behavioral_engine().await {
                error!("Failed to initialize behavioral engine: {}", e);
                return Err(e);
            }
        }
        
        // Initialisation des modules de surveillance
        if let Err(e) = self.initialize_monitoring_modules().await {
            error!("Failed to initialize monitoring modules: {}", e);
            return Err(e);
        }
        
        // Démarrage des tâches de traitement d'événements
        self.start_event_processing_tasks().await;
        
        // Démarrage des tâches de maintenance
        self.start_maintenance_tasks().await;
        
        // Mise à jour du statut
        {
            let mut status = self.status.lock().unwrap();
            status.status = AgentState::Running;
            status.last_heartbeat = Utc::now();
        }
        
        info!("ERDPS Agent started successfully");
        Ok(())
    }

    /// Arrête l'agent ERDPS
    pub async fn stop(&mut self) {
        info!("Stopping ERDPS Agent...");
        
        // Mise à jour du statut
        {
            let mut status = self.status.lock().unwrap();
            status.status = AgentState::Stopping;
        }
        
        // Signal d'arrêt
        {
            let mut shutdown = self.shutdown_signal.lock().unwrap();
            *shutdown = true;
        }
        
        // Arrêt des modules de surveillance
        if let Some(ref file_monitor) = self.file_monitor {
            file_monitor.stop().await;
        }
        
        if let Some(ref process_monitor) = self.process_monitor {
            process_monitor.stop().await;
        }
        
        if let Some(ref network_monitor) = self.network_monitor {
            network_monitor.stop().await;
        }
        
        if let Some(ref registry_monitor) = self.registry_monitor {
            registry_monitor.stop().await;
        }
        
        // Arrêt du moteur de détection
        if let Some(ref behavioral_engine) = self.behavioral_engine {
            behavioral_engine.stop().await;
        }
        
        // Envoi des derniers événements
        self.flush_events().await;
        
        // Mise à jour du statut final
        {
            let mut status = self.status.lock().unwrap();
            status.status = AgentState::Stopped;
        }
        
        info!("ERDPS Agent stopped");
    }

    /// Initialise le client gRPC
    async fn initialize_grpc_client(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Initializing gRPC client...");
        
        let grpc_client = GrpcClient::new(self.config.grpc_client_config.clone()).await?;
        self.grpc_client = Some(grpc_client);
        
        info!("gRPC client initialized successfully");
        Ok(())
    }

    /// Initialise le moteur de détection comportementale
    async fn initialize_behavioral_engine(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Initializing behavioral detection engine...");
        
        let behavioral_engine = BehavioralEngine::new(
            self.config.behavioral_engine_config.clone(),
            self.threat_alert_sender.clone(),
        ).await?;
        
        self.behavioral_engine = Some(behavioral_engine);
        
        if let Some(ref engine) = self.behavioral_engine {
            engine.start().await?;
        }
        
        info!("Behavioral detection engine initialized successfully");
        Ok(())
    }

    /// Initialise les modules de surveillance
    async fn initialize_monitoring_modules(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Initializing monitoring modules...");
        
        let mut active_monitors = Vec::new();
        
        // Surveillance des fichiers
        if self.config.enable_file_monitoring {
            let file_monitor = FileMonitor::new(
                self.config.file_monitor_config.clone(),
                self.file_event_sender.clone(),
            );
            
            file_monitor.start().await?;
            self.file_monitor = Some(file_monitor);
            active_monitors.push("FileMonitor".to_string());
            info!("File monitoring enabled");
        }
        
        // Surveillance des processus
        if self.config.enable_process_monitoring {
            let process_monitor = ProcessMonitor::new(
                self.config.process_monitor_config.clone(),
                self.process_event_sender.clone(),
            );
            
            process_monitor.start().await?;
            self.process_monitor = Some(process_monitor);
            active_monitors.push("ProcessMonitor".to_string());
            info!("Process monitoring enabled");
        }
        
        // Surveillance réseau
        if self.config.enable_network_monitoring {
            let network_monitor = NetworkMonitor::new(
                self.config.network_monitor_config.clone(),
                self.network_event_sender.clone(),
            );
            
            network_monitor.start().await?;
            self.network_monitor = Some(network_monitor);
            active_monitors.push("NetworkMonitor".to_string());
            info!("Network monitoring enabled");
        }
        
        // Surveillance du registre
        if self.config.enable_registry_monitoring {
            let registry_monitor = RegistryMonitor::new(
                self.config.registry_monitor_config.clone(),
                self.registry_event_sender.clone(),
            );
            
            registry_monitor.start().await?;
            self.registry_monitor = Some(registry_monitor);
            active_monitors.push("RegistryMonitor".to_string());
            info!("Registry monitoring enabled");
        }
        
        // Mise à jour du statut
        {
            let mut status = self.status.lock().unwrap();
            status.active_monitors = active_monitors;
        }
        
        info!("Monitoring modules initialized successfully");
        Ok(())
    }

    /// Démarre les tâches de traitement d'événements
    async fn start_event_processing_tasks(&self) {
        info!("Starting event processing tasks...");
        
        // Traitement des événements de fichiers
        let file_receiver = self.file_event_receiver.clone();
        let behavioral_engine_file = self.behavioral_engine.as_ref().map(|e| e.clone());
        let event_queue_file = self.event_queue.clone();
        let event_stats_file = self.event_statistics.clone();
        let shutdown_file = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::process_file_events(
                file_receiver,
                behavioral_engine_file,
                event_queue_file,
                event_stats_file,
                shutdown_file,
            ).await;
        });
        
        // Traitement des événements de processus
        let process_receiver = self.process_event_receiver.clone();
        let behavioral_engine_process = self.behavioral_engine.as_ref().map(|e| e.clone());
        let event_queue_process = self.event_queue.clone();
        let event_stats_process = self.event_statistics.clone();
        let shutdown_process = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::process_process_events(
                process_receiver,
                behavioral_engine_process,
                event_queue_process,
                event_stats_process,
                shutdown_process,
            ).await;
        });
        
        // Traitement des événements réseau
        let network_receiver = self.network_event_receiver.clone();
        let behavioral_engine_network = self.behavioral_engine.as_ref().map(|e| e.clone());
        let event_queue_network = self.event_queue.clone();
        let event_stats_network = self.event_statistics.clone();
        let shutdown_network = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::process_network_events(
                network_receiver,
                behavioral_engine_network,
                event_queue_network,
                event_stats_network,
                shutdown_network,
            ).await;
        });
        
        // Traitement des événements de registre
        let registry_receiver = self.registry_event_receiver.clone();
        let behavioral_engine_registry = self.behavioral_engine.as_ref().map(|e| e.clone());
        let event_queue_registry = self.event_queue.clone();
        let event_stats_registry = self.event_statistics.clone();
        let shutdown_registry = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::process_registry_events(
                registry_receiver,
                behavioral_engine_registry,
                event_queue_registry,
                event_stats_registry,
                shutdown_registry,
            ).await;
        });
        
        // Traitement des alertes de menaces
        let threat_receiver = self.threat_alert_receiver.clone();
        let event_queue_threat = self.event_queue.clone();
        let event_stats_threat = self.event_statistics.clone();
        let shutdown_threat = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::process_threat_alerts(
                threat_receiver,
                event_queue_threat,
                event_stats_threat,
                shutdown_threat,
            ).await;
        });
        
        info!("Event processing tasks started");
    }

    /// Démarre les tâches de maintenance
    async fn start_maintenance_tasks(&self) {
        info!("Starting maintenance tasks...");
        
        // Tâche de reporting périodique
        let config_reporting = self.config.clone();
        let event_queue_reporting = self.event_queue.clone();
        let grpc_client_reporting = self.grpc_client.as_ref().map(|c| c.clone());
        let shutdown_reporting = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::reporting_task(
                config_reporting,
                event_queue_reporting,
                grpc_client_reporting,
                shutdown_reporting,
            ).await;
        });
        
        // Tâche de heartbeat
        let config_heartbeat = self.config.clone();
        let status_heartbeat = self.status.clone();
        let grpc_client_heartbeat = self.grpc_client.as_ref().map(|c| c.clone());
        let shutdown_heartbeat = self.shutdown_signal.clone();
        let start_time = self.start_time;
        
        tokio::spawn(async move {
            Self::heartbeat_task(
                config_heartbeat,
                status_heartbeat,
                grpc_client_heartbeat,
                shutdown_heartbeat,
                start_time,
            ).await;
        });
        
        // Tâche de surveillance des ressources système
        let status_resources = self.status.clone();
        let shutdown_resources = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::system_resources_task(
                status_resources,
                shutdown_resources,
            ).await;
        });
        
        // Tâche de nettoyage
        let event_queue_cleanup = self.event_queue.clone();
        let event_stats_cleanup = self.event_statistics.clone();
        let config_cleanup = self.config.clone();
        let shutdown_cleanup = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::cleanup_task(
                event_queue_cleanup,
                event_stats_cleanup,
                config_cleanup,
                shutdown_cleanup,
            ).await;
        });
        
        info!("Maintenance tasks started");
    }

    /// Traite les événements de fichiers
    async fn process_file_events(
        receiver: Arc<Mutex<mpsc::UnboundedReceiver<FileEvent>>>,
        behavioral_engine: Option<BehavioralEngine>,
        event_queue: Arc<Mutex<Vec<AgentEvent>>>,
        event_statistics: Arc<Mutex<HashMap<String, u64>>>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        loop {
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Réception d'événements
            let event = {
                let mut recv = receiver.lock().unwrap();
                recv.try_recv()
            };
            
            match event {
                Ok(file_event) => {
                    debug!("Processing file event: {:?}", file_event.event_id);
                    
                    // Envoi au moteur de détection comportementale
                    if let Some(ref engine) = behavioral_engine {
                        if let Err(e) = engine.process_file_event(file_event.clone()).await {
                            error!("Failed to process file event in behavioral engine: {}", e);
                        }
                    }
                    
                    // Création d'un événement agent
                    let agent_event = AgentEvent {
                        event_id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        event_type: AgentEventType::FileEvent,
                        source_module: "FileMonitor".to_string(),
                        severity: EventSeverity::Low,
                        data: serde_json::to_value(&file_event).unwrap_or_default(),
                        processed: false,
                    };
                    
                    // Ajout à la queue
                    {
                        let mut queue = event_queue.lock().unwrap();
                        queue.push(agent_event);
                    }
                    
                    // Mise à jour des statistiques
                    {
                        let mut stats = event_statistics.lock().unwrap();
                        *stats.entry("file_events".to_string()).or_insert(0) += 1;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    warn!("File event channel disconnected");
                    break;
                }
            }
        }
        
        debug!("File event processing stopped");
    }

    /// Traite les événements de processus
    async fn process_process_events(
        receiver: Arc<Mutex<mpsc::UnboundedReceiver<ProcessEvent>>>,
        behavioral_engine: Option<BehavioralEngine>,
        event_queue: Arc<Mutex<Vec<AgentEvent>>>,
        event_statistics: Arc<Mutex<HashMap<String, u64>>>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        loop {
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Réception d'événements
            let event = {
                let mut recv = receiver.lock().unwrap();
                recv.try_recv()
            };
            
            match event {
                Ok(process_event) => {
                    debug!("Processing process event: {:?}", process_event.event_id);
                    
                    // Envoi au moteur de détection comportementale
                    if let Some(ref engine) = behavioral_engine {
                        if let Err(e) = engine.process_process_event(process_event.clone()).await {
                            error!("Failed to process process event in behavioral engine: {}", e);
                        }
                    }
                    
                    // Création d'un événement agent
                    let agent_event = AgentEvent {
                        event_id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        event_type: AgentEventType::ProcessEvent,
                        source_module: "ProcessMonitor".to_string(),
                        severity: EventSeverity::Medium,
                        data: serde_json::to_value(&process_event).unwrap_or_default(),
                        processed: false,
                    };
                    
                    // Ajout à la queue
                    {
                        let mut queue = event_queue.lock().unwrap();
                        queue.push(agent_event);
                    }
                    
                    // Mise à jour des statistiques
                    {
                        let mut stats = event_statistics.lock().unwrap();
                        *stats.entry("process_events".to_string()).or_insert(0) += 1;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    warn!("Process event channel disconnected");
                    break;
                }
            }
        }
        
        debug!("Process event processing stopped");
    }

    /// Traite les événements réseau
    async fn process_network_events(
        receiver: Arc<Mutex<mpsc::UnboundedReceiver<NetworkEvent>>>,
        behavioral_engine: Option<BehavioralEngine>,
        event_queue: Arc<Mutex<Vec<AgentEvent>>>,
        event_statistics: Arc<Mutex<HashMap<String, u64>>>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        loop {
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Réception d'événements
            let event = {
                let mut recv = receiver.lock().unwrap();
                recv.try_recv()
            };
            
            match event {
                Ok(network_event) => {
                    debug!("Processing network event: {:?}", network_event.event_id);
                    
                    // Envoi au moteur de détection comportementale
                    if let Some(ref engine) = behavioral_engine {
                        if let Err(e) = engine.process_network_event(network_event.clone()).await {
                            error!("Failed to process network event in behavioral engine: {}", e);
                        }
                    }
                    
                    // Création d'un événement agent
                    let agent_event = AgentEvent {
                        event_id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        event_type: AgentEventType::NetworkEvent,
                        source_module: "NetworkMonitor".to_string(),
                        severity: EventSeverity::Low,
                        data: serde_json::to_value(&network_event).unwrap_or_default(),
                        processed: false,
                    };
                    
                    // Ajout à la queue
                    {
                        let mut queue = event_queue.lock().unwrap();
                        queue.push(agent_event);
                    }
                    
                    // Mise à jour des statistiques
                    {
                        let mut stats = event_statistics.lock().unwrap();
                        *stats.entry("network_events".to_string()).or_insert(0) += 1;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    warn!("Network event channel disconnected");
                    break;
                }
            }
        }
        
        debug!("Network event processing stopped");
    }

    /// Traite les événements de registre
    async fn process_registry_events(
        receiver: Arc<Mutex<mpsc::UnboundedReceiver<RegistryEvent>>>,
        behavioral_engine: Option<BehavioralEngine>,
        event_queue: Arc<Mutex<Vec<AgentEvent>>>,
        event_statistics: Arc<Mutex<HashMap<String, u64>>>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        loop {
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Réception d'événements
            let event = {
                let mut recv = receiver.lock().unwrap();
                recv.try_recv()
            };
            
            match event {
                Ok(registry_event) => {
                    debug!("Processing registry event: {:?}", registry_event.event_id);
                    
                    // Envoi au moteur de détection comportementale
                    if let Some(ref engine) = behavioral_engine {
                        if let Err(e) = engine.process_registry_event(registry_event.clone()).await {
                            error!("Failed to process registry event in behavioral engine: {}", e);
                        }
                    }
                    
                    // Création d'un événement agent
                    let agent_event = AgentEvent {
                        event_id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        event_type: AgentEventType::RegistryEvent,
                        source_module: "RegistryMonitor".to_string(),
                        severity: EventSeverity::Medium,
                        data: serde_json::to_value(&registry_event).unwrap_or_default(),
                        processed: false,
                    };
                    
                    // Ajout à la queue
                    {
                        let mut queue = event_queue.lock().unwrap();
                        queue.push(agent_event);
                    }
                    
                    // Mise à jour des statistiques
                    {
                        let mut stats = event_statistics.lock().unwrap();
                        *stats.entry("registry_events".to_string()).or_insert(0) += 1;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    warn!("Registry event channel disconnected");
                    break;
                }
            }
        }
        
        debug!("Registry event processing stopped");
    }

    /// Traite les alertes de menaces
    async fn process_threat_alerts(
        receiver: Arc<Mutex<mpsc::UnboundedReceiver<ThreatAlert>>>,
        event_queue: Arc<Mutex<Vec<AgentEvent>>>,
        event_statistics: Arc<Mutex<HashMap<String, u64>>>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        loop {
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Réception d'alertes
            let alert = {
                let mut recv = receiver.lock().unwrap();
                recv.try_recv()
            };
            
            match alert {
                Ok(threat_alert) => {
                    warn!("Processing threat alert: {:?} - {}", threat_alert.alert_id, threat_alert.threat_type);
                    
                    // Création d'un événement agent critique
                    let agent_event = AgentEvent {
                        event_id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        event_type: AgentEventType::ThreatAlert,
                        source_module: "BehavioralEngine".to_string(),
                        severity: match threat_alert.severity {
                            1..=3 => EventSeverity::Low,
                            4..=6 => EventSeverity::Medium,
                            7..=8 => EventSeverity::High,
                            _ => EventSeverity::Critical,
                        },
                        data: serde_json::to_value(&threat_alert).unwrap_or_default(),
                        processed: false,
                    };
                    
                    // Ajout prioritaire à la queue
                    {
                        let mut queue = event_queue.lock().unwrap();
                        queue.insert(0, agent_event); // Insertion en tête pour priorité
                    }
                    
                    // Mise à jour des statistiques
                    {
                        let mut stats = event_statistics.lock().unwrap();
                        *stats.entry("threat_alerts".to_string()).or_insert(0) += 1;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    warn!("Threat alert channel disconnected");
                    break;
                }
            }
        }
        
        debug!("Threat alert processing stopped");
    }

    /// Tâche de reporting périodique
    async fn reporting_task(
        config: ERDPSAgentConfig,
        event_queue: Arc<Mutex<Vec<AgentEvent>>>,
        grpc_client: Option<GrpcClient>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        let mut interval = interval(Duration::from_secs(config.reporting_interval_seconds));
        
        loop {
            interval.tick().await;
            
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Collecte des événements à envoyer
            let events_to_send = {
                let mut queue = event_queue.lock().unwrap();
                let mut events = Vec::new();
                
                // Prendre jusqu'à max_events_per_batch événements
                let count = queue.len().min(config.max_events_per_batch);
                for _ in 0..count {
                    if let Some(event) = queue.pop() {
                        events.push(event);
                    }
                }
                
                events
            };
            
            if !events_to_send.is_empty() {
                debug!("Sending {} events to server", events_to_send.len());
                
                // Envoi au serveur via gRPC
                if let Some(ref client) = grpc_client {
                    if let Err(e) = client.send_events(events_to_send).await {
                        error!("Failed to send events to server: {}", e);
                    }
                }
            }
        }
        
        debug!("Reporting task stopped");
    }

    /// Tâche de heartbeat
    async fn heartbeat_task(
        config: ERDPSAgentConfig,
        status: Arc<Mutex<AgentStatus>>,
        grpc_client: Option<GrpcClient>,
        shutdown_signal: Arc<Mutex<bool>>,
        start_time: SystemTime,
    ) {
        let mut interval = interval(Duration::from_secs(config.heartbeat_interval_seconds));
        
        loop {
            interval.tick().await;
            
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Mise à jour du statut
            let current_status = {
                let mut status_guard = status.lock().unwrap();
                status_guard.last_heartbeat = Utc::now();
                
                if let Ok(uptime) = SystemTime::now().duration_since(start_time) {
                    status_guard.uptime_seconds = uptime.as_secs();
                }
                
                status_guard.clone()
            };
            
            // Envoi du heartbeat au serveur
            if let Some(ref client) = grpc_client {
                if let Err(e) = client.send_heartbeat(current_status).await {
                    error!("Failed to send heartbeat to server: {}", e);
                }
            }
            
            debug!("Heartbeat sent");
        }
        
        debug!("Heartbeat task stopped");
    }

    /// Tâche de surveillance des ressources système
    async fn system_resources_task(
        status: Arc<Mutex<AgentStatus>>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        let mut interval = interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Collecte des métriques système
            let resources = Self::collect_system_resources().await;
            
            // Mise à jour du statut
            {
                let mut status_guard = status.lock().unwrap();
                status_guard.system_resources = resources;
            }
        }
        
        debug!("System resources monitoring stopped");
    }

    /// Collecte les métriques des ressources système
    async fn collect_system_resources() -> SystemResources {
        // Implémentation simplifiée - à améliorer avec des APIs système réelles
        SystemResources {
            cpu_usage_percent: 0.0,
            memory_usage_mb: 0,
            disk_usage_percent: 0.0,
            network_usage_kbps: 0,
        }
    }

    /// Tâche de nettoyage périodique
    async fn cleanup_task(
        event_queue: Arc<Mutex<Vec<AgentEvent>>>,
        event_statistics: Arc<Mutex<HashMap<String, u64>>>,
        config: ERDPSAgentConfig,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        let mut interval = interval(Duration::from_secs(3600)); // 1 heure
        let max_age = Duration::from_secs(config.data_retention_hours * 3600);
        
        loop {
            interval.tick().await;
            
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Nettoyage de la queue d'événements
            {
                let mut queue = event_queue.lock().unwrap();
                let now = Utc::now();
                
                queue.retain(|event| {
                    let age = now.signed_duration_since(event.timestamp);
                    age.num_seconds() < max_age.as_secs() as i64
                });
                
                debug!("Event queue cleanup completed, {} events remaining", queue.len());
            }
            
            // Réinitialisation des statistiques anciennes
            {
                let mut stats = event_statistics.lock().unwrap();
                // Garder seulement les statistiques récentes
                // Pour l'instant, on garde tout - à améliorer
                debug!("Statistics cleanup completed, {} entries", stats.len());
            }
        }
        
        debug!("Cleanup task stopped");
    }

    /// Vide la queue d'événements (envoi forcé)
    async fn flush_events(&self) {
        info!("Flushing remaining events...");
        
        let events_to_send = {
            let mut queue = self.event_queue.lock().unwrap();
            queue.drain(..).collect::<Vec<_>>()
        };
        
        if !events_to_send.is_empty() {
            info!("Sending {} remaining events", events_to_send.len());
            
            if let Some(ref client) = self.grpc_client {
                if let Err(e) = client.send_events(events_to_send).await {
                    error!("Failed to send remaining events: {}", e);
                }
            }
        }
    }

    /// Obtient le statut actuel de l'agent
    pub fn get_status(&self) -> AgentStatus {
        self.status.lock().unwrap().clone()
    }

    /// Obtient les statistiques de l'agent
    pub fn get_statistics(&self) -> HashMap<String, u64> {
        self.event_statistics.lock().unwrap().clone()
    }

    /// Met à jour la configuration de l'agent
    pub async fn update_config(&mut self, new_config: ERDPSAgentConfig) -> Result<(), Box<dyn std::error::Error>> {
        info!("Updating agent configuration...");
        
        // Validation de la configuration
        if new_config.agent_id != self.config.agent_id {
            return Err("Agent ID cannot be changed".into());
        }
        
        // Mise à jour de la configuration
        self.config = new_config;
        
        // Redémarrage des modules si nécessaire
        // Pour l'instant, on log seulement - à implémenter
        info!("Configuration updated successfully");
        
        Ok(())
    }
}

// Tests unitaires

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_creation() {
        let config = ERDPSAgentConfig::default();
        let agent = ERDPSAgent::new(config);
        
        let status = agent.get_status();
        assert_eq!(status.status, AgentState::Starting);
        assert!(!status.agent_id.is_empty());
    }

    #[test]
    fn test_config_validation() {
        let config = ERDPSAgentConfig::default();
        assert!(config.enable_file_monitoring);
        assert!(config.enable_process_monitoring);
        assert!(config.enable_network_monitoring);
        assert!(config.enable_registry_monitoring);
        assert!(config.enable_behavioral_detection);
    }

    #[test]
    fn test_event_severity_ordering() {
        assert!(EventSeverity::Critical > EventSeverity::High);
        assert!(EventSeverity::High > EventSeverity::Medium);
        assert!(EventSeverity::Medium > EventSeverity::Low);
    }

    #[tokio::test]
    async fn test_system_resources_collection() {
        let resources = ERDPSAgent::collect_system_resources().await;
        assert!(resources.cpu_usage_percent >= 0.0);
        assert!(resources.memory_usage_mb >= 0);
    }
}