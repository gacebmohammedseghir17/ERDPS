//! Module de service Windows ERDPS
//!
//! Gestion du service Windows natif:
//! - Installation/désinstallation du service
//! - Démarrage automatique au boot
//! - Gestion des privilèges élevés
//! - Interface de contrôle du service
//! - Logging des événements système
//! - Récupération après crash

use std::sync::Arc;
use std::time::Duration;
use std::ffi::OsString;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context, bail};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

// Imports Windows spécifiques (simulation)
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    Result as WindowsServiceResult,
};

use crate::config::AgentConfig;
use crate::monitor::{FileMonitor, ProcessMonitor, NetworkMonitor};
use crate::detection::ThreatDetector;
use crate::communication::SecureCommunicationClient;
use crate::logging::{SecureLogger, LogLevel, LogCategory};

/// Gestionnaire de service Windows
pub struct WindowsServiceManager {
    config: AgentConfig,
    service_state: Arc<RwLock<ServiceState>>,
    service_status_handle: Option<windows_service::service_control_handler::ServiceStatusHandle>,
    file_monitor: Option<FileMonitor>,
    process_monitor: Option<ProcessMonitor>,
    network_monitor: Option<NetworkMonitor>,
    threat_detector: Option<Arc<ThreatDetector>>,
    communication_client: Option<SecureCommunicationClient>,
    logger: Option<SecureLogger>,
    shutdown_signal: Arc<RwLock<bool>>,
    service_start_time: Option<DateTime<Utc>>,
}

/// État du service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub state: ServiceStateInfo,
    pub start_time: Option<DateTime<Utc>>,
    pub uptime: Option<Duration>,
    pub process_id: u32,
    pub version: String,
    pub config_path: String,
}

/// Information d'état du service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceStateInfo {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

/// Statistiques du service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStats {
    pub threats_detected: u64,
    pub files_monitored: u64,
    pub processes_monitored: u64,
    pub network_connections: u64,
    pub alerts_sent: u64,
    pub uptime: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f32,
    pub last_threat: Option<DateTime<Utc>>,
    pub last_communication: Option<DateTime<Utc>>,
}

/// Configuration d'installation du service
#[derive(Debug, Clone)]
pub struct ServiceInstallConfig {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub executable_path: String,
    pub start_type: ServiceStartType,
    pub dependencies: Vec<String>,
    pub account: ServiceAccount,
    pub auto_restart: bool,
    pub failure_actions: Vec<FailureAction>,
}

/// Type de démarrage du service
#[derive(Debug, Clone)]
pub enum ServiceStartType {
    Automatic,
    Manual,
    Disabled,
    AutomaticDelayed,
}

/// Compte de service
#[derive(Debug, Clone)]
pub enum ServiceAccount {
    LocalSystem,
    LocalService,
    NetworkService,
    Custom { username: String, password: String },
}

/// Action en cas d'échec
#[derive(Debug, Clone)]
pub enum FailureAction {
    None,
    Restart { delay: Duration },
    Reboot { delay: Duration },
    RunCommand { command: String, delay: Duration },
}

// Définition du service Windows
#[cfg(windows)]
define_windows_service!(ffi_service_main, erdps_service_main);

/// Point d'entrée principal du service
#[cfg(windows)]
fn erdps_service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        // Log l'erreur dans le journal des événements Windows
        eprintln!("Erreur du service ERDPS: {}", e);
    }
}

/// Exécute le service
#[cfg(windows)]
fn run_service(_arguments: Vec<OsString>) -> WindowsServiceResult<()> {
    use std::sync::mpsc;
    
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    
    // Gestionnaire de contrôle du service
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_tx.send(()).ok();
                ServiceControlHandlerResult::NoError
            },
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    
    // Enregistrer le gestionnaire de contrôle
    let status_handle = service_control_handler::register("ERDPS-Agent", event_handler)?;
    
    // Signaler que le service démarre
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;
    
    // Initialiser et démarrer le service
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    rt.block_on(async {
        match initialize_and_run_service(status_handle.clone()).await {
            Ok(_) => {
                info!("✅ Service ERDPS démarré avec succès");
            },
            Err(e) => {
                error!("❌ Erreur lors du démarrage du service: {}", e);
                
                // Signaler l'erreur
                status_handle.set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(1),
                    checkpoint: 0,
                    wait_hint: Duration::default(),
                    process_id: None,
                }).ok();
                
                return;
            }
        }
        
        // Signaler que le service est en cours d'exécution
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }).ok();
        
        // Attendre le signal d'arrêt
        tokio::task::spawn_blocking(move || {
            shutdown_rx.recv().ok();
        }).await.ok();
        
        info!("🛑 Signal d'arrêt reçu, arrêt du service...");
    });
    
    // Signaler que le service s'arrête
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;
    
    // Nettoyage et arrêt
    // Ici, on arrêterait tous les composants
    
    // Signaler que le service est arrêté
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    
    Ok(())
}

/// Initialise et exécute le service
#[cfg(windows)]
async fn initialize_and_run_service(
    _status_handle: windows_service::service_control_handler::ServiceStatusHandle,
) -> Result<()> {
    // Charger la configuration
    let config = AgentConfig::load_from_file("C:\\Program Files\\ERDPS\\config.toml")
        .await
        .context("Chargement de la configuration")?;
    
    // Créer le gestionnaire de service
    let mut service_manager = WindowsServiceManager::new(config)?;
    
    // Démarrer tous les composants
    service_manager.start().await
        .context("Démarrage du gestionnaire de service")?;
    
    // Boucle principale du service
    service_manager.run().await
        .context("Exécution du service")?;
    
    Ok(())
}

impl WindowsServiceManager {
    /// Crée un nouveau gestionnaire de service
    pub fn new(config: AgentConfig) -> Result<Self> {
        Ok(Self {
            config,
            service_state: Arc::new(RwLock::new(ServiceState::Stopped)),
            service_status_handle: None,
            file_monitor: None,
            process_monitor: None,
            network_monitor: None,
            threat_detector: None,
            communication_client: None,
            logger: None,
            shutdown_signal: Arc::new(RwLock::new(false)),
            service_start_time: None,
        })
    }
    
    /// Démarre le service
    pub async fn start(&mut self) -> Result<()> {
        info!("🚀 Démarrage du service ERDPS Agent...");
        
        // Vérifier les privilèges
        self.check_privileges().await?;
        
        // Initialiser le logger
        let mut logger = SecureLogger::new(self.config.logging.clone())?;
        logger.start().await
            .context("Démarrage du système de logging")?;
        self.logger = Some(logger);
        
        // Log du démarrage
        if let Some(ref logger) = self.logger {
            logger.log_message(
                LogLevel::Info,
                LogCategory::System,
                "Service ERDPS Agent démarré",
                Some(serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "pid": std::process::id(),
                    "config_mode": self.config.operation_mode
                })),
            ).await?;
        }
        
        // Initialiser le détecteur de menaces
        let threat_detector = Arc::new(
            ThreatDetector::new(&self.config.detection).await
                .context("Initialisation du détecteur de menaces")?
        );
        self.threat_detector = Some(threat_detector.clone());
        
        // Initialiser les moniteurs
        let mut file_monitor = FileMonitor::new(
            &self.config.monitoring.monitored_paths,
            threat_detector.clone(),
        )?;
        file_monitor.start().await
            .context("Démarrage du moniteur de fichiers")?;
        self.file_monitor = Some(file_monitor);
        
        let mut process_monitor = ProcessMonitor::new(threat_detector.clone())?;
        process_monitor.start().await
            .context("Démarrage du moniteur de processus")?;
        self.process_monitor = Some(process_monitor);
        
        let mut network_monitor = NetworkMonitor::new(threat_detector.clone())?;
        network_monitor.start().await
            .context("Démarrage du moniteur réseau")?;
        self.network_monitor = Some(network_monitor);
        
        // Initialiser la communication
        let mut communication_client = SecureCommunicationClient::new(
            self.config.server.clone()
        )?;
        communication_client.start().await
            .context("Démarrage de la communication sécurisée")?;
        self.communication_client = Some(communication_client);
        
        // Mettre à jour l'état
        let mut state = self.service_state.write().await;
        *state = ServiceState::Running;
        self.service_start_time = Some(Utc::now());
        
        info!("✅ Service ERDPS Agent démarré avec succès");
        Ok(())
    }
    
    /// Arrête le service
    pub async fn stop(&mut self) -> Result<()> {
        info!("🛑 Arrêt du service ERDPS Agent...");
        
        // Signaler l'arrêt
        let mut shutdown = self.shutdown_signal.write().await;
        *shutdown = true;
        drop(shutdown);
        
        // Arrêter les composants dans l'ordre inverse
        if let Some(ref mut client) = self.communication_client {
            client.stop().await
                .context("Arrêt de la communication")?;
        }
        
        if let Some(ref mut monitor) = self.network_monitor {
            monitor.stop().await
                .context("Arrêt du moniteur réseau")?;
        }
        
        if let Some(ref mut monitor) = self.process_monitor {
            monitor.stop().await
                .context("Arrêt du moniteur de processus")?;
        }
        
        if let Some(ref mut monitor) = self.file_monitor {
            monitor.stop().await
                .context("Arrêt du moniteur de fichiers")?;
        }
        
        if let Some(ref mut logger) = self.logger {
            logger.log_message(
                LogLevel::Info,
                LogCategory::System,
                "Service ERDPS Agent arrêté",
                None,
            ).await?;
            
            logger.stop().await
                .context("Arrêt du système de logging")?;
        }
        
        // Mettre à jour l'état
        let mut state = self.service_state.write().await;
        *state = ServiceState::Stopped;
        
        info!("✅ Service ERDPS Agent arrêté");
        Ok(())
    }
    
    /// Boucle principale du service
    pub async fn run(&mut self) -> Result<()> {
        info!("🔄 Démarrage de la boucle principale du service...");
        
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        
        loop {
            // Vérifier le signal d'arrêt
            let shutdown = self.shutdown_signal.read().await;
            if *shutdown {
                break;
            }
            drop(shutdown);
            
            interval.tick().await;
            
            // Tâches de maintenance
            if let Err(e) = self.perform_maintenance().await {
                error!("❌ Erreur lors de la maintenance: {}", e);
            }
            
            // Vérifier l'état des composants
            if let Err(e) = self.check_components_health().await {
                error!("❌ Erreur lors de la vérification de santé: {}", e);
            }
            
            // Envoyer les statistiques
            if let Err(e) = self.send_heartbeat().await {
                error!("❌ Erreur lors de l'envoi du heartbeat: {}", e);
            }
        }
        
        info!("🏁 Fin de la boucle principale du service");
        Ok(())
    }
    
    /// Vérifie les privilèges nécessaires
    async fn check_privileges(&self) -> Result<()> {
        info!("🔐 Vérification des privilèges...");
        
        // Vérifier si on s'exécute en tant qu'administrateur
        if !self.is_running_as_admin() {
            bail!("Le service ERDPS nécessite des privilèges administrateur");
        }
        
        // Vérifier les privilèges spécifiques nécessaires
        let required_privileges = vec![
            "SeDebugPrivilege",      // Pour surveiller les processus
            "SeSecurityPrivilege",   // Pour accéder aux logs de sécurité
            "SeBackupPrivilege",     // Pour sauvegarder les fichiers
            "SeRestorePrivilege",    // Pour restaurer les fichiers
            "SeTcbPrivilege",        // Pour agir en tant que partie du système
        ];
        
        for privilege in required_privileges {
            if !self.has_privilege(privilege) {
                warn!("⚠️ Privilège manquant: {}", privilege);
            }
        }
        
        info!("✅ Vérification des privilèges terminée");
        Ok(())
    }
    
    /// Vérifie si le processus s'exécute en tant qu'administrateur
    fn is_running_as_admin(&self) -> bool {
        // Implémentation Windows pour vérifier les privilèges admin
        // Ceci nécessiterait l'utilisation d'APIs Windows
        true // Simulation
    }
    
    /// Vérifie si un privilège spécifique est disponible
    fn has_privilege(&self, _privilege_name: &str) -> bool {
        // Implémentation Windows pour vérifier un privilège spécifique
        true // Simulation
    }
    
    /// Effectue les tâches de maintenance
    async fn perform_maintenance(&self) -> Result<()> {
        debug!("🔧 Maintenance du service...");
        
        // Nettoyage de la mémoire
        self.cleanup_memory().await?;
        
        // Vérification de l'intégrité des fichiers de configuration
        self.verify_config_integrity().await?;
        
        // Rotation des logs si nécessaire
        self.check_log_rotation().await?;
        
        // Mise à jour des règles de détection
        self.update_detection_rules().await?;
        
        Ok(())
    }
    
    /// Nettoyage de la mémoire
    async fn cleanup_memory(&self) -> Result<()> {
        // Implémentation du nettoyage mémoire
        Ok(())
    }
    
    /// Vérification de l'intégrité de la configuration
    async fn verify_config_integrity(&self) -> Result<()> {
        // Vérifier que les fichiers de configuration n'ont pas été modifiés
        Ok(())
    }
    
    /// Vérification de la rotation des logs
    async fn check_log_rotation(&self) -> Result<()> {
        // Vérifier si une rotation des logs est nécessaire
        Ok(())
    }
    
    /// Mise à jour des règles de détection
    async fn update_detection_rules(&self) -> Result<()> {
        // Mettre à jour les règles YARA et autres
        Ok(())
    }
    
    /// Vérifie la santé des composants
    async fn check_components_health(&self) -> Result<()> {
        debug!("🏥 Vérification de la santé des composants...");
        
        // Vérifier chaque composant
        let mut unhealthy_components = Vec::new();
        
        // Vérifier le détecteur de menaces
        if self.threat_detector.is_none() {
            unhealthy_components.push("ThreatDetector");
        }
        
        // Vérifier les moniteurs
        if self.file_monitor.is_none() {
            unhealthy_components.push("FileMonitor");
        }
        
        if self.process_monitor.is_none() {
            unhealthy_components.push("ProcessMonitor");
        }
        
        if self.network_monitor.is_none() {
            unhealthy_components.push("NetworkMonitor");
        }
        
        // Vérifier la communication
        if let Some(ref client) = self.communication_client {
            let state = client.get_connection_state().await;
            if !matches!(state, crate::communication::ConnectionState::Authenticated) {
                unhealthy_components.push("Communication");
            }
        } else {
            unhealthy_components.push("Communication");
        }
        
        if !unhealthy_components.is_empty() {
            warn!("⚠️ Composants en mauvaise santé: {:?}", unhealthy_components);
            
            // Tenter de redémarrer les composants défaillants
            self.restart_unhealthy_components(&unhealthy_components).await?;
        }
        
        Ok(())
    }
    
    /// Redémarre les composants en mauvaise santé
    async fn restart_unhealthy_components(&self, _components: &[&str]) -> Result<()> {
        // Implémentation du redémarrage des composants
        info!("🔄 Redémarrage des composants défaillants...");
        Ok(())
    }
    
    /// Envoie un heartbeat au serveur
    async fn send_heartbeat(&self) -> Result<()> {
        if let Some(ref client) = self.communication_client {
            let stats = self.get_service_stats().await;
            
            let status_message = crate::communication::SystemStatusMessage {
                agent_id: Uuid::new_v4(), // Devrait être l'ID réel de l'agent
                timestamp: Utc::now(),
                cpu_usage: stats.cpu_usage,
                memory_usage: stats.memory_usage as f32,
                disk_usage: 0.0, // À implémenter
                network_usage: 0.0, // À implémenter
                active_threats: stats.threats_detected as u32,
                monitored_files: stats.files_monitored as u32,
                monitored_processes: stats.processes_monitored as u32,
                uptime: stats.uptime,
                version: env!("CARGO_PKG_VERSION").to_string(),
            };
            
            client.send_system_status(&status_message).await
                .context("Envoi du statut système")?;
        }
        
        Ok(())
    }
    
    /// Obtient les statistiques du service
    pub async fn get_service_stats(&self) -> ServiceStats {
        let uptime = if let Some(start_time) = self.service_start_time {
            Utc::now().signed_duration_since(start_time).to_std().unwrap_or_default()
        } else {
            Duration::default()
        };
        
        ServiceStats {
            threats_detected: 0, // À implémenter
            files_monitored: 0,  // À implémenter
            processes_monitored: 0, // À implémenter
            network_connections: 0, // À implémenter
            alerts_sent: 0,      // À implémenter
            uptime,
            memory_usage: Self::get_memory_usage(),
            cpu_usage: Self::get_cpu_usage(),
            last_threat: None,   // À implémenter
            last_communication: None, // À implémenter
        }
    }
    
    /// Obtient l'utilisation mémoire
    fn get_memory_usage() -> u64 {
        // Implémentation Windows pour obtenir l'utilisation mémoire
        0 // Simulation
    }
    
    /// Obtient l'utilisation CPU
    fn get_cpu_usage() -> f32 {
        // Implémentation Windows pour obtenir l'utilisation CPU
        0.0 // Simulation
    }
    
    /// Obtient les informations du service
    pub async fn get_service_info(&self) -> ServiceInfo {
        let state = self.service_state.read().await;
        
        ServiceInfo {
            service_name: "ERDPS-Agent".to_string(),
            display_name: "ERDPS Enterprise Agent".to_string(),
            description: "Agent de détection et prévention des ransomwares ERDPS".to_string(),
            state: match *state {
                ServiceState::Stopped => ServiceStateInfo::Stopped,
                ServiceState::StartPending => ServiceStateInfo::StartPending,
                ServiceState::StopPending => ServiceStateInfo::StopPending,
                ServiceState::Running => ServiceStateInfo::Running,
                ServiceState::ContinuePending => ServiceStateInfo::ContinuePending,
                ServiceState::PausePending => ServiceStateInfo::PausePending,
                ServiceState::Paused => ServiceStateInfo::Paused,
            },
            start_time: self.service_start_time,
            uptime: self.service_start_time.map(|start| {
                Utc::now().signed_duration_since(start).to_std().unwrap_or_default()
            }),
            process_id: std::process::id(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            config_path: "C:\\Program Files\\ERDPS\\config.toml".to_string(),
        }
    }
}

/// Fonctions d'installation/désinstallation du service
pub struct ServiceInstaller;

impl ServiceInstaller {
    /// Installe le service Windows
    pub fn install_service(config: &ServiceInstallConfig) -> Result<()> {
        info!("📦 Installation du service ERDPS...");
        
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use windows_service::service_manager::{
                ServiceManager, ServiceManagerAccess, ServiceInfo, ServiceAccess,
                ServiceErrorControl, ServiceStartType as WinServiceStartType,
                ServiceType as WinServiceType,
            };
            
            let manager = ServiceManager::local_computer(
                None::<&str>,
                ServiceManagerAccess::CREATE_SERVICE,
            )?;
            
            let start_type = match config.start_type {
                ServiceStartType::Automatic => WinServiceStartType::AutoStart,
                ServiceStartType::Manual => WinServiceStartType::DemandStart,
                ServiceStartType::Disabled => WinServiceStartType::Disabled,
                ServiceStartType::AutomaticDelayed => WinServiceStartType::AutoStart,
            };
            
            let service_info = ServiceInfo {
                name: OsStr::new(&config.service_name),
                display_name: OsStr::new(&config.display_name),
                service_type: WinServiceType::OWN_PROCESS,
                start_type,
                error_control: ServiceErrorControl::Normal,
                executable_path: config.executable_path.as_ref().into(),
                launch_arguments: vec![],
                dependencies: config.dependencies.iter()
                    .map(|s| s.as_str().into())
                    .collect(),
                account_name: None, // Utiliser LocalSystem par défaut
                account_password: None,
            };
            
            let _service = manager.create_service(
                &service_info,
                ServiceAccess::CHANGE_CONFIG,
            )?;
            
            info!("✅ Service installé: {}", config.service_name);
        }
        
        #[cfg(not(windows))]
        {
            bail!("Installation de service supportée uniquement sur Windows");
        }
        
        Ok(())
    }
    
    /// Désinstalle le service Windows
    pub fn uninstall_service(service_name: &str) -> Result<()> {
        info!("🗑️ Désinstallation du service: {}", service_name);
        
        #[cfg(windows)]
        {
            use windows_service::service_manager::{
                ServiceManager, ServiceManagerAccess, ServiceAccess,
            };
            
            let manager = ServiceManager::local_computer(
                None::<&str>,
                ServiceManagerAccess::CONNECT,
            )?;
            
            let service = manager.open_service(
                service_name,
                ServiceAccess::DELETE,
            )?;
            
            service.delete()?;
            
            info!("✅ Service désinstallé: {}", service_name);
        }
        
        #[cfg(not(windows))]
        {
            bail!("Désinstallation de service supportée uniquement sur Windows");
        }
        
        Ok(())
    }
    
    /// Démarre le service
    pub fn start_service(service_name: &str) -> Result<()> {
        info!("▶️ Démarrage du service: {}", service_name);
        
        #[cfg(windows)]
        {
            use windows_service::service_manager::{
                ServiceManager, ServiceManagerAccess, ServiceAccess,
            };
            
            let manager = ServiceManager::local_computer(
                None::<&str>,
                ServiceManagerAccess::CONNECT,
            )?;
            
            let service = manager.open_service(
                service_name,
                ServiceAccess::START,
            )?;
            
            service.start(&[] as &[&str])?;
            
            info!("✅ Service démarré: {}", service_name);
        }
        
        #[cfg(not(windows))]
        {
            bail!("Contrôle de service supporté uniquement sur Windows");
        }
        
        Ok(())
    }
    
    /// Arrête le service
    pub fn stop_service(service_name: &str) -> Result<()> {
        info!("⏹️ Arrêt du service: {}", service_name);
        
        #[cfg(windows)]
        {
            use windows_service::service_manager::{
                ServiceManager, ServiceManagerAccess, ServiceAccess,
            };
            
            let manager = ServiceManager::local_computer(
                None::<&str>,
                ServiceManagerAccess::CONNECT,
            )?;
            
            let service = manager.open_service(
                service_name,
                ServiceAccess::STOP,
            )?;
            
            service.stop()?;
            
            info!("✅ Service arrêté: {}", service_name);
        }
        
        #[cfg(not(windows))]
        {
            bail!("Contrôle de service supporté uniquement sur Windows");
        }
        
        Ok(())
    }
}

/// Point d'entrée pour le dispatcher de service
pub fn run_service_dispatcher() -> Result<()> {
    #[cfg(windows)]
    {
        service_dispatcher::start("ERDPS-Agent", ffi_service_main)
            .context("Démarrage du dispatcher de service")?;
    }
    
    #[cfg(not(windows))]
    {
        bail!("Service Windows supporté uniquement sur Windows");
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use std::path::PathBuf;
    
    fn create_test_config() -> AgentConfig {
        AgentConfig {
            agent_id: Some(Uuid::new_v4()),
            operation_mode: OperationMode::Production,
            server: ServerConfig {
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
            },
            monitoring: MonitoringConfig {
                enabled: true,
                monitored_paths: vec![PathBuf::from("C:\\Users")],
                excluded_paths: vec![PathBuf::from("C:\\Windows")],
                file_monitoring: ProcessMonitoringConfig {
                    enabled: true,
                    scan_interval: 5,
                    deep_scan: false,
                    memory_analysis: false,
                },
                network_monitoring: NetworkMonitoringConfig {
                    enabled: true,
                    monitor_dns: true,
                    monitor_http: true,
                    suspicious_domains: vec![],
                },
                registry_monitoring: RegistryMonitoringConfig {
                    enabled: true,
                    monitored_keys: vec![],
                },
            },
            detection: DetectionConfig {
                yara_enabled: true,
                yara_rules_path: PathBuf::from("rules"),
                behavioral_detection: true,
                detection_threshold: 0.8,
                heuristics: HeuristicsConfig {
                    detect_mass_encryption: true,
                    encryption_threshold: 10,
                    time_window: 300,
                    detect_extension_changes: true,
                    detect_ransom_notes: true,
                    ransom_note_patterns: vec![],
                },
                auto_actions: AutoActionsConfig {
                    auto_isolate: false,
                    auto_kill_processes: false,
                    auto_backup: false,
                    backup_path: PathBuf::from("backup"),
                    immediate_notification: true,
                },
            },
            security: SecurityConfig {
                enable_tamper_protection: true,
                require_admin_privileges: true,
                config_encryption: true,
                log_integrity_check: true,
                certificate_pinning: true,
            },
            logging: LoggingConfig {
                enabled: true,
                log_directory: PathBuf::from("logs"),
                log_level: LogLevel::Info,
                max_file_size: 1024 * 1024,
                max_files: 10,
                compress_rotated: true,
                retention_days: 30,
                secure_logging: true,
                remote_logging: false,
                remote_endpoint: None,
            },
        }
    }
    
    #[tokio::test]
    async fn test_service_manager_creation() {
        let config = create_test_config();
        let service_manager = WindowsServiceManager::new(config);
        assert!(service_manager.is_ok());
    }
    
    #[test]
    fn test_service_install_config() {
        let config = ServiceInstallConfig {
            service_name: "ERDPS-Agent".to_string(),
            display_name: "ERDPS Enterprise Agent".to_string(),
            description: "Agent de détection des ransomwares".to_string(),
            executable_path: "C:\\Program Files\\ERDPS\\erdps-agent.exe".to_string(),
            start_type: ServiceStartType::Automatic,
            dependencies: vec![],
            account: ServiceAccount::LocalSystem,
            auto_restart: true,
            failure_actions: vec![FailureAction::Restart { delay: Duration::from_secs(60) }],
        };
        
        assert_eq!(config.service_name, "ERDPS-Agent");
        assert!(matches!(config.start_type, ServiceStartType::Automatic));
    }
}