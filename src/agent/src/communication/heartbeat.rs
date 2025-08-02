//! Heartbeat Manager for ERDPS Agent
//!
//! Gestionnaire de heartbeat pour maintenir la connexion avec le serveur
//! Surveillance de la santé de l'agent et reporting périodique
//!
//! @author ERDPS Communication Team
//! @version 1.0.0
//! @license Proprietary

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::AgentConfig;
use crate::communication::protocol::{HeartbeatMessage, AgentStatus};
use crate::communication::grpc_client::GrpcClient;

/// Gestionnaire de heartbeat
#[derive(Debug)]
pub struct HeartbeatManager {
    /// Configuration de l'agent
    config: Arc<AgentConfig>,
    
    /// Client gRPC
    grpc_client: Arc<GrpcClient>,
    
    /// État du heartbeat
    state: Arc<RwLock<HeartbeatState>>,
    
    /// Canal pour arrêter le heartbeat
    shutdown_tx: Option<mpsc::Sender<()>>,
    
    /// Statistiques du heartbeat
    stats: Arc<RwLock<HeartbeatStats>>,
}

/// État du heartbeat
#[derive(Debug, Clone)]
struct HeartbeatState {
    /// Heartbeat actif
    is_active: bool,
    
    /// Dernier heartbeat envoyé
    last_heartbeat: Option<DateTime<Utc>>,
    
    /// Dernier heartbeat réussi
    last_successful_heartbeat: Option<DateTime<Utc>>,
    
    /// Nombre d'échecs consécutifs
    consecutive_failures: u32,
    
    /// État de santé de l'agent
    health_status: HealthStatus,
    
    /// Métriques système
    system_metrics: SystemMetrics,
}

/// État de santé de l'agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Agent en bonne santé
    Healthy,
    
    /// Agent dégradé
    Degraded {
        reason: String,
        since: DateTime<Utc>,
    },
    
    /// Agent en erreur
    Error {
        reason: String,
        since: DateTime<Utc>,
    },
    
    /// Agent en cours d'arrêt
    Shutting Down,
}

/// Métriques système
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// Utilisation CPU (%)
    pub cpu_usage: f32,
    
    /// Utilisation mémoire (MB)
    pub memory_usage: u64,
    
    /// Utilisation disque (%)
    pub disk_usage: f32,
    
    /// Nombre de threads actifs
    pub active_threads: u32,
    
    /// Nombre de handles ouverts
    pub open_handles: u32,
    
    /// Uptime de l'agent (secondes)
    pub uptime_seconds: u64,
    
    /// Timestamp de collecte
    pub collected_at: DateTime<Utc>,
}

/// Statistiques du heartbeat
#[derive(Debug, Default, Clone)]
struct HeartbeatStats {
    /// Nombre total de heartbeats envoyés
    total_heartbeats: u64,
    
    /// Nombre de heartbeats réussis
    successful_heartbeats: u64,
    
    /// Nombre d'échecs
    failed_heartbeats: u64,
    
    /// Temps de réponse moyen (ms)
    average_response_time: f64,
    
    /// Dernier temps de réponse (ms)
    last_response_time: u64,
    
    /// Temps de réponse maximum (ms)
    max_response_time: u64,
    
    /// Temps de réponse minimum (ms)
    min_response_time: u64,
    
    /// Démarrage du heartbeat
    started_at: Option<DateTime<Utc>>,
}

impl Default for HeartbeatState {
    fn default() -> Self {
        Self {
            is_active: false,
            last_heartbeat: None,
            last_successful_heartbeat: None,
            consecutive_failures: 0,
            health_status: HealthStatus::Healthy,
            system_metrics: SystemMetrics::default(),
        }
    }
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0,
            disk_usage: 0.0,
            active_threads: 0,
            open_handles: 0,
            uptime_seconds: 0,
            collected_at: Utc::now(),
        }
    }
}

impl HeartbeatManager {
    /// Crée un nouveau gestionnaire de heartbeat
    pub fn new(config: Arc<AgentConfig>, grpc_client: Arc<GrpcClient>) -> Self {
        info!("Initializing heartbeat manager");
        
        Self {
            config,
            grpc_client,
            state: Arc::new(RwLock::new(HeartbeatState::default())),
            shutdown_tx: None,
            stats: Arc::new(RwLock::new(HeartbeatStats::default())),
        }
    }
    
    /// Démarre le heartbeat
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting heartbeat manager");
        
        // Vérification si déjà démarré
        {
            let state = self.state.read().await;
            if state.is_active {
                warn!("Heartbeat manager is already running");
                return Ok(());
            }
        }
        
        // Création du canal d'arrêt
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);
        
        // Mise à jour de l'état
        {
            let mut state = self.state.write().await;
            state.is_active = true;
            
            let mut stats = self.stats.write().await;
            stats.started_at = Some(Utc::now());
        }
        
        // Clonage des références pour la tâche
        let state = Arc::clone(&self.state);
        let stats = Arc::clone(&self.stats);
        let grpc_client = Arc::clone(&self.grpc_client);
        let config = Arc::clone(&self.config);
        
        // Démarrage de la tâche de heartbeat
        tokio::spawn(async move {
            let mut heartbeat_interval = interval(Duration::from_secs(config.server.heartbeat_interval));
            let agent_start_time = Instant::now();
            
            info!("Heartbeat task started with interval: {}s", config.server.heartbeat_interval);
            
            loop {
                tokio::select! {
                    _ = heartbeat_interval.tick() => {
                        if let Err(e) = Self::send_heartbeat(
                            &state,
                            &stats,
                            &grpc_client,
                            &config,
                            agent_start_time
                        ).await {
                            error!("Failed to send heartbeat: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Heartbeat task shutting down");
                        break;
                    }
                }
            }
            
            // Mise à jour de l'état d'arrêt
            {
                let mut state_guard = state.write().await;
                state_guard.is_active = false;
                state_guard.health_status = HealthStatus::Shutting Down;
            }
            
            info!("Heartbeat task stopped");
        });
        
        info!("Heartbeat manager started successfully");
        Ok(())
    }
    
    /// Arrête le heartbeat
    pub async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Stopping heartbeat manager");
        
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }
        
        // Attendre que le heartbeat s'arrête
        let mut attempts = 0;
        while attempts < 10 {
            {
                let state = self.state.read().await;
                if !state.is_active {
                    break;
                }
            }
            
            sleep(Duration::from_millis(100)).await;
            attempts += 1;
        }
        
        info!("Heartbeat manager stopped");
        Ok(())
    }
    
    /// Envoie un heartbeat
    async fn send_heartbeat(
        state: &Arc<RwLock<HeartbeatState>>,
        stats: &Arc<RwLock<HeartbeatStats>>,
        grpc_client: &Arc<GrpcClient>,
        config: &Arc<AgentConfig>,
        agent_start_time: Instant,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        // Collecte des métriques système
        let system_metrics = Self::collect_system_metrics(agent_start_time).await;
        
        // Création du message de heartbeat
        let heartbeat_message = {
            let state_guard = state.read().await;
            HeartbeatMessage {
                agent_id: config.agent.id.clone(),
                timestamp: Utc::now(),
                status: AgentStatus {
                    health: state_guard.health_status.clone(),
                    uptime_seconds: system_metrics.uptime_seconds,
                    cpu_usage: system_metrics.cpu_usage,
                    memory_usage: system_metrics.memory_usage,
                    active_monitors: Self::count_active_monitors(),
                    last_activity: state_guard.last_successful_heartbeat,
                },
                system_metrics: system_metrics.clone(),
                version: config.agent.version.clone(),
                build_info: format!("{}_{}", config.agent.build_number, config.agent.build_date),
            }
        };
        
        // Mise à jour de l'état avant l'envoi
        {
            let mut state_guard = state.write().await;
            state_guard.last_heartbeat = Some(Utc::now());
            state_guard.system_metrics = system_metrics;
        }
        
        // Envoi du heartbeat
        match grpc_client.send_heartbeat(heartbeat_message).await {
            Ok(_) => {
                let response_time = start_time.elapsed().as_millis() as u64;
                
                // Mise à jour de l'état de succès
                {
                    let mut state_guard = state.write().await;
                    state_guard.last_successful_heartbeat = Some(Utc::now());
                    state_guard.consecutive_failures = 0;
                    
                    // Mise à jour du statut de santé si nécessaire
                    if matches!(state_guard.health_status, HealthStatus::Degraded { .. }) {
                        state_guard.health_status = HealthStatus::Healthy;
                    }
                }
                
                // Mise à jour des statistiques
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_heartbeats += 1;
                    stats_guard.successful_heartbeats += 1;
                    stats_guard.last_response_time = response_time;
                    
                    // Mise à jour des temps de réponse
                    if stats_guard.min_response_time == 0 || response_time < stats_guard.min_response_time {
                        stats_guard.min_response_time = response_time;
                    }
                    if response_time > stats_guard.max_response_time {
                        stats_guard.max_response_time = response_time;
                    }
                    
                    // Calcul de la moyenne mobile
                    let total_successful = stats_guard.successful_heartbeats as f64;
                    stats_guard.average_response_time = 
                        (stats_guard.average_response_time * (total_successful - 1.0) + response_time as f64) / total_successful;
                }
                
                debug!("Heartbeat sent successfully in {}ms", response_time);
                Ok(())
            }
            Err(e) => {
                // Mise à jour de l'état d'échec
                {
                    let mut state_guard = state.write().await;
                    state_guard.consecutive_failures += 1;
                    
                    // Mise à jour du statut de santé
                    if state_guard.consecutive_failures >= config.server.max_heartbeat_failures {
                        state_guard.health_status = HealthStatus::Error {
                            reason: format!("Heartbeat failures: {}", state_guard.consecutive_failures),
                            since: Utc::now(),
                        };
                    } else if state_guard.consecutive_failures >= 3 {
                        state_guard.health_status = HealthStatus::Degraded {
                            reason: format!("Heartbeat issues: {}", state_guard.consecutive_failures),
                            since: Utc::now(),
                        };
                    }
                }
                
                // Mise à jour des statistiques
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_heartbeats += 1;
                    stats_guard.failed_heartbeats += 1;
                }
                
                warn!("Heartbeat failed: {}", e);
                Err(e)
            }
        }
    }
    
    /// Collecte les métriques système
    async fn collect_system_metrics(agent_start_time: Instant) -> SystemMetrics {
        // Simulation de collecte de métriques système
        // Dans un vrai projet, on utiliserait des APIs Windows ou des bibliothèques comme sysinfo
        
        SystemMetrics {
            cpu_usage: Self::get_cpu_usage().await,
            memory_usage: Self::get_memory_usage().await,
            disk_usage: Self::get_disk_usage().await,
            active_threads: Self::get_thread_count().await,
            open_handles: Self::get_handle_count().await,
            uptime_seconds: agent_start_time.elapsed().as_secs(),
            collected_at: Utc::now(),
        }
    }
    
    /// Obtient l'utilisation CPU
    async fn get_cpu_usage() -> f32 {
        // Simulation - dans un vrai projet, utiliser les APIs Windows
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(1.0..15.0) // Simulation d'une utilisation CPU normale
    }
    
    /// Obtient l'utilisation mémoire
    async fn get_memory_usage() -> u64 {
        // Simulation - dans un vrai projet, utiliser GetProcessMemoryInfo
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(50..200) // MB
    }
    
    /// Obtient l'utilisation disque
    async fn get_disk_usage() -> f32 {
        // Simulation - dans un vrai projet, utiliser GetDiskFreeSpaceEx
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(30.0..80.0) // %
    }
    
    /// Obtient le nombre de threads
    async fn get_thread_count() -> u32 {
        // Simulation - dans un vrai projet, utiliser les APIs de processus
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(10..50)
    }
    
    /// Obtient le nombre de handles
    async fn get_handle_count() -> u32 {
        // Simulation - dans un vrai projet, utiliser GetProcessHandleCount
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(100..500)
    }
    
    /// Compte les moniteurs actifs
    fn count_active_monitors() -> u32 {
        // Simulation - dans un vrai projet, compter les moniteurs réellement actifs
        4 // File, Process, Network, Registry
    }
    
    /// Met à jour le statut de santé
    pub async fn update_health_status(&self, status: HealthStatus) {
        let mut state = self.state.write().await;
        state.health_status = status;
        debug!("Health status updated: {:?}", state.health_status);
    }
    
    /// Obtient l'état actuel du heartbeat
    pub async fn get_state(&self) -> HeartbeatState {
        self.state.read().await.clone()
    }
    
    /// Obtient les statistiques du heartbeat
    pub async fn get_stats(&self) -> HeartbeatStats {
        self.stats.read().await.clone()
    }
    
    /// Vérifie si le heartbeat est actif
    pub async fn is_active(&self) -> bool {
        self.state.read().await.is_active
    }
    
    /// Obtient le taux de succès du heartbeat
    pub async fn get_success_rate(&self) -> f64 {
        let stats = self.stats.read().await;
        if stats.total_heartbeats == 0 {
            return 1.0;
        }
        
        stats.successful_heartbeats as f64 / stats.total_heartbeats as f64
    }
    
    /// Force l'envoi d'un heartbeat immédiat
    pub async fn force_heartbeat(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Forcing immediate heartbeat");
        
        let agent_start_time = Instant::now(); // Approximation
        
        Self::send_heartbeat(
            &self.state,
            &self.stats,
            &self.grpc_client,
            &self.config,
            agent_start_time,
        ).await
    }
}

// Tests unitaires
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use crate::communication::grpc_client::GrpcClient;
    
    #[tokio::test]
    async fn test_heartbeat_manager_creation() {
        let config = Arc::new(AgentConfig::default());
        let grpc_client = Arc::new(GrpcClient::new(&config.server).await.unwrap());
        
        let manager = HeartbeatManager::new(config, grpc_client);
        assert!(!manager.is_active().await);
    }
    
    #[tokio::test]
    async fn test_system_metrics_collection() {
        let start_time = Instant::now();
        let metrics = HeartbeatManager::collect_system_metrics(start_time).await;
        
        assert!(metrics.cpu_usage >= 0.0);
        assert!(metrics.memory_usage > 0);
        assert!(metrics.uptime_seconds >= 0);
    }
    
    #[tokio::test]
    async fn test_health_status_update() {
        let config = Arc::new(AgentConfig::default());
        let grpc_client = Arc::new(GrpcClient::new(&config.server).await.unwrap());
        
        let manager = HeartbeatManager::new(config, grpc_client);
        
        let new_status = HealthStatus::Degraded {
            reason: "Test degradation".to_string(),
            since: Utc::now(),
        };
        
        manager.update_health_status(new_status.clone()).await;
        
        let state = manager.get_state().await;
        match state.health_status {
            HealthStatus::Degraded { reason, .. } => {
                assert_eq!(reason, "Test degradation");
            }
            _ => panic!("Expected degraded status"),
        }
    }
    
    #[test]
    fn test_system_metrics_default() {
        let metrics = SystemMetrics::default();
        assert_eq!(metrics.cpu_usage, 0.0);
        assert_eq!(metrics.memory_usage, 0);
        assert_eq!(metrics.active_threads, 0);
    }
    
    #[test]
    fn test_health_status_serialization() {
        let status = HealthStatus::Error {
            reason: "Test error".to_string(),
            since: Utc::now(),
        };
        
        let serialized = serde_json::to_string(&status).unwrap();
        let deserialized: HealthStatus = serde_json::from_str(&serialized).unwrap();
        
        match deserialized {
            HealthStatus::Error { reason, .. } => {
                assert_eq!(reason, "Test error");
            }
            _ => panic!("Expected error status"),
        }
    }
}