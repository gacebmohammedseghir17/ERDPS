//! Reporting Manager for ERDPS Agent
//!
//! Gestionnaire de rapports pour l'envoi de données périodiques au serveur
//! Collecte et transmission des statistiques, événements et métriques
//!
//! @author ERDPS Communication Team
//! @version 1.0.0
//! @license Proprietary

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::AgentConfig;
use crate::communication::protocol::{
    PeriodicReport, FileEvent, ProcessEvent, NetworkEvent, RegistryEvent, ThreatAlert
};
use crate::communication::grpc_client::GrpcClient;

/// Gestionnaire de rapports
#[derive(Debug)]
pub struct ReportingManager {
    /// Configuration de l'agent
    config: Arc<AgentConfig>,
    
    /// Client gRPC
    grpc_client: Arc<GrpcClient>,
    
    /// État du reporting
    state: Arc<RwLock<ReportingState>>,
    
    /// Canal pour arrêter le reporting
    shutdown_tx: Option<mpsc::Sender<()>>,
    
    /// Statistiques du reporting
    stats: Arc<RwLock<ReportingStats>>,
    
    /// Buffer des événements
    event_buffer: Arc<RwLock<EventBuffer>>,
}

/// État du reporting
#[derive(Debug, Clone)]
struct ReportingState {
    /// Reporting actif
    is_active: bool,
    
    /// Dernier rapport envoyé
    last_report: Option<DateTime<Utc>>,
    
    /// Dernier rapport réussi
    last_successful_report: Option<DateTime<Utc>>,
    
    /// Nombre d'échecs consécutifs
    consecutive_failures: u32,
    
    /// Taille actuelle du buffer
    buffer_size: usize,
    
    /// Prochain rapport programmé
    next_report_due: Option<DateTime<Utc>>,
}

/// Statistiques du reporting
#[derive(Debug, Default, Clone)]
struct ReportingStats {
    /// Nombre total de rapports envoyés
    total_reports: u64,
    
    /// Nombre de rapports réussis
    successful_reports: u64,
    
    /// Nombre d'échecs
    failed_reports: u64,
    
    /// Taille moyenne des rapports (bytes)
    average_report_size: u64,
    
    /// Temps de transmission moyen (ms)
    average_transmission_time: f64,
    
    /// Nombre total d'événements traités
    total_events_processed: u64,
    
    /// Nombre d'événements perdus (buffer overflow)
    events_lost: u64,
    
    /// Démarrage du reporting
    started_at: Option<DateTime<Utc>>,
    
    /// Répartition des types d'événements
    event_type_counts: HashMap<String, u64>,
}

/// Buffer des événements
#[derive(Debug)]
struct EventBuffer {
    /// Événements de fichiers
    file_events: VecDeque<FileEvent>,
    
    /// Événements de processus
    process_events: VecDeque<ProcessEvent>,
    
    /// Événements réseau
    network_events: VecDeque<NetworkEvent>,
    
    /// Événements de registre
    registry_events: VecDeque<RegistryEvent>,
    
    /// Alertes de menaces
    threat_alerts: VecDeque<ThreatAlert>,
    
    /// Taille maximale du buffer
    max_size: usize,
    
    /// Événements perdus par type
    lost_events: HashMap<String, u64>,
}

/// Métriques de performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Événements traités par seconde
    pub events_per_second: f64,
    
    /// Latence moyenne de traitement (ms)
    pub average_processing_latency: f64,
    
    /// Utilisation du buffer (%)
    pub buffer_utilization: f64,
    
    /// Débit de transmission (KB/s)
    pub transmission_throughput: f64,
    
    /// Timestamp de collecte
    pub collected_at: DateTime<Utc>,
}

/// Résumé d'activité
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivitySummary {
    /// Période couverte
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    
    /// Nombre d'événements par type
    pub event_counts: HashMap<String, u64>,
    
    /// Nombre d'alertes par niveau de sévérité
    pub alert_counts: HashMap<String, u64>,
    
    /// Processus les plus actifs
    pub top_processes: Vec<String>,
    
    /// Extensions de fichiers les plus touchées
    pub top_file_extensions: Vec<String>,
    
    /// Adresses IP les plus contactées
    pub top_network_destinations: Vec<String>,
}

impl Default for ReportingState {
    fn default() -> Self {
        Self {
            is_active: false,
            last_report: None,
            last_successful_report: None,
            consecutive_failures: 0,
            buffer_size: 0,
            next_report_due: None,
        }
    }
}

impl EventBuffer {
    fn new(max_size: usize) -> Self {
        Self {
            file_events: VecDeque::new(),
            process_events: VecDeque::new(),
            network_events: VecDeque::new(),
            registry_events: VecDeque::new(),
            threat_alerts: VecDeque::new(),
            max_size,
            lost_events: HashMap::new(),
        }
    }
    
    fn total_size(&self) -> usize {
        self.file_events.len() +
        self.process_events.len() +
        self.network_events.len() +
        self.registry_events.len() +
        self.threat_alerts.len()
    }
    
    fn is_full(&self) -> bool {
        self.total_size() >= self.max_size
    }
    
    fn clear(&mut self) {
        self.file_events.clear();
        self.process_events.clear();
        self.network_events.clear();
        self.registry_events.clear();
        self.threat_alerts.clear();
    }
}

impl ReportingManager {
    /// Crée un nouveau gestionnaire de rapports
    pub fn new(config: Arc<AgentConfig>, grpc_client: Arc<GrpcClient>) -> Self {
        info!("Initializing reporting manager");
        
        let buffer_size = config.performance.max_events_buffer_size.unwrap_or(10000);
        
        Self {
            config,
            grpc_client,
            state: Arc::new(RwLock::new(ReportingState::default())),
            shutdown_tx: None,
            stats: Arc::new(RwLock::new(ReportingStats::default())),
            event_buffer: Arc::new(RwLock::new(EventBuffer::new(buffer_size))),
        }
    }
    
    /// Démarre le gestionnaire de rapports
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting reporting manager");
        
        // Vérification si déjà démarré
        {
            let state = self.state.read().await;
            if state.is_active {
                warn!("Reporting manager is already running");
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
            state.next_report_due = Some(Utc::now() + chrono::Duration::seconds(self.config.server.report_interval as i64));
            
            let mut stats = self.stats.write().await;
            stats.started_at = Some(Utc::now());
        }
        
        // Clonage des références pour la tâche
        let state = Arc::clone(&self.state);
        let stats = Arc::clone(&self.stats);
        let event_buffer = Arc::clone(&self.event_buffer);
        let grpc_client = Arc::clone(&self.grpc_client);
        let config = Arc::clone(&self.config);
        
        // Démarrage de la tâche de reporting
        tokio::spawn(async move {
            let mut report_interval = interval(Duration::from_secs(config.server.report_interval));
            
            info!("Reporting task started with interval: {}s", config.server.report_interval);
            
            loop {
                tokio::select! {
                    _ = report_interval.tick() => {
                        if let Err(e) = Self::generate_and_send_report(
                            &state,
                            &stats,
                            &event_buffer,
                            &grpc_client,
                            &config
                        ).await {
                            error!("Failed to send periodic report: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Reporting task shutting down");
                        
                        // Envoi d'un dernier rapport avant l'arrêt
                        if let Err(e) = Self::generate_and_send_report(
                            &state,
                            &stats,
                            &event_buffer,
                            &grpc_client,
                            &config
                        ).await {
                            warn!("Failed to send final report: {}", e);
                        }
                        
                        break;
                    }
                }
            }
            
            // Mise à jour de l'état d'arrêt
            {
                let mut state_guard = state.write().await;
                state_guard.is_active = false;
            }
            
            info!("Reporting task stopped");
        });
        
        info!("Reporting manager started successfully");
        Ok(())
    }
    
    /// Arrête le gestionnaire de rapports
    pub async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Stopping reporting manager");
        
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }
        
        // Attendre que le reporting s'arrête
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
        
        info!("Reporting manager stopped");
        Ok(())
    }
    
    /// Ajoute un événement de fichier au buffer
    pub async fn add_file_event(&self, event: FileEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buffer = self.event_buffer.write().await;
        
        if buffer.is_full() {
            // Suppression du plus ancien événement de fichier
            if !buffer.file_events.is_empty() {
                buffer.file_events.pop_front();
                *buffer.lost_events.entry("file".to_string()).or_insert(0) += 1;
                
                // Mise à jour des statistiques
                let mut stats = self.stats.write().await;
                stats.events_lost += 1;
            }
        }
        
        buffer.file_events.push_back(event);
        
        // Mise à jour des statistiques
        {
            let mut stats = self.stats.write().await;
            stats.total_events_processed += 1;
            *stats.event_type_counts.entry("file".to_string()).or_insert(0) += 1;
        }
        
        // Mise à jour de la taille du buffer
        {
            let mut state = self.state.write().await;
            state.buffer_size = buffer.total_size();
        }
        
        Ok(())
    }
    
    /// Ajoute un événement de processus au buffer
    pub async fn add_process_event(&self, event: ProcessEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buffer = self.event_buffer.write().await;
        
        if buffer.is_full() {
            if !buffer.process_events.is_empty() {
                buffer.process_events.pop_front();
                *buffer.lost_events.entry("process".to_string()).or_insert(0) += 1;
                
                let mut stats = self.stats.write().await;
                stats.events_lost += 1;
            }
        }
        
        buffer.process_events.push_back(event);
        
        {
            let mut stats = self.stats.write().await;
            stats.total_events_processed += 1;
            *stats.event_type_counts.entry("process".to_string()).or_insert(0) += 1;
        }
        
        {
            let mut state = self.state.write().await;
            state.buffer_size = buffer.total_size();
        }
        
        Ok(())
    }
    
    /// Ajoute un événement réseau au buffer
    pub async fn add_network_event(&self, event: NetworkEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buffer = self.event_buffer.write().await;
        
        if buffer.is_full() {
            if !buffer.network_events.is_empty() {
                buffer.network_events.pop_front();
                *buffer.lost_events.entry("network".to_string()).or_insert(0) += 1;
                
                let mut stats = self.stats.write().await;
                stats.events_lost += 1;
            }
        }
        
        buffer.network_events.push_back(event);
        
        {
            let mut stats = self.stats.write().await;
            stats.total_events_processed += 1;
            *stats.event_type_counts.entry("network".to_string()).or_insert(0) += 1;
        }
        
        {
            let mut state = self.state.write().await;
            state.buffer_size = buffer.total_size();
        }
        
        Ok(())
    }
    
    /// Ajoute un événement de registre au buffer
    pub async fn add_registry_event(&self, event: RegistryEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buffer = self.event_buffer.write().await;
        
        if buffer.is_full() {
            if !buffer.registry_events.is_empty() {
                buffer.registry_events.pop_front();
                *buffer.lost_events.entry("registry".to_string()).or_insert(0) += 1;
                
                let mut stats = self.stats.write().await;
                stats.events_lost += 1;
            }
        }
        
        buffer.registry_events.push_back(event);
        
        {
            let mut stats = self.stats.write().await;
            stats.total_events_processed += 1;
            *stats.event_type_counts.entry("registry".to_string()).or_insert(0) += 1;
        }
        
        {
            let mut state = self.state.write().await;
            state.buffer_size = buffer.total_size();
        }
        
        Ok(())
    }
    
    /// Ajoute une alerte de menace au buffer
    pub async fn add_threat_alert(&self, alert: ThreatAlert) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buffer = self.event_buffer.write().await;
        
        if buffer.is_full() {
            if !buffer.threat_alerts.is_empty() {
                buffer.threat_alerts.pop_front();
                *buffer.lost_events.entry("threat".to_string()).or_insert(0) += 1;
                
                let mut stats = self.stats.write().await;
                stats.events_lost += 1;
            }
        }
        
        buffer.threat_alerts.push_back(alert);
        
        {
            let mut stats = self.stats.write().await;
            stats.total_events_processed += 1;
            *stats.event_type_counts.entry("threat".to_string()).or_insert(0) += 1;
        }
        
        {
            let mut state = self.state.write().await;
            state.buffer_size = buffer.total_size();
        }
        
        Ok(())
    }
    
    /// Génère et envoie un rapport périodique
    async fn generate_and_send_report(
        state: &Arc<RwLock<ReportingState>>,
        stats: &Arc<RwLock<ReportingStats>>,
        event_buffer: &Arc<RwLock<EventBuffer>>,
        grpc_client: &Arc<GrpcClient>,
        config: &Arc<AgentConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        debug!("Generating periodic report");
        
        // Collecte des événements du buffer
        let (file_events, process_events, network_events, registry_events, threat_alerts) = {
            let mut buffer = event_buffer.write().await;
            
            let file_events: Vec<FileEvent> = buffer.file_events.drain(..).collect();
            let process_events: Vec<ProcessEvent> = buffer.process_events.drain(..).collect();
            let network_events: Vec<NetworkEvent> = buffer.network_events.drain(..).collect();
            let registry_events: Vec<RegistryEvent> = buffer.registry_events.drain(..).collect();
            let threat_alerts: Vec<ThreatAlert> = buffer.threat_alerts.drain(..).collect();
            
            (file_events, process_events, network_events, registry_events, threat_alerts)
        };
        
        // Génération des métriques de performance
        let performance_metrics = Self::generate_performance_metrics(stats).await;
        
        // Génération du résumé d'activité
        let activity_summary = Self::generate_activity_summary(
            &file_events,
            &process_events,
            &network_events,
            &registry_events,
            &threat_alerts,
        ).await;
        
        // Création du rapport périodique
        let report = PeriodicReport {
            agent_id: config.agent.id.clone(),
            report_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            period_start: {
                let state_guard = state.read().await;
                state_guard.last_successful_report.unwrap_or_else(|| Utc::now() - chrono::Duration::seconds(config.server.report_interval as i64))
            },
            period_end: Utc::now(),
            file_events,
            process_events,
            network_events,
            registry_events,
            threat_alerts,
            performance_metrics,
            activity_summary,
            agent_version: config.agent.version.clone(),
        };
        
        // Calcul de la taille du rapport
        let report_size = Self::estimate_report_size(&report);
        
        // Mise à jour de l'état avant l'envoi
        {
            let mut state_guard = state.write().await;
            state_guard.last_report = Some(Utc::now());
            state_guard.buffer_size = 0; // Buffer vidé
            state_guard.next_report_due = Some(Utc::now() + chrono::Duration::seconds(config.server.report_interval as i64));
        }
        
        // Envoi du rapport
        match grpc_client.send_periodic_report(report).await {
            Ok(_) => {
                let transmission_time = start_time.elapsed().as_millis() as u64;
                
                // Mise à jour de l'état de succès
                {
                    let mut state_guard = state.write().await;
                    state_guard.last_successful_report = Some(Utc::now());
                    state_guard.consecutive_failures = 0;
                }
                
                // Mise à jour des statistiques
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_reports += 1;
                    stats_guard.successful_reports += 1;
                    
                    // Mise à jour de la taille moyenne des rapports
                    let total_successful = stats_guard.successful_reports as f64;
                    stats_guard.average_report_size = 
                        ((stats_guard.average_report_size as f64 * (total_successful - 1.0)) + report_size as f64) as u64 / total_successful as u64;
                    
                    // Mise à jour du temps de transmission moyen
                    stats_guard.average_transmission_time = 
                        (stats_guard.average_transmission_time * (total_successful - 1.0) + transmission_time as f64) / total_successful;
                }
                
                info!("Periodic report sent successfully in {}ms (size: {} bytes)", transmission_time, report_size);
                Ok(())
            }
            Err(e) => {
                // Mise à jour de l'état d'échec
                {
                    let mut state_guard = state.write().await;
                    state_guard.consecutive_failures += 1;
                }
                
                // Mise à jour des statistiques
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_reports += 1;
                    stats_guard.failed_reports += 1;
                }
                
                error!("Failed to send periodic report: {}", e);
                Err(e)
            }
        }
    }
    
    /// Génère les métriques de performance
    async fn generate_performance_metrics(stats: &Arc<RwLock<ReportingStats>>) -> PerformanceMetrics {
        let stats_guard = stats.read().await;
        
        let events_per_second = if let Some(started_at) = stats_guard.started_at {
            let elapsed_seconds = Utc::now().signed_duration_since(started_at).num_seconds() as f64;
            if elapsed_seconds > 0.0 {
                stats_guard.total_events_processed as f64 / elapsed_seconds
            } else {
                0.0
            }
        } else {
            0.0
        };
        
        PerformanceMetrics {
            events_per_second,
            average_processing_latency: 5.0, // Simulation
            buffer_utilization: 0.0, // Sera calculé ailleurs
            transmission_throughput: stats_guard.average_transmission_time,
            collected_at: Utc::now(),
        }
    }
    
    /// Génère le résumé d'activité
    async fn generate_activity_summary(
        file_events: &[FileEvent],
        process_events: &[ProcessEvent],
        network_events: &[NetworkEvent],
        registry_events: &[RegistryEvent],
        threat_alerts: &[ThreatAlert],
    ) -> ActivitySummary {
        let mut event_counts = HashMap::new();
        event_counts.insert("file".to_string(), file_events.len() as u64);
        event_counts.insert("process".to_string(), process_events.len() as u64);
        event_counts.insert("network".to_string(), network_events.len() as u64);
        event_counts.insert("registry".to_string(), registry_events.len() as u64);
        
        let mut alert_counts = HashMap::new();
        for alert in threat_alerts {
            *alert_counts.entry(alert.severity.clone()).or_insert(0) += 1;
        }
        
        // Analyse des processus les plus actifs
        let mut process_activity: HashMap<String, u64> = HashMap::new();
        for event in process_events {
            *process_activity.entry(event.process_name.clone()).or_insert(0) += 1;
        }
        let mut top_processes: Vec<(String, u64)> = process_activity.into_iter().collect();
        top_processes.sort_by(|a, b| b.1.cmp(&a.1));
        let top_processes: Vec<String> = top_processes.into_iter().take(10).map(|(name, _)| name).collect();
        
        // Analyse des extensions de fichiers
        let mut extension_activity: HashMap<String, u64> = HashMap::new();
        for event in file_events {
            if let Some(ext) = std::path::Path::new(&event.file_path).extension() {
                if let Some(ext_str) = ext.to_str() {
                    *extension_activity.entry(ext_str.to_lowercase()).or_insert(0) += 1;
                }
            }
        }
        let mut top_file_extensions: Vec<(String, u64)> = extension_activity.into_iter().collect();
        top_file_extensions.sort_by(|a, b| b.1.cmp(&a.1));
        let top_file_extensions: Vec<String> = top_file_extensions.into_iter().take(10).map(|(ext, _)| ext).collect();
        
        // Analyse des destinations réseau
        let mut network_destinations: HashMap<String, u64> = HashMap::new();
        for event in network_events {
            *network_destinations.entry(event.remote_address.clone()).or_insert(0) += 1;
        }
        let mut top_network_destinations: Vec<(String, u64)> = network_destinations.into_iter().collect();
        top_network_destinations.sort_by(|a, b| b.1.cmp(&a.1));
        let top_network_destinations: Vec<String> = top_network_destinations.into_iter().take(10).map(|(addr, _)| addr).collect();
        
        ActivitySummary {
            period_start: Utc::now() - chrono::Duration::minutes(15), // Approximation
            period_end: Utc::now(),
            event_counts,
            alert_counts,
            top_processes,
            top_file_extensions,
            top_network_destinations,
        }
    }
    
    /// Estime la taille d'un rapport
    fn estimate_report_size(report: &PeriodicReport) -> usize {
        // Estimation basique - dans un vrai projet, on sérialiserait le rapport
        let base_size = 1024; // Métadonnées de base
        let events_size = 
            report.file_events.len() * 200 +
            report.process_events.len() * 150 +
            report.network_events.len() * 100 +
            report.registry_events.len() * 120 +
            report.threat_alerts.len() * 300;
        
        base_size + events_size
    }
    
    /// Force l'envoi d'un rapport immédiat
    pub async fn force_report(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Forcing immediate report");
        
        Self::generate_and_send_report(
            &self.state,
            &self.stats,
            &self.event_buffer,
            &self.grpc_client,
            &self.config,
        ).await
    }
    
    /// Obtient l'état actuel du reporting
    pub async fn get_state(&self) -> ReportingState {
        self.state.read().await.clone()
    }
    
    /// Obtient les statistiques du reporting
    pub async fn get_stats(&self) -> ReportingStats {
        self.stats.read().await.clone()
    }
    
    /// Vérifie si le reporting est actif
    pub async fn is_active(&self) -> bool {
        self.state.read().await.is_active
    }
    
    /// Obtient le taux de succès du reporting
    pub async fn get_success_rate(&self) -> f64 {
        let stats = self.stats.read().await;
        if stats.total_reports == 0 {
            return 1.0;
        }
        
        stats.successful_reports as f64 / stats.total_reports as f64
    }
    
    /// Obtient l'utilisation actuelle du buffer
    pub async fn get_buffer_utilization(&self) -> f64 {
        let buffer = self.event_buffer.read().await;
        let current_size = buffer.total_size();
        let max_size = buffer.max_size;
        
        if max_size == 0 {
            return 0.0;
        }
        
        (current_size as f64 / max_size as f64) * 100.0
    }
    
    /// Vide le buffer d'événements
    pub async fn clear_buffer(&self) {
        let mut buffer = self.event_buffer.write().await;
        buffer.clear();
        
        let mut state = self.state.write().await;
        state.buffer_size = 0;
        
        info!("Event buffer cleared");
    }
}

// Tests unitaires
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use crate::communication::grpc_client::GrpcClient;
    use crate::communication::protocol::*;
    
    #[tokio::test]
    async fn test_reporting_manager_creation() {
        let config = Arc::new(AgentConfig::default());
        let grpc_client = Arc::new(GrpcClient::new(&config.server).await.unwrap());
        
        let manager = ReportingManager::new(config, grpc_client);
        assert!(!manager.is_active().await);
    }
    
    #[tokio::test]
    async fn test_event_buffer_operations() {
        let config = Arc::new(AgentConfig::default());
        let grpc_client = Arc::new(GrpcClient::new(&config.server).await.unwrap());
        
        let manager = ReportingManager::new(config, grpc_client);
        
        // Test d'ajout d'événement de fichier
        let file_event = FileEvent {
            event_id: "test-1".to_string(),
            timestamp: Utc::now(),
            event_type: "created".to_string(),
            file_path: "C:\\test.txt".to_string(),
            process_id: 1234,
            process_name: "test.exe".to_string(),
            file_size: Some(1024),
            file_hash: Some("abc123".to_string()),
            entropy: Some(7.5),
            is_suspicious: false,
        };
        
        manager.add_file_event(file_event).await.unwrap();
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.total_events_processed, 1);
        assert_eq!(stats.event_type_counts.get("file"), Some(&1));
    }
    
    #[tokio::test]
    async fn test_buffer_utilization() {
        let config = Arc::new(AgentConfig::default());
        let grpc_client = Arc::new(GrpcClient::new(&config.server).await.unwrap());
        
        let manager = ReportingManager::new(config, grpc_client);
        
        let initial_utilization = manager.get_buffer_utilization().await;
        assert_eq!(initial_utilization, 0.0);
    }
    
    #[test]
    fn test_event_buffer_creation() {
        let buffer = EventBuffer::new(1000);
        assert_eq!(buffer.max_size, 1000);
        assert_eq!(buffer.total_size(), 0);
        assert!(!buffer.is_full());
    }
    
    #[test]
    fn test_performance_metrics_serialization() {
        let metrics = PerformanceMetrics {
            events_per_second: 100.5,
            average_processing_latency: 5.2,
            buffer_utilization: 75.0,
            transmission_throughput: 1024.0,
            collected_at: Utc::now(),
        };
        
        let serialized = serde_json::to_string(&metrics).unwrap();
        let deserialized: PerformanceMetrics = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized.events_per_second, 100.5);
        assert_eq!(deserialized.buffer_utilization, 75.0);
    }
}