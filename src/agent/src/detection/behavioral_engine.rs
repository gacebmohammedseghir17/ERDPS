//! Moteur de détection comportementale pour ERDPS
//!
//! Ce module implémente l'analyse comportementale en temps réel pour détecter
//! les patterns d'activité suspects caractéristiques des ransomwares.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::interval;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use log::{debug, error, info, warn};

/// Configuration du moteur comportemental
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralConfig {
    /// Seuil de fichiers chiffrés par minute pour déclencher une alerte
    pub encryption_threshold: u32,
    /// Fenêtre de temps pour l'analyse (en secondes)
    pub analysis_window: u64,
    /// Extensions de fichiers surveillées
    pub monitored_extensions: Vec<String>,
    /// Processus suspects à surveiller
    pub suspicious_processes: Vec<String>,
    /// Seuil de création de fichiers par minute
    pub file_creation_threshold: u32,
    /// Seuil de suppression de fichiers par minute
    pub file_deletion_threshold: u32,
    /// Seuil d'accès réseau suspect
    pub network_threshold: u32,
    /// Activer la détection de chiffrement massif
    pub enable_mass_encryption_detection: bool,
    /// Activer la détection de modification de registre
    pub enable_registry_detection: bool,
    /// Activer la détection de processus suspects
    pub enable_process_detection: bool,
    /// Score minimum pour déclencher une alerte
    pub alert_threshold: f64,
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            encryption_threshold: 50,
            analysis_window: 300, // 5 minutes
            monitored_extensions: vec![
                ".doc".to_string(), ".docx".to_string(), ".pdf".to_string(),
                ".jpg".to_string(), ".png".to_string(), ".mp4".to_string(),
                ".xlsx".to_string(), ".pptx".to_string(), ".txt".to_string(),
                ".zip".to_string(), ".rar".to_string()
            ],
            suspicious_processes: vec![
                "powershell.exe".to_string(),
                "cmd.exe".to_string(),
                "wscript.exe".to_string(),
                "cscript.exe".to_string(),
                "rundll32.exe".to_string()
            ],
            file_creation_threshold: 100,
            file_deletion_threshold: 50,
            network_threshold: 20,
            enable_mass_encryption_detection: true,
            enable_registry_detection: true,
            enable_process_detection: true,
            alert_threshold: 7.0,
        }
    }
}

/// Types d'événements comportementaux
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BehavioralEventType {
    MassFileEncryption,
    SuspiciousProcessActivity,
    RegistryModification,
    NetworkCommunication,
    FileSystemManipulation,
    ServiceCreation,
    ScheduledTaskCreation,
    ShadowCopyDeletion,
    BackupDeletion,
    SystemRecoveryDisabling,
}

/// Événement comportemental détecté
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEvent {
    /// ID unique de l'événement
    pub id: String,
    /// Type d'événement
    pub event_type: BehavioralEventType,
    /// Timestamp de l'événement
    pub timestamp: u64,
    /// Processus responsable
    pub process_name: String,
    /// PID du processus
    pub process_id: u32,
    /// Chemin du processus
    pub process_path: PathBuf,
    /// Fichiers affectés
    pub affected_files: Vec<PathBuf>,
    /// Score de risque (0.0 - 10.0)
    pub risk_score: f64,
    /// Détails supplémentaires
    pub details: HashMap<String, String>,
    /// Métadonnées de l'événement
    pub metadata: HashMap<String, String>,
}

/// Alerte comportementale
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAlert {
    /// ID unique de l'alerte
    pub id: String,
    /// Timestamp de l'alerte
    pub timestamp: u64,
    /// Score de risque total
    pub total_risk_score: f64,
    /// Événements qui ont déclenché l'alerte
    pub triggering_events: Vec<BehavioralEvent>,
    /// Processus principal suspect
    pub primary_process: String,
    /// Nombre de fichiers affectés
    pub affected_files_count: u32,
    /// Recommandations d'action
    pub recommended_actions: Vec<String>,
    /// Niveau de criticité (Low, Medium, High, Critical)
    pub severity: String,
    /// Description de la menace détectée
    pub threat_description: String,
}

/// Statistiques du moteur comportemental
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralStats {
    /// Nombre total d'événements analysés
    pub total_events: u64,
    /// Nombre d'alertes générées
    pub alerts_generated: u64,
    /// Événements par type
    pub events_by_type: HashMap<BehavioralEventType, u64>,
    /// Score de risque moyen
    pub average_risk_score: f64,
    /// Processus les plus actifs
    pub top_processes: HashMap<String, u64>,
    /// Extensions de fichiers les plus affectées
    pub top_file_extensions: HashMap<String, u64>,
    /// Temps de traitement moyen (ms)
    pub avg_processing_time: f64,
    /// Dernière analyse
    pub last_analysis: u64,
}

impl Default for BehavioralStats {
    fn default() -> Self {
        Self {
            total_events: 0,
            alerts_generated: 0,
            events_by_type: HashMap::new(),
            average_risk_score: 0.0,
            top_processes: HashMap::new(),
            top_file_extensions: HashMap::new(),
            avg_processing_time: 0.0,
            last_analysis: 0,
        }
    }
}

/// État du moteur comportemental
#[derive(Debug, Clone, PartialEq)]
pub enum BehavioralEngineState {
    Stopped,
    Starting,
    Running,
    Analyzing,
    Error(String),
}

/// Fenêtre d'analyse temporelle
#[derive(Debug)]
struct AnalysisWindow {
    events: VecDeque<BehavioralEvent>,
    start_time: Instant,
    duration: Duration,
}

impl AnalysisWindow {
    fn new(duration: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            start_time: Instant::now(),
            duration,
        }
    }

    fn add_event(&mut self, event: BehavioralEvent) {
        self.events.push_back(event);
        self.cleanup_old_events();
    }

    fn cleanup_old_events(&mut self) {
        let cutoff_time = Instant::now() - self.duration;
        let cutoff_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.duration.as_secs();

        self.events.retain(|event| event.timestamp > cutoff_timestamp);
    }

    fn get_events_by_type(&self, event_type: &BehavioralEventType) -> Vec<&BehavioralEvent> {
        self.events.iter().filter(|e| &e.event_type == event_type).collect()
    }

    fn calculate_risk_score(&self) -> f64 {
        if self.events.is_empty() {
            return 0.0;
        }

        let total_score: f64 = self.events.iter().map(|e| e.risk_score).sum();
        let event_count = self.events.len() as f64;
        
        // Facteur de multiplication basé sur la fréquence
        let frequency_multiplier = if event_count > 10.0 {
            1.5
        } else if event_count > 5.0 {
            1.2
        } else {
            1.0
        };

        (total_score / event_count) * frequency_multiplier
    }
}

/// Moteur de détection comportementale
pub struct BehavioralEngine {
    config: BehavioralConfig,
    state: Arc<RwLock<BehavioralEngineState>>,
    stats: Arc<RwLock<BehavioralStats>>,
    analysis_window: Arc<RwLock<AnalysisWindow>>,
    alert_sender: Option<mpsc::UnboundedSender<BehavioralAlert>>,
    shutdown_sender: Option<mpsc::Sender<()>>,
}

impl BehavioralEngine {
    /// Crée une nouvelle instance du moteur comportemental
    pub fn new(config: BehavioralConfig) -> Self {
        let analysis_window = AnalysisWindow::new(Duration::from_secs(config.analysis_window));
        
        Self {
            config,
            state: Arc::new(RwLock::new(BehavioralEngineState::Stopped)),
            stats: Arc::new(RwLock::new(BehavioralStats::default())),
            analysis_window: Arc::new(RwLock::new(analysis_window)),
            alert_sender: None,
            shutdown_sender: None,
        }
    }

    /// Démarre le moteur comportemental
    pub async fn start(&mut self, alert_sender: mpsc::UnboundedSender<BehavioralAlert>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting behavioral detection engine...");
        
        {
            let mut state = self.state.write().unwrap();
            *state = BehavioralEngineState::Starting;
        }

        self.alert_sender = Some(alert_sender);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_sender = Some(shutdown_tx);

        // Démarrer la tâche d'analyse périodique
        let config = self.config.clone();
        let state = Arc::clone(&self.state);
        let stats = Arc::clone(&self.stats);
        let analysis_window = Arc::clone(&self.analysis_window);
        let alert_sender_clone = self.alert_sender.clone();
        
        tokio::spawn(async move {
            let mut analysis_interval = interval(Duration::from_secs(30)); // Analyse toutes les 30 secondes
            
            loop {
                tokio::select! {
                    _ = analysis_interval.tick() => {
                        if let Err(e) = Self::analysis_task(&config, &state, &stats, &analysis_window, &alert_sender_clone).await {
                            error!("Behavioral analysis task failed: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Behavioral engine analysis task shutting down");
                        break;
                    }
                }
            }
        });

        {
            let mut state = self.state.write().unwrap();
            *state = BehavioralEngineState::Running;
        }

        info!("Behavioral detection engine started successfully");
        Ok(())
    }

    /// Arrête le moteur comportemental
    pub async fn stop(&mut self) {
        info!("Stopping behavioral detection engine...");
        
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(()).await;
        }

        {
            let mut state = self.state.write().unwrap();
            *state = BehavioralEngineState::Stopped;
        }

        info!("Behavioral detection engine stopped");
    }

    /// Ajoute un événement pour analyse
    pub async fn add_event(&self, event: BehavioralEvent) {
        debug!("Adding behavioral event: {:?}", event.event_type);
        
        // Mettre à jour les statistiques
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_events += 1;
            *stats.events_by_type.entry(event.event_type.clone()).or_insert(0) += 1;
            *stats.top_processes.entry(event.process_name.clone()).or_insert(0) += 1;
            
            // Mettre à jour le score de risque moyen
            let total_score = stats.average_risk_score * (stats.total_events - 1) as f64 + event.risk_score;
            stats.average_risk_score = total_score / stats.total_events as f64;
            
            stats.last_analysis = chrono::Utc::now().timestamp() as u64;
        }

        // Ajouter l'événement à la fenêtre d'analyse
        {
            let mut window = self.analysis_window.write().unwrap();
            window.add_event(event);
        }

        // Déclencher une analyse immédiate si nécessaire
        self.trigger_immediate_analysis().await;
    }

    /// Déclenche une analyse immédiate
    async fn trigger_immediate_analysis(&self) {
        let risk_score = {
            let window = self.analysis_window.read().unwrap();
            window.calculate_risk_score()
        };

        if risk_score >= self.config.alert_threshold {
            if let Err(e) = self.generate_alert().await {
                error!("Failed to generate behavioral alert: {}", e);
            }
        }
    }

    /// Génère une alerte comportementale
    async fn generate_alert(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (events, risk_score) = {
            let window = self.analysis_window.read().unwrap();
            (window.events.clone().into_iter().collect::<Vec<_>>(), window.calculate_risk_score())
        };

        if events.is_empty() {
            return Ok(());
        }

        let primary_process = events.iter()
            .map(|e| &e.process_name)
            .fold(HashMap::new(), |mut acc, process| {
                *acc.entry(process.clone()).or_insert(0) += 1;
                acc
            })
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(process, _)| process)
            .unwrap_or_else(|| "Unknown".to_string());

        let affected_files_count = events.iter()
            .map(|e| e.affected_files.len())
            .sum::<usize>() as u32;

        let severity = match risk_score {
            s if s >= 9.0 => "Critical",
            s if s >= 7.0 => "High",
            s if s >= 5.0 => "Medium",
            _ => "Low",
        }.to_string();

        let threat_description = self.generate_threat_description(&events, risk_score);
        let recommended_actions = self.generate_recommendations(&events, risk_score);

        let alert = BehavioralAlert {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            total_risk_score: risk_score,
            triggering_events: events,
            primary_process,
            affected_files_count,
            recommended_actions,
            severity,
            threat_description,
        };

        // Envoyer l'alerte
        if let Some(sender) = &self.alert_sender {
            sender.send(alert)?;
        }

        // Mettre à jour les statistiques
        {
            let mut stats = self.stats.write().unwrap();
            stats.alerts_generated += 1;
        }

        info!("Behavioral alert generated with risk score: {:.2}", risk_score);
        Ok(())
    }

    /// Génère une description de la menace
    fn generate_threat_description(&self, events: &[BehavioralEvent], risk_score: f64) -> String {
        let event_types: Vec<_> = events.iter()
            .map(|e| &e.event_type)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let mut description = String::new();
        
        if event_types.contains(&&BehavioralEventType::MassFileEncryption) {
            description.push_str("Détection de chiffrement massif de fichiers. ");
        }
        
        if event_types.contains(&&BehavioralEventType::SuspiciousProcessActivity) {
            description.push_str("Activité suspecte de processus détectée. ");
        }
        
        if event_types.contains(&&BehavioralEventType::ShadowCopyDeletion) {
            description.push_str("Suppression de copies de sauvegarde système. ");
        }
        
        if event_types.contains(&&BehavioralEventType::RegistryModification) {
            description.push_str("Modifications suspectes du registre Windows. ");
        }

        if description.is_empty() {
            description = "Comportement suspect détecté par l'analyse heuristique.".to_string();
        }

        format!("{} Score de risque: {:.1}/10.0", description.trim(), risk_score)
    }

    /// Génère des recommandations d'action
    fn generate_recommendations(&self, events: &[BehavioralEvent], risk_score: f64) -> Vec<String> {
        let mut recommendations = Vec::new();

        if risk_score >= 9.0 {
            recommendations.push("URGENT: Isoler immédiatement l'endpoint du réseau".to_string());
            recommendations.push("Arrêter tous les processus suspects identifiés".to_string());
            recommendations.push("Lancer une analyse forensique complète".to_string());
        } else if risk_score >= 7.0 {
            recommendations.push("Surveiller étroitement l'activité de l'endpoint".to_string());
            recommendations.push("Vérifier l'intégrité des fichiers critiques".to_string());
            recommendations.push("Considérer l'isolation préventive".to_string());
        } else {
            recommendations.push("Continuer la surveillance renforcée".to_string());
            recommendations.push("Documenter l'incident pour analyse".to_string());
        }

        // Recommandations spécifiques par type d'événement
        let event_types: std::collections::HashSet<_> = events.iter().map(|e| &e.event_type).collect();
        
        if event_types.contains(&&BehavioralEventType::MassFileEncryption) {
            recommendations.push("Vérifier les sauvegardes et leur intégrité".to_string());
        }
        
        if event_types.contains(&&BehavioralEventType::ShadowCopyDeletion) {
            recommendations.push("Restaurer les copies de sauvegarde si possible".to_string());
        }

        recommendations
    }

    /// Tâche d'analyse périodique
    async fn analysis_task(
        config: &BehavioralConfig,
        state: &Arc<RwLock<BehavioralEngineState>>,
        stats: &Arc<RwLock<BehavioralStats>>,
        analysis_window: &Arc<RwLock<AnalysisWindow>>,
        alert_sender: &Option<mpsc::UnboundedSender<BehavioralAlert>>
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut state = state.write().unwrap();
            *state = BehavioralEngineState::Analyzing;
        }

        let start_time = Instant::now();
        
        // Nettoyer les anciens événements
        {
            let mut window = analysis_window.write().unwrap();
            window.cleanup_old_events();
        }

        // Calculer les métriques d'analyse
        let processing_time = start_time.elapsed().as_millis() as f64;
        
        {
            let mut stats = stats.write().unwrap();
            let total_time = stats.avg_processing_time * (stats.total_events.saturating_sub(1)) as f64 + processing_time;
            stats.avg_processing_time = total_time / stats.total_events.max(1) as f64;
        }

        {
            let mut state = state.write().unwrap();
            *state = BehavioralEngineState::Running;
        }

        Ok(())
    }

    /// Récupère l'état actuel du moteur
    pub fn get_state(&self) -> BehavioralEngineState {
        self.state.read().unwrap().clone()
    }

    /// Récupère les statistiques du moteur
    pub fn get_stats(&self) -> BehavioralStats {
        self.stats.read().unwrap().clone()
    }

    /// Vérifie si le moteur est en cours d'exécution
    pub fn is_running(&self) -> bool {
        matches!(*self.state.read().unwrap(), BehavioralEngineState::Running | BehavioralEngineState::Analyzing)
    }

    /// Récupère la configuration actuelle
    pub fn get_config(&self) -> &BehavioralConfig {
        &self.config
    }

    /// Met à jour la configuration
    pub fn update_config(&mut self, new_config: BehavioralConfig) {
        self.config = new_config;
        
        // Mettre à jour la fenêtre d'analyse
        {
            let mut window = self.analysis_window.write().unwrap();
            *window = AnalysisWindow::new(Duration::from_secs(self.config.analysis_window));
        }
        
        info!("Behavioral engine configuration updated");
    }

    /// Réinitialise les statistiques
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write().unwrap();
        *stats = BehavioralStats::default();
        info!("Behavioral engine statistics reset");
    }

    /// Récupère les événements récents
    pub fn get_recent_events(&self, limit: usize) -> Vec<BehavioralEvent> {
        let window = self.analysis_window.read().unwrap();
        window.events.iter().rev().take(limit).cloned().collect()
    }
}

/// Fonctions utilitaires pour créer des événements comportementaux
impl BehavioralEngine {
    /// Crée un événement de chiffrement massif
    pub fn create_mass_encryption_event(
        process_name: String,
        process_id: u32,
        process_path: PathBuf,
        affected_files: Vec<PathBuf>
    ) -> BehavioralEvent {
        let risk_score = (affected_files.len() as f64 / 10.0).min(10.0);
        
        BehavioralEvent {
            id: Uuid::new_v4().to_string(),
            event_type: BehavioralEventType::MassFileEncryption,
            timestamp: chrono::Utc::now().timestamp() as u64,
            process_name,
            process_id,
            process_path,
            affected_files,
            risk_score,
            details: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Crée un événement de processus suspect
    pub fn create_suspicious_process_event(
        process_name: String,
        process_id: u32,
        process_path: PathBuf,
        details: HashMap<String, String>
    ) -> BehavioralEvent {
        BehavioralEvent {
            id: Uuid::new_v4().to_string(),
            event_type: BehavioralEventType::SuspiciousProcessActivity,
            timestamp: chrono::Utc::now().timestamp() as u64,
            process_name,
            process_id,
            process_path,
            affected_files: Vec::new(),
            risk_score: 6.0,
            details,
            metadata: HashMap::new(),
        }
    }

    /// Crée un événement de suppression de Shadow Copy
    pub fn create_shadow_copy_deletion_event(
        process_name: String,
        process_id: u32,
        process_path: PathBuf
    ) -> BehavioralEvent {
        BehavioralEvent {
            id: Uuid::new_v4().to_string(),
            event_type: BehavioralEventType::ShadowCopyDeletion,
            timestamp: chrono::Utc::now().timestamp() as u64,
            process_name,
            process_id,
            process_path,
            affected_files: Vec::new(),
            risk_score: 9.0, // Très suspect
            details: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_behavioral_engine_creation() {
        let config = BehavioralConfig::default();
        let engine = BehavioralEngine::new(config);
        
        assert_eq!(engine.get_state(), BehavioralEngineState::Stopped);
        assert!(!engine.is_running());
    }

    #[tokio::test]
    async fn test_analysis_window() {
        let mut window = AnalysisWindow::new(Duration::from_secs(60));
        
        let event = BehavioralEvent {
            id: Uuid::new_v4().to_string(),
            event_type: BehavioralEventType::MassFileEncryption,
            timestamp: chrono::Utc::now().timestamp() as u64,
            process_name: "test.exe".to_string(),
            process_id: 1234,
            process_path: PathBuf::from("C:\\test.exe"),
            affected_files: vec![PathBuf::from("C:\\file1.txt")],
            risk_score: 8.0,
            details: HashMap::new(),
            metadata: HashMap::new(),
        };
        
        window.add_event(event.clone());
        assert_eq!(window.events.len(), 1);
        
        let risk_score = window.calculate_risk_score();
        assert_eq!(risk_score, 8.0);
    }

    #[test]
    fn test_event_creation() {
        let event = BehavioralEngine::create_mass_encryption_event(
            "ransomware.exe".to_string(),
            1234,
            PathBuf::from("C:\\ransomware.exe"),
            vec![PathBuf::from("C:\\file1.txt"), PathBuf::from("C:\\file2.txt")]
        );
        
        assert_eq!(event.event_type, BehavioralEventType::MassFileEncryption);
        assert_eq!(event.process_name, "ransomware.exe");
        assert_eq!(event.affected_files.len(), 2);
        assert!(event.risk_score > 0.0);
    }

    #[test]
    fn test_threat_description_generation() {
        let config = BehavioralConfig::default();
        let engine = BehavioralEngine::new(config);
        
        let events = vec![
            BehavioralEngine::create_mass_encryption_event(
                "test.exe".to_string(),
                1234,
                PathBuf::from("C:\\test.exe"),
                vec![PathBuf::from("C:\\file1.txt")]
            )
        ];
        
        let description = engine.generate_threat_description(&events, 8.0);
        assert!(description.contains("chiffrement massif"));
        assert!(description.contains("8.0"));
    }

    #[test]
    fn test_recommendations_generation() {
        let config = BehavioralConfig::default();
        let engine = BehavioralEngine::new(config);
        
        let events = vec![
            BehavioralEngine::create_shadow_copy_deletion_event(
                "vssadmin.exe".to_string(),
                1234,
                PathBuf::from("C:\\Windows\\System32\\vssadmin.exe")
            )
        ];
        
        let recommendations = engine.generate_recommendations(&events, 9.0);
        assert!(!recommendations.is_empty());
        assert!(recommendations.iter().any(|r| r.contains("URGENT")));
    }
}