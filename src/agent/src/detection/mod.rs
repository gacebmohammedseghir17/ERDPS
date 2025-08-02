//! Module de détection ERDPS
//!
//! Ce module contient tous les moteurs de détection pour l'agent ERDPS,
//! incluant la détection YARA et l'analyse comportementale.

pub mod yara_engine;
pub mod behavioral_engine;

// Re-exports pour faciliter l'utilisation
pub use yara_engine::{
    YaraEngine,
    YaraConfig,
    YaraMatch,
    YaraStats,
    YaraEngineState,
    MatchedString,
};

pub use behavioral_engine::{
    BehavioralEngine,
    BehavioralConfig,
    BehavioralEvent,
    BehavioralEventType,
    BehavioralAlert,
    BehavioralStats,
    BehavioralEngineState,
};

use std::sync::Arc;
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};
use log::{error, info, warn};

/// Configuration globale du système de détection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Configuration du moteur YARA
    pub yara: YaraConfig,
    /// Configuration du moteur comportemental
    pub behavioral: BehavioralConfig,
    /// Activer la détection YARA
    pub enable_yara: bool,
    /// Activer la détection comportementale
    pub enable_behavioral: bool,
    /// Délai entre les analyses (en secondes)
    pub scan_interval: u64,
    /// Nombre maximum d'alertes par minute
    pub max_alerts_per_minute: u32,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            yara: YaraConfig::default(),
            behavioral: BehavioralConfig::default(),
            enable_yara: true,
            enable_behavioral: true,
            scan_interval: 60,
            max_alerts_per_minute: 10,
        }
    }
}

/// Gestionnaire principal des moteurs de détection
pub struct DetectionManager {
    config: DetectionConfig,
    yara_engine: Option<YaraEngine>,
    behavioral_engine: Option<BehavioralEngine>,
    yara_detection_receiver: Option<mpsc::UnboundedReceiver<YaraMatch>>,
    behavioral_alert_receiver: Option<mpsc::UnboundedReceiver<BehavioralAlert>>,
    unified_alert_sender: Option<mpsc::UnboundedSender<DetectionAlert>>,
}

/// Alerte unifiée du système de détection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionAlert {
    /// ID unique de l'alerte
    pub id: String,
    /// Type d'alerte
    pub alert_type: DetectionAlertType,
    /// Timestamp de l'alerte
    pub timestamp: u64,
    /// Niveau de criticité
    pub severity: AlertSeverity,
    /// Score de risque (0.0 - 10.0)
    pub risk_score: f64,
    /// Description de la menace
    pub description: String,
    /// Données spécifiques à l'alerte
    pub data: DetectionAlertData,
    /// Actions recommandées
    pub recommended_actions: Vec<String>,
}

/// Type d'alerte de détection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionAlertType {
    YaraMatch,
    BehavioralThreat,
    CombinedThreat,
}

/// Niveau de criticité
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Données spécifiques à l'alerte
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionAlertData {
    Yara(YaraMatch),
    Behavioral(BehavioralAlert),
    Combined {
        yara_matches: Vec<YaraMatch>,
        behavioral_alerts: Vec<BehavioralAlert>,
    },
}

/// Statistiques globales de détection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionStats {
    /// Statistiques YARA
    pub yara_stats: Option<YaraStats>,
    /// Statistiques comportementales
    pub behavioral_stats: Option<BehavioralStats>,
    /// Nombre total d'alertes générées
    pub total_alerts: u64,
    /// Alertes par type
    pub alerts_by_type: std::collections::HashMap<DetectionAlertType, u64>,
    /// Alertes par niveau de criticité
    pub alerts_by_severity: std::collections::HashMap<AlertSeverity, u64>,
    /// Temps de fonctionnement (en secondes)
    pub uptime: u64,
    /// Dernière activité
    pub last_activity: u64,
}

impl Default for DetectionStats {
    fn default() -> Self {
        Self {
            yara_stats: None,
            behavioral_stats: None,
            total_alerts: 0,
            alerts_by_type: std::collections::HashMap::new(),
            alerts_by_severity: std::collections::HashMap::new(),
            uptime: 0,
            last_activity: 0,
        }
    }
}

impl DetectionManager {
    /// Crée une nouvelle instance du gestionnaire de détection
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            config,
            yara_engine: None,
            behavioral_engine: None,
            yara_detection_receiver: None,
            behavioral_alert_receiver: None,
            unified_alert_sender: None,
        }
    }

    /// Démarre le gestionnaire de détection
    pub async fn start(&mut self, alert_sender: mpsc::UnboundedSender<DetectionAlert>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting detection manager...");
        
        self.unified_alert_sender = Some(alert_sender);
        
        // Démarrer le moteur YARA si activé
        if self.config.enable_yara {
            let (yara_tx, yara_rx) = mpsc::unbounded_channel();
            let mut yara_engine = YaraEngine::new(self.config.yara.clone());
            yara_engine.start(yara_tx).await?;
            
            self.yara_engine = Some(yara_engine);
            self.yara_detection_receiver = Some(yara_rx);
            info!("YARA detection engine started");
        }
        
        // Démarrer le moteur comportemental si activé
        if self.config.enable_behavioral {
            let (behavioral_tx, behavioral_rx) = mpsc::unbounded_channel();
            let mut behavioral_engine = BehavioralEngine::new(self.config.behavioral.clone());
            behavioral_engine.start(behavioral_tx).await?;
            
            self.behavioral_engine = Some(behavioral_engine);
            self.behavioral_alert_receiver = Some(behavioral_rx);
            info!("Behavioral detection engine started");
        }
        
        // Démarrer la tâche de traitement des alertes
        self.start_alert_processing_task().await;
        
        info!("Detection manager started successfully");
        Ok(())
    }

    /// Arrête le gestionnaire de détection
    pub async fn stop(&mut self) {
        info!("Stopping detection manager...");
        
        if let Some(mut yara_engine) = self.yara_engine.take() {
            yara_engine.stop().await;
        }
        
        if let Some(mut behavioral_engine) = self.behavioral_engine.take() {
            behavioral_engine.stop().await;
        }
        
        info!("Detection manager stopped");
    }

    /// Démarre la tâche de traitement des alertes
    async fn start_alert_processing_task(&mut self) {
        let mut yara_rx = self.yara_detection_receiver.take();
        let mut behavioral_rx = self.behavioral_alert_receiver.take();
        let alert_sender = self.unified_alert_sender.clone();
        
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Traiter les détections YARA
                    Some(yara_match) = async {
                        match &mut yara_rx {
                            Some(rx) => rx.recv().await,
                            None => None,
                        }
                    } => {
                        if let Err(e) = Self::process_yara_detection(yara_match, &alert_sender).await {
                            error!("Failed to process YARA detection: {}", e);
                        }
                    }
                    
                    // Traiter les alertes comportementales
                    Some(behavioral_alert) = async {
                        match &mut behavioral_rx {
                            Some(rx) => rx.recv().await,
                            None => None,
                        }
                    } => {
                        if let Err(e) = Self::process_behavioral_alert(behavioral_alert, &alert_sender).await {
                            error!("Failed to process behavioral alert: {}", e);
                        }
                    }
                    
                    else => {
                        // Tous les canaux sont fermés
                        break;
                    }
                }
            }
            
            info!("Detection alert processing task terminated");
        });
    }

    /// Traite une détection YARA
    async fn process_yara_detection(
        yara_match: YaraMatch,
        alert_sender: &Option<mpsc::UnboundedSender<DetectionAlert>>
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let severity = match yara_match.severity {
            9..=10 => AlertSeverity::Critical,
            7..=8 => AlertSeverity::High,
            4..=6 => AlertSeverity::Medium,
            _ => AlertSeverity::Low,
        };
        
        let recommended_actions = match severity {
            AlertSeverity::Critical => vec![
                "Isoler immédiatement l'endpoint".to_string(),
                "Arrêter le processus malveillant".to_string(),
                "Lancer une analyse forensique".to_string(),
            ],
            AlertSeverity::High => vec![
                "Surveiller étroitement l'activité".to_string(),
                "Vérifier l'intégrité des fichiers".to_string(),
                "Considérer l'isolation".to_string(),
            ],
            _ => vec![
                "Continuer la surveillance".to_string(),
                "Documenter l'incident".to_string(),
            ],
        };
        
        let alert = DetectionAlert {
            id: uuid::Uuid::new_v4().to_string(),
            alert_type: DetectionAlertType::YaraMatch,
            timestamp: chrono::Utc::now().timestamp() as u64,
            severity,
            risk_score: yara_match.severity as f64,
            description: format!(
                "Détection YARA: {} dans le fichier {:?}",
                yara_match.rule_name,
                yara_match.file_path
            ),
            data: DetectionAlertData::Yara(yara_match),
            recommended_actions,
        };
        
        if let Some(sender) = alert_sender {
            sender.send(alert)?;
        }
        
        Ok(())
    }

    /// Traite une alerte comportementale
    async fn process_behavioral_alert(
        behavioral_alert: BehavioralAlert,
        alert_sender: &Option<mpsc::UnboundedSender<DetectionAlert>>
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let severity = match behavioral_alert.severity.as_str() {
            "Critical" => AlertSeverity::Critical,
            "High" => AlertSeverity::High,
            "Medium" => AlertSeverity::Medium,
            _ => AlertSeverity::Low,
        };
        
        let alert = DetectionAlert {
            id: uuid::Uuid::new_v4().to_string(),
            alert_type: DetectionAlertType::BehavioralThreat,
            timestamp: chrono::Utc::now().timestamp() as u64,
            severity,
            risk_score: behavioral_alert.total_risk_score,
            description: behavioral_alert.threat_description.clone(),
            data: DetectionAlertData::Behavioral(behavioral_alert.clone()),
            recommended_actions: behavioral_alert.recommended_actions,
        };
        
        if let Some(sender) = alert_sender {
            sender.send(alert)?;
        }
        
        Ok(())
    }

    /// Analyse un fichier avec tous les moteurs activés
    pub async fn scan_file(&self, file_path: &std::path::Path) -> Result<Vec<DetectionAlert>, Box<dyn std::error::Error + Send + Sync>> {
        let mut alerts = Vec::new();
        
        // Analyse YARA
        if let Some(yara_engine) = &self.yara_engine {
            let yara_matches = yara_engine.scan_file(file_path).await?;
            for yara_match in yara_matches {
                if let Ok(_) = Self::process_yara_detection(yara_match, &None).await {
                    // L'alerte a été traitée
                }
            }
        }
        
        Ok(alerts)
    }

    /// Ajoute un événement comportemental
    pub async fn add_behavioral_event(&self, event: BehavioralEvent) {
        if let Some(behavioral_engine) = &self.behavioral_engine {
            behavioral_engine.add_event(event).await;
        }
    }

    /// Récupère les statistiques globales
    pub fn get_stats(&self) -> DetectionStats {
        let mut stats = DetectionStats::default();
        
        if let Some(yara_engine) = &self.yara_engine {
            stats.yara_stats = Some(yara_engine.get_stats());
        }
        
        if let Some(behavioral_engine) = &self.behavioral_engine {
            stats.behavioral_stats = Some(behavioral_engine.get_stats());
        }
        
        stats.last_activity = chrono::Utc::now().timestamp() as u64;
        stats
    }

    /// Vérifie si le gestionnaire est en cours d'exécution
    pub fn is_running(&self) -> bool {
        let yara_running = self.yara_engine.as_ref().map_or(true, |e| e.is_running());
        let behavioral_running = self.behavioral_engine.as_ref().map_or(true, |e| e.is_running());
        
        yara_running && behavioral_running
    }

    /// Met à jour la configuration
    pub async fn update_config(&mut self, new_config: DetectionConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Updating detection manager configuration");
        
        // Mettre à jour la configuration YARA
        if let Some(yara_engine) = &mut self.yara_engine {
            yara_engine.update_config(new_config.yara.clone());
        }
        
        // Mettre à jour la configuration comportementale
        if let Some(behavioral_engine) = &mut self.behavioral_engine {
            behavioral_engine.update_config(new_config.behavioral.clone());
        }
        
        self.config = new_config;
        Ok(())
    }

    /// Force une mise à jour des règles YARA
    pub async fn force_yara_update(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(yara_engine) = &self.yara_engine {
            yara_engine.force_rules_update().await?;
        }
        Ok(())
    }

    /// Récupère la configuration actuelle
    pub fn get_config(&self) -> &DetectionConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_detection_manager_creation() {
        let config = DetectionConfig::default();
        let manager = DetectionManager::new(config);
        
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn test_alert_severity_conversion() {
        let yara_match = YaraMatch {
            id: "test".to_string(),
            rule_name: "test_rule".to_string(),
            namespace: "test".to_string(),
            tags: vec![],
            metadata: std::collections::HashMap::new(),
            file_path: PathBuf::from("test.exe"),
            file_size: 1024,
            file_hash: "abc123".to_string(),
            timestamp: 0,
            severity: 9,
            matched_strings: vec![],
            scan_duration: 10,
        };
        
        let (tx, _rx) = mpsc::unbounded_channel();
        let result = DetectionManager::process_yara_detection(yara_match, &Some(tx)).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_alert_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
    }
}