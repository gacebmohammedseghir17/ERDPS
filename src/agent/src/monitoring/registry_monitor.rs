//! ERDPS Registry Monitor
//!
//! Surveillance en temps réel du registre Windows pour la détection de ransomwares
//! Utilise les APIs Windows pour surveiller les modifications du registre
//!
//! Fonctionnalités:
//! - Surveillance des clés critiques du registre
//! - Détection de modifications suspectes
//! - Surveillance des clés de démarrage
//! - Détection de persistance malveillante
//! - Intégration avec le moteur de détection comportementale
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::detection::behavioral_engine::RegistryEvent;

// Importation des APIs Windows
use winapi::um::winreg::{
    RegOpenKeyExW,
    RegCloseKey,
    RegNotifyChangeKeyValue,
    RegQueryValueExW,
    RegEnumKeyExW,
    RegEnumValueW,
    HKEY_LOCAL_MACHINE,
    HKEY_CURRENT_USER,
    HKEY_CLASSES_ROOT,
    KEY_READ,
    KEY_NOTIFY,
    REG_NOTIFY_CHANGE_NAME,
    REG_NOTIFY_CHANGE_ATTRIBUTES,
    REG_NOTIFY_CHANGE_LAST_SET,
    REG_NOTIFY_CHANGE_SECURITY,
};
use winapi::shared::minwindef::{HKEY, DWORD, LPBYTE};
use winapi::shared::winerror::{ERROR_SUCCESS, ERROR_MORE_DATA};
use winapi::um::winnt::{HANDLE, WCHAR};
use winapi::um::synchapi::{WaitForSingleObject, CreateEventW};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::winbase::{WAIT_OBJECT_0, WAIT_TIMEOUT, INFINITE};
use std::ptr;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStringExt, OsStrExt};

// Configuration de surveillance du registre

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryMonitorConfig {
    pub monitor_startup_keys: bool,
    pub monitor_security_keys: bool,
    pub monitor_system_keys: bool,
    pub monitor_software_keys: bool,
    pub monitor_user_keys: bool,
    pub critical_keys: Vec<String>,
    pub excluded_keys: Vec<String>,
    pub excluded_processes: Vec<String>,
    pub max_events_per_minute: u32,
    pub enable_value_monitoring: bool,
    pub enable_key_monitoring: bool,
    pub notification_timeout_ms: u32,
    pub deep_scan_interval_minutes: u32,
}

impl Default for RegistryMonitorConfig {
    fn default() -> Self {
        Self {
            monitor_startup_keys: true,
            monitor_security_keys: true,
            monitor_system_keys: true,
            monitor_software_keys: true,
            monitor_user_keys: true,
            critical_keys: vec![
                // Clés de démarrage
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
                "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                
                // Clés de services
                "HKLM\\SYSTEM\\CurrentControlSet\\Services".to_string(),
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot".to_string(),
                
                // Clés de sécurité
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies".to_string(),
                "HKLM\\SOFTWARE\\Policies".to_string(),
                "HKCU\\SOFTWARE\\Policies".to_string(),
                
                // Clés système critiques
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager".to_string(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon".to_string(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders".to_string(),
                
                // Clés de chiffrement
                "HKLM\\SOFTWARE\\Microsoft\\Cryptography".to_string(),
                "HKCU\\SOFTWARE\\Microsoft\\Cryptography".to_string(),
                
                // Clés d'associations de fichiers
                "HKCR\\.exe".to_string(),
                "HKCR\\.com".to_string(),
                "HKCR\\.bat".to_string(),
                "HKCR\\.cmd".to_string(),
                "HKCR\\.scr".to_string(),
                "HKCR\\.pif".to_string(),
            ],
            excluded_keys: vec![
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer".to_string(),
                "HKLM\\SOFTWARE\\Classes\\Installer".to_string(),
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs".to_string(),
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU".to_string(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate".to_string(),
            ],
            excluded_processes: vec![
                "svchost.exe".to_string(),
                "System".to_string(),
                "winlogon.exe".to_string(),
                "csrss.exe".to_string(),
                "lsass.exe".to_string(),
                "services.exe".to_string(),
                "explorer.exe".to_string(),
                "regedit.exe".to_string(),
                "reg.exe".to_string(),
            ],
            max_events_per_minute: 100,
            enable_value_monitoring: true,
            enable_key_monitoring: true,
            notification_timeout_ms: 5000,
            deep_scan_interval_minutes: 60,
        }
    }
}

// Structures de données pour les événements du registre

#[derive(Debug, Clone)]
struct RegistryChangeEvent {
    event_id: Uuid,
    timestamp: SystemTime,
    key_path: String,
    value_name: Option<String>,
    change_type: RegistryChangeType,
    old_value: Option<String>,
    new_value: Option<String>,
    process_id: u32,
    process_name: String,
    is_suspicious: bool,
    risk_score: u8,
}

#[derive(Debug, Clone, PartialEq)]
enum RegistryChangeType {
    KeyCreated,
    KeyDeleted,
    KeyRenamed,
    ValueCreated,
    ValueModified,
    ValueDeleted,
    PermissionsChanged,
    Unknown,
}

#[derive(Debug, Clone)]
struct RegistryWatcher {
    key_handle: HKEY,
    event_handle: HANDLE,
    key_path: String,
    notification_filter: DWORD,
    watch_subtree: bool,
}

#[derive(Debug, Clone)]
struct SuspiciousRegistryActivity {
    activity_id: Uuid,
    timestamp: SystemTime,
    process_id: u32,
    process_name: String,
    activity_type: SuspiciousRegistryActivityType,
    description: String,
    affected_keys: Vec<String>,
    severity: u8,
    indicators: Vec<String>,
}

#[derive(Debug, Clone)]
enum SuspiciousRegistryActivityType {
    StartupPersistence,
    SecurityBypass,
    SystemModification,
    FileAssociationHijack,
    ServiceInstallation,
    CryptographyTampering,
    MassKeyModification,
    PrivilegeEscalation,
}

// Moniteur de registre principal

pub struct RegistryMonitor {
    config: RegistryMonitorConfig,
    event_sender: mpsc::UnboundedSender<RegistryEvent>,
    watchers: Arc<Mutex<Vec<RegistryWatcher>>>,
    event_cache: Arc<Mutex<HashMap<String, RegistryChangeEvent>>>,
    suspicious_activities: Arc<Mutex<Vec<SuspiciousRegistryActivity>>>,
    event_counter: Arc<Mutex<HashMap<String, u32>>>,
    shutdown_signal: Arc<Mutex<bool>>,
}

impl RegistryMonitor {
    pub fn new(
        config: RegistryMonitorConfig,
        event_sender: mpsc::UnboundedSender<RegistryEvent>,
    ) -> Self {
        Self {
            config,
            event_sender,
            watchers: Arc::new(Mutex::new(Vec::new())),
            event_cache: Arc::new(Mutex::new(HashMap::new())),
            suspicious_activities: Arc::new(Mutex::new(Vec::new())),
            event_counter: Arc::new(Mutex::new(HashMap::new())),
            shutdown_signal: Arc::new(Mutex::new(false)),
        }
    }

    /// Démarre la surveillance du registre
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting registry monitoring...");
        
        // Initialisation des watchers pour les clés critiques
        self.initialize_watchers().await?;
        
        // Démarrage de la surveillance des événements
        let watchers_monitor = self.watchers.clone();
        let event_sender_monitor = self.event_sender.clone();
        let event_cache_monitor = self.event_cache.clone();
        let config_monitor = self.config.clone();
        let shutdown_monitor = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::monitor_registry_events(
                watchers_monitor,
                event_sender_monitor,
                event_cache_monitor,
                config_monitor,
                shutdown_monitor,
            ).await;
        });
        
        // Démarrage de l'analyse des activités suspectes
        let event_cache_analysis = self.event_cache.clone();
        let suspicious_activities_analysis = self.suspicious_activities.clone();
        let config_analysis = self.config.clone();
        let shutdown_analysis = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::analyze_suspicious_activities(
                event_cache_analysis,
                suspicious_activities_analysis,
                config_analysis,
                shutdown_analysis,
            ).await;
        });
        
        // Démarrage du scan profond périodique
        let config_scan = self.config.clone();
        let event_sender_scan = self.event_sender.clone();
        let shutdown_scan = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::deep_scan_task(
                config_scan,
                event_sender_scan,
                shutdown_scan,
            ).await;
        });
        
        // Démarrage du nettoyage périodique
        let event_cache_cleanup = self.event_cache.clone();
        let suspicious_activities_cleanup = self.suspicious_activities.clone();
        let event_counter_cleanup = self.event_counter.clone();
        let shutdown_cleanup = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::cleanup_task(
                event_cache_cleanup,
                suspicious_activities_cleanup,
                event_counter_cleanup,
                shutdown_cleanup,
            ).await;
        });
        
        info!("Registry monitoring started successfully");
        Ok(())
    }

    /// Arrête la surveillance du registre
    pub async fn stop(&self) {
        info!("Stopping registry monitoring...");
        
        {
            let mut shutdown = self.shutdown_signal.lock().unwrap();
            *shutdown = true;
        }
        
        // Fermeture des watchers
        self.cleanup_watchers().await;
        
        info!("Registry monitoring stopped");
    }

    /// Initialise les watchers pour les clés critiques
    async fn initialize_watchers(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut watchers = self.watchers.lock().unwrap();
        
        for key_path in &self.config.critical_keys {
            match Self::create_registry_watcher(key_path) {
                Ok(watcher) => {
                    debug!("Created watcher for key: {}", key_path);
                    watchers.push(watcher);
                }
                Err(e) => {
                    warn!("Failed to create watcher for key {}: {}", key_path, e);
                }
            }
        }
        
        info!("Initialized {} registry watchers", watchers.len());
        Ok(())
    }

    /// Crée un watcher pour une clé de registre
    fn create_registry_watcher(key_path: &str) -> Result<RegistryWatcher, Box<dyn std::error::Error>> {
        let (root_key, subkey_path) = Self::parse_registry_path(key_path)?;
        
        unsafe {
            let mut key_handle: HKEY = ptr::null_mut();
            let subkey_wide: Vec<u16> = OsString::from(subkey_path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            
            // Ouverture de la clé avec les permissions de lecture et notification
            let result = RegOpenKeyExW(
                root_key,
                subkey_wide.as_ptr(),
                0,
                KEY_READ | KEY_NOTIFY,
                &mut key_handle,
            );
            
            if result != ERROR_SUCCESS as i32 {
                return Err(format!("Failed to open registry key {}: {}", key_path, result).into());
            }
            
            // Création de l'événement pour les notifications
            let event_handle = CreateEventW(
                ptr::null_mut(),
                0, // Auto-reset
                0, // Non-signaled
                ptr::null(),
            );
            
            if event_handle == INVALID_HANDLE_VALUE {
                RegCloseKey(key_handle);
                return Err("Failed to create event handle".into());
            }
            
            // Configuration des notifications
            let notification_filter = REG_NOTIFY_CHANGE_NAME |
                                    REG_NOTIFY_CHANGE_ATTRIBUTES |
                                    REG_NOTIFY_CHANGE_LAST_SET |
                                    REG_NOTIFY_CHANGE_SECURITY;
            
            let result = RegNotifyChangeKeyValue(
                key_handle,
                1, // Watch subtree
                notification_filter,
                event_handle,
                1, // Asynchronous
            );
            
            if result != ERROR_SUCCESS as i32 {
                CloseHandle(event_handle);
                RegCloseKey(key_handle);
                return Err(format!("Failed to register for notifications: {}", result).into());
            }
            
            Ok(RegistryWatcher {
                key_handle,
                event_handle,
                key_path: key_path.to_string(),
                notification_filter,
                watch_subtree: true,
            })
        }
    }

    /// Parse un chemin de registre
    fn parse_registry_path(path: &str) -> Result<(HKEY, &str), Box<dyn std::error::Error>> {
        if path.starts_with("HKLM\\") {
            Ok((HKEY_LOCAL_MACHINE, &path[5..]))
        } else if path.starts_with("HKCU\\") {
            Ok((HKEY_CURRENT_USER, &path[5..]))
        } else if path.starts_with("HKCR\\") {
            Ok((HKEY_CLASSES_ROOT, &path[5..]))
        } else {
            Err(format!("Unsupported registry root: {}", path).into())
        }
    }

    /// Surveille les événements du registre
    async fn monitor_registry_events(
        watchers: Arc<Mutex<Vec<RegistryWatcher>>>,
        event_sender: mpsc::UnboundedSender<RegistryEvent>,
        event_cache: Arc<Mutex<HashMap<String, RegistryChangeEvent>>>,
        config: RegistryMonitorConfig,
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
            
            // Vérification des événements pour chaque watcher
            {
                let watchers_guard = watchers.lock().unwrap();
                for watcher in watchers_guard.iter() {
                    unsafe {
                        let wait_result = WaitForSingleObject(
                            watcher.event_handle,
                            config.notification_timeout_ms,
                        );
                        
                        if wait_result == WAIT_OBJECT_0 {
                            // Événement détecté
                            debug!("Registry change detected for key: {}", watcher.key_path);
                            
                            // Analyse de la modification
                            if let Ok(change_event) = Self::analyze_registry_change(watcher, &config).await {
                                // Mise en cache de l'événement
                                {
                                    let mut cache = event_cache.lock().unwrap();
                                    cache.insert(change_event.event_id.to_string(), change_event.clone());
                                    
                                    // Limitation de la taille du cache
                                    if cache.len() > 1000 {
                                        let oldest_key = cache.keys().next().unwrap().clone();
                                        cache.remove(&oldest_key);
                                    }
                                }
                                
                                // Génération d'événement
                                Self::generate_registry_event(&change_event, &event_sender).await;
                            }
                            
                            // Réenregistrement pour les notifications
                            let result = RegNotifyChangeKeyValue(
                                watcher.key_handle,
                                1,
                                watcher.notification_filter,
                                watcher.event_handle,
                                1,
                            );
                            
                            if result != ERROR_SUCCESS as i32 {
                                error!("Failed to re-register for notifications: {}", result);
                            }
                        }
                    }
                }
            }
            
            sleep(Duration::from_millis(100)).await;
        }
        
        debug!("Registry monitoring loop stopped");
    }

    /// Analyse une modification du registre
    async fn analyze_registry_change(
        watcher: &RegistryWatcher,
        config: &RegistryMonitorConfig,
    ) -> Result<RegistryChangeEvent, Box<dyn std::error::Error>> {
        let event = RegistryChangeEvent {
            event_id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            key_path: watcher.key_path.clone(),
            value_name: None, // À implémenter avec une analyse plus détaillée
            change_type: RegistryChangeType::Unknown,
            old_value: None,
            new_value: None,
            process_id: Self::get_current_process_id(),
            process_name: Self::get_current_process_name(),
            is_suspicious: Self::is_suspicious_key(&watcher.key_path, config),
            risk_score: Self::calculate_risk_score(&watcher.key_path, config),
        };
        
        Ok(event)
    }

    /// Obtient l'ID du processus actuel
    fn get_current_process_id() -> u32 {
        unsafe {
            winapi::um::processthreadsapi::GetCurrentProcessId()
        }
    }

    /// Obtient le nom du processus actuel
    fn get_current_process_name() -> String {
        // Implémentation simplifiée
        "Unknown".to_string()
    }

    /// Détermine si une clé est suspecte
    fn is_suspicious_key(key_path: &str, config: &RegistryMonitorConfig) -> bool {
        // Vérification des clés critiques
        let is_critical = config.critical_keys.iter().any(|critical_key| {
            key_path.to_lowercase().contains(&critical_key.to_lowercase())
        });
        
        // Vérification des clés exclues
        let is_excluded = config.excluded_keys.iter().any(|excluded_key| {
            key_path.to_lowercase().contains(&excluded_key.to_lowercase())
        });
        
        is_critical && !is_excluded
    }

    /// Calcule le score de risque d'une clé
    fn calculate_risk_score(key_path: &str, config: &RegistryMonitorConfig) -> u8 {
        let mut score = 1;
        
        let key_lower = key_path.to_lowercase();
        
        // Clés de démarrage (score élevé)
        if key_lower.contains("run") || key_lower.contains("startup") {
            score += 4;
        }
        
        // Clés de services
        if key_lower.contains("services") {
            score += 3;
        }
        
        // Clés de sécurité
        if key_lower.contains("policies") || key_lower.contains("security") {
            score += 3;
        }
        
        // Clés système critiques
        if key_lower.contains("winlogon") || key_lower.contains("session manager") {
            score += 5;
        }
        
        // Associations de fichiers
        if key_lower.contains(".exe") || key_lower.contains(".com") {
            score += 4;
        }
        
        // Clés de chiffrement
        if key_lower.contains("cryptography") {
            score += 2;
        }
        
        score.min(10)
    }

    /// Génère un événement de registre
    async fn generate_registry_event(
        change_event: &RegistryChangeEvent,
        event_sender: &mpsc::UnboundedSender<RegistryEvent>,
    ) {
        let event = RegistryEvent {
            event_id: change_event.event_id,
            timestamp: Utc::now(),
            process_id: change_event.process_id,
            process_name: change_event.process_name.clone(),
            key_path: change_event.key_path.clone(),
            value_name: change_event.value_name.clone(),
            operation: match change_event.change_type {
                RegistryChangeType::KeyCreated => "KeyCreated".to_string(),
                RegistryChangeType::KeyDeleted => "KeyDeleted".to_string(),
                RegistryChangeType::ValueModified => "ValueModified".to_string(),
                _ => "Unknown".to_string(),
            },
            old_value: change_event.old_value.clone(),
            new_value: change_event.new_value.clone(),
        };
        
        if let Err(e) = event_sender.send(event) {
            error!("Failed to send registry event: {}", e);
        }
    }

    /// Analyse les activités suspectes
    async fn analyze_suspicious_activities(
        event_cache: Arc<Mutex<HashMap<String, RegistryChangeEvent>>>,
        suspicious_activities: Arc<Mutex<Vec<SuspiciousRegistryActivity>>>,
        config: RegistryMonitorConfig,
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
            
            // Analyse des événements récents
            {
                let cache = event_cache.lock().unwrap();
                let recent_events: Vec<_> = cache.values()
                    .filter(|event| {
                        if let Ok(age) = SystemTime::now().duration_since(event.timestamp) {
                            age < Duration::from_secs(300) // 5 minutes
                        } else {
                            false
                        }
                    })
                    .collect();
                
                // Détection de modifications en masse
                if recent_events.len() > 20 {
                    let activity = SuspiciousRegistryActivity {
                        activity_id: Uuid::new_v4(),
                        timestamp: SystemTime::now(),
                        process_id: 0,
                        process_name: "Multiple".to_string(),
                        activity_type: SuspiciousRegistryActivityType::MassKeyModification,
                        description: format!("Mass registry modification detected: {} changes in 5 minutes", recent_events.len()),
                        affected_keys: recent_events.iter().map(|e| e.key_path.clone()).collect(),
                        severity: 8,
                        indicators: vec!["High frequency registry changes".to_string()],
                    };
                    
                    let mut activities = suspicious_activities.lock().unwrap();
                    activities.push(activity);
                }
                
                // Détection de modifications de clés de démarrage
                let startup_modifications: Vec<_> = recent_events.iter()
                    .filter(|event| {
                        event.key_path.to_lowercase().contains("run") ||
                        event.key_path.to_lowercase().contains("startup")
                    })
                    .collect();
                
                if !startup_modifications.is_empty() {
                    for event in startup_modifications {
                        let activity = SuspiciousRegistryActivity {
                            activity_id: Uuid::new_v4(),
                            timestamp: event.timestamp,
                            process_id: event.process_id,
                            process_name: event.process_name.clone(),
                            activity_type: SuspiciousRegistryActivityType::StartupPersistence,
                            description: format!("Startup persistence detected: {}", event.key_path),
                            affected_keys: vec![event.key_path.clone()],
                            severity: event.risk_score,
                            indicators: vec!["Startup registry modification".to_string()],
                        };
                        
                        let mut activities = suspicious_activities.lock().unwrap();
                        activities.push(activity);
                    }
                }
            }
            
            sleep(Duration::from_secs(60)).await;
        }
        
        debug!("Suspicious activity analysis loop stopped");
    }

    /// Tâche de scan profond périodique
    async fn deep_scan_task(
        config: RegistryMonitorConfig,
        event_sender: mpsc::UnboundedSender<RegistryEvent>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        let scan_interval = Duration::from_secs(config.deep_scan_interval_minutes as u64 * 60);
        
        loop {
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            info!("Starting deep registry scan...");
            
            // Scan des clés critiques
            for key_path in &config.critical_keys {
                if let Err(e) = Self::deep_scan_key(key_path, &event_sender).await {
                    warn!("Failed to deep scan key {}: {}", key_path, e);
                }
            }
            
            info!("Deep registry scan completed");
            
            sleep(scan_interval).await;
        }
        
        debug!("Deep scan task stopped");
    }

    /// Effectue un scan profond d'une clé
    async fn deep_scan_key(
        key_path: &str,
        event_sender: &mpsc::UnboundedSender<RegistryEvent>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (root_key, subkey_path) = Self::parse_registry_path(key_path)?;
        
        unsafe {
            let mut key_handle: HKEY = ptr::null_mut();
            let subkey_wide: Vec<u16> = OsString::from(subkey_path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            
            let result = RegOpenKeyExW(
                root_key,
                subkey_wide.as_ptr(),
                0,
                KEY_READ,
                &mut key_handle,
            );
            
            if result != ERROR_SUCCESS as i32 {
                return Err(format!("Failed to open key for deep scan: {}", result).into());
            }
            
            // Énumération des sous-clés
            let mut index = 0;
            loop {
                let mut name_buffer = [0u16; 256];
                let mut name_size = name_buffer.len() as DWORD;
                
                let result = RegEnumKeyExW(
                    key_handle,
                    index,
                    name_buffer.as_mut_ptr(),
                    &mut name_size,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                
                if result != ERROR_SUCCESS as i32 {
                    break;
                }
                
                let subkey_name = String::from_utf16_lossy(&name_buffer[..name_size as usize]);
                debug!("Found subkey: {}", subkey_name);
                
                index += 1;
            }
            
            // Énumération des valeurs
            index = 0;
            loop {
                let mut name_buffer = [0u16; 256];
                let mut name_size = name_buffer.len() as DWORD;
                let mut value_type: DWORD = 0;
                let mut data_size: DWORD = 0;
                
                let result = RegEnumValueW(
                    key_handle,
                    index,
                    name_buffer.as_mut_ptr(),
                    &mut name_size,
                    ptr::null_mut(),
                    &mut value_type,
                    ptr::null_mut(),
                    &mut data_size,
                );
                
                if result != ERROR_SUCCESS as i32 {
                    break;
                }
                
                let value_name = String::from_utf16_lossy(&name_buffer[..name_size as usize]);
                debug!("Found value: {} (type: {}, size: {})", value_name, value_type, data_size);
                
                index += 1;
            }
            
            RegCloseKey(key_handle);
        }
        
        Ok(())
    }

    /// Tâche de nettoyage périodique
    async fn cleanup_task(
        event_cache: Arc<Mutex<HashMap<String, RegistryChangeEvent>>>,
        suspicious_activities: Arc<Mutex<Vec<SuspiciousRegistryActivity>>>,
        event_counter: Arc<Mutex<HashMap<String, u32>>>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        let cleanup_interval = Duration::from_secs(300); // 5 minutes
        let max_age = Duration::from_secs(3600); // 1 heure
        
        loop {
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Nettoyage du cache d'événements
            {
                let mut cache = event_cache.lock().unwrap();
                let now = SystemTime::now();
                
                cache.retain(|_, event| {
                    if let Ok(age) = now.duration_since(event.timestamp) {
                        age <= max_age
                    } else {
                        true
                    }
                });
                
                debug!("Event cache cleanup completed, {} entries remaining", cache.len());
            }
            
            // Nettoyage des activités suspectes
            {
                let mut activities = suspicious_activities.lock().unwrap();
                let now = SystemTime::now();
                
                activities.retain(|activity| {
                    if let Ok(age) = now.duration_since(activity.timestamp) {
                        age <= max_age
                    } else {
                        true
                    }
                });
                
                debug!("Suspicious activities cleanup completed, {} entries remaining", activities.len());
            }
            
            // Réinitialisation des compteurs d'événements
            {
                let mut counter = event_counter.lock().unwrap();
                counter.clear();
                debug!("Event counters reset");
            }
            
            sleep(cleanup_interval).await;
        }
        
        debug!("Registry monitor cleanup task stopped");
    }

    /// Nettoie les watchers
    async fn cleanup_watchers(&self) {
        let mut watchers = self.watchers.lock().unwrap();
        
        for watcher in watchers.drain(..) {
            unsafe {
                if !watcher.event_handle.is_null() {
                    CloseHandle(watcher.event_handle);
                }
                if !watcher.key_handle.is_null() {
                    RegCloseKey(watcher.key_handle);
                }
            }
        }
        
        debug!("Registry watchers cleaned up");
    }

    /// Obtient les statistiques de surveillance
    pub async fn get_statistics(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        // Statistiques des watchers
        let watchers = self.watchers.lock().unwrap();
        stats.insert("active_watchers_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(watchers.len())));
        
        // Statistiques des événements
        let cache = self.event_cache.lock().unwrap();
        stats.insert("cached_events_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(cache.len())));
        
        let suspicious_events = cache.values().filter(|e| e.is_suspicious).count();
        stats.insert("suspicious_events_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(suspicious_events)));
        
        // Statistiques des activités suspectes
        let activities = self.suspicious_activities.lock().unwrap();
        stats.insert("suspicious_activities_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(activities.len())));
        
        // Configuration
        stats.insert("startup_monitoring_enabled".to_string(), 
                    serde_json::Value::Bool(self.config.monitor_startup_keys));
        stats.insert("security_monitoring_enabled".to_string(), 
                    serde_json::Value::Bool(self.config.monitor_security_keys));
        stats.insert("deep_scan_enabled".to_string(), 
                    serde_json::Value::Bool(self.config.deep_scan_interval_minutes > 0));
        
        stats
    }
}

// Tests unitaires

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_path_parsing() {
        let (root, subkey) = RegistryMonitor::parse_registry_path(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        ).unwrap();
        
        assert_eq!(root, HKEY_LOCAL_MACHINE);
        assert_eq!(subkey, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    }

    #[test]
    fn test_suspicious_key_detection() {
        let config = RegistryMonitorConfig::default();
        
        assert!(RegistryMonitor::is_suspicious_key(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            &config
        ));
        
        assert!(!RegistryMonitor::is_suspicious_key(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer",
            &config
        ));
    }

    #[test]
    fn test_risk_score_calculation() {
        let config = RegistryMonitorConfig::default();
        
        let score1 = RegistryMonitor::calculate_risk_score(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            &config
        );
        assert!(score1 >= 4);
        
        let score2 = RegistryMonitor::calculate_risk_score(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            &config
        );
        assert!(score2 >= 5);
    }

    #[tokio::test]
    async fn test_registry_monitor_creation() {
        let config = RegistryMonitorConfig::default();
        let (sender, _receiver) = mpsc::unbounded_channel();
        
        let monitor = RegistryMonitor::new(config, sender);
        assert!(!monitor.shutdown_signal.lock().unwrap().clone());
    }

    #[test]
    fn test_change_type_classification() {
        // Test de classification des types de changements
        let event = RegistryChangeEvent {
            event_id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            key_path: "HKLM\\SOFTWARE\\Test".to_string(),
            value_name: Some("TestValue".to_string()),
            change_type: RegistryChangeType::ValueModified,
            old_value: Some("OldValue".to_string()),
            new_value: Some("NewValue".to_string()),
            process_id: 1234,
            process_name: "test.exe".to_string(),
            is_suspicious: true,
            risk_score: 5,
        };
        
        assert_eq!(event.change_type, RegistryChangeType::ValueModified);
        assert!(event.is_suspicious);
    }
}