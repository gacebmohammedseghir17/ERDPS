//! ERDPS File System Monitor
//!
//! Surveillance en temps réel du système de fichiers pour la détection de ransomwares
//! Utilise les APIs Windows pour surveiller les opérations sur les fichiers
//!
//! Fonctionnalités:
//! - Surveillance en temps réel des opérations de fichiers
//! - Calcul d'entropie pour détecter le chiffrement
//! - Détection des extensions suspectes
//! - Surveillance des répertoires protégés
//! - Intégration avec le moteur de détection comportementale
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use std::fs;
use std::io::Read;

use crate::detection::behavioral_engine::{FileEvent, FileOperation};

// Importation des APIs Windows
use winapi::um::winnt::{
    FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_ATTRIBUTES,
    FILE_NOTIFY_CHANGE_SIZE,
    FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_CREATION,
    FILE_NOTIFY_CHANGE_SECURITY,
};
use winapi::um::fileapi::{
    CreateFileW,
    ReadDirectoryChangesW,
    OPEN_EXISTING,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;
use winapi::um::winnt::{GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE};
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::ioapiset::GetOverlappedResult;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::shared::minwindef::{DWORD, LPVOID, FALSE};
use std::ptr;
use std::mem;

// Configuration de surveillance

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorConfig {
    pub watched_directories: Vec<PathBuf>,
    pub excluded_directories: Vec<PathBuf>,
    pub excluded_extensions: Vec<String>,
    pub max_file_size_mb: u64,
    pub entropy_calculation: bool,
    pub hash_calculation: bool,
    pub buffer_size: usize,
    pub polling_interval_ms: u64,
    pub recursive_monitoring: bool,
}

impl Default for FileMonitorConfig {
    fn default() -> Self {
        Self {
            watched_directories: vec![
                PathBuf::from(r"C:\Users"),
                PathBuf::from(r"C:\Documents and Settings"),
                PathBuf::from(r"C:\ProgramData"),
                PathBuf::from(r"D:\"),
                PathBuf::from(r"E:\"),
            ],
            excluded_directories: vec![
                PathBuf::from(r"C:\Windows\System32"),
                PathBuf::from(r"C:\Windows\SysWOW64"),
                PathBuf::from(r"C:\Program Files"),
                PathBuf::from(r"C:\Program Files (x86)"),
                PathBuf::from(r"C:\ProgramData\Microsoft"),
                PathBuf::from(r"C:\Users\All Users"),
                PathBuf::from(r"C:\$Recycle.Bin"),
                PathBuf::from(r"C:\System Volume Information"),
            ],
            excluded_extensions: vec![
                ".tmp".to_string(),
                ".log".to_string(),
                ".cache".to_string(),
                ".db".to_string(),
                ".lock".to_string(),
                ".swp".to_string(),
                ".bak".to_string(),
            ],
            max_file_size_mb: 100,
            entropy_calculation: true,
            hash_calculation: true,
            buffer_size: 64 * 1024, // 64KB
            polling_interval_ms: 100,
            recursive_monitoring: true,
        }
    }
}

// Structures pour les notifications Windows

#[repr(C)]
#[derive(Debug)]
struct FileNotifyInformation {
    next_entry_offset: DWORD,
    action: DWORD,
    file_name_length: DWORD,
    file_name: [u16; 1], // Variable length
}

#[derive(Debug, Clone)]
struct FileChange {
    action: FileChangeAction,
    file_path: PathBuf,
    timestamp: SystemTime,
}

#[derive(Debug, Clone)]
enum FileChangeAction {
    Added,
    Removed,
    Modified,
    RenamedOld,
    RenamedNew,
}

// Moniteur de fichiers principal

pub struct FileMonitor {
    config: FileMonitorConfig,
    event_sender: mpsc::UnboundedSender<FileEvent>,
    active_handles: Arc<Mutex<HashMap<PathBuf, isize>>>,
    file_cache: Arc<Mutex<HashMap<PathBuf, FileMetadata>>>,
    shutdown_signal: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone)]
struct FileMetadata {
    size: u64,
    modified: SystemTime,
    hash: Option<String>,
    entropy: Option<f64>,
    extension: Option<String>,
}

impl FileMonitor {
    pub fn new(
        config: FileMonitorConfig,
        event_sender: mpsc::UnboundedSender<FileEvent>,
    ) -> Self {
        Self {
            config,
            event_sender,
            active_handles: Arc::new(Mutex::new(HashMap::new())),
            file_cache: Arc::new(Mutex::new(HashMap::new())),
            shutdown_signal: Arc::new(Mutex::new(false)),
        }
    }

    /// Démarre la surveillance des fichiers
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting file system monitoring...");
        
        // Validation des répertoires à surveiller
        for dir in &self.config.watched_directories {
            if !dir.exists() {
                warn!("Watched directory does not exist: {:?}", dir);
                continue;
            }
            
            if !dir.is_dir() {
                warn!("Watched path is not a directory: {:?}", dir);
                continue;
            }
            
            info!("Monitoring directory: {:?}", dir);
            
            // Démarrage de la surveillance pour chaque répertoire
            let dir_clone = dir.clone();
            let config_clone = self.config.clone();
            let event_sender_clone = self.event_sender.clone();
            let file_cache_clone = self.file_cache.clone();
            let shutdown_signal_clone = self.shutdown_signal.clone();
            
            tokio::spawn(async move {
                if let Err(e) = Self::monitor_directory(
                    dir_clone,
                    config_clone,
                    event_sender_clone,
                    file_cache_clone,
                    shutdown_signal_clone,
                ).await {
                    error!("Directory monitoring failed: {}", e);
                }
            });
        }
        
        // Démarrage du nettoyage périodique du cache
        let file_cache_cleanup = self.file_cache.clone();
        let shutdown_cleanup = self.shutdown_signal.clone();
        tokio::spawn(async move {
            Self::cache_cleanup_task(file_cache_cleanup, shutdown_cleanup).await;
        });
        
        info!("File system monitoring started successfully");
        Ok(())
    }

    /// Arrête la surveillance des fichiers
    pub async fn stop(&self) {
        info!("Stopping file system monitoring...");
        
        // Signal d'arrêt
        {
            let mut shutdown = self.shutdown_signal.lock().unwrap();
            *shutdown = true;
        }
        
        // Fermeture des handles actifs
        {
            let mut handles = self.active_handles.lock().unwrap();
            for (path, handle) in handles.drain() {
                unsafe {
                    CloseHandle(handle as *mut _);
                }
                debug!("Closed monitoring handle for: {:?}", path);
            }
        }
        
        info!("File system monitoring stopped");
    }

    /// Surveillance d'un répertoire spécifique
    async fn monitor_directory(
        directory: PathBuf,
        config: FileMonitorConfig,
        event_sender: mpsc::UnboundedSender<FileEvent>,
        file_cache: Arc<Mutex<HashMap<PathBuf, FileMetadata>>>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir_str = directory.to_string_lossy();
        let mut dir_wide: Vec<u16> = dir_str.encode_utf16().collect();
        dir_wide.push(0); // Null terminator
        
        // Ouverture du handle de répertoire
        let handle = unsafe {
            CreateFileW(
                dir_wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!("Failed to open directory handle for: {:?}", directory).into());
        }
        
        debug!("Opened directory handle for: {:?}", directory);
        
        // Buffer pour les notifications
        let mut buffer = vec![0u8; config.buffer_size];
        let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
        
        loop {
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Lecture des changements de répertoire
            let mut bytes_returned: DWORD = 0;
            let success = unsafe {
                ReadDirectoryChangesW(
                    handle,
                    buffer.as_mut_ptr() as LPVOID,
                    buffer.len() as DWORD,
                    if config.recursive_monitoring { 1 } else { 0 },
                    FILE_NOTIFY_CHANGE_FILE_NAME
                        | FILE_NOTIFY_CHANGE_DIR_NAME
                        | FILE_NOTIFY_CHANGE_ATTRIBUTES
                        | FILE_NOTIFY_CHANGE_SIZE
                        | FILE_NOTIFY_CHANGE_LAST_WRITE
                        | FILE_NOTIFY_CHANGE_CREATION,
                    &mut bytes_returned,
                    &mut overlapped,
                    ptr::null_mut(),
                )
            };
            
            if success == 0 {
                warn!("ReadDirectoryChangesW failed for: {:?}", directory);
                sleep(Duration::from_millis(config.polling_interval_ms)).await;
                continue;
            }
            
            // Attente de la completion
            let mut bytes_transferred: DWORD = 0;
            let overlapped_result = unsafe {
                GetOverlappedResult(
                    handle,
                    &mut overlapped,
                    &mut bytes_transferred,
                    1, // Wait
                )
            };
            
            if overlapped_result == 0 || bytes_transferred == 0 {
                sleep(Duration::from_millis(config.polling_interval_ms)).await;
                continue;
            }
            
            // Traitement des notifications
            Self::process_file_notifications(
                &buffer[..bytes_transferred as usize],
                &directory,
                &config,
                &event_sender,
                &file_cache,
            ).await;
            
            // Pause avant la prochaine itération
            sleep(Duration::from_millis(config.polling_interval_ms)).await;
        }
        
        // Fermeture du handle
        unsafe {
            CloseHandle(handle);
        }
        
        debug!("Directory monitoring stopped for: {:?}", directory);
        Ok(())
    }

    /// Traitement des notifications de fichiers
    async fn process_file_notifications(
        buffer: &[u8],
        base_directory: &Path,
        config: &FileMonitorConfig,
        event_sender: &mpsc::UnboundedSender<FileEvent>,
        file_cache: &Arc<Mutex<HashMap<PathBuf, FileMetadata>>>,
    ) {
        let mut offset = 0;
        
        while offset < buffer.len() {
            if offset + mem::size_of::<FileNotifyInformation>() > buffer.len() {
                break;
            }
            
            let info = unsafe {
                &*(buffer.as_ptr().add(offset) as *const FileNotifyInformation)
            };
            
            // Extraction du nom de fichier
            let filename_bytes = unsafe {
                std::slice::from_raw_parts(
                    buffer.as_ptr().add(offset + mem::size_of::<FileNotifyInformation>() - 2),
                    info.file_name_length as usize,
                )
            };
            
            let filename_u16 = unsafe {
                std::slice::from_raw_parts(
                    filename_bytes.as_ptr() as *const u16,
                    filename_bytes.len() / 2,
                )
            };
            
            let filename = String::from_utf16_lossy(filename_u16);
            let file_path = base_directory.join(&filename);
            
            // Filtrage des fichiers exclus
            if Self::should_exclude_file(&file_path, config) {
                if info.next_entry_offset == 0 {
                    break;
                }
                offset += info.next_entry_offset as usize;
                continue;
            }
            
            // Détermination de l'action
            let action = match info.action {
                1 => FileChangeAction::Added,     // FILE_ACTION_ADDED
                2 => FileChangeAction::Removed,   // FILE_ACTION_REMOVED
                3 => FileChangeAction::Modified,  // FILE_ACTION_MODIFIED
                4 => FileChangeAction::RenamedOld, // FILE_ACTION_RENAMED_OLD_NAME
                5 => FileChangeAction::RenamedNew, // FILE_ACTION_RENAMED_NEW_NAME
                _ => {
                    debug!("Unknown file action: {}", info.action);
                    if info.next_entry_offset == 0 {
                        break;
                    }
                    offset += info.next_entry_offset as usize;
                    continue;
                }
            };
            
            debug!("File change detected: {:?} - {:?}", action, file_path);
            
            // Traitement de l'événement
            Self::handle_file_change(
                FileChange {
                    action,
                    file_path,
                    timestamp: SystemTime::now(),
                },
                config,
                event_sender,
                file_cache,
            ).await;
            
            // Passage à la notification suivante
            if info.next_entry_offset == 0 {
                break;
            }
            offset += info.next_entry_offset as usize;
        }
    }

    /// Gestion d'un changement de fichier
    async fn handle_file_change(
        change: FileChange,
        config: &FileMonitorConfig,
        event_sender: &mpsc::UnboundedSender<FileEvent>,
        file_cache: &Arc<Mutex<HashMap<PathBuf, FileMetadata>>>,
    ) {
        let file_path = &change.file_path;
        
        // Obtention des informations du processus responsable
        let (process_id, process_name) = Self::get_process_info_for_file(file_path).await;
        
        // Détermination de l'opération
        let operation = match change.action {
            FileChangeAction::Added => FileOperation::Create,
            FileChangeAction::Modified => FileOperation::Write,
            FileChangeAction::Removed => FileOperation::Delete,
            FileChangeAction::RenamedOld => return, // Ignoré, on attend RenamedNew
            FileChangeAction::RenamedNew => {
                // Pour les renommages, on essaie de détecter si c'est un chiffrement
                if Self::is_likely_encryption_rename(file_path) {
                    FileOperation::Encrypt
                } else {
                    FileOperation::Rename { old_path: file_path.clone() }
                }
            }
        };
        
        // Calcul des métadonnées du fichier
        let (file_size, entropy, hash, extension) = if file_path.exists() && file_path.is_file() {
            let metadata = match fs::metadata(file_path) {
                Ok(meta) => meta,
                Err(e) => {
                    debug!("Failed to get file metadata for {:?}: {}", file_path, e);
                    return;
                }
            };
            
            let size = metadata.len();
            
            // Limitation de taille pour éviter les gros fichiers
            if size > config.max_file_size_mb * 1024 * 1024 {
                debug!("File too large, skipping: {:?} ({} bytes)", file_path, size);
                return;
            }
            
            let extension = file_path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| format!(".{}", ext.to_lowercase()));
            
            let entropy = if config.entropy_calculation {
                Self::calculate_file_entropy(file_path).await
            } else {
                None
            };
            
            let hash = if config.hash_calculation {
                Self::calculate_file_hash(file_path).await
            } else {
                None
            };
            
            (size, entropy, hash, extension)
        } else {
            (0, None, None, None)
        };
        
        // Mise à jour du cache
        if file_path.exists() {
            let metadata = FileMetadata {
                size: file_size,
                modified: change.timestamp,
                hash: hash.clone(),
                entropy,
                extension: extension.clone(),
            };
            
            let mut cache = file_cache.lock().unwrap();
            cache.insert(file_path.clone(), metadata);
        } else {
            let mut cache = file_cache.lock().unwrap();
            cache.remove(file_path);
        }
        
        // Création de l'événement
        let event = FileEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            process_id,
            process_name,
            file_path: file_path.clone(),
            operation,
            file_size,
            file_extension: extension,
            entropy,
            hash_sha256: hash,
        };
        
        // Envoi de l'événement
        if let Err(e) = event_sender.send(event) {
            error!("Failed to send file event: {}", e);
        }
    }

    /// Vérifie si un fichier doit être exclu de la surveillance
    fn should_exclude_file(file_path: &Path, config: &FileMonitorConfig) -> bool {
        // Vérification des répertoires exclus
        for excluded_dir in &config.excluded_directories {
            if file_path.starts_with(excluded_dir) {
                return true;
            }
        }
        
        // Vérification des extensions exclues
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            let ext_lower = format!(".{}", extension.to_lowercase());
            if config.excluded_extensions.contains(&ext_lower) {
                return true;
            }
        }
        
        // Exclusion des fichiers temporaires et système
        let filename = file_path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        
        if filename.starts_with('.') || 
           filename.starts_with('~') ||
           filename.contains("tmp") ||
           filename.contains("temp") {
            return true;
        }
        
        false
    }

    /// Détermine si un renommage est probablement un chiffrement
    fn is_likely_encryption_rename(file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            let ext_lower = extension.to_lowercase();
            
            // Extensions communes de ransomware
            let ransomware_extensions = [
                "encrypted", "locked", "crypto", "crypt", "enc", "locky",
                "cerber", "wannacry", "petya", "ryuk", "maze", "sodinokibi",
                "dharma", "phobos", "stop", "djvu", "nemty", "clop",
            ];
            
            return ransomware_extensions.contains(&ext_lower.as_str());
        }
        
        // Vérification des patterns de noms de fichiers chiffrés
        let filename = file_path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        
        // Fichiers avec des noms aléatoires ou des patterns suspects
        if filename.len() > 20 && filename.chars().all(|c| c.is_ascii_alphanumeric()) {
            return true;
        }
        
        // Fichiers avec des extensions multiples suspectes
        if filename.matches('.').count() > 2 {
            return true;
        }
        
        false
    }

    /// Calcule l'entropie d'un fichier
    async fn calculate_file_entropy(file_path: &Path) -> Option<f64> {
        let mut file = match fs::File::open(file_path) {
            Ok(f) => f,
            Err(_) => return None,
        };
        
        let mut buffer = vec![0u8; 8192]; // 8KB buffer
        let mut byte_counts = [0u64; 256];
        let mut total_bytes = 0u64;
        
        // Lecture et comptage des bytes
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(bytes_read) => {
                    for &byte in &buffer[..bytes_read] {
                        byte_counts[byte as usize] += 1;
                        total_bytes += 1;
                    }
                    
                    // Limitation pour éviter les calculs trop longs
                    if total_bytes > 1024 * 1024 { // 1MB max
                        break;
                    }
                }
                Err(_) => return None,
            }
        }
        
        if total_bytes == 0 {
            return Some(0.0);
        }
        
        // Calcul de l'entropie de Shannon
        let mut entropy = 0.0;
        for &count in &byte_counts {
            if count > 0 {
                let probability = count as f64 / total_bytes as f64;
                entropy -= probability * probability.log2();
            }
        }
        
        Some(entropy)
    }

    /// Calcule le hash SHA-256 d'un fichier
    async fn calculate_file_hash(file_path: &Path) -> Option<String> {
        let mut file = match fs::File::open(file_path) {
            Ok(f) => f,
            Err(_) => return None,
        };
        
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 8192];
        let mut total_bytes = 0u64;
        
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(bytes_read) => {
                    hasher.update(&buffer[..bytes_read]);
                    total_bytes += bytes_read as u64;
                    
                    // Limitation pour éviter les calculs trop longs
                    if total_bytes > 10 * 1024 * 1024 { // 10MB max
                        break;
                    }
                }
                Err(_) => return None,
            }
        }
        
        let result = hasher.finalize();
        Some(format!("{:x}", result))
    }

    /// Obtient les informations du processus responsable d'une opération sur fichier
    async fn get_process_info_for_file(file_path: &Path) -> (u32, String) {
        // Cette fonction nécessiterait l'utilisation d'APIs Windows avancées
        // comme Process Monitor ou ETW pour tracer les opérations de fichiers
        // Pour l'instant, on retourne des valeurs par défaut
        
        // TODO: Implémenter la détection du processus via ETW ou autres APIs
        let current_process_id = std::process::id();
        let process_name = "unknown".to_string();
        
        (current_process_id, process_name)
    }

    /// Tâche de nettoyage périodique du cache
    async fn cache_cleanup_task(
        file_cache: Arc<Mutex<HashMap<PathBuf, FileMetadata>>>,
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
            
            // Nettoyage du cache
            {
                let mut cache = file_cache.lock().unwrap();
                let now = SystemTime::now();
                
                cache.retain(|path, metadata| {
                    // Suppression des entrées anciennes
                    if let Ok(age) = now.duration_since(metadata.modified) {
                        if age > max_age {
                            debug!("Removing old cache entry: {:?}", path);
                            return false;
                        }
                    }
                    
                    // Suppression des entrées pour fichiers inexistants
                    if !path.exists() {
                        debug!("Removing cache entry for deleted file: {:?}", path);
                        return false;
                    }
                    
                    true
                });
                
                debug!("Cache cleanup completed, {} entries remaining", cache.len());
            }
            
            // Attente avant le prochain nettoyage
            sleep(cleanup_interval).await;
        }
        
        debug!("Cache cleanup task stopped");
    }

    /// Obtient les statistiques de surveillance
    pub async fn get_statistics(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        // Statistiques du cache
        let cache = self.file_cache.lock().unwrap();
        stats.insert("cached_files_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(cache.len())));
        
        // Statistiques des handles actifs
        let handles = self.active_handles.lock().unwrap();
        stats.insert("active_handles_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(handles.len())));
        
        // Répertoires surveillés
        stats.insert("watched_directories_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(self.config.watched_directories.len())));
        
        // Configuration
        stats.insert("entropy_calculation_enabled".to_string(), 
                    serde_json::Value::Bool(self.config.entropy_calculation));
        stats.insert("hash_calculation_enabled".to_string(), 
                    serde_json::Value::Bool(self.config.hash_calculation));
        stats.insert("recursive_monitoring_enabled".to_string(), 
                    serde_json::Value::Bool(self.config.recursive_monitoring));
        
        stats
    }
}

// Tests unitaires

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;

    #[tokio::test]
    async fn test_entropy_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_entropy.txt");
        
        // Fichier avec entropie faible (répétitif)
        {
            let mut file = File::create(&file_path).unwrap();
            file.write_all(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        }
        
        let entropy = FileMonitor::calculate_file_entropy(&file_path).await;
        assert!(entropy.is_some());
        assert!(entropy.unwrap() < 2.0); // Entropie faible
        
        // Fichier avec entropie élevée (aléatoire)
        {
            let mut file = File::create(&file_path).unwrap();
            let random_data: Vec<u8> = (0..1000).map(|i| (i * 17 + 42) as u8).collect();
            file.write_all(&random_data).unwrap();
        }
        
        let entropy = FileMonitor::calculate_file_entropy(&file_path).await;
        assert!(entropy.is_some());
        assert!(entropy.unwrap() > 6.0); // Entropie élevée
    }

    #[tokio::test]
    async fn test_hash_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_hash.txt");
        
        {
            let mut file = File::create(&file_path).unwrap();
            file.write_all(b"Hello, World!").unwrap();
        }
        
        let hash = FileMonitor::calculate_file_hash(&file_path).await;
        assert!(hash.is_some());
        
        // Hash SHA-256 de "Hello, World!"
        let expected_hash = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
        assert_eq!(hash.unwrap(), expected_hash);
    }

    #[test]
    fn test_encryption_rename_detection() {
        assert!(FileMonitor::is_likely_encryption_rename(Path::new("document.txt.encrypted")));
        assert!(FileMonitor::is_likely_encryption_rename(Path::new("photo.jpg.locked")));
        assert!(FileMonitor::is_likely_encryption_rename(Path::new("file.docx.wannacry")));
        assert!(!FileMonitor::is_likely_encryption_rename(Path::new("document.txt")));
        assert!(!FileMonitor::is_likely_encryption_rename(Path::new("backup.bak")));
    }

    #[test]
    fn test_file_exclusion() {
        let config = FileMonitorConfig::default();
        
        // Fichiers à exclure
        assert!(FileMonitor::should_exclude_file(Path::new(r"C:\Windows\System32\kernel32.dll"), &config));
        assert!(FileMonitor::should_exclude_file(Path::new("document.tmp"), &config));
        assert!(FileMonitor::should_exclude_file(Path::new(".hidden_file"), &config));
        assert!(FileMonitor::should_exclude_file(Path::new("~temp_file"), &config));
        
        // Fichiers à inclure
        assert!(!FileMonitor::should_exclude_file(Path::new(r"C:\Users\user\document.docx"), &config));
        assert!(!FileMonitor::should_exclude_file(Path::new("important.pdf"), &config));
    }
}