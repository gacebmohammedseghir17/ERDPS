//! ERDPS Process Monitor
//!
//! Surveillance en temps réel des processus pour la détection de ransomwares
//! Utilise les APIs Windows pour surveiller les opérations sur les processus
//!
//! Fonctionnalités:
//! - Surveillance de création/terminaison de processus
//! - Détection d'injection de processus
//! - Surveillance des modifications de mémoire
//! - Détection de process hollowing
//! - Intégration avec le moteur de détection comportementale
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::detection::behavioral_engine::{ProcessEvent, ProcessOperation};

// Importation des APIs Windows
use winapi::um::winnt::{
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
    PROCESS_ALL_ACCESS,
    TOKEN_QUERY,
    TokenIntegrityLevel,
};
use winapi::um::processthreadsapi::{
    OpenProcess,
    GetCurrentProcessId,
    CreateToolhelp32Snapshot,
    Process32FirstW,
    Process32NextW,
    OpenProcessToken,
};
use winapi::um::tlhelp32::{
    TH32CS_SNAPPROCESS,
    PROCESSENTRY32W,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::psapi::{
    GetModuleFileNameExW,
    EnumProcessModules,
    GetModuleInformation,
    MODULEINFO,
};
use winapi::shared::minwindef::{HMODULE, DWORD, MAX_PATH};
use winapi::um::memoryapi::{VirtualQueryEx, ReadProcessMemory};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use std::ptr;
use std::mem;

// Configuration de surveillance des processus

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    pub monitor_process_creation: bool,
    pub monitor_process_termination: bool,
    pub monitor_process_injection: bool,
    pub monitor_memory_modifications: bool,
    pub monitor_dll_injection: bool,
    pub excluded_processes: Vec<String>,
    pub suspicious_process_names: Vec<String>,
    pub polling_interval_ms: u64,
    pub max_process_history: usize,
    pub injection_detection_threshold: u32,
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            monitor_process_creation: true,
            monitor_process_termination: true,
            monitor_process_injection: true,
            monitor_memory_modifications: true,
            monitor_dll_injection: true,
            excluded_processes: vec![
                "System".to_string(),
                "Registry".to_string(),
                "smss.exe".to_string(),
                "csrss.exe".to_string(),
                "wininit.exe".to_string(),
                "winlogon.exe".to_string(),
                "services.exe".to_string(),
                "lsass.exe".to_string(),
                "svchost.exe".to_string(),
                "spoolsv.exe".to_string(),
                "explorer.exe".to_string(),
                "dwm.exe".to_string(),
            ],
            suspicious_process_names: vec![
                "cmd.exe".to_string(),
                "powershell.exe".to_string(),
                "pwsh.exe".to_string(),
                "wscript.exe".to_string(),
                "cscript.exe".to_string(),
                "mshta.exe".to_string(),
                "rundll32.exe".to_string(),
                "regsvr32.exe".to_string(),
                "certutil.exe".to_string(),
                "bitsadmin.exe".to_string(),
            ],
            polling_interval_ms: 1000,
            max_process_history: 1000,
            injection_detection_threshold: 5,
        }
    }
}

// Structures de données pour les processus

#[derive(Debug, Clone)]
struct ProcessInfo {
    process_id: u32,
    parent_process_id: u32,
    process_name: String,
    executable_path: PathBuf,
    command_line: String,
    creation_time: SystemTime,
    user_context: String,
    integrity_level: String,
    modules: Vec<ModuleInfo>,
    memory_regions: Vec<MemoryRegion>,
    injection_count: u32,
    is_suspicious: bool,
}

#[derive(Debug, Clone)]
struct ModuleInfo {
    name: String,
    base_address: usize,
    size: u32,
    path: PathBuf,
}

#[derive(Debug, Clone)]
struct MemoryRegion {
    base_address: usize,
    size: usize,
    protection: u32,
    state: u32,
    is_executable: bool,
}

#[derive(Debug, Clone)]
struct InjectionEvent {
    source_process_id: u32,
    target_process_id: u32,
    injection_type: InjectionType,
    timestamp: SystemTime,
    details: String,
}

#[derive(Debug, Clone)]
enum InjectionType {
    DllInjection,
    ProcessHollowing,
    ThreadInjection,
    AtomBombing,
    ProcessDoppelganging,
    ManualDllMapping,
}

// Moniteur de processus principal

pub struct ProcessMonitor {
    config: ProcessMonitorConfig,
    event_sender: mpsc::UnboundedSender<ProcessEvent>,
    process_cache: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    injection_history: Arc<Mutex<Vec<InjectionEvent>>>,
    shutdown_signal: Arc<Mutex<bool>>,
}

impl ProcessMonitor {
    pub fn new(
        config: ProcessMonitorConfig,
        event_sender: mpsc::UnboundedSender<ProcessEvent>,
    ) -> Self {
        Self {
            config,
            event_sender,
            process_cache: Arc::new(Mutex::new(HashMap::new())),
            injection_history: Arc::new(Mutex::new(Vec::new())),
            shutdown_signal: Arc::new(Mutex::new(false)),
        }
    }

    /// Démarre la surveillance des processus
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting process monitoring...");
        
        // Initialisation du cache avec les processus existants
        self.initialize_process_cache().await?;
        
        // Démarrage de la surveillance principale
        let config_clone = self.config.clone();
        let event_sender_clone = self.event_sender.clone();
        let process_cache_clone = self.process_cache.clone();
        let injection_history_clone = self.injection_history.clone();
        let shutdown_signal_clone = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::monitor_processes(
                config_clone,
                event_sender_clone,
                process_cache_clone,
                injection_history_clone,
                shutdown_signal_clone,
            ).await;
        });
        
        // Démarrage de la surveillance d'injection
        if self.config.monitor_process_injection {
            let config_injection = self.config.clone();
            let process_cache_injection = self.process_cache.clone();
            let injection_history_injection = self.injection_history.clone();
            let event_sender_injection = self.event_sender.clone();
            let shutdown_injection = self.shutdown_signal.clone();
            
            tokio::spawn(async move {
                Self::monitor_injections(
                    config_injection,
                    process_cache_injection,
                    injection_history_injection,
                    event_sender_injection,
                    shutdown_injection,
                ).await;
            });
        }
        
        // Démarrage du nettoyage périodique
        let injection_cleanup = self.injection_history.clone();
        let shutdown_cleanup = self.shutdown_signal.clone();
        tokio::spawn(async move {
            Self::cleanup_task(injection_cleanup, shutdown_cleanup).await;
        });
        
        info!("Process monitoring started successfully");
        Ok(())
    }

    /// Arrête la surveillance des processus
    pub async fn stop(&self) {
        info!("Stopping process monitoring...");
        
        {
            let mut shutdown = self.shutdown_signal.lock().unwrap();
            *shutdown = true;
        }
        
        info!("Process monitoring stopped");
    }

    /// Initialise le cache avec les processus existants
    async fn initialize_process_cache(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Initializing process cache...");
        
        let processes = Self::enumerate_processes().await?;
        
        {
            let mut cache = self.process_cache.lock().unwrap();
            for process in processes {
                cache.insert(process.process_id, process);
            }
        }
        
        let cache_size = self.process_cache.lock().unwrap().len();
        info!("Process cache initialized with {} processes", cache_size);
        
        Ok(())
    }

    /// Surveillance principale des processus
    async fn monitor_processes(
        config: ProcessMonitorConfig,
        event_sender: mpsc::UnboundedSender<ProcessEvent>,
        process_cache: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
        injection_history: Arc<Mutex<Vec<InjectionEvent>>>,
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
            
            // Énumération des processus actuels
            match Self::enumerate_processes().await {
                Ok(current_processes) => {
                    let mut current_pids: HashMap<u32, ProcessInfo> = HashMap::new();
                    for process in current_processes {
                        current_pids.insert(process.process_id, process);
                    }
                    
                    // Comparaison avec le cache pour détecter les changements
                    {
                        let mut cache = process_cache.lock().unwrap();
                        
                        // Détection des nouveaux processus
                        for (pid, process_info) in &current_pids {
                            if !cache.contains_key(pid) {
                                debug!("New process detected: {} (PID: {})", process_info.process_name, pid);
                                
                                // Envoi de l'événement de création
                                if config.monitor_process_creation {
                                    let event = ProcessEvent {
                                        event_id: Uuid::new_v4(),
                                        timestamp: Utc::now(),
                                        process_id: *pid,
                                        parent_process_id: process_info.parent_process_id,
                                        process_name: process_info.process_name.clone(),
                                        command_line: process_info.command_line.clone(),
                                        executable_path: process_info.executable_path.clone(),
                                        operation: ProcessOperation::Create,
                                        user_context: process_info.user_context.clone(),
                                        integrity_level: process_info.integrity_level.clone(),
                                    };
                                    
                                    if let Err(e) = event_sender.send(event) {
                                        error!("Failed to send process creation event: {}", e);
                                    }
                                }
                                
                                cache.insert(*pid, process_info.clone());
                            }
                        }
                        
                        // Détection des processus terminés
                        let terminated_pids: Vec<u32> = cache.keys()
                            .filter(|pid| !current_pids.contains_key(pid))
                            .cloned()
                            .collect();
                        
                        for pid in terminated_pids {
                            if let Some(process_info) = cache.remove(&pid) {
                                debug!("Process terminated: {} (PID: {})", process_info.process_name, pid);
                                
                                // Envoi de l'événement de terminaison
                                if config.monitor_process_termination {
                                    let event = ProcessEvent {
                                        event_id: Uuid::new_v4(),
                                        timestamp: Utc::now(),
                                        process_id: pid,
                                        parent_process_id: process_info.parent_process_id,
                                        process_name: process_info.process_name.clone(),
                                        command_line: process_info.command_line.clone(),
                                        executable_path: process_info.executable_path.clone(),
                                        operation: ProcessOperation::Terminate,
                                        user_context: process_info.user_context.clone(),
                                        integrity_level: process_info.integrity_level.clone(),
                                    };
                                    
                                    if let Err(e) = event_sender.send(event) {
                                        error!("Failed to send process termination event: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to enumerate processes: {}", e);
                }
            }
            
            // Attente avant la prochaine itération
            sleep(Duration::from_millis(config.polling_interval_ms)).await;
        }
        
        debug!("Process monitoring loop stopped");
    }

    /// Surveillance des injections de processus
    async fn monitor_injections(
        config: ProcessMonitorConfig,
        process_cache: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
        injection_history: Arc<Mutex<Vec<InjectionEvent>>>,
        event_sender: mpsc::UnboundedSender<ProcessEvent>,
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
            
            // Analyse des processus pour détecter les injections
            {
                let cache = process_cache.lock().unwrap();
                for (pid, process_info) in cache.iter() {
                    if Self::should_exclude_process(&process_info.process_name, &config) {
                        continue;
                    }
                    
                    // Détection d'injection DLL
                    if config.monitor_dll_injection {
                        if let Some(injection) = Self::detect_dll_injection(*pid, process_info).await {
                            Self::handle_injection_detection(
                                injection,
                                &injection_history,
                                &event_sender,
                            ).await;
                        }
                    }
                    
                    // Détection de process hollowing
                    if let Some(injection) = Self::detect_process_hollowing(*pid, process_info).await {
                        Self::handle_injection_detection(
                            injection,
                            &injection_history,
                            &event_sender,
                        ).await;
                    }
                    
                    // Détection de modifications de mémoire suspectes
                    if config.monitor_memory_modifications {
                        if let Some(injection) = Self::detect_memory_modifications(*pid, process_info).await {
                            Self::handle_injection_detection(
                                injection,
                                &injection_history,
                                &event_sender,
                            ).await;
                        }
                    }
                }
            }
            
            // Attente avant la prochaine analyse
            sleep(Duration::from_millis(config.polling_interval_ms * 2)).await;
        }
        
        debug!("Injection monitoring loop stopped");
    }

    /// Énumère tous les processus du système
    async fn enumerate_processes() -> Result<Vec<ProcessInfo>, Box<dyn std::error::Error>> {
        let mut processes = Vec::new();
        
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err("Failed to create process snapshot".into());
            }
            
            let mut process_entry: PROCESSENTRY32W = mem::zeroed();
            process_entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
            
            if Process32FirstW(snapshot, &mut process_entry) != 0 {
                loop {
                    let process_name = String::from_utf16_lossy(
                        &process_entry.szExeFile[..process_entry.szExeFile.iter().position(|&x| x == 0).unwrap_or(process_entry.szExeFile.len())]
                    );
                    
                    let process_info = Self::get_detailed_process_info(
                        process_entry.th32ProcessID,
                        process_entry.th32ParentProcessID,
                        process_name,
                    ).await;
                    
                    if let Some(info) = process_info {
                        processes.push(info);
                    }
                    
                    if Process32NextW(snapshot, &mut process_entry) == 0 {
                        break;
                    }
                }
            }
            
            CloseHandle(snapshot);
        }
        
        Ok(processes)
    }

    /// Obtient les informations détaillées d'un processus
    async fn get_detailed_process_info(
        process_id: u32,
        parent_process_id: u32,
        process_name: String,
    ) -> Option<ProcessInfo> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id);
            if handle.is_null() {
                return None;
            }
            
            // Obtention du chemin de l'exécutable
            let mut exe_path = vec![0u16; MAX_PATH];
            let exe_path_len = GetModuleFileNameExW(
                handle,
                ptr::null_mut(),
                exe_path.as_mut_ptr(),
                MAX_PATH as u32,
            );
            
            let executable_path = if exe_path_len > 0 {
                PathBuf::from(String::from_utf16_lossy(&exe_path[..exe_path_len as usize]))
            } else {
                PathBuf::new()
            };
            
            // Obtention du niveau d'intégrité
            let integrity_level = Self::get_process_integrity_level(handle);
            
            // Obtention des modules
            let modules = Self::get_process_modules(handle).unwrap_or_default();
            
            // Obtention des régions mémoire
            let memory_regions = Self::get_process_memory_regions(handle).unwrap_or_default();
            
            CloseHandle(handle);
            
            Some(ProcessInfo {
                process_id,
                parent_process_id,
                process_name: process_name.clone(),
                executable_path,
                command_line: String::new(), // TODO: Obtenir la ligne de commande
                creation_time: SystemTime::now(),
                user_context: "Unknown".to_string(), // TODO: Obtenir le contexte utilisateur
                integrity_level,
                modules,
                memory_regions,
                injection_count: 0,
                is_suspicious: Self::is_suspicious_process(&process_name),
            })
        }
    }

    /// Obtient le niveau d'intégrité d'un processus
    fn get_process_integrity_level(process_handle: *mut std::ffi::c_void) -> String {
        unsafe {
            let mut token_handle = ptr::null_mut();
            if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle) == 0 {
                return "Unknown".to_string();
            }
            
            let mut token_info_length = 0;
            GetTokenInformation(
                token_handle,
                TokenIntegrityLevel,
                ptr::null_mut(),
                0,
                &mut token_info_length,
            );
            
            if token_info_length == 0 {
                CloseHandle(token_handle);
                return "Unknown".to_string();
            }
            
            let mut token_info = vec![0u8; token_info_length as usize];
            if GetTokenInformation(
                token_handle,
                TokenIntegrityLevel,
                token_info.as_mut_ptr() as *mut _,
                token_info_length,
                &mut token_info_length,
            ) == 0 {
                CloseHandle(token_handle);
                return "Unknown".to_string();
            }
            
            CloseHandle(token_handle);
            
            // Analyse du niveau d'intégrité (simplifié)
            "Medium".to_string() // TODO: Analyser correctement le token
        }
    }

    /// Obtient la liste des modules d'un processus
    fn get_process_modules(process_handle: *mut std::ffi::c_void) -> Result<Vec<ModuleInfo>, Box<dyn std::error::Error>> {
        let mut modules = Vec::new();
        
        unsafe {
            let mut module_handles = vec![ptr::null_mut(); 1024];
            let mut bytes_needed = 0;
            
            if EnumProcessModules(
                process_handle,
                module_handles.as_mut_ptr(),
                (module_handles.len() * mem::size_of::<HMODULE>()) as u32,
                &mut bytes_needed,
            ) == 0 {
                return Ok(modules);
            }
            
            let module_count = bytes_needed as usize / mem::size_of::<HMODULE>();
            
            for i in 0..module_count.min(module_handles.len()) {
                let module_handle = module_handles[i];
                if module_handle.is_null() {
                    continue;
                }
                
                // Nom du module
                let mut module_name = vec![0u16; MAX_PATH];
                let name_len = GetModuleFileNameExW(
                    process_handle,
                    module_handle,
                    module_name.as_mut_ptr(),
                    MAX_PATH as u32,
                );
                
                let name = if name_len > 0 {
                    String::from_utf16_lossy(&module_name[..name_len as usize])
                } else {
                    "Unknown".to_string()
                };
                
                // Informations du module
                let mut module_info: MODULEINFO = mem::zeroed();
                if GetModuleInformation(
                    process_handle,
                    module_handle,
                    &mut module_info,
                    mem::size_of::<MODULEINFO>() as u32,
                ) != 0 {
                    modules.push(ModuleInfo {
                        name: PathBuf::from(&name).file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        base_address: module_info.lpBaseOfDll as usize,
                        size: module_info.SizeOfImage,
                        path: PathBuf::from(name),
                    });
                }
            }
        }
        
        Ok(modules)
    }

    /// Obtient les régions mémoire d'un processus
    fn get_process_memory_regions(process_handle: *mut std::ffi::c_void) -> Result<Vec<MemoryRegion>, Box<dyn std::error::Error>> {
        let mut regions = Vec::new();
        let mut address = 0usize;
        
        unsafe {
            loop {
                let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
                let result = VirtualQueryEx(
                    process_handle,
                    address as *const _,
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                
                if result == 0 {
                    break;
                }
                
                if mbi.State == MEM_COMMIT {
                    regions.push(MemoryRegion {
                        base_address: mbi.BaseAddress as usize,
                        size: mbi.RegionSize,
                        protection: mbi.Protect,
                        state: mbi.State,
                        is_executable: (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0,
                    });
                }
                
                address = mbi.BaseAddress as usize + mbi.RegionSize;
                
                // Limitation pour éviter les boucles infinies
                if regions.len() > 1000 {
                    break;
                }
            }
        }
        
        Ok(regions)
    }

    /// Détecte l'injection de DLL
    async fn detect_dll_injection(process_id: u32, process_info: &ProcessInfo) -> Option<InjectionEvent> {
        // Heuristiques simples pour détecter l'injection de DLL
        
        // Vérification des modules suspects
        for module in &process_info.modules {
            if module.name.to_lowercase().contains("inject") ||
               module.name.to_lowercase().contains("hook") ||
               module.path.to_string_lossy().contains("temp") {
                return Some(InjectionEvent {
                    source_process_id: 0, // Inconnu
                    target_process_id: process_id,
                    injection_type: InjectionType::DllInjection,
                    timestamp: SystemTime::now(),
                    details: format!("Suspicious DLL detected: {}", module.name),
                });
            }
        }
        
        None
    }

    /// Détecte le process hollowing
    async fn detect_process_hollowing(process_id: u32, process_info: &ProcessInfo) -> Option<InjectionEvent> {
        // Vérification des régions mémoire exécutables suspectes
        let executable_regions: Vec<_> = process_info.memory_regions.iter()
            .filter(|region| region.is_executable)
            .collect();
        
        // Si trop de régions exécutables, c'est suspect
        if executable_regions.len() > 50 {
            return Some(InjectionEvent {
                source_process_id: 0,
                target_process_id: process_id,
                injection_type: InjectionType::ProcessHollowing,
                timestamp: SystemTime::now(),
                details: format!("Excessive executable memory regions: {}", executable_regions.len()),
            });
        }
        
        None
    }

    /// Détecte les modifications de mémoire suspectes
    async fn detect_memory_modifications(process_id: u32, process_info: &ProcessInfo) -> Option<InjectionEvent> {
        // Vérification des régions mémoire avec des protections suspectes
        for region in &process_info.memory_regions {
            if region.protection == PAGE_EXECUTE_READWRITE && region.size > 1024 * 1024 {
                return Some(InjectionEvent {
                    source_process_id: 0,
                    target_process_id: process_id,
                    injection_type: InjectionType::ThreadInjection,
                    timestamp: SystemTime::now(),
                    details: format!("Suspicious memory region: RWX protection, size: {} bytes", region.size),
                });
            }
        }
        
        None
    }

    /// Gère la détection d'une injection
    async fn handle_injection_detection(
        injection: InjectionEvent,
        injection_history: &Arc<Mutex<Vec<InjectionEvent>>>,
        event_sender: &mpsc::UnboundedSender<ProcessEvent>,
    ) {
        debug!("Injection detected: {:?}", injection);
        
        // Ajout à l'historique
        {
            let mut history = injection_history.lock().unwrap();
            history.push(injection.clone());
            
            // Limitation de la taille de l'historique
            if history.len() > 1000 {
                history.remove(0);
            }
        }
        
        // Création de l'événement de processus
        let operation = match injection.injection_type {
            InjectionType::DllInjection => ProcessOperation::InjectDll,
            InjectionType::ProcessHollowing => ProcessOperation::HollowProcess,
            InjectionType::ThreadInjection => ProcessOperation::InjectThread,
            _ => ProcessOperation::ModifyMemory,
        };
        
        let event = ProcessEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            process_id: injection.target_process_id,
            parent_process_id: 0,
            process_name: "Unknown".to_string(),
            command_line: String::new(),
            executable_path: PathBuf::new(),
            operation,
            user_context: "Unknown".to_string(),
            integrity_level: "Unknown".to_string(),
        };
        
        if let Err(e) = event_sender.send(event) {
            error!("Failed to send injection event: {}", e);
        }
    }

    /// Vérifie si un processus doit être exclu
    fn should_exclude_process(process_name: &str, config: &ProcessMonitorConfig) -> bool {
        config.excluded_processes.iter().any(|excluded| {
            process_name.to_lowercase().contains(&excluded.to_lowercase())
        })
    }

    /// Vérifie si un processus est suspect
    fn is_suspicious_process(process_name: &str) -> bool {
        let suspicious_patterns = [
            "temp", "tmp", "download", "appdata", "roaming",
            "programdata", "public", "users", "documents",
        ];
        
        suspicious_patterns.iter().any(|pattern| {
            process_name.to_lowercase().contains(pattern)
        })
    }

    /// Tâche de nettoyage périodique
    async fn cleanup_task(
        injection_history: Arc<Mutex<Vec<InjectionEvent>>>,
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
            
            // Nettoyage de l'historique d'injection
            {
                let mut history = injection_history.lock().unwrap();
                let now = SystemTime::now();
                
                history.retain(|injection| {
                    if let Ok(age) = now.duration_since(injection.timestamp) {
                        age <= max_age
                    } else {
                        true
                    }
                });
                
                debug!("Injection history cleanup completed, {} entries remaining", history.len());
            }
            
            sleep(cleanup_interval).await;
        }
        
        debug!("Process monitor cleanup task stopped");
    }

    /// Obtient les statistiques de surveillance
    pub async fn get_statistics(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        // Statistiques du cache de processus
        let cache = self.process_cache.lock().unwrap();
        stats.insert("monitored_processes_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(cache.len())));
        
        let suspicious_processes = cache.values().filter(|p| p.is_suspicious).count();
        stats.insert("suspicious_processes_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(suspicious_processes)));
        
        // Statistiques d'injection
        let history = self.injection_history.lock().unwrap();
        stats.insert("injection_events_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(history.len())));
        
        // Configuration
        stats.insert("process_creation_monitoring".to_string(), 
                    serde_json::Value::Bool(self.config.monitor_process_creation));
        stats.insert("injection_monitoring".to_string(), 
                    serde_json::Value::Bool(self.config.monitor_process_injection));
        stats.insert("memory_monitoring".to_string(), 
                    serde_json::Value::Bool(self.config.monitor_memory_modifications));
        
        stats
    }
}

// Tests unitaires

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_exclusion() {
        let config = ProcessMonitorConfig::default();
        
        assert!(ProcessMonitor::should_exclude_process("svchost.exe", &config));
        assert!(ProcessMonitor::should_exclude_process("System", &config));
        assert!(ProcessMonitor::should_exclude_process("csrss.exe", &config));
        assert!(!ProcessMonitor::should_exclude_process("notepad.exe", &config));
        assert!(!ProcessMonitor::should_exclude_process("malware.exe", &config));
    }

    #[test]
    fn test_suspicious_process_detection() {
        assert!(ProcessMonitor::is_suspicious_process("C:\\temp\\malware.exe"));
        assert!(ProcessMonitor::is_suspicious_process("download_file.exe"));
        assert!(ProcessMonitor::is_suspicious_process("appdata_process.exe"));
        assert!(!ProcessMonitor::is_suspicious_process("notepad.exe"));
        assert!(!ProcessMonitor::is_suspicious_process("chrome.exe"));
    }

    #[tokio::test]
    async fn test_process_monitor_creation() {
        let config = ProcessMonitorConfig::default();
        let (sender, _receiver) = mpsc::unbounded_channel();
        
        let monitor = ProcessMonitor::new(config, sender);
        assert!(!monitor.shutdown_signal.lock().unwrap().clone());
    }
}