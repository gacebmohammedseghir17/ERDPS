//! ERDPS Agent - Point d'entrée principal
//!
//! Agent de protection contre les ransomwares pour Windows
//! Surveillance en temps réel et détection comportementale
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use std::env;
use std::path::PathBuf;
use std::process;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod agent;
mod config;
mod monitoring;
mod detection;
mod communication;
mod utils;

use agent::{ERDPSAgent, ERDPSAgentConfig};
use config::AgentConfig;

// Configuration par défaut
const DEFAULT_CONFIG_PATH: &str = "config/agent.toml";
const DEFAULT_LOG_LEVEL: &str = "INFO";
const SERVICE_NAME: &str = "ERDPSAgent";

#[tokio::main]
async fn main() {
    // Initialisation du logging
    if let Err(e) = initialize_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        process::exit(1);
    }
    
    info!("Starting ERDPS Agent v1.0.0");
    info!("Enterprise Ransomware Detection and Prevention System");
    info!("Copyright (c) 2024 ERDPS Security Team");
    
    // Vérification des privilèges administrateur
    if !is_running_as_admin() {
        error!("ERDPS Agent requires administrator privileges to function properly");
        error!("Please run as administrator or install as a Windows service");
        process::exit(1);
    }
    
    // Parsing des arguments de ligne de commande
    let args = parse_command_line_args();
    
    // Chargement de la configuration
    let config = match load_configuration(&args.config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };
    
    // Validation de la configuration
    if let Err(e) = validate_configuration(&config) {
        error!("Configuration validation failed: {}", e);
        process::exit(1);
    }
    
    // Création et démarrage de l'agent
    let mut agent = ERDPSAgent::new(config);
    
    // Gestion des signaux système
    let shutdown_signal = setup_signal_handlers();
    
    // Démarrage de l'agent
    if let Err(e) = agent.start().await {
        error!("Failed to start ERDPS Agent: {}", e);
        process::exit(1);
    }
    
    info!("ERDPS Agent started successfully");
    info!("Agent ID: {}", agent.get_status().agent_id);
    info!("Press Ctrl+C to stop the agent");
    
    // Attente du signal d'arrêt
    shutdown_signal.await;
    
    info!("Shutdown signal received, stopping ERDPS Agent...");
    
    // Arrêt propre de l'agent
    agent.stop().await;
    
    info!("ERDPS Agent stopped successfully");
}

// Structure pour les arguments de ligne de commande
#[derive(Debug)]
struct CommandLineArgs {
    config_path: PathBuf,
    log_level: String,
    service_mode: bool,
    install_service: bool,
    uninstall_service: bool,
    start_service: bool,
    stop_service: bool,
}

/// Parse les arguments de ligne de commande
fn parse_command_line_args() -> CommandLineArgs {
    let args: Vec<String> = env::args().collect();
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut log_level = DEFAULT_LOG_LEVEL.to_string();
    let mut service_mode = false;
    let mut install_service = false;
    let mut uninstall_service = false;
    let mut start_service = false;
    let mut stop_service = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    config_path = PathBuf::from(&args[i + 1]);
                    i += 1;
                } else {
                    eprintln!("Error: --config requires a path argument");
                    print_usage_and_exit();
                }
            }
            "--log-level" | "-l" => {
                if i + 1 < args.len() {
                    log_level = args[i + 1].clone();
                    i += 1;
                } else {
                    eprintln!("Error: --log-level requires a level argument");
                    print_usage_and_exit();
                }
            }
            "--service" => {
                service_mode = true;
            }
            "--install-service" => {
                install_service = true;
            }
            "--uninstall-service" => {
                uninstall_service = true;
            }
            "--start-service" => {
                start_service = true;
            }
            "--stop-service" => {
                stop_service = true;
            }
            "--help" | "-h" => {
                print_usage_and_exit();
            }
            "--version" | "-v" => {
                println!("ERDPS Agent v1.0.0");
                process::exit(0);
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                print_usage_and_exit();
            }
        }
        i += 1;
    }
    
    // Gestion des commandes de service
    if install_service {
        install_windows_service();
        process::exit(0);
    }
    
    if uninstall_service {
        uninstall_windows_service();
        process::exit(0);
    }
    
    if start_service {
        start_windows_service();
        process::exit(0);
    }
    
    if stop_service {
        stop_windows_service();
        process::exit(0);
    }
    
    CommandLineArgs {
        config_path,
        log_level,
        service_mode,
        install_service,
        uninstall_service,
        start_service,
        stop_service,
    }
}

/// Affiche l'aide et quitte
fn print_usage_and_exit() {
    println!("ERDPS Agent v1.0.0 - Enterprise Ransomware Detection and Prevention System");
    println!();
    println!("USAGE:");
    println!("    erdps-agent.exe [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    -c, --config <PATH>        Configuration file path [default: config/agent.toml]");
    println!("    -l, --log-level <LEVEL>    Log level (TRACE, DEBUG, INFO, WARN, ERROR) [default: INFO]");
    println!("    --service                  Run in service mode");
    println!("    --install-service          Install as Windows service");
    println!("    --uninstall-service        Uninstall Windows service");
    println!("    --start-service            Start Windows service");
    println!("    --stop-service             Stop Windows service");
    println!("    -h, --help                 Print this help message");
    println!("    -v, --version              Print version information");
    println!();
    println!("EXAMPLES:");
    println!("    erdps-agent.exe                                    # Run in console mode");
    println!("    erdps-agent.exe --config custom-config.toml       # Use custom config");
    println!("    erdps-agent.exe --install-service                 # Install as service");
    println!("    erdps-agent.exe --log-level DEBUG                 # Enable debug logging");
    println!();
    process::exit(0);
}

/// Initialise le système de logging
fn initialize_logging() -> Result<(), Box<dyn std::error::Error>> {
    let log_level = env::var("ERDPS_LOG_LEVEL")
        .unwrap_or_else(|_| DEFAULT_LOG_LEVEL.to_string());
    
    let level = match log_level.to_uppercase().as_str() {
        "TRACE" => tracing::Level::TRACE,
        "DEBUG" => tracing::Level::DEBUG,
        "INFO" => tracing::Level::INFO,
        "WARN" => tracing::Level::WARN,
        "ERROR" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    
    // Configuration du logging vers fichier et console
    let file_appender = tracing_appender::rolling::daily("logs", "erdps-agent.log");
    let (non_blocking_file, _guard) = tracing_appender::non_blocking(file_appender);
    
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_level(true)
                .with_ansi(true)
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking_file)
                .with_target(true)
                .with_thread_ids(true)
                .with_level(true)
                .with_ansi(false)
        )
        .with(tracing_subscriber::filter::LevelFilter::from_level(level))
        .init();
    
    Ok(())
}

/// Vérifie si l'application s'exécute avec des privilèges administrateur
fn is_running_as_admin() -> bool {
    #[cfg(windows)]
    {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{
            TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY, HANDLE,
        };
        use std::mem;
        use std::ptr;
        
        unsafe {
            let mut token: HANDLE = ptr::null_mut();
            let process = GetCurrentProcess();
            
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut size = mem::size_of::<TOKEN_ELEVATION>() as u32;
            
            let result = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                size,
                &mut size,
            );
            
            CloseHandle(token);
            
            result != 0 && elevation.TokenIsElevated != 0
        }
    }
    
    #[cfg(not(windows))]
    {
        // Sur les systèmes non-Windows, on assume que c'est OK
        true
    }
}

/// Charge la configuration depuis le fichier
fn load_configuration(config_path: &PathBuf) -> Result<ERDPSAgentConfig, Box<dyn std::error::Error>> {
    info!("Loading configuration from: {:?}", config_path);
    
    if !config_path.exists() {
        warn!("Configuration file not found, creating default configuration");
        let default_config = ERDPSAgentConfig::default();
        
        // Création du répertoire de configuration si nécessaire
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        // Sauvegarde de la configuration par défaut
        let config_content = toml::to_string_pretty(&default_config)?;
        std::fs::write(config_path, config_content)?;
        
        info!("Default configuration created at: {:?}", config_path);
        return Ok(default_config);
    }
    
    // Lecture du fichier de configuration
    let config_content = std::fs::read_to_string(config_path)?;
    let config: ERDPSAgentConfig = toml::from_str(&config_content)?;
    
    info!("Configuration loaded successfully");
    Ok(config)
}

/// Valide la configuration
fn validate_configuration(config: &ERDPSAgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Validation de l'ID de l'agent
    if config.agent_id.is_empty() {
        return Err("Agent ID cannot be empty".into());
    }
    
    // Validation de l'endpoint du serveur
    if config.server_endpoint.is_empty() {
        return Err("Server endpoint cannot be empty".into());
    }
    
    // Validation des intervalles
    if config.reporting_interval_seconds == 0 {
        return Err("Reporting interval must be greater than 0".into());
    }
    
    if config.heartbeat_interval_seconds == 0 {
        return Err("Heartbeat interval must be greater than 0".into());
    }
    
    // Validation du niveau de log
    match config.log_level.to_uppercase().as_str() {
        "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR" => {},
        _ => return Err(format!("Invalid log level: {}", config.log_level).into()),
    }
    
    // Validation que au moins un module de surveillance est activé
    if !config.enable_file_monitoring &&
       !config.enable_process_monitoring &&
       !config.enable_network_monitoring &&
       !config.enable_registry_monitoring {
        return Err("At least one monitoring module must be enabled".into());
    }
    
    info!("Configuration validation passed");
    Ok(())
}

/// Configure les gestionnaires de signaux système
async fn setup_signal_handlers() {
    #[cfg(windows)]
    {
        // Sur Windows, on écoute Ctrl+C
        if let Err(e) = signal::ctrl_c().await {
            error!("Failed to listen for Ctrl+C signal: {}", e);
        }
    }
    
    #[cfg(unix)]
    {
        use signal::{unix::SignalKind, unix::signal};
        
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT");
            }
        }
    }
}

/// Installe l'agent comme service Windows
fn install_windows_service() {
    #[cfg(windows)]
    {
        use std::process::Command;
        
        info!("Installing ERDPS Agent as Windows service...");
        
        let exe_path = env::current_exe().unwrap_or_else(|_| {
            PathBuf::from("erdps-agent.exe")
        });
        
        let output = Command::new("sc")
            .args([
                "create",
                SERVICE_NAME,
                &format!("binPath= \"{}\" --service", exe_path.display()),
                "start= auto",
                "DisplayName= ERDPS Agent",
                "description= Enterprise Ransomware Detection and Prevention System Agent",
            ])
            .output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    info!("Service installed successfully");
                    info!("Use 'sc start {}' to start the service", SERVICE_NAME);
                } else {
                    error!("Failed to install service: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => {
                error!("Failed to execute sc command: {}", e);
            }
        }
    }
    
    #[cfg(not(windows))]
    {
        error!("Service installation is only supported on Windows");
    }
}

/// Désinstalle le service Windows
fn uninstall_windows_service() {
    #[cfg(windows)]
    {
        use std::process::Command;
        
        info!("Uninstalling ERDPS Agent Windows service...");
        
        let output = Command::new("sc")
            .args(["delete", SERVICE_NAME])
            .output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    info!("Service uninstalled successfully");
                } else {
                    error!("Failed to uninstall service: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => {
                error!("Failed to execute sc command: {}", e);
            }
        }
    }
    
    #[cfg(not(windows))]
    {
        error!("Service management is only supported on Windows");
    }
}

/// Démarre le service Windows
fn start_windows_service() {
    #[cfg(windows)]
    {
        use std::process::Command;
        
        info!("Starting ERDPS Agent Windows service...");
        
        let output = Command::new("sc")
            .args(["start", SERVICE_NAME])
            .output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    info!("Service started successfully");
                } else {
                    error!("Failed to start service: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => {
                error!("Failed to execute sc command: {}", e);
            }
        }
    }
    
    #[cfg(not(windows))]
    {
        error!("Service management is only supported on Windows");
    }
}

/// Arrête le service Windows
fn stop_windows_service() {
    #[cfg(windows)]
    {
        use std::process::Command;
        
        info!("Stopping ERDPS Agent Windows service...");
        
        let output = Command::new("sc")
            .args(["stop", SERVICE_NAME])
            .output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    info!("Service stopped successfully");
                } else {
                    error!("Failed to stop service: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => {
                error!("Failed to execute sc command: {}", e);
            }
        }
    }
    
    #[cfg(not(windows))]
    {
        error!("Service management is only supported on Windows");
    }
}

// Tests unitaires

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_command_line_parsing() {
        // Test de parsing des arguments - à implémenter
        assert!(true);
    }
    
    #[test]
    fn test_configuration_validation() {
        let mut config = ERDPSAgentConfig::default();
        assert!(validate_configuration(&config).is_ok());
        
        // Test avec agent_id vide
        config.agent_id = String::new();
        assert!(validate_configuration(&config).is_err());
    }
    
    #[test]
    fn test_log_level_validation() {
        let mut config = ERDPSAgentConfig::default();
        
        config.log_level = "INFO".to_string();
        assert!(validate_configuration(&config).is_ok());
        
        config.log_level = "INVALID".to_string();
        assert!(validate_configuration(&config).is_err());
    }
}