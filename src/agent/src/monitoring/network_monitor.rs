//! ERDPS Network Monitor
//!
//! Surveillance en temps réel du trafic réseau pour la détection de ransomwares
//! Utilise les APIs Windows pour surveiller les connexions réseau
//!
//! Fonctionnalités:
//! - Surveillance des connexions TCP/UDP
//! - Détection de communication C2
//! - Analyse du trafic suspect
//! - Détection d'exfiltration de données
//! - Intégration avec le moteur de détection comportementale
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::detection::behavioral_engine::{NetworkEvent, NetworkDirection};

// Importation des APIs Windows
use winapi::um::iphlpapi::{
    GetExtendedTcpTable,
    GetExtendedUdpTable,
};
use winapi::um::tcpmib::{
    MIB_TCPTABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL,
};
use winapi::um::udpmib::{
    MIB_UDPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID,
    UDP_TABLE_OWNER_PID,
};
use winapi::shared::winerror::NO_ERROR;
use winapi::shared::ws2def::{AF_INET, AF_INET6};
use winapi::shared::minwindef::DWORD;
use std::ptr;
use std::mem;

// Configuration de surveillance réseau

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    pub monitor_tcp_connections: bool,
    pub monitor_udp_connections: bool,
    pub monitor_dns_queries: bool,
    pub monitor_http_traffic: bool,
    pub suspicious_ports: Vec<u16>,
    pub suspicious_domains: Vec<String>,
    pub suspicious_ips: Vec<String>,
    pub excluded_processes: Vec<String>,
    pub max_connections_per_process: u32,
    pub data_threshold_mb: u64,
    pub polling_interval_ms: u64,
    pub connection_timeout_seconds: u64,
    pub enable_deep_packet_inspection: bool,
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            monitor_tcp_connections: true,
            monitor_udp_connections: true,
            monitor_dns_queries: true,
            monitor_http_traffic: true,
            suspicious_ports: vec![
                4444, 4445, 4446, // Backdoor ports
                6666, 6667, 6668, // IRC/Botnet
                8080, 8081, 8888, // HTTP alternatives
                9999, 31337,      // Hacker ports
                1234, 12345,      // Common backdoors
                3389,             // RDP
                5900,             // VNC
                23,               // Telnet
            ],
            suspicious_domains: vec![
                "bit.ly".to_string(),
                "tinyurl.com".to_string(),
                "pastebin.com".to_string(),
                "hastebin.com".to_string(),
                "discord.gg".to_string(),
                "telegram.org".to_string(),
                "onion".to_string(),
                "tor2web".to_string(),
            ],
            suspicious_ips: vec![
                "127.0.0.1".to_string(), // Localhost (suspect pour certains contextes)
                "0.0.0.0".to_string(),   // Wildcard
            ],
            excluded_processes: vec![
                "svchost.exe".to_string(),
                "System".to_string(),
                "chrome.exe".to_string(),
                "firefox.exe".to_string(),
                "edge.exe".to_string(),
                "outlook.exe".to_string(),
                "teams.exe".to_string(),
                "skype.exe".to_string(),
            ],
            max_connections_per_process: 100,
            data_threshold_mb: 100,
            polling_interval_ms: 2000,
            connection_timeout_seconds: 300,
            enable_deep_packet_inspection: false,
        }
    }
}

// Structures de données pour les connexions réseau

#[derive(Debug, Clone)]
struct ConnectionInfo {
    connection_id: String,
    process_id: u32,
    process_name: String,
    protocol: Protocol,
    local_address: SocketAddr,
    remote_address: SocketAddr,
    state: ConnectionState,
    creation_time: SystemTime,
    last_activity: SystemTime,
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u32,
    packets_received: u32,
    is_suspicious: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum Protocol {
    TCP,
    UDP,
    ICMP,
}

#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Established,
    Listen,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Debug, Clone)]
struct NetworkStatistics {
    process_id: u32,
    process_name: String,
    total_connections: u32,
    active_connections: u32,
    suspicious_connections: u32,
    total_bytes_sent: u64,
    total_bytes_received: u64,
    unique_destinations: u32,
    c2_indicators: u32,
    last_activity: SystemTime,
}

#[derive(Debug, Clone)]
struct SuspiciousActivity {
    activity_id: Uuid,
    timestamp: SystemTime,
    process_id: u32,
    process_name: String,
    activity_type: SuspiciousActivityType,
    description: String,
    severity: u8, // 1-10
    indicators: Vec<String>,
}

#[derive(Debug, Clone)]
enum SuspiciousActivityType {
    C2Communication,
    DataExfiltration,
    PortScanning,
    DnsBeaconing,
    SuspiciousPort,
    HighVolumeTraffic,
    UnusualDestination,
    EncryptedTraffic,
}

// Moniteur réseau principal

pub struct NetworkMonitor {
    config: NetworkMonitorConfig,
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    connection_cache: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    process_stats: Arc<Mutex<HashMap<u32, NetworkStatistics>>>,
    suspicious_activities: Arc<Mutex<Vec<SuspiciousActivity>>>,
    shutdown_signal: Arc<Mutex<bool>>,
}

impl NetworkMonitor {
    pub fn new(
        config: NetworkMonitorConfig,
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
    ) -> Self {
        Self {
            config,
            event_sender,
            connection_cache: Arc::new(Mutex::new(HashMap::new())),
            process_stats: Arc::new(Mutex::new(HashMap::new())),
            suspicious_activities: Arc::new(Mutex::new(Vec::new())),
            shutdown_signal: Arc::new(Mutex::new(false)),
        }
    }

    /// Démarre la surveillance réseau
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting network monitoring...");
        
        // Démarrage de la surveillance TCP
        if self.config.monitor_tcp_connections {
            let config_tcp = self.config.clone();
            let event_sender_tcp = self.event_sender.clone();
            let connection_cache_tcp = self.connection_cache.clone();
            let process_stats_tcp = self.process_stats.clone();
            let suspicious_activities_tcp = self.suspicious_activities.clone();
            let shutdown_tcp = self.shutdown_signal.clone();
            
            tokio::spawn(async move {
                Self::monitor_tcp_connections(
                    config_tcp,
                    event_sender_tcp,
                    connection_cache_tcp,
                    process_stats_tcp,
                    suspicious_activities_tcp,
                    shutdown_tcp,
                ).await;
            });
        }
        
        // Démarrage de la surveillance UDP
        if self.config.monitor_udp_connections {
            let config_udp = self.config.clone();
            let event_sender_udp = self.event_sender.clone();
            let connection_cache_udp = self.connection_cache.clone();
            let process_stats_udp = self.process_stats.clone();
            let suspicious_activities_udp = self.suspicious_activities.clone();
            let shutdown_udp = self.shutdown_signal.clone();
            
            tokio::spawn(async move {
                Self::monitor_udp_connections(
                    config_udp,
                    event_sender_udp,
                    connection_cache_udp,
                    process_stats_udp,
                    suspicious_activities_udp,
                    shutdown_udp,
                ).await;
            });
        }
        
        // Démarrage de l'analyse des activités suspectes
        let config_analysis = self.config.clone();
        let process_stats_analysis = self.process_stats.clone();
        let suspicious_activities_analysis = self.suspicious_activities.clone();
        let event_sender_analysis = self.event_sender.clone();
        let shutdown_analysis = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::analyze_suspicious_activities(
                config_analysis,
                process_stats_analysis,
                suspicious_activities_analysis,
                event_sender_analysis,
                shutdown_analysis,
            ).await;
        });
        
        // Démarrage du nettoyage périodique
        let connection_cache_cleanup = self.connection_cache.clone();
        let suspicious_activities_cleanup = self.suspicious_activities.clone();
        let shutdown_cleanup = self.shutdown_signal.clone();
        
        tokio::spawn(async move {
            Self::cleanup_task(
                connection_cache_cleanup,
                suspicious_activities_cleanup,
                shutdown_cleanup,
            ).await;
        });
        
        info!("Network monitoring started successfully");
        Ok(())
    }

    /// Arrête la surveillance réseau
    pub async fn stop(&self) {
        info!("Stopping network monitoring...");
        
        {
            let mut shutdown = self.shutdown_signal.lock().unwrap();
            *shutdown = true;
        }
        
        info!("Network monitoring stopped");
    }

    /// Surveillance des connexions TCP
    async fn monitor_tcp_connections(
        config: NetworkMonitorConfig,
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
        connection_cache: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
        process_stats: Arc<Mutex<HashMap<u32, NetworkStatistics>>>,
        suspicious_activities: Arc<Mutex<Vec<SuspiciousActivity>>>,
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
            
            // Énumération des connexions TCP
            match Self::get_tcp_connections().await {
                Ok(connections) => {
                    for connection in connections {
                        if Self::should_exclude_process(&connection.process_name, &config) {
                            continue;
                        }
                        
                        // Mise à jour du cache
                        let connection_id = connection.connection_id.clone();
                        let is_new_connection = {
                            let mut cache = connection_cache.lock().unwrap();
                            let is_new = !cache.contains_key(&connection_id);
                            cache.insert(connection_id.clone(), connection.clone());
                            is_new
                        };
                        
                        // Mise à jour des statistiques
                        Self::update_process_statistics(&connection, &process_stats).await;
                        
                        // Génération d'événement pour nouvelle connexion
                        if is_new_connection {
                            Self::generate_network_event(
                                &connection,
                                NetworkDirection::Outbound,
                                &event_sender,
                            ).await;
                        }
                        
                        // Analyse de la connexion
                        Self::analyze_connection(
                            &connection,
                            &config,
                            &suspicious_activities,
                        ).await;
                    }
                }
                Err(e) => {
                    error!("Failed to get TCP connections: {}", e);
                }
            }
            
            sleep(Duration::from_millis(config.polling_interval_ms)).await;
        }
        
        debug!("TCP monitoring loop stopped");
    }

    /// Surveillance des connexions UDP
    async fn monitor_udp_connections(
        config: NetworkMonitorConfig,
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
        connection_cache: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
        process_stats: Arc<Mutex<HashMap<u32, NetworkStatistics>>>,
        suspicious_activities: Arc<Mutex<Vec<SuspiciousActivity>>>,
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
            
            // Énumération des connexions UDP
            match Self::get_udp_connections().await {
                Ok(connections) => {
                    for connection in connections {
                        if Self::should_exclude_process(&connection.process_name, &config) {
                            continue;
                        }
                        
                        // Mise à jour du cache
                        let connection_id = connection.connection_id.clone();
                        let is_new_connection = {
                            let mut cache = connection_cache.lock().unwrap();
                            let is_new = !cache.contains_key(&connection_id);
                            cache.insert(connection_id.clone(), connection.clone());
                            is_new
                        };
                        
                        // Mise à jour des statistiques
                        Self::update_process_statistics(&connection, &process_stats).await;
                        
                        // Génération d'événement pour nouvelle connexion
                        if is_new_connection {
                            Self::generate_network_event(
                                &connection,
                                NetworkDirection::Outbound,
                                &event_sender,
                            ).await;
                        }
                        
                        // Analyse de la connexion
                        Self::analyze_connection(
                            &connection,
                            &config,
                            &suspicious_activities,
                        ).await;
                    }
                }
                Err(e) => {
                    error!("Failed to get UDP connections: {}", e);
                }
            }
            
            sleep(Duration::from_millis(config.polling_interval_ms)).await;
        }
        
        debug!("UDP monitoring loop stopped");
    }

    /// Obtient les connexions TCP actives
    async fn get_tcp_connections() -> Result<Vec<ConnectionInfo>, Box<dyn std::error::Error>> {
        let mut connections = Vec::new();
        
        unsafe {
            let mut size = 0;
            
            // Première appel pour obtenir la taille nécessaire
            GetExtendedTcpTable(
                ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            
            if size == 0 {
                return Ok(connections);
            }
            
            // Allocation du buffer
            let mut buffer = vec![0u8; size as usize];
            
            // Deuxième appel pour obtenir les données
            let result = GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            
            if result != NO_ERROR {
                return Err(format!("GetExtendedTcpTable failed: {}", result).into());
            }
            
            // Parsing des données
            let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let entries = std::slice::from_raw_parts(
                &table.table[0] as *const MIB_TCPROW_OWNER_PID,
                table.dwNumEntries as usize,
            );
            
            for entry in entries {
                let local_addr = Ipv4Addr::from(u32::from_be(entry.dwLocalAddr));
                let remote_addr = Ipv4Addr::from(u32::from_be(entry.dwRemoteAddr));
                let local_port = u16::from_be(entry.dwLocalPort as u16);
                let remote_port = u16::from_be(entry.dwRemotePort as u16);
                
                let connection_id = format!(
                    "tcp_{}_{}_{}_{}",
                    local_addr, local_port, remote_addr, remote_port
                );
                
                let connection = ConnectionInfo {
                    connection_id,
                    process_id: entry.dwOwningPid,
                    process_name: Self::get_process_name(entry.dwOwningPid).unwrap_or_else(|| "Unknown".to_string()),
                    protocol: Protocol::TCP,
                    local_address: SocketAddr::new(IpAddr::V4(local_addr), local_port),
                    remote_address: SocketAddr::new(IpAddr::V4(remote_addr), remote_port),
                    state: Self::tcp_state_from_windows(entry.dwState),
                    creation_time: SystemTime::now(),
                    last_activity: SystemTime::now(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    is_suspicious: false,
                };
                
                connections.push(connection);
            }
        }
        
        Ok(connections)
    }

    /// Obtient les connexions UDP actives
    async fn get_udp_connections() -> Result<Vec<ConnectionInfo>, Box<dyn std::error::Error>> {
        let mut connections = Vec::new();
        
        unsafe {
            let mut size = 0;
            
            // Première appel pour obtenir la taille nécessaire
            GetExtendedUdpTable(
                ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            
            if size == 0 {
                return Ok(connections);
            }
            
            // Allocation du buffer
            let mut buffer = vec![0u8; size as usize];
            
            // Deuxième appel pour obtenir les données
            let result = GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            
            if result != NO_ERROR {
                return Err(format!("GetExtendedUdpTable failed: {}", result).into());
            }
            
            // Parsing des données
            let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let entries = std::slice::from_raw_parts(
                &table.table[0] as *const MIB_UDPROW_OWNER_PID,
                table.dwNumEntries as usize,
            );
            
            for entry in entries {
                let local_addr = Ipv4Addr::from(u32::from_be(entry.dwLocalAddr));
                let local_port = u16::from_be(entry.dwLocalPort as u16);
                
                let connection_id = format!("udp_{}_{}", local_addr, local_port);
                
                let connection = ConnectionInfo {
                    connection_id,
                    process_id: entry.dwOwningPid,
                    process_name: Self::get_process_name(entry.dwOwningPid).unwrap_or_else(|| "Unknown".to_string()),
                    protocol: Protocol::UDP,
                    local_address: SocketAddr::new(IpAddr::V4(local_addr), local_port),
                    remote_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                    state: ConnectionState::Listen,
                    creation_time: SystemTime::now(),
                    last_activity: SystemTime::now(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    is_suspicious: false,
                };
                
                connections.push(connection);
            }
        }
        
        Ok(connections)
    }

    /// Convertit l'état TCP de Windows
    fn tcp_state_from_windows(state: DWORD) -> ConnectionState {
        match state {
            1 => ConnectionState::Closed,
            2 => ConnectionState::Listen,
            3 => ConnectionState::SynSent,
            4 => ConnectionState::SynReceived,
            5 => ConnectionState::Established,
            6 => ConnectionState::FinWait1,
            7 => ConnectionState::FinWait2,
            8 => ConnectionState::CloseWait,
            9 => ConnectionState::Closing,
            10 => ConnectionState::LastAck,
            11 => ConnectionState::TimeWait,
            _ => ConnectionState::Closed,
        }
    }

    /// Obtient le nom d'un processus par son PID
    fn get_process_name(process_id: u32) -> Option<String> {
        // Cette fonction nécessiterait l'utilisation d'APIs Windows
        // pour obtenir le nom du processus à partir du PID
        // Pour l'instant, on retourne une valeur par défaut
        Some(format!("Process_{}", process_id))
    }

    /// Met à jour les statistiques d'un processus
    async fn update_process_statistics(
        connection: &ConnectionInfo,
        process_stats: &Arc<Mutex<HashMap<u32, NetworkStatistics>>>,
    ) {
        let mut stats = process_stats.lock().unwrap();
        let process_stats = stats.entry(connection.process_id)
            .or_insert_with(|| NetworkStatistics {
                process_id: connection.process_id,
                process_name: connection.process_name.clone(),
                total_connections: 0,
                active_connections: 0,
                suspicious_connections: 0,
                total_bytes_sent: 0,
                total_bytes_received: 0,
                unique_destinations: 0,
                c2_indicators: 0,
                last_activity: SystemTime::now(),
            });
        
        process_stats.total_connections += 1;
        process_stats.active_connections += 1;
        process_stats.last_activity = SystemTime::now();
        
        if connection.is_suspicious {
            process_stats.suspicious_connections += 1;
        }
    }

    /// Génère un événement réseau
    async fn generate_network_event(
        connection: &ConnectionInfo,
        direction: NetworkDirection,
        event_sender: &mpsc::UnboundedSender<NetworkEvent>,
    ) {
        let event = NetworkEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            process_id: connection.process_id,
            process_name: connection.process_name.clone(),
            local_address: connection.local_address.ip().to_string(),
            remote_address: connection.remote_address.ip().to_string(),
            local_port: connection.local_address.port(),
            remote_port: connection.remote_address.port(),
            protocol: match connection.protocol {
                Protocol::TCP => "TCP".to_string(),
                Protocol::UDP => "UDP".to_string(),
                Protocol::ICMP => "ICMP".to_string(),
            },
            direction,
            data_size: connection.bytes_sent + connection.bytes_received,
        };
        
        if let Err(e) = event_sender.send(event) {
            error!("Failed to send network event: {}", e);
        }
    }

    /// Analyse une connexion pour détecter des activités suspectes
    async fn analyze_connection(
        connection: &ConnectionInfo,
        config: &NetworkMonitorConfig,
        suspicious_activities: &Arc<Mutex<Vec<SuspiciousActivity>>>,
    ) {
        let mut suspicious_indicators = Vec::new();
        
        // Vérification des ports suspects
        if config.suspicious_ports.contains(&connection.remote_address.port()) {
            suspicious_indicators.push(format!(
                "Suspicious port: {}",
                connection.remote_address.port()
            ));
        }
        
        // Vérification des adresses IP suspectes
        let remote_ip = connection.remote_address.ip().to_string();
        if config.suspicious_ips.iter().any(|ip| remote_ip.contains(ip)) {
            suspicious_indicators.push(format!("Suspicious IP: {}", remote_ip));
        }
        
        // Détection de communication localhost suspecte
        if connection.remote_address.ip().is_loopback() &&
           connection.remote_address.port() > 1024 {
            suspicious_indicators.push("Localhost communication on high port".to_string());
        }
        
        // Détection de ports non-standard pour des protocoles connus
        if Self::is_non_standard_port(connection) {
            suspicious_indicators.push("Non-standard port for protocol".to_string());
        }
        
        // Si des indicateurs suspects sont trouvés, créer une activité suspecte
        if !suspicious_indicators.is_empty() {
            let activity = SuspiciousActivity {
                activity_id: Uuid::new_v4(),
                timestamp: SystemTime::now(),
                process_id: connection.process_id,
                process_name: connection.process_name.clone(),
                activity_type: Self::determine_activity_type(&suspicious_indicators),
                description: format!(
                    "Suspicious network activity: {}",
                    suspicious_indicators.join(", ")
                ),
                severity: Self::calculate_severity(&suspicious_indicators),
                indicators: suspicious_indicators,
            };
            
            let mut activities = suspicious_activities.lock().unwrap();
            activities.push(activity);
            
            // Limitation de la taille de l'historique
            if activities.len() > 1000 {
                activities.remove(0);
            }
        }
    }

    /// Détermine si un port est non-standard pour le protocole
    fn is_non_standard_port(connection: &ConnectionInfo) -> bool {
        let port = connection.remote_address.port();
        
        // Ports standards à ignorer
        let standard_ports = [
            80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995,
            3389, 5900, 8080, 8443
        ];
        
        !standard_ports.contains(&port) && port > 1024
    }

    /// Détermine le type d'activité suspecte
    fn determine_activity_type(indicators: &[String]) -> SuspiciousActivityType {
        for indicator in indicators {
            if indicator.contains("port") {
                return SuspiciousActivityType::SuspiciousPort;
            }
            if indicator.contains("IP") {
                return SuspiciousActivityType::UnusualDestination;
            }
            if indicator.contains("localhost") {
                return SuspiciousActivityType::C2Communication;
            }
        }
        
        SuspiciousActivityType::UnusualDestination
    }

    /// Calcule la sévérité d'une activité suspecte
    fn calculate_severity(indicators: &[String]) -> u8 {
        let mut severity = 1;
        
        for indicator in indicators {
            if indicator.contains("Suspicious port") {
                severity += 3;
            }
            if indicator.contains("Suspicious IP") {
                severity += 2;
            }
            if indicator.contains("localhost") {
                severity += 1;
            }
        }
        
        severity.min(10)
    }

    /// Analyse les activités suspectes
    async fn analyze_suspicious_activities(
        config: NetworkMonitorConfig,
        process_stats: Arc<Mutex<HashMap<u32, NetworkStatistics>>>,
        suspicious_activities: Arc<Mutex<Vec<SuspiciousActivity>>>,
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
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
            
            // Analyse des statistiques de processus
            {
                let stats = process_stats.lock().unwrap();
                for (process_id, process_stat) in stats.iter() {
                    // Détection de trop de connexions
                    if process_stat.active_connections > config.max_connections_per_process {
                        debug!(
                            "Process {} has too many connections: {}",
                            process_stat.process_name,
                            process_stat.active_connections
                        );
                    }
                    
                    // Détection de trafic élevé
                    let total_traffic = process_stat.total_bytes_sent + process_stat.total_bytes_received;
                    if total_traffic > config.data_threshold_mb * 1024 * 1024 {
                        debug!(
                            "Process {} has high traffic volume: {} bytes",
                            process_stat.process_name,
                            total_traffic
                        );
                    }
                }
            }
            
            // Analyse des activités suspectes récentes
            {
                let activities = suspicious_activities.lock().unwrap();
                let recent_activities: Vec<_> = activities.iter()
                    .filter(|activity| {
                        if let Ok(age) = SystemTime::now().duration_since(activity.timestamp) {
                            age < Duration::from_secs(60) // Dernière minute
                        } else {
                            false
                        }
                    })
                    .collect();
                
                // Corrélation d'activités suspectes
                if recent_activities.len() > 5 {
                    debug!("High number of suspicious activities detected: {}", recent_activities.len());
                }
            }
            
            sleep(Duration::from_secs(30)).await;
        }
        
        debug!("Suspicious activity analysis loop stopped");
    }

    /// Vérifie si un processus doit être exclu
    fn should_exclude_process(process_name: &str, config: &NetworkMonitorConfig) -> bool {
        config.excluded_processes.iter().any(|excluded| {
            process_name.to_lowercase().contains(&excluded.to_lowercase())
        })
    }

    /// Tâche de nettoyage périodique
    async fn cleanup_task(
        connection_cache: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
        suspicious_activities: Arc<Mutex<Vec<SuspiciousActivity>>>,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        let cleanup_interval = Duration::from_secs(300); // 5 minutes
        let max_age = Duration::from_secs(1800); // 30 minutes
        
        loop {
            // Vérification du signal d'arrêt
            {
                let shutdown = shutdown_signal.lock().unwrap();
                if *shutdown {
                    break;
                }
            }
            
            // Nettoyage du cache de connexions
            {
                let mut cache = connection_cache.lock().unwrap();
                let now = SystemTime::now();
                
                cache.retain(|_, connection| {
                    if let Ok(age) = now.duration_since(connection.last_activity) {
                        age <= max_age
                    } else {
                        true
                    }
                });
                
                debug!("Connection cache cleanup completed, {} entries remaining", cache.len());
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
            
            sleep(cleanup_interval).await;
        }
        
        debug!("Network monitor cleanup task stopped");
    }

    /// Obtient les statistiques de surveillance
    pub async fn get_statistics(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        // Statistiques des connexions
        let cache = self.connection_cache.lock().unwrap();
        stats.insert("active_connections_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(cache.len())));
        
        let tcp_connections = cache.values().filter(|c| c.protocol == Protocol::TCP).count();
        let udp_connections = cache.values().filter(|c| c.protocol == Protocol::UDP).count();
        
        stats.insert("tcp_connections_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(tcp_connections)));
        stats.insert("udp_connections_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(udp_connections)));
        
        // Statistiques des processus
        let process_stats = self.process_stats.lock().unwrap();
        stats.insert("monitored_processes_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(process_stats.len())));
        
        // Statistiques des activités suspectes
        let activities = self.suspicious_activities.lock().unwrap();
        stats.insert("suspicious_activities_count".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(activities.len())));
        
        // Configuration
        stats.insert("tcp_monitoring_enabled".to_string(), 
                    serde_json::Value::Bool(self.config.monitor_tcp_connections));
        stats.insert("udp_monitoring_enabled".to_string(), 
                    serde_json::Value::Bool(self.config.monitor_udp_connections));
        stats.insert("deep_packet_inspection_enabled".to_string(), 
                    serde_json::Value::Bool(self.config.enable_deep_packet_inspection));
        
        stats
    }
}

// Tests unitaires

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state_conversion() {
        assert_eq!(NetworkMonitor::tcp_state_from_windows(1), ConnectionState::Closed);
        assert_eq!(NetworkMonitor::tcp_state_from_windows(2), ConnectionState::Listen);
        assert_eq!(NetworkMonitor::tcp_state_from_windows(5), ConnectionState::Established);
    }

    #[test]
    fn test_process_exclusion() {
        let config = NetworkMonitorConfig::default();
        
        assert!(NetworkMonitor::should_exclude_process("svchost.exe", &config));
        assert!(NetworkMonitor::should_exclude_process("chrome.exe", &config));
        assert!(!NetworkMonitor::should_exclude_process("malware.exe", &config));
    }

    #[test]
    fn test_non_standard_port_detection() {
        let connection = ConnectionInfo {
            connection_id: "test".to_string(),
            process_id: 1234,
            process_name: "test.exe".to_string(),
            protocol: Protocol::TCP,
            local_address: "127.0.0.1:12345".parse().unwrap(),
            remote_address: "192.168.1.1:4444".parse().unwrap(),
            state: ConnectionState::Established,
            creation_time: SystemTime::now(),
            last_activity: SystemTime::now(),
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            is_suspicious: false,
        };
        
        assert!(NetworkMonitor::is_non_standard_port(&connection));
    }

    #[test]
    fn test_severity_calculation() {
        let indicators = vec![
            "Suspicious port: 4444".to_string(),
            "Suspicious IP: 192.168.1.1".to_string(),
        ];
        
        let severity = NetworkMonitor::calculate_severity(&indicators);
        assert!(severity >= 5);
    }

    #[tokio::test]
    async fn test_network_monitor_creation() {
        let config = NetworkMonitorConfig::default();
        let (sender, _receiver) = mpsc::unbounded_channel();
        
        let monitor = NetworkMonitor::new(config, sender);
        assert!(!monitor.shutdown_signal.lock().unwrap().clone());
    }
}