/**
 * Types pour les structures de données du serveur ERDPS
 * Définit les interfaces pour agents, menaces, événements et statuts
 * 
 * @author ERDPS Security Team
 * @version 1.0.0
 */

/**
 * Statut du serveur
 */
export enum ServerStatus {
  INITIALIZING = 'initializing',
  READY = 'ready',
  RUNNING = 'running',
  SHUTTING_DOWN = 'shutting_down',
  ERROR = 'error',
  MAINTENANCE = 'maintenance'
}

/**
 * Informations sur un agent ERDPS
 */
export interface Agent {
  /** Identifiant unique de l'agent */
  id: string;
  /** Nom d'hôte de la machine */
  hostname: string;
  /** Adresse IP de l'agent */
  ipAddress: string;
  /** Adresse MAC */
  macAddress: string;
  /** Version de l'agent */
  version: string;
  /** Système d'exploitation */
  operatingSystem: OSInfo;
  /** Statut de l'agent */
  status: AgentStatus;
  /** Date de première connexion */
  firstSeen: Date;
  /** Date de dernière activité */
  lastSeen: Date;
  /** Configuration de l'agent */
  configuration: AgentConfiguration;
  /** Métriques de performance */
  metrics: AgentMetrics;
  /** Groupes d'appartenance */
  groups: string[];
  /** Tags personnalisés */
  tags: Record<string, string>;
  /** Certificat de l'agent */
  certificate: CertificateInfo;
  /** Politique de sécurité appliquée */
  securityPolicy: string;
  /** Dernière mise à jour de configuration */
  lastConfigUpdate: Date;
  /** Erreurs récentes */
  recentErrors: AgentError[];
}

/**
 * Statut d'un agent
 */
export enum AgentStatus {
  ONLINE = 'online',
  OFFLINE = 'offline',
  CONNECTING = 'connecting',
  DISCONNECTED = 'disconnected',
  ERROR = 'error',
  UPDATING = 'updating',
  QUARANTINED = 'quarantined',
  MAINTENANCE = 'maintenance'
}

/**
 * Informations sur le système d'exploitation
 */
export interface OSInfo {
  /** Nom du système */
  name: string;
  /** Version */
  version: string;
  /** Architecture */
  architecture: string;
  /** Build */
  build: string;
  /** Service pack */
  servicePack?: string;
  /** Langue */
  language: string;
  /** Fuseau horaire */
  timezone: string;
  /** Domaine */
  domain?: string;
  /** Utilisateur actuel */
  currentUser: string;
  /** Privilèges administrateur */
  isAdmin: boolean;
}

/**
 * Configuration d'un agent
 */
export interface AgentConfiguration {
  /** Mode de fonctionnement */
  operationMode: OperationMode;
  /** Intervalle de heartbeat en secondes */
  heartbeatInterval: number;
  /** Configuration de monitoring */
  monitoring: MonitoringConfiguration;
  /** Configuration de détection */
  detection: DetectionConfiguration;
  /** Configuration de communication */
  communication: CommunicationConfiguration;
  /** Configuration de logging */
  logging: LoggingConfiguration;
  /** Actions automatiques */
  autoActions: AutoActionConfiguration;
  /** Exclusions */
  exclusions: ExclusionConfiguration;
}

/**
 * Mode de fonctionnement de l'agent
 */
export enum OperationMode {
  MONITOR = 'monitor',
  PROTECT = 'protect',
  QUARANTINE = 'quarantine',
  MAINTENANCE = 'maintenance'
}

/**
 * Configuration de monitoring
 */
export interface MonitoringConfiguration {
  /** Monitoring des fichiers */
  fileMonitoring: FileMonitoringConfig;
  /** Monitoring des processus */
  processMonitoring: ProcessMonitoringConfig;
  /** Monitoring réseau */
  networkMonitoring: NetworkMonitoringConfig;
  /** Monitoring du registre */
  registryMonitoring: RegistryMonitoringConfig;
  /** Monitoring des services */
  serviceMonitoring: ServiceMonitoringConfig;
}

/**
 * Configuration de monitoring des fichiers
 */
export interface FileMonitoringConfig {
  /** Activation */
  enabled: boolean;
  /** Répertoires surveillés */
  watchedDirectories: string[];
  /** Extensions surveillées */
  watchedExtensions: string[];
  /** Répertoires exclus */
  excludedDirectories: string[];
  /** Taille maximale de fichier à analyser */
  maxFileSize: number;
  /** Analyse en temps réel */
  realTimeAnalysis: boolean;
}

/**
 * Configuration de monitoring des processus
 */
export interface ProcessMonitoringConfig {
  /** Activation */
  enabled: boolean;
  /** Surveillance des injections */
  monitorInjections: boolean;
  /** Surveillance des hooks */
  monitorHooks: boolean;
  /** Surveillance de la mémoire */
  monitorMemory: boolean;
  /** Processus exclus */
  excludedProcesses: string[];
  /** Seuil CPU */
  cpuThreshold: number;
  /** Seuil mémoire */
  memoryThreshold: number;
}

/**
 * Configuration de monitoring réseau
 */
export interface NetworkMonitoringConfig {
  /** Activation */
  enabled: boolean;
  /** Surveillance des connexions */
  monitorConnections: boolean;
  /** Surveillance du trafic */
  monitorTraffic: boolean;
  /** Ports surveillés */
  monitoredPorts: number[];
  /** IPs exclues */
  excludedIPs: string[];
  /** Domaines exclus */
  excludedDomains: string[];
}

/**
 * Configuration de monitoring du registre
 */
export interface RegistryMonitoringConfig {
  /** Activation */
  enabled: boolean;
  /** Clés surveillées */
  watchedKeys: string[];
  /** Clés exclues */
  excludedKeys: string[];
  /** Surveillance des modifications */
  monitorModifications: boolean;
  /** Surveillance des créations */
  monitorCreations: boolean;
  /** Surveillance des suppressions */
  monitorDeletions: boolean;
}

/**
 * Configuration de monitoring des services
 */
export interface ServiceMonitoringConfig {
  /** Activation */
  enabled: boolean;
  /** Services surveillés */
  monitoredServices: string[];
  /** Services exclus */
  excludedServices: string[];
  /** Surveillance des démarrages */
  monitorStartups: boolean;
  /** Surveillance des arrêts */
  monitorShutdowns: boolean;
}

/**
 * Configuration de détection
 */
export interface DetectionConfiguration {
  /** Règles YARA */
  yaraRules: YaraRuleConfig;
  /** Analyse comportementale */
  behavioralAnalysis: BehavioralAnalysisConfig;
  /** Détection heuristique */
  heuristicDetection: HeuristicDetectionConfig;
  /** Intégration antivirus */
  antivirusIntegration: AntivirusIntegrationConfig;
  /** Analyse de réputation */
  reputationAnalysis: ReputationAnalysisConfig;
}

/**
 * Configuration des règles YARA
 */
export interface YaraRuleConfig {
  /** Activation */
  enabled: boolean;
  /** Chemin vers les règles */
  rulesPath: string;
  /** Mise à jour automatique */
  autoUpdate: boolean;
  /** Intervalle de mise à jour en heures */
  updateInterval: number;
  /** Règles personnalisées */
  customRules: string[];
}

/**
 * Configuration de l'analyse comportementale
 */
export interface BehavioralAnalysisConfig {
  /** Activation */
  enabled: boolean;
  /** Seuil de détection */
  detectionThreshold: number;
  /** Fenêtre d'analyse en minutes */
  analysisWindow: number;
  /** Patterns surveillés */
  monitoredPatterns: string[];
}

/**
 * Configuration de détection heuristique
 */
export interface HeuristicDetectionConfig {
  /** Activation */
  enabled: boolean;
  /** Niveau de sensibilité */
  sensitivityLevel: 'low' | 'medium' | 'high';
  /** Analyse de l'entropie */
  entropyAnalysis: boolean;
  /** Analyse des API */
  apiAnalysis: boolean;
}

/**
 * Configuration d'intégration antivirus
 */
export interface AntivirusIntegrationConfig {
  /** Activation */
  enabled: boolean;
  /** Moteur antivirus */
  engine: 'clamav' | 'windows_defender' | 'custom';
  /** Configuration du moteur */
  engineConfig: Record<string, any>;
}

/**
 * Configuration d'analyse de réputation
 */
export interface ReputationAnalysisConfig {
  /** Activation */
  enabled: boolean;
  /** Services de réputation */
  services: ReputationService[];
  /** Cache de réputation */
  cacheEnabled: boolean;
  /** Durée de cache en heures */
  cacheDuration: number;
}

/**
 * Service de réputation
 */
export interface ReputationService {
  /** Nom du service */
  name: string;
  /** URL de l'API */
  apiUrl: string;
  /** Clé d'API */
  apiKey: string;
  /** Timeout en millisecondes */
  timeout: number;
  /** Poids dans la décision */
  weight: number;
}

/**
 * Configuration de communication
 */
export interface CommunicationConfiguration {
  /** URL du serveur */
  serverUrl: string;
  /** Port du serveur */
  serverPort: number;
  /** Utilisation de TLS */
  useTLS: boolean;
  /** Vérification du certificat */
  verifyCertificate: boolean;
  /** Timeout de connexion */
  connectionTimeout: number;
  /** Intervalle de reconnexion */
  reconnectInterval: number;
  /** Nombre maximum de tentatives */
  maxRetries: number;
  /** Taille du buffer */
  bufferSize: number;
  /** Compression */
  compression: boolean;
}

/**
 * Configuration de logging
 */
export interface LoggingConfiguration {
  /** Niveau de log */
  level: 'debug' | 'info' | 'warn' | 'error';
  /** Destination des logs */
  destination: 'file' | 'syslog' | 'eventlog';
  /** Taille maximale des fichiers de log */
  maxFileSize: number;
  /** Nombre de fichiers de rotation */
  maxFiles: number;
  /** Chiffrement des logs */
  encryption: boolean;
  /** Compression des logs */
  compression: boolean;
}

/**
 * Configuration des actions automatiques
 */
export interface AutoActionConfiguration {
  /** Quarantaine automatique */
  autoQuarantine: boolean;
  /** Suppression automatique */
  autoDelete: boolean;
  /** Blocage automatique */
  autoBlock: boolean;
  /** Notification automatique */
  autoNotify: boolean;
  /** Seuil de déclenchement */
  triggerThreshold: number;
}

/**
 * Configuration des exclusions
 */
export interface ExclusionConfiguration {
  /** Fichiers exclus */
  excludedFiles: string[];
  /** Processus exclus */
  excludedProcesses: string[];
  /** Extensions exclues */
  excludedExtensions: string[];
  /** Répertoires exclus */
  excludedDirectories: string[];
  /** Hashes exclus */
  excludedHashes: string[];
}

/**
 * Métriques de performance d'un agent
 */
export interface AgentMetrics {
  /** Utilisation CPU */
  cpuUsage: number;
  /** Utilisation mémoire */
  memoryUsage: number;
  /** Utilisation disque */
  diskUsage: number;
  /** Utilisation réseau */
  networkUsage: NetworkUsage;
  /** Nombre de fichiers analysés */
  filesScanned: number;
  /** Nombre de menaces détectées */
  threatsDetected: number;
  /** Nombre d'événements générés */
  eventsGenerated: number;
  /** Temps de réponse moyen */
  averageResponseTime: number;
  /** Dernière mise à jour des métriques */
  lastUpdate: Date;
}

/**
 * Utilisation réseau
 */
export interface NetworkUsage {
  /** Bytes envoyés */
  bytesSent: number;
  /** Bytes reçus */
  bytesReceived: number;
  /** Paquets envoyés */
  packetsSent: number;
  /** Paquets reçus */
  packetsReceived: number;
}

/**
 * Informations sur un certificat
 */
export interface CertificateInfo {
  /** Empreinte du certificat */
  fingerprint: string;
  /** Sujet du certificat */
  subject: string;
  /** Émetteur du certificat */
  issuer: string;
  /** Date de début de validité */
  validFrom: Date;
  /** Date de fin de validité */
  validTo: Date;
  /** Numéro de série */
  serialNumber: string;
  /** Algorithme de signature */
  signatureAlgorithm: string;
  /** Statut de révocation */
  revocationStatus: 'valid' | 'revoked' | 'unknown';
}

/**
 * Erreur d'agent
 */
export interface AgentError {
  /** Identifiant de l'erreur */
  id: string;
  /** Code d'erreur */
  code: string;
  /** Message d'erreur */
  message: string;
  /** Détails de l'erreur */
  details?: string;
  /** Timestamp */
  timestamp: Date;
  /** Sévérité */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Composant concerné */
  component: string;
  /** Stack trace */
  stackTrace?: string;
}

/**
 * Menace détectée
 */
export interface Threat {
  /** Identifiant unique de la menace */
  id: string;
  /** Identifiant de l'agent qui a détecté */
  agentId: string;
  /** Type de menace */
  type: ThreatType;
  /** Catégorie de menace */
  category: ThreatCategory;
  /** Sévérité */
  severity: ThreatSeverity;
  /** Nom de la menace */
  name: string;
  /** Description */
  description: string;
  /** Fichier concerné */
  filePath?: string;
  /** Hash du fichier */
  fileHash?: string;
  /** Processus concerné */
  processName?: string;
  /** PID du processus */
  processId?: number;
  /** Adresse IP source */
  sourceIP?: string;
  /** Port source */
  sourcePort?: number;
  /** Adresse IP destination */
  destinationIP?: string;
  /** Port destination */
  destinationPort?: number;
  /** Règle de détection */
  detectionRule: string;
  /** Score de confiance */
  confidenceScore: number;
  /** Timestamp de détection */
  detectedAt: Date;
  /** Statut de la menace */
  status: ThreatStatus;
  /** Actions prises */
  actions: ThreatAction[];
  /** Contexte de détection */
  context: ThreatContext;
  /** Métadonnées */
  metadata: Record<string, any>;
}

/**
 * Type de menace
 */
export enum ThreatType {
  MALWARE = 'malware',
  RANSOMWARE = 'ransomware',
  TROJAN = 'trojan',
  VIRUS = 'virus',
  WORM = 'worm',
  ROOTKIT = 'rootkit',
  SPYWARE = 'spyware',
  ADWARE = 'adware',
  BACKDOOR = 'backdoor',
  BOTNET = 'botnet',
  PHISHING = 'phishing',
  SUSPICIOUS_BEHAVIOR = 'suspicious_behavior',
  POLICY_VIOLATION = 'policy_violation',
  NETWORK_INTRUSION = 'network_intrusion',
  DATA_EXFILTRATION = 'data_exfiltration'
}

/**
 * Catégorie de menace
 */
export enum ThreatCategory {
  FILE_BASED = 'file_based',
  MEMORY_BASED = 'memory_based',
  NETWORK_BASED = 'network_based',
  BEHAVIORAL = 'behavioral',
  REGISTRY_BASED = 'registry_based',
  PROCESS_BASED = 'process_based'
}

/**
 * Sévérité de menace
 */
export enum ThreatSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Statut de menace
 */
export enum ThreatStatus {
  DETECTED = 'detected',
  ANALYZING = 'analyzing',
  CONFIRMED = 'confirmed',
  FALSE_POSITIVE = 'false_positive',
  QUARANTINED = 'quarantined',
  CLEANED = 'cleaned',
  BLOCKED = 'blocked',
  IGNORED = 'ignored'
}

/**
 * Action prise sur une menace
 */
export interface ThreatAction {
  /** Type d'action */
  type: ThreatActionType;
  /** Timestamp de l'action */
  timestamp: Date;
  /** Utilisateur qui a effectué l'action */
  user?: string;
  /** Résultat de l'action */
  result: 'success' | 'failure' | 'partial';
  /** Détails */
  details?: string;
}

/**
 * Type d'action sur menace
 */
export enum ThreatActionType {
  QUARANTINE = 'quarantine',
  DELETE = 'delete',
  CLEAN = 'clean',
  BLOCK = 'block',
  ALLOW = 'allow',
  IGNORE = 'ignore',
  RESTORE = 'restore',
  ANALYZE = 'analyze'
}

/**
 * Contexte de détection d'une menace
 */
export interface ThreatContext {
  /** Utilisateur actuel */
  currentUser: string;
  /** Processus parent */
  parentProcess?: string;
  /** Ligne de commande */
  commandLine?: string;
  /** Variables d'environnement */
  environment?: Record<string, string>;
  /** Connexions réseau actives */
  networkConnections?: NetworkConnection[];
  /** Fichiers récemment modifiés */
  recentFileChanges?: FileChange[];
  /** Processus en cours */
  runningProcesses?: ProcessInfo[];
}

/**
 * Connexion réseau
 */
export interface NetworkConnection {
  /** Protocole */
  protocol: 'tcp' | 'udp';
  /** Adresse locale */
  localAddress: string;
  /** Port local */
  localPort: number;
  /** Adresse distante */
  remoteAddress: string;
  /** Port distant */
  remotePort: number;
  /** État de la connexion */
  state: string;
  /** PID du processus */
  processId: number;
}

/**
 * Changement de fichier
 */
export interface FileChange {
  /** Chemin du fichier */
  path: string;
  /** Type de changement */
  changeType: 'created' | 'modified' | 'deleted' | 'renamed';
  /** Timestamp */
  timestamp: Date;
  /** Taille du fichier */
  size?: number;
  /** Hash du fichier */
  hash?: string;
}

/**
 * Informations sur un processus
 */
export interface ProcessInfo {
  /** PID */
  pid: number;
  /** Nom du processus */
  name: string;
  /** Chemin de l'exécutable */
  executablePath: string;
  /** Ligne de commande */
  commandLine: string;
  /** PID du processus parent */
  parentPid?: number;
  /** Utilisateur propriétaire */
  owner: string;
  /** Utilisation CPU */
  cpuUsage: number;
  /** Utilisation mémoire */
  memoryUsage: number;
  /** Timestamp de démarrage */
  startTime: Date;
}

/**
 * Événement système
 */
export interface SystemEvent {
  /** Identifiant unique */
  id: string;
  /** Identifiant de l'agent */
  agentId: string;
  /** Type d'événement */
  type: EventType;
  /** Catégorie */
  category: EventCategory;
  /** Timestamp */
  timestamp: Date;
  /** Source de l'événement */
  source: string;
  /** Message */
  message: string;
  /** Données de l'événement */
  data: Record<string, any>;
  /** Sévérité */
  severity: EventSeverity;
  /** Tags */
  tags: string[];
  /** Corrélation ID */
  correlationId?: string;
}

/**
 * Type d'événement
 */
export enum EventType {
  FILE_CREATED = 'file_created',
  FILE_MODIFIED = 'file_modified',
  FILE_DELETED = 'file_deleted',
  PROCESS_STARTED = 'process_started',
  PROCESS_TERMINATED = 'process_terminated',
  NETWORK_CONNECTION = 'network_connection',
  REGISTRY_MODIFIED = 'registry_modified',
  SERVICE_STARTED = 'service_started',
  SERVICE_STOPPED = 'service_stopped',
  USER_LOGIN = 'user_login',
  USER_LOGOUT = 'user_logout',
  THREAT_DETECTED = 'threat_detected',
  POLICY_VIOLATION = 'policy_violation',
  SYSTEM_ERROR = 'system_error'
}

/**
 * Catégorie d'événement
 */
export enum EventCategory {
  SECURITY = 'security',
  SYSTEM = 'system',
  APPLICATION = 'application',
  NETWORK = 'network',
  AUDIT = 'audit'
}

/**
 * Sévérité d'événement
 */
export enum EventSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical'
}

/**
 * Rapport de sécurité
 */
export interface SecurityReport {
  /** Identifiant du rapport */
  id: string;
  /** Type de rapport */
  type: ReportType;
  /** Titre */
  title: string;
  /** Description */
  description: string;
  /** Période couverte */
  period: ReportPeriod;
  /** Date de génération */
  generatedAt: Date;
  /** Généré par */
  generatedBy: string;
  /** Données du rapport */
  data: ReportData;
  /** Format */
  format: 'json' | 'pdf' | 'html' | 'csv';
  /** Statut */
  status: 'generating' | 'completed' | 'failed';
}

/**
 * Type de rapport
 */
export enum ReportType {
  THREAT_SUMMARY = 'threat_summary',
  AGENT_STATUS = 'agent_status',
  SECURITY_POSTURE = 'security_posture',
  COMPLIANCE = 'compliance',
  PERFORMANCE = 'performance',
  INCIDENT = 'incident'
}

/**
 * Période de rapport
 */
export interface ReportPeriod {
  /** Date de début */
  startDate: Date;
  /** Date de fin */
  endDate: Date;
  /** Type de période */
  type: 'hourly' | 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly' | 'custom';
}

/**
 * Données de rapport
 */
export interface ReportData {
  /** Résumé exécutif */
  executiveSummary: ExecutiveSummary;
  /** Métriques */
  metrics: ReportMetrics;
  /** Graphiques */
  charts: ChartData[];
  /** Tableaux */
  tables: TableData[];
  /** Recommandations */
  recommendations: Recommendation[];
}

/**
 * Résumé exécutif
 */
export interface ExecutiveSummary {
  /** Points clés */
  keyPoints: string[];
  /** Tendances */
  trends: string[];
  /** Risques identifiés */
  risks: string[];
  /** Actions recommandées */
  actions: string[];
}

/**
 * Métriques de rapport
 */
export interface ReportMetrics {
  /** Nombre total d'agents */
  totalAgents: number;
  /** Agents en ligne */
  onlineAgents: number;
  /** Menaces détectées */
  threatsDetected: number;
  /** Menaces bloquées */
  threatsBlocked: number;
  /** Faux positifs */
  falsePositives: number;
  /** Temps de réponse moyen */
  averageResponseTime: number;
  /** Disponibilité du système */
  systemUptime: number;
}

/**
 * Données de graphique
 */
export interface ChartData {
  /** Titre du graphique */
  title: string;
  /** Type de graphique */
  type: 'line' | 'bar' | 'pie' | 'area' | 'scatter';
  /** Données */
  data: any[];
  /** Configuration */
  config: Record<string, any>;
}

/**
 * Données de tableau
 */
export interface TableData {
  /** Titre du tableau */
  title: string;
  /** En-têtes de colonnes */
  headers: string[];
  /** Lignes de données */
  rows: any[][];
  /** Configuration */
  config: Record<string, any>;
}

/**
 * Recommandation
 */
export interface Recommendation {
  /** Titre */
  title: string;
  /** Description */
  description: string;
  /** Priorité */
  priority: 'low' | 'medium' | 'high' | 'critical';
  /** Catégorie */
  category: string;
  /** Actions suggérées */
  actions: string[];
  /** Impact estimé */
  estimatedImpact: string;
}