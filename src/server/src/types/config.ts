/**
 * Types de configuration pour le serveur ERDPS
 * Définit toutes les interfaces de configuration pour la sécurité enterprise
 * 
 * @author ERDPS Security Team
 * @version 1.0.0
 */

/**
 * Configuration principale du serveur
 */
export interface ServerConfig {
  /** Port d'écoute du serveur HTTPS */
  port: number;
  /** Adresse d'écoute */
  host: string;
  /** Origines autorisées pour CORS */
  allowedOrigins: string[];
  /** Configuration SSL/TLS */
  ssl: SSLConfig;
  /** Environnement d'exécution */
  environment: 'development' | 'staging' | 'production';
  /** Niveau de log */
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  /** Timeout des requêtes en millisecondes */
  requestTimeout: number;
  /** Taille maximale du body des requêtes */
  maxRequestSize: string;
  /** Configuration des workers */
  workers: WorkerConfig;
}

/**
 * Configuration SSL/TLS
 */
export interface SSLConfig {
  /** Chemin vers la clé privée */
  keyPath: string;
  /** Chemin vers le certificat */
  certPath: string;
  /** Chemin vers le certificat CA (optionnel) */
  caPath?: string;
  /** Version TLS minimum */
  minVersion: 'TLSv1.2' | 'TLSv1.3';
  /** Suites de chiffrement autorisées */
  ciphers: string[];
  /** Courbes elliptiques autorisées */
  ecdhCurve: string;
  /** Activation de HSTS */
  hsts: boolean;
  /** Durée HSTS en secondes */
  hstsMaxAge: number;
}

/**
 * Configuration des workers
 */
export interface WorkerConfig {
  /** Nombre de workers */
  count: number;
  /** Mémoire maximale par worker */
  maxMemory: string;
  /** Timeout de redémarrage */
  restartTimeout: number;
  /** Nombre maximum de redémarrages */
  maxRestarts: number;
}

/**
 * Configuration de sécurité
 */
export interface SecurityConfig {
  /** Configuration JWT */
  jwt: JWTConfig;
  /** Configuration de chiffrement */
  encryption: EncryptionConfig;
  /** Configuration des certificats */
  certificates: CertificateConfig;
  /** Configuration de l'authentification */
  authentication: AuthenticationConfig;
  /** Configuration de l'autorisation */
  authorization: AuthorizationConfig;
  /** Configuration de l'audit */
  audit: AuditConfig;
  /** Configuration anti-brute force */
  bruteForce: BruteForceConfig;
  /** Configuration de la validation d'entrée */
  inputValidation: InputValidationConfig;
}

/**
 * Configuration JWT
 */
export interface JWTConfig {
  /** Clé secrète pour signer les tokens */
  secret: string;
  /** Algorithme de signature */
  algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
  /** Durée de vie des tokens d'accès */
  accessTokenExpiry: string;
  /** Durée de vie des tokens de rafraîchissement */
  refreshTokenExpiry: string;
  /** Émetteur des tokens */
  issuer: string;
  /** Audience des tokens */
  audience: string;
  /** Activation de la rotation des tokens */
  tokenRotation: boolean;
}

/**
 * Configuration de chiffrement
 */
export interface EncryptionConfig {
  /** Algorithme de chiffrement principal */
  algorithm: 'AES-256-GCM' | 'ChaCha20-Poly1305';
  /** Taille de la clé en bits */
  keySize: number;
  /** Taille de l'IV en bytes */
  ivSize: number;
  /** Taille du tag d'authentification */
  tagSize: number;
  /** Algorithme de dérivation de clé */
  kdf: 'PBKDF2' | 'Argon2id' | 'scrypt';
  /** Nombre d'itérations pour KDF */
  kdfIterations: number;
  /** Taille du sel pour KDF */
  saltSize: number;
}

/**
 * Configuration des certificats
 */
export interface CertificateConfig {
  /** Chemin vers le magasin de certificats */
  storePath: string;
  /** Mot de passe du magasin */
  storePassword: string;
  /** Algorithme de signature */
  signatureAlgorithm: 'SHA256withRSA' | 'SHA384withRSA' | 'SHA512withRSA';
  /** Durée de validité des certificats en jours */
  validityDays: number;
  /** Taille de clé RSA */
  keySize: number;
  /** Configuration de révocation */
  revocation: RevocationConfig;
}

/**
 * Configuration de révocation de certificats
 */
export interface RevocationConfig {
  /** URL du serveur OCSP */
  ocspUrl: string;
  /** URL de la CRL */
  crlUrl: string;
  /** Intervalle de vérification en heures */
  checkInterval: number;
  /** Timeout de vérification en millisecondes */
  timeout: number;
}

/**
 * Configuration de l'authentification
 */
export interface AuthenticationConfig {
  /** Méthodes d'authentification autorisées */
  methods: AuthMethod[];
  /** Configuration MFA */
  mfa: MFAConfig;
  /** Configuration des sessions */
  session: SessionConfig;
  /** Configuration LDAP/AD */
  ldap?: LDAPConfig;
  /** Configuration SAML */
  saml?: SAMLConfig;
}

/**
 * Méthodes d'authentification
 */
export enum AuthMethod {
  LOCAL = 'local',
  LDAP = 'ldap',
  SAML = 'saml',
  CERTIFICATE = 'certificate',
  API_KEY = 'api_key'
}

/**
 * Configuration MFA
 */
export interface MFAConfig {
  /** MFA obligatoire */
  required: boolean;
  /** Méthodes MFA autorisées */
  methods: MFAMethod[];
  /** Configuration TOTP */
  totp: TOTPConfig;
  /** Configuration SMS */
  sms?: SMSConfig;
  /** Configuration email */
  email?: EmailMFAConfig;
}

/**
 * Méthodes MFA
 */
export enum MFAMethod {
  TOTP = 'totp',
  SMS = 'sms',
  EMAIL = 'email',
  HARDWARE_TOKEN = 'hardware_token'
}

/**
 * Configuration TOTP
 */
export interface TOTPConfig {
  /** Nom de l'émetteur */
  issuer: string;
  /** Période en secondes */
  period: number;
  /** Nombre de chiffres */
  digits: number;
  /** Algorithme de hachage */
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  /** Fenêtre de tolérance */
  window: number;
}

/**
 * Configuration SMS
 */
export interface SMSConfig {
  /** Fournisseur SMS */
  provider: 'twilio' | 'aws_sns';
  /** Configuration du fournisseur */
  config: Record<string, any>;
  /** Template du message */
  template: string;
  /** Durée de validité en minutes */
  validityMinutes: number;
}

/**
 * Configuration email MFA
 */
export interface EmailMFAConfig {
  /** Template du message */
  template: string;
  /** Durée de validité en minutes */
  validityMinutes: number;
  /** Expéditeur */
  from: string;
}

/**
 * Configuration des sessions
 */
export interface SessionConfig {
  /** Durée de vie des sessions en millisecondes */
  maxAge: number;
  /** Nom du cookie de session */
  cookieName: string;
  /** Domaine du cookie */
  cookieDomain: string;
  /** Cookie sécurisé uniquement */
  secure: boolean;
  /** Cookie HTTP uniquement */
  httpOnly: boolean;
  /** SameSite policy */
  sameSite: 'strict' | 'lax' | 'none';
  /** Régénération de l'ID de session */
  regenerateId: boolean;
}

/**
 * Configuration LDAP
 */
export interface LDAPConfig {
  /** URL du serveur LDAP */
  url: string;
  /** DN de base */
  baseDN: string;
  /** DN de liaison */
  bindDN: string;
  /** Mot de passe de liaison */
  bindPassword: string;
  /** Filtre de recherche utilisateur */
  userSearchFilter: string;
  /** Attributs utilisateur */
  userAttributes: string[];
  /** Filtre de recherche groupe */
  groupSearchFilter: string;
  /** Attributs groupe */
  groupAttributes: string[];
  /** Timeout de connexion */
  timeout: number;
  /** Utilisation de TLS */
  tls: boolean;
}

/**
 * Configuration SAML
 */
export interface SAMLConfig {
  /** URL de l'IdP */
  idpUrl: string;
  /** Certificat de l'IdP */
  idpCert: string;
  /** URL de callback */
  callbackUrl: string;
  /** ID de l'entité */
  entityId: string;
  /** Clé privée SP */
  privateKey: string;
  /** Certificat SP */
  cert: string;
  /** Algorithme de signature */
  signatureAlgorithm: string;
}

/**
 * Configuration de l'autorisation
 */
export interface AuthorizationConfig {
  /** Modèle d'autorisation */
  model: 'rbac' | 'abac';
  /** Rôles par défaut */
  defaultRoles: string[];
  /** Configuration RBAC */
  rbac?: RBACConfig;
  /** Configuration ABAC */
  abac?: ABACConfig;
}

/**
 * Configuration RBAC
 */
export interface RBACConfig {
  /** Hiérarchie des rôles */
  roleHierarchy: Record<string, string[]>;
  /** Permissions par rôle */
  rolePermissions: Record<string, string[]>;
  /** Héritage des permissions */
  inheritPermissions: boolean;
}

/**
 * Configuration ABAC
 */
export interface ABACConfig {
  /** Moteur de règles */
  engine: 'opa' | 'casbin';
  /** Chemin vers les politiques */
  policiesPath: string;
  /** Rechargement automatique */
  autoReload: boolean;
}

/**
 * Configuration de l'audit
 */
export interface AuditConfig {
  /** Activation de l'audit */
  enabled: boolean;
  /** Événements à auditer */
  events: AuditEvent[];
  /** Destination des logs d'audit */
  destination: 'file' | 'database' | 'syslog' | 'elasticsearch';
  /** Configuration de la destination */
  destinationConfig: Record<string, any>;
  /** Rétention des logs en jours */
  retentionDays: number;
  /** Chiffrement des logs */
  encryption: boolean;
  /** Signature des logs */
  signing: boolean;
}

/**
 * Événements d'audit
 */
export enum AuditEvent {
  LOGIN = 'login',
  LOGOUT = 'logout',
  LOGIN_FAILED = 'login_failed',
  PASSWORD_CHANGE = 'password_change',
  PERMISSION_DENIED = 'permission_denied',
  DATA_ACCESS = 'data_access',
  DATA_MODIFICATION = 'data_modification',
  CONFIGURATION_CHANGE = 'configuration_change',
  THREAT_DETECTED = 'threat_detected',
  AGENT_CONNECTED = 'agent_connected',
  AGENT_DISCONNECTED = 'agent_disconnected'
}

/**
 * Configuration anti-brute force
 */
export interface BruteForceConfig {
  /** Activation de la protection */
  enabled: boolean;
  /** Nombre maximum de tentatives */
  maxAttempts: number;
  /** Fenêtre de temps en millisecondes */
  windowMs: number;
  /** Durée de blocage en millisecondes */
  blockDuration: number;
  /** Blocage progressif */
  progressiveDelay: boolean;
  /** Liste blanche d'IPs */
  whitelist: string[];
}

/**
 * Configuration de validation d'entrée
 */
export interface InputValidationConfig {
  /** Validation stricte */
  strict: boolean;
  /** Taille maximale des chaînes */
  maxStringLength: number;
  /** Taille maximale des tableaux */
  maxArrayLength: number;
  /** Profondeur maximale des objets */
  maxObjectDepth: number;
  /** Expressions régulières interdites */
  forbiddenPatterns: string[];
  /** Sanitisation automatique */
  autoSanitize: boolean;
}

/**
 * Configuration de la base de données
 */
export interface DatabaseConfig {
  /** Type de base de données */
  type: 'postgresql' | 'mysql' | 'sqlite';
  /** Hôte */
  host: string;
  /** Port */
  port: number;
  /** Nom de la base */
  database: string;
  /** Utilisateur */
  username: string;
  /** Mot de passe */
  password: string;
  /** Configuration SSL */
  ssl: boolean;
  /** Configuration du pool de connexions */
  pool: PoolConfig;
  /** Configuration des migrations */
  migrations: MigrationConfig;
  /** Configuration de la sauvegarde */
  backup: BackupConfig;
}

/**
 * Configuration du pool de connexions
 */
export interface PoolConfig {
  /** Nombre minimum de connexions */
  min: number;
  /** Nombre maximum de connexions */
  max: number;
  /** Timeout d'acquisition en millisecondes */
  acquireTimeoutMillis: number;
  /** Timeout d'inactivité en millisecondes */
  idleTimeoutMillis: number;
  /** Intervalle de nettoyage en millisecondes */
  reapIntervalMillis: number;
}

/**
 * Configuration des migrations
 */
export interface MigrationConfig {
  /** Répertoire des migrations */
  directory: string;
  /** Table des migrations */
  tableName: string;
  /** Extension des fichiers */
  extension: string;
}

/**
 * Configuration de sauvegarde
 */
export interface BackupConfig {
  /** Activation des sauvegardes automatiques */
  enabled: boolean;
  /** Intervalle en heures */
  interval: number;
  /** Répertoire de sauvegarde */
  directory: string;
  /** Rétention en jours */
  retention: number;
  /** Compression */
  compression: boolean;
  /** Chiffrement */
  encryption: boolean;
}

/**
 * Configuration Redis
 */
export interface RedisConfig {
  /** Hôte */
  host: string;
  /** Port */
  port: number;
  /** Mot de passe */
  password?: string;
  /** Base de données */
  db: number;
  /** Configuration du cluster */
  cluster?: RedisClusterConfig;
  /** Configuration des sentinelles */
  sentinel?: RedisSentinelConfig;
  /** Timeout de connexion */
  connectTimeout: number;
  /** Timeout de commande */
  commandTimeout: number;
  /** Nombre de tentatives de reconnexion */
  retryAttempts: number;
  /** Délai entre les tentatives */
  retryDelay: number;
}

/**
 * Configuration du cluster Redis
 */
export interface RedisClusterConfig {
  /** Nœuds du cluster */
  nodes: Array<{ host: string; port: number }>;
  /** Options du cluster */
  options: Record<string, any>;
}

/**
 * Configuration des sentinelles Redis
 */
export interface RedisSentinelConfig {
  /** Sentinelles */
  sentinels: Array<{ host: string; port: number }>;
  /** Nom du maître */
  name: string;
  /** Options des sentinelles */
  options: Record<string, any>;
}

/**
 * Configuration des notifications
 */
export interface NotificationConfig {
  /** Canaux de notification activés */
  channels: NotificationChannel[];
  /** Configuration email */
  email?: EmailConfig;
  /** Configuration SMS */
  sms?: SMSNotificationConfig;
  /** Configuration Slack */
  slack?: SlackConfig;
  /** Configuration webhook */
  webhook?: WebhookConfig;
  /** Templates de notification */
  templates: Record<string, NotificationTemplate>;
}

/**
 * Canaux de notification
 */
export enum NotificationChannel {
  EMAIL = 'email',
  SMS = 'sms',
  SLACK = 'slack',
  WEBHOOK = 'webhook',
  PUSH = 'push'
}

/**
 * Configuration email
 */
export interface EmailConfig {
  /** Serveur SMTP */
  smtp: SMTPConfig;
  /** Expéditeur par défaut */
  defaultFrom: string;
  /** Templates */
  templates: Record<string, EmailTemplate>;
}

/**
 * Configuration SMTP
 */
export interface SMTPConfig {
  /** Hôte */
  host: string;
  /** Port */
  port: number;
  /** Sécurité */
  secure: boolean;
  /** Authentification */
  auth: {
    user: string;
    pass: string;
  };
}

/**
 * Template email
 */
export interface EmailTemplate {
  /** Sujet */
  subject: string;
  /** Corps HTML */
  html: string;
  /** Corps texte */
  text: string;
}

/**
 * Configuration SMS pour notifications
 */
export interface SMSNotificationConfig {
  /** Fournisseur */
  provider: 'twilio' | 'aws_sns';
  /** Configuration */
  config: Record<string, any>;
  /** Templates */
  templates: Record<string, string>;
}

/**
 * Configuration Slack
 */
export interface SlackConfig {
  /** Token d'API */
  token: string;
  /** Canal par défaut */
  defaultChannel: string;
  /** Templates */
  templates: Record<string, SlackTemplate>;
}

/**
 * Template Slack
 */
export interface SlackTemplate {
  /** Texte */
  text: string;
  /** Attachments */
  attachments?: any[];
  /** Blocs */
  blocks?: any[];
}

/**
 * Configuration webhook
 */
export interface WebhookConfig {
  /** URL par défaut */
  defaultUrl: string;
  /** Headers par défaut */
  defaultHeaders: Record<string, string>;
  /** Timeout */
  timeout: number;
  /** Nombre de tentatives */
  retries: number;
}

/**
 * Template de notification
 */
export interface NotificationTemplate {
  /** Titre */
  title: string;
  /** Message */
  message: string;
  /** Priorité */
  priority: 'low' | 'medium' | 'high' | 'critical';
  /** Variables */
  variables: string[];
}