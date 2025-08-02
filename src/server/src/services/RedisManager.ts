/**
 * ERDPS Redis Manager - Gestionnaire Redis pour cache et sessions
 * 
 * Fonctionnalités:
 * - Gestion des sessions utilisateur sécurisées
 * - Cache des données de détection et alertes
 * - Stockage temporaire des logs d'agents
 * - Gestion des tokens d'authentification
 * - Cache des règles YARA et signatures
 * 
 * Sécurité:
 * - Chiffrement des données sensibles
 * - Expiration automatique des sessions
 * - Isolation des données par tenant
 * - Audit des accès
 * 
 * @author ERDPS Security Team
 * @version 1.0.0
 * @license Proprietary
 */

import Redis from 'ioredis';
import { createHash, createCipher, createDecipher } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import config from 'config';

// Types et interfaces
interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db: number;
  keyPrefix: string;
  retryDelayOnFailover: number;
  maxRetriesPerRequest: number;
  lazyConnect: boolean;
  keepAlive: number;
  family: number;
  connectTimeout: number;
  commandTimeout: number;
}

interface SessionData {
  userId: string;
  username: string;
  role: string;
  permissions: string[];
  lastActivity: number;
  ipAddress: string;
  userAgent: string;
  tenantId?: string;
}

interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
  encrypted: boolean;
}

interface AlertCache {
  id: string;
  agentId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  description: string;
  timestamp: number;
  acknowledged: boolean;
  assignedTo?: string;
}

interface AgentStatus {
  agentId: string;
  hostname: string;
  ipAddress: string;
  lastHeartbeat: number;
  version: string;
  status: 'online' | 'offline' | 'error';
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
}

/**
 * Gestionnaire Redis principal pour ERDPS
 * Gère le cache, les sessions et la communication temps réel
 */
export class RedisManager {
  private client: Redis;
  private subscriber: Redis;
  private publisher: Redis;
  private logger: winston.Logger;
  private encryptionKey: string;
  private isConnected: boolean = false;

  // Constantes de configuration
  private readonly SESSION_TTL = 8 * 60 * 60; // 8 heures
  private readonly CACHE_TTL = 30 * 60; // 30 minutes
  private readonly ALERT_TTL = 24 * 60 * 60; // 24 heures
  private readonly AGENT_STATUS_TTL = 5 * 60; // 5 minutes
  private readonly MAX_RETRY_ATTEMPTS = 3;

  // Préfixes des clés Redis
  private readonly KEYS = {
    SESSION: 'erdps:session:',
    CACHE: 'erdps:cache:',
    ALERT: 'erdps:alert:',
    AGENT: 'erdps:agent:',
    YARA_RULES: 'erdps:yara:',
    USER_ACTIVITY: 'erdps:activity:',
    RATE_LIMIT: 'erdps:ratelimit:',
    AUDIT_LOG: 'erdps:audit:'
  };

  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: 'redis-manager' },
      transports: [
        new winston.transports.File({ filename: 'logs/redis-error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/redis-combined.log' })
      ]
    });

    this.encryptionKey = config.get('security.encryptionKey') || process.env.ERDPS_ENCRYPTION_KEY || 'default-key-change-in-production';
    this.initializeRedis();
  }

  /**
   * Initialise les connexions Redis
   */
  private async initializeRedis(): Promise<void> {
    try {
      const redisConfig: RedisConfig = {
        host: config.get('redis.host') || 'localhost',
        port: config.get('redis.port') || 6379,
        password: config.get('redis.password'),
        db: config.get('redis.db') || 0,
        keyPrefix: config.get('redis.keyPrefix') || 'erdps:',
        retryDelayOnFailover: 100,
        maxRetriesPerRequest: this.MAX_RETRY_ATTEMPTS,
        lazyConnect: true,
        keepAlive: 30000,
        family: 4,
        connectTimeout: 10000,
        commandTimeout: 5000
      };

      // Client principal
      this.client = new Redis(redisConfig);
      
      // Client pour les publications
      this.publisher = new Redis(redisConfig);
      
      // Client pour les souscriptions
      this.subscriber = new Redis(redisConfig);

      // Gestion des événements de connexion
      this.client.on('connect', () => {
        this.isConnected = true;
        this.logger.info('Redis client connected successfully');
      });

      this.client.on('error', (error) => {
        this.isConnected = false;
        this.logger.error('Redis client error:', error);
      });

      this.client.on('close', () => {
        this.isConnected = false;
        this.logger.warn('Redis client connection closed');
      });

      // Connexion initiale
      await this.client.connect();
      await this.publisher.connect();
      await this.subscriber.connect();

      this.logger.info('Redis Manager initialized successfully');
    } catch (error) {
      this.logger.error('Failed to initialize Redis:', error);
      throw new Error(`Redis initialization failed: ${error.message}`);
    }
  }

  /**
   * Chiffre les données sensibles
   */
  private encrypt(data: string): string {
    try {
      const cipher = createCipher('aes-256-cbc', this.encryptionKey);
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return encrypted;
    } catch (error) {
      this.logger.error('Encryption failed:', error);
      throw new Error('Data encryption failed');
    }
  }

  /**
   * Déchiffre les données
   */
  private decrypt(encryptedData: string): string {
    try {
      const decipher = createDecipher('aes-256-cbc', this.encryptionKey);
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      this.logger.error('Decryption failed:', error);
      throw new Error('Data decryption failed');
    }
  }

  /**
   * Gestion des sessions utilisateur
   */
  public async createSession(sessionData: SessionData): Promise<string> {
    try {
      const sessionId = uuidv4();
      const sessionKey = this.KEYS.SESSION + sessionId;
      
      const encryptedData = this.encrypt(JSON.stringify(sessionData));
      
      await this.client.setex(sessionKey, this.SESSION_TTL, encryptedData);
      
      // Log de l'activité utilisateur
      await this.logUserActivity(sessionData.userId, 'session_created', {
        sessionId,
        ipAddress: sessionData.ipAddress,
        userAgent: sessionData.userAgent
      });
      
      this.logger.info(`Session created for user ${sessionData.username}`, {
        sessionId,
        userId: sessionData.userId,
        ipAddress: sessionData.ipAddress
      });
      
      return sessionId;
    } catch (error) {
      this.logger.error('Failed to create session:', error);
      throw new Error('Session creation failed');
    }
  }

  /**
   * Récupère les données de session
   */
  public async getSession(sessionId: string): Promise<SessionData | null> {
    try {
      const sessionKey = this.KEYS.SESSION + sessionId;
      const encryptedData = await this.client.get(sessionKey);
      
      if (!encryptedData) {
        return null;
      }
      
      const decryptedData = this.decrypt(encryptedData);
      const sessionData: SessionData = JSON.parse(decryptedData);
      
      // Mise à jour de la dernière activité
      sessionData.lastActivity = Date.now();
      await this.updateSession(sessionId, sessionData);
      
      return sessionData;
    } catch (error) {
      this.logger.error('Failed to get session:', error);
      return null;
    }
  }

  /**
   * Met à jour une session existante
   */
  public async updateSession(sessionId: string, sessionData: SessionData): Promise<boolean> {
    try {
      const sessionKey = this.KEYS.SESSION + sessionId;
      const encryptedData = this.encrypt(JSON.stringify(sessionData));
      
      const result = await this.client.setex(sessionKey, this.SESSION_TTL, encryptedData);
      return result === 'OK';
    } catch (error) {
      this.logger.error('Failed to update session:', error);
      return false;
    }
  }

  /**
   * Supprime une session
   */
  public async deleteSession(sessionId: string): Promise<boolean> {
    try {
      const sessionKey = this.KEYS.SESSION + sessionId;
      const result = await this.client.del(sessionKey);
      
      this.logger.info(`Session deleted: ${sessionId}`);
      return result > 0;
    } catch (error) {
      this.logger.error('Failed to delete session:', error);
      return false;
    }
  }

  /**
   * Gestion du cache des alertes
   */
  public async cacheAlert(alert: AlertCache): Promise<boolean> {
    try {
      const alertKey = this.KEYS.ALERT + alert.id;
      const cacheEntry: CacheEntry<AlertCache> = {
        data: alert,
        timestamp: Date.now(),
        ttl: this.ALERT_TTL,
        encrypted: true
      };
      
      const encryptedData = this.encrypt(JSON.stringify(cacheEntry));
      await this.client.setex(alertKey, this.ALERT_TTL, encryptedData);
      
      // Ajout à la liste des alertes actives
      await this.client.zadd('erdps:alerts:active', Date.now(), alert.id);
      
      // Publication de l'alerte en temps réel
      await this.publisher.publish('erdps:alerts:new', JSON.stringify(alert));
      
      this.logger.info(`Alert cached: ${alert.id}`, {
        severity: alert.severity,
        type: alert.type,
        agentId: alert.agentId
      });
      
      return true;
    } catch (error) {
      this.logger.error('Failed to cache alert:', error);
      return false;
    }
  }

  /**
   * Récupère une alerte du cache
   */
  public async getAlert(alertId: string): Promise<AlertCache | null> {
    try {
      const alertKey = this.KEYS.ALERT + alertId;
      const encryptedData = await this.client.get(alertKey);
      
      if (!encryptedData) {
        return null;
      }
      
      const decryptedData = this.decrypt(encryptedData);
      const cacheEntry: CacheEntry<AlertCache> = JSON.parse(decryptedData);
      
      return cacheEntry.data;
    } catch (error) {
      this.logger.error('Failed to get alert:', error);
      return null;
    }
  }

  /**
   * Gestion du statut des agents
   */
  public async updateAgentStatus(agentStatus: AgentStatus): Promise<boolean> {
    try {
      const agentKey = this.KEYS.AGENT + agentStatus.agentId;
      const statusData = JSON.stringify(agentStatus);
      
      await this.client.setex(agentKey, this.AGENT_STATUS_TTL, statusData);
      
      // Mise à jour de la liste des agents actifs
      if (agentStatus.status === 'online') {
        await this.client.zadd('erdps:agents:online', Date.now(), agentStatus.agentId);
      } else {
        await this.client.zrem('erdps:agents:online', agentStatus.agentId);
      }
      
      return true;
    } catch (error) {
      this.logger.error('Failed to update agent status:', error);
      return false;
    }
  }

  /**
   * Récupère le statut d'un agent
   */
  public async getAgentStatus(agentId: string): Promise<AgentStatus | null> {
    try {
      const agentKey = this.KEYS.AGENT + agentId;
      const statusData = await this.client.get(agentKey);
      
      if (!statusData) {
        return null;
      }
      
      return JSON.parse(statusData) as AgentStatus;
    } catch (error) {
      this.logger.error('Failed to get agent status:', error);
      return null;
    }
  }

  /**
   * Récupère tous les agents en ligne
   */
  public async getOnlineAgents(): Promise<string[]> {
    try {
      const onlineAgents = await this.client.zrange('erdps:agents:online', 0, -1);
      return onlineAgents;
    } catch (error) {
      this.logger.error('Failed to get online agents:', error);
      return [];
    }
  }

  /**
   * Gestion du cache des règles YARA
   */
  public async cacheYaraRules(rules: string, version: string): Promise<boolean> {
    try {
      const rulesKey = this.KEYS.YARA_RULES + 'current';
      const versionKey = this.KEYS.YARA_RULES + 'version';
      
      const encryptedRules = this.encrypt(rules);
      
      await this.client.set(rulesKey, encryptedRules);
      await this.client.set(versionKey, version);
      
      this.logger.info(`YARA rules cached, version: ${version}`);
      return true;
    } catch (error) {
      this.logger.error('Failed to cache YARA rules:', error);
      return false;
    }
  }

  /**
   * Récupère les règles YARA
   */
  public async getYaraRules(): Promise<{ rules: string; version: string } | null> {
    try {
      const rulesKey = this.KEYS.YARA_RULES + 'current';
      const versionKey = this.KEYS.YARA_RULES + 'version';
      
      const [encryptedRules, version] = await Promise.all([
        this.client.get(rulesKey),
        this.client.get(versionKey)
      ]);
      
      if (!encryptedRules || !version) {
        return null;
      }
      
      const rules = this.decrypt(encryptedRules);
      return { rules, version };
    } catch (error) {
      this.logger.error('Failed to get YARA rules:', error);
      return null;
    }
  }

  /**
   * Limitation de taux (rate limiting)
   */
  public async checkRateLimit(identifier: string, limit: number, windowSeconds: number): Promise<boolean> {
    try {
      const key = this.KEYS.RATE_LIMIT + identifier;
      const current = await this.client.incr(key);
      
      if (current === 1) {
        await this.client.expire(key, windowSeconds);
      }
      
      return current <= limit;
    } catch (error) {
      this.logger.error('Failed to check rate limit:', error);
      return false;
    }
  }

  /**
   * Log de l'activité utilisateur
   */
  private async logUserActivity(userId: string, action: string, metadata: any): Promise<void> {
    try {
      const activityKey = this.KEYS.USER_ACTIVITY + userId;
      const activity = {
        action,
        timestamp: Date.now(),
        metadata
      };
      
      await this.client.lpush(activityKey, JSON.stringify(activity));
      await this.client.ltrim(activityKey, 0, 99); // Garde les 100 dernières activités
      await this.client.expire(activityKey, 7 * 24 * 60 * 60); // 7 jours
    } catch (error) {
      this.logger.error('Failed to log user activity:', error);
    }
  }

  /**
   * Nettoyage des données expirées
   */
  public async cleanup(): Promise<void> {
    try {
      // Nettoyage des agents hors ligne
      const cutoffTime = Date.now() - (10 * 60 * 1000); // 10 minutes
      await this.client.zremrangebyscore('erdps:agents:online', 0, cutoffTime);
      
      // Nettoyage des alertes anciennes
      const alertCutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 heures
      await this.client.zremrangebyscore('erdps:alerts:active', 0, alertCutoff);
      
      this.logger.info('Redis cleanup completed');
    } catch (error) {
      this.logger.error('Failed to cleanup Redis:', error);
    }
  }

  /**
   * Statistiques Redis
   */
  public async getStats(): Promise<any> {
    try {
      const info = await this.client.info();
      const dbSize = await this.client.dbsize();
      const memory = await this.client.info('memory');
      
      return {
        connected: this.isConnected,
        dbSize,
        info: info.split('\r\n').reduce((acc, line) => {
          const [key, value] = line.split(':');
          if (key && value) acc[key] = value;
          return acc;
        }, {}),
        memory: memory.split('\r\n').reduce((acc, line) => {
          const [key, value] = line.split(':');
          if (key && value) acc[key] = value;
          return acc;
        }, {})
      };
    } catch (error) {
      this.logger.error('Failed to get Redis stats:', error);
      return { connected: false, error: error.message };
    }
  }

  /**
   * Fermeture propre des connexions
   */
  public async disconnect(): Promise<void> {
    try {
      await Promise.all([
        this.client.quit(),
        this.publisher.quit(),
        this.subscriber.quit()
      ]);
      
      this.isConnected = false;
      this.logger.info('Redis connections closed successfully');
    } catch (error) {
      this.logger.error('Failed to disconnect from Redis:', error);
    }
  }

  /**
   * Vérification de la santé de Redis
   */
  public async healthCheck(): Promise<boolean> {
    try {
      const result = await this.client.ping();
      return result === 'PONG' && this.isConnected;
    } catch (error) {
      this.logger.error('Redis health check failed:', error);
      return false;
    }
  }
}

// Export du singleton
export const redisManager = new RedisManager();
export default redisManager;