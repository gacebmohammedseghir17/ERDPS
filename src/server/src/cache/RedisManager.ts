/**
 * Gestionnaire Redis pour le cache et les sessions ERDPS
 * Gère les connexions Redis, le cache distribué et les sessions
 * 
 * @author ERDPS Security Team
 * @version 1.0.0
 */

import Redis, { RedisOptions, Cluster } from 'ioredis';
import { RedisConfig, RedisClusterConfig, RedisSentinelConfig } from '../types/config';
import { Logger } from '../utils/Logger';
import { createHash } from 'crypto';

/**
 * Interface pour les statistiques Redis
 */
export interface RedisStats {
  connectedClients: number;
  usedMemory: number;
  totalKeys: number;
  hitRate: number;
  missRate: number;
  totalCommands: number;
  commandsPerSecond: number;
  uptime: number;
  lastUpdate: Date;
}

/**
 * Interface pour les options de cache
 */
export interface CacheOptions {
  ttl?: number; // Time to live en secondes
  compress?: boolean;
  serialize?: boolean;
  namespace?: string;
}

/**
 * Interface pour les données de session
 */
export interface SessionData {
  userId: string;
  username: string;
  roles: string[];
  permissions: string[];
  ipAddress: string;
  userAgent: string;
  loginTime: Date;
  lastActivity: Date;
  mfaVerified: boolean;
  metadata?: Record<string, any>;
}

/**
 * Interface pour les métriques en temps réel
 */
export interface RealtimeMetrics {
  timestamp: Date;
  activeAgents: number;
  threatsDetected: number;
  systemLoad: number;
  networkTraffic: number;
  alertsGenerated: number;
}

/**
 * Gestionnaire Redis principal
 */
export class RedisManager {
  private config: RedisConfig;
  private logger: Logger;
  private client: Redis | Cluster | null;
  private subscriber: Redis | null;
  private publisher: Redis | null;
  private connected: boolean;
  private stats: RedisStats;
  private commandCount: number;
  private hitCount: number;
  private missCount: number;
  private lastStatsUpdate: Date;

  constructor(config: RedisConfig) {
    this.config = config;
    this.logger = new Logger('RedisManager');
    this.client = null;
    this.subscriber = null;
    this.publisher = null;
    this.connected = false;
    this.commandCount = 0;
    this.hitCount = 0;
    this.missCount = 0;
    this.lastStatsUpdate = new Date();
    this.stats = {
      connectedClients: 0,
      usedMemory: 0,
      totalKeys: 0,
      hitRate: 0,
      missRate: 0,
      totalCommands: 0,
      commandsPerSecond: 0,
      uptime: 0,
      lastUpdate: new Date()
    };
  }

  /**
   * Établit la connexion à Redis
   */
  public async connect(): Promise<void> {
    try {
      this.logger.info('Connexion à Redis...');

      // Configuration de base
      const baseOptions: RedisOptions = {
        connectTimeout: this.config.connectTimeout,
        commandTimeout: this.config.commandTimeout,
        retryDelayOnFailover: this.config.retryDelay,
        maxRetriesPerRequest: this.config.retryAttempts,
        lazyConnect: true,
        keepAlive: 30000,
        family: 4,
        db: this.config.db
      };

      // Connexion selon le type de configuration
      if (this.config.cluster) {
        this.client = await this.connectCluster(baseOptions);
      } else if (this.config.sentinel) {
        this.client = await this.connectSentinel(baseOptions);
      } else {
        this.client = await this.connectStandalone(baseOptions);
      }

      // Configuration des événements
      this.setupEventListeners();

      // Connexion effective
      await this.client.connect();

      // Création des clients pub/sub
      await this.setupPubSub();

      // Test de connexion
      await this.validateConnection();

      // Démarrage du monitoring
      this.startMonitoring();

      this.connected = true;
      this.logger.info('Connexion à Redis établie');

    } catch (error) {
      this.logger.error('Erreur de connexion à Redis:', error);
      throw error;
    }
  }

  /**
   * Ferme la connexion à Redis
   */
  public async disconnect(): Promise<void> {
    if (this.client) {
      this.logger.info('Fermeture de la connexion à Redis...');
      
      if (this.subscriber) {
        await this.subscriber.disconnect();
      }
      
      if (this.publisher) {
        await this.publisher.disconnect();
      }
      
      await this.client.disconnect();
      
      this.client = null;
      this.subscriber = null;
      this.publisher = null;
      this.connected = false;
      
      this.logger.info('Connexion Redis fermée');
    }
  }

  /**
   * Valide la connexion Redis
   */
  public async validateConnection(): Promise<void> {
    if (!this.client) {
      throw new Error('Client Redis non initialisé');
    }

    try {
      const result = await this.client.ping();
      if (result !== 'PONG') {
        throw new Error('Réponse ping invalide');
      }
      this.logger.info('Validation de connexion Redis réussie');
    } catch (error) {
      this.logger.error('Échec de validation de connexion Redis:', error);
      throw error;
    }
  }

  // ==================== OPÉRATIONS DE CACHE ====================

  /**
   * Stocke une valeur dans le cache
   */
  public async set(
    key: string,
    value: any,
    options: CacheOptions = {}
  ): Promise<void> {
    if (!this.client) {
      throw new Error('Redis non connecté');
    }

    try {
      const finalKey = this.buildKey(key, options.namespace);
      let serializedValue: string;

      // Sérialisation
      if (options.serialize !== false) {
        serializedValue = JSON.stringify(value);
      } else {
        serializedValue = value.toString();
      }

      // Compression (si activée)
      if (options.compress) {
        serializedValue = await this.compress(serializedValue);
      }

      // Stockage avec TTL
      if (options.ttl) {
        await this.client.setex(finalKey, options.ttl, serializedValue);
      } else {
        await this.client.set(finalKey, serializedValue);
      }

      this.commandCount++;
      this.logger.debug(`Valeur stockée en cache: ${finalKey}`);

    } catch (error) {
      this.logger.error('Erreur lors du stockage en cache:', error);
      throw error;
    }
  }

  /**
   * Récupère une valeur du cache
   */
  public async get<T = any>(
    key: string,
    options: CacheOptions = {}
  ): Promise<T | null> {
    if (!this.client) {
      throw new Error('Redis non connecté');
    }

    try {
      const finalKey = this.buildKey(key, options.namespace);
      let value = await this.client.get(finalKey);

      this.commandCount++;

      if (value === null) {
        this.missCount++;
        return null;
      }

      this.hitCount++;

      // Décompression (si nécessaire)
      if (options.compress) {
        value = await this.decompress(value);
      }

      // Désérialisation
      if (options.serialize !== false) {
        return JSON.parse(value);
      } else {
        return value as T;
      }

    } catch (error) {
      this.logger.error('Erreur lors de la récupération du cache:', error);
      this.missCount++;
      return null;
    }
  }

  /**
   * Supprime une clé du cache
   */
  public async del(key: string, namespace?: string): Promise<boolean> {
    if (!this.client) {
      throw new Error('Redis non connecté');
    }

    try {
      const finalKey = this.buildKey(key, namespace);
      const result = await this.client.del(finalKey);
      this.commandCount++;
      return result > 0;
    } catch (error) {
      this.logger.error('Erreur lors de la suppression du cache:', error);
      return false;
    }
  }

  /**
   * Vérifie l'existence d'une clé
   */
  public async exists(key: string, namespace?: string): Promise<boolean> {
    if (!this.client) {
      throw new Error('Redis non connecté');
    }

    try {
      const finalKey = this.buildKey(key, namespace);
      const result = await this.client.exists(finalKey);
      this.commandCount++;
      return result > 0;
    } catch (error) {
      this.logger.error('Erreur lors de la vérification d\'existence:', error);
      return false;
    }
  }

  /**
   * Définit l'expiration d'une clé
   */
  public async expire(key: string, seconds: number, namespace?: string): Promise<boolean> {
    if (!this.client) {
      throw new Error('Redis non connecté');
    }

    try {
      const finalKey = this.buildKey(key, namespace);
      const result = await this.client.expire(finalKey, seconds);
      this.commandCount++;
      return result === 1;
    } catch (error) {
      this.logger.error('Erreur lors de la définition d\'expiration:', error);
      return false;
    }
  }

  // ==================== GESTION DES SESSIONS ====================

  /**
   * Stocke une session
   */
  public async setSession(
    sessionId: string,
    sessionData: SessionData,
    ttl: number = 86400 // 24 heures par défaut
  ): Promise<void> {
    await this.set(`session:${sessionId}`, sessionData, {
      ttl,
      namespace: 'sessions',
      serialize: true
    });
  }

  /**
   * Récupère une session
   */
  public async getSession(sessionId: string): Promise<SessionData | null> {
    return await this.get<SessionData>(`session:${sessionId}`, {
      namespace: 'sessions',
      serialize: true
    });
  }

  /**
   * Supprime une session
   */
  public async deleteSession(sessionId: string): Promise<boolean> {
    return await this.del(`session:${sessionId}`, 'sessions');
  }

  /**
   * Met à jour l'activité d'une session
   */
  public async updateSessionActivity(
    sessionId: string,
    ttl: number = 86400
  ): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      session.lastActivity = new Date();
      await this.setSession(sessionId, session, ttl);
    }
  }

  // ==================== MÉTRIQUES TEMPS RÉEL ====================

  /**
   * Stocke des métriques en temps réel
   */
  public async setRealtimeMetrics(metrics: RealtimeMetrics): Promise<void> {
    const key = `metrics:${Date.now()}`;
    await this.set(key, metrics, {
      ttl: 3600, // 1 heure
      namespace: 'realtime'
    });

    // Maintenir seulement les 100 dernières métriques
    await this.trimRealtimeMetrics();
  }

  /**
   * Récupère les métriques récentes
   */
  public async getRecentMetrics(limit: number = 50): Promise<RealtimeMetrics[]> {
    if (!this.client) {
      throw new Error('Redis non connecté');
    }

    try {
      const pattern = this.buildKey('metrics:*', 'realtime');
      const keys = await this.client.keys(pattern);
      
      // Tri par timestamp (plus récent en premier)
      keys.sort((a, b) => {
        const timestampA = parseInt(a.split(':').pop() || '0');
        const timestampB = parseInt(b.split(':').pop() || '0');
        return timestampB - timestampA;
      });

      const limitedKeys = keys.slice(0, limit);
      const metrics: RealtimeMetrics[] = [];

      for (const key of limitedKeys) {
        const data = await this.client.get(key);
        if (data) {
          metrics.push(JSON.parse(data));
        }
      }

      return metrics;

    } catch (error) {
      this.logger.error('Erreur lors de la récupération des métriques:', error);
      return [];
    }
  }

  // ==================== PUB/SUB ====================

  /**
   * Publie un message
   */
  public async publish(channel: string, message: any): Promise<number> {
    if (!this.publisher) {
      throw new Error('Publisher Redis non initialisé');
    }

    try {
      const serializedMessage = JSON.stringify(message);
      const result = await this.publisher.publish(channel, serializedMessage);
      this.commandCount++;
      return result;
    } catch (error) {
      this.logger.error('Erreur lors de la publication:', error);
      throw error;
    }
  }

  /**
   * S'abonne à un canal
   */
  public async subscribe(
    channel: string,
    callback: (message: any) => void
  ): Promise<void> {
    if (!this.subscriber) {
      throw new Error('Subscriber Redis non initialisé');
    }

    try {
      await this.subscriber.subscribe(channel);
      
      this.subscriber.on('message', (receivedChannel, message) => {
        if (receivedChannel === channel) {
          try {
            const parsedMessage = JSON.parse(message);
            callback(parsedMessage);
          } catch (error) {
            this.logger.error('Erreur de parsing du message:', error);
          }
        }
      });

      this.logger.info(`Abonné au canal: ${channel}`);

    } catch (error) {
      this.logger.error('Erreur lors de l\'abonnement:', error);
      throw error;
    }
  }

  /**
   * Se désabonne d'un canal
   */
  public async unsubscribe(channel: string): Promise<void> {
    if (!this.subscriber) {
      throw new Error('Subscriber Redis non initialisé');
    }

    try {
      await this.subscriber.unsubscribe(channel);
      this.logger.info(`Désabonné du canal: ${channel}`);
    } catch (error) {
      this.logger.error('Erreur lors du désabonnement:', error);
      throw error;
    }
  }

  // ==================== MÉTHODES PRIVÉES ====================

  /**
   * Connexion standalone
   */
  private async connectStandalone(baseOptions: RedisOptions): Promise<Redis> {
    const options: RedisOptions = {
      ...baseOptions,
      host: this.config.host,
      port: this.config.port,
      password: this.config.password
    };

    return new Redis(options);
  }

  /**
   * Connexion cluster
   */
  private async connectCluster(baseOptions: RedisOptions): Promise<Cluster> {
    if (!this.config.cluster) {
      throw new Error('Configuration cluster manquante');
    }

    const clusterOptions = {
      ...baseOptions,
      ...this.config.cluster.options
    };

    return new Redis.Cluster(this.config.cluster.nodes, clusterOptions);
  }

  /**
   * Connexion sentinel
   */
  private async connectSentinel(baseOptions: RedisOptions): Promise<Redis> {
    if (!this.config.sentinel) {
      throw new Error('Configuration sentinel manquante');
    }

    const options: RedisOptions = {
      ...baseOptions,
      sentinels: this.config.sentinel.sentinels,
      name: this.config.sentinel.name,
      password: this.config.password,
      ...this.config.sentinel.options
    };

    return new Redis(options);
  }

  /**
   * Configure les clients pub/sub
   */
  private async setupPubSub(): Promise<void> {
    // Création du publisher
    if (this.config.cluster) {
      this.publisher = new Redis.Cluster(
        this.config.cluster.nodes,
        this.config.cluster.options
      );
    } else {
      this.publisher = new Redis({
        host: this.config.host,
        port: this.config.port,
        password: this.config.password,
        db: this.config.db
      });
    }

    // Création du subscriber
    if (this.config.cluster) {
      this.subscriber = new Redis.Cluster(
        this.config.cluster.nodes,
        this.config.cluster.options
      );
    } else {
      this.subscriber = new Redis({
        host: this.config.host,
        port: this.config.port,
        password: this.config.password,
        db: this.config.db
      });
    }

    await this.publisher.connect();
    await this.subscriber.connect();
  }

  /**
   * Configure les écouteurs d'événements
   */
  private setupEventListeners(): void {
    if (!this.client) return;

    this.client.on('connect', () => {
      this.logger.info('Redis connecté');
    });

    this.client.on('ready', () => {
      this.logger.info('Redis prêt');
    });

    this.client.on('error', (error) => {
      this.logger.error('Erreur Redis:', error);
    });

    this.client.on('close', () => {
      this.logger.warn('Connexion Redis fermée');
    });

    this.client.on('reconnecting', () => {
      this.logger.info('Reconnexion Redis en cours...');
    });
  }

  /**
   * Démarre le monitoring
   */
  private startMonitoring(): void {
    setInterval(async () => {
      try {
        await this.updateStats();
      } catch (error) {
        this.logger.error('Erreur lors de la mise à jour des statistiques:', error);
      }
    }, 30000); // Toutes les 30 secondes
  }

  /**
   * Met à jour les statistiques
   */
  private async updateStats(): Promise<void> {
    if (!this.client) return;

    try {
      const info = await this.client.info();
      const lines = info.split('\r\n');
      const stats: any = {};

      for (const line of lines) {
        const [key, value] = line.split(':');
        if (key && value) {
          stats[key] = value;
        }
      }

      // Mise à jour des statistiques
      this.stats.connectedClients = parseInt(stats.connected_clients || '0');
      this.stats.usedMemory = parseInt(stats.used_memory || '0');
      this.stats.totalKeys = await this.client.dbsize();
      this.stats.uptime = parseInt(stats.uptime_in_seconds || '0');
      this.stats.totalCommands = this.commandCount;

      // Calcul des taux
      const now = new Date();
      const timeDiff = (now.getTime() - this.lastStatsUpdate.getTime()) / 1000;
      this.stats.commandsPerSecond = this.commandCount / timeDiff;
      
      const totalRequests = this.hitCount + this.missCount;
      if (totalRequests > 0) {
        this.stats.hitRate = (this.hitCount / totalRequests) * 100;
        this.stats.missRate = (this.missCount / totalRequests) * 100;
      }

      this.stats.lastUpdate = now;
      this.lastStatsUpdate = now;

    } catch (error) {
      this.logger.debug('Erreur lors de la mise à jour des statistiques:', error);
    }
  }

  /**
   * Construit une clé avec namespace
   */
  private buildKey(key: string, namespace?: string): string {
    const prefix = 'erdps';
    if (namespace) {
      return `${prefix}:${namespace}:${key}`;
    }
    return `${prefix}:${key}`;
  }

  /**
   * Compresse une chaîne
   */
  private async compress(data: string): Promise<string> {
    // Implémentation simple avec base64 (à remplacer par une vraie compression)
    return Buffer.from(data).toString('base64');
  }

  /**
   * Décompresse une chaîne
   */
  private async decompress(data: string): Promise<string> {
    // Implémentation simple avec base64 (à remplacer par une vraie décompression)
    return Buffer.from(data, 'base64').toString('utf8');
  }

  /**
   * Nettoie les anciennes métriques
   */
  private async trimRealtimeMetrics(): Promise<void> {
    if (!this.client) return;

    try {
      const pattern = this.buildKey('metrics:*', 'realtime');
      const keys = await this.client.keys(pattern);
      
      if (keys.length > 100) {
        // Tri par timestamp
        keys.sort((a, b) => {
          const timestampA = parseInt(a.split(':').pop() || '0');
          const timestampB = parseInt(b.split(':').pop() || '0');
          return timestampA - timestampB;
        });

        // Suppression des plus anciennes
        const toDelete = keys.slice(0, keys.length - 100);
        if (toDelete.length > 0) {
          await this.client.del(...toDelete);
        }
      }
    } catch (error) {
      this.logger.error('Erreur lors du nettoyage des métriques:', error);
    }
  }

  /**
   * Retourne les statistiques Redis
   */
  public getStats(): RedisStats {
    return { ...this.stats };
  }

  /**
   * Vérifie si Redis est connecté
   */
  public isConnected(): boolean {
    return this.connected && this.client !== null;
  }

  /**
   * Vide tout le cache
   */
  public async flushAll(): Promise<void> {
    if (!this.client) {
      throw new Error('Redis non connecté');
    }

    await this.client.flushall();
    this.logger.warn('Cache Redis vidé complètement');
  }

  /**
   * Retourne l'instance Redis (pour les opérations avancées)
   */
  public getClient(): Redis | Cluster | null {
    return this.client;
  }
}

export default RedisManager;