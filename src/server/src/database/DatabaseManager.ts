/**
 * Gestionnaire de base de données pour le serveur ERDPS
 * Gère les connexions, migrations, et opérations de base de données
 * 
 * @author ERDPS Security Team
 * @version 1.0.0
 */

import { Knex, knex } from 'knex';
import { DatabaseConfig, PoolConfig } from '../types/config';
import { Logger } from '../utils/Logger';
import { Agent, Threat, SystemEvent, SecurityReport } from '../types/server';
import { createHash } from 'crypto';
import { join } from 'path';
import { existsSync, mkdirSync } from 'fs';

/**
 * Interface pour les statistiques de base de données
 */
export interface DatabaseStats {
  totalConnections: number;
  activeConnections: number;
  idleConnections: number;
  totalQueries: number;
  slowQueries: number;
  averageQueryTime: number;
  lastBackup: Date | null;
  databaseSize: number;
}

/**
 * Interface pour les options de requête
 */
export interface QueryOptions {
  timeout?: number;
  transaction?: Knex.Transaction;
  cache?: boolean;
  cacheTTL?: number;
}

/**
 * Interface pour les résultats paginés
 */
export interface PaginatedResult<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

/**
 * Gestionnaire de base de données principal
 */
export class DatabaseManager {
  private config: DatabaseConfig;
  private logger: Logger;
  private db: Knex | null;
  private connected: boolean;
  private stats: DatabaseStats;
  private queryCache: Map<string, { data: any; expiry: number }>;
  private connectionPool: any;

  constructor(config: DatabaseConfig) {
    this.config = config;
    this.logger = new Logger('DatabaseManager');
    this.db = null;
    this.connected = false;
    this.stats = {
      totalConnections: 0,
      activeConnections: 0,
      idleConnections: 0,
      totalQueries: 0,
      slowQueries: 0,
      averageQueryTime: 0,
      lastBackup: null,
      databaseSize: 0
    };
    this.queryCache = new Map();
  }

  /**
   * Établit la connexion à la base de données
   */
  public async connect(): Promise<void> {
    try {
      this.logger.info('Connexion à la base de données...');

      // Configuration de Knex
      const knexConfig: Knex.Config = {
        client: this.getClientType(),
        connection: this.getConnectionConfig(),
        pool: this.getPoolConfig(),
        migrations: {
          directory: join(process.cwd(), this.config.migrations.directory),
          tableName: this.config.migrations.tableName,
          extension: this.config.migrations.extension
        },
        seeds: {
          directory: join(process.cwd(), 'seeds')
        },
        acquireConnectionTimeout: 60000,
        useNullAsDefault: true,
        debug: process.env.NODE_ENV === 'development'
      };

      // Création de l'instance Knex
      this.db = knex(knexConfig);

      // Test de connexion
      await this.testConnection();

      // Configuration des événements
      this.setupEventListeners();

      // Démarrage du monitoring
      this.startMonitoring();

      this.connected = true;
      this.logger.info('Connexion à la base de données établie');

    } catch (error) {
      this.logger.error('Erreur de connexion à la base de données:', error);
      throw error;
    }
  }

  /**
   * Ferme la connexion à la base de données
   */
  public async disconnect(): Promise<void> {
    if (this.db) {
      this.logger.info('Fermeture de la connexion à la base de données...');
      await this.db.destroy();
      this.db = null;
      this.connected = false;
      this.logger.info('Connexion fermée');
    }
  }

  /**
   * Exécute les migrations de base de données
   */
  public async runMigrations(): Promise<void> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    try {
      this.logger.info('Exécution des migrations...');
      
      const [batchNo, log] = await this.db.migrate.latest();
      
      if (log.length === 0) {
        this.logger.info('Aucune migration à exécuter');
      } else {
        this.logger.info(`Migrations exécutées (batch ${batchNo}):`, log);
      }

    } catch (error) {
      this.logger.error('Erreur lors des migrations:', error);
      throw error;
    }
  }

  /**
   * Valide le schéma de base de données
   */
  public async validateSchema(): Promise<void> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    try {
      this.logger.info('Validation du schéma de base de données...');

      // Vérification des tables principales
      const requiredTables = [
        'agents',
        'threats',
        'events',
        'users',
        'roles',
        'permissions',
        'audit_logs',
        'configurations',
        'reports'
      ];

      for (const table of requiredTables) {
        const exists = await this.db.schema.hasTable(table);
        if (!exists) {
          throw new Error(`Table manquante: ${table}`);
        }
      }

      this.logger.info('Schéma de base de données validé');

    } catch (error) {
      this.logger.error('Erreur de validation du schéma:', error);
      throw error;
    }
  }

  /**
   * Démarre une transaction
   */
  public async beginTransaction(): Promise<Knex.Transaction> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    return this.db.transaction();
  }

  /**
   * Valide une transaction
   */
  public async commitTransaction(trx: Knex.Transaction): Promise<void> {
    await trx.commit();
  }

  /**
   * Annule une transaction
   */
  public async rollbackTransaction(trx: Knex.Transaction): Promise<void> {
    await trx.rollback();
  }

  // ==================== OPÉRATIONS AGENTS ====================

  /**
   * Crée ou met à jour un agent
   */
  public async upsertAgent(agent: Partial<Agent>, options?: QueryOptions): Promise<Agent> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    const query = options?.transaction || this.db;
    
    try {
      const [result] = await query('agents')
        .insert({
          id: agent.id,
          hostname: agent.hostname,
          ip_address: agent.ipAddress,
          mac_address: agent.macAddress,
          version: agent.version,
          operating_system: JSON.stringify(agent.operatingSystem),
          status: agent.status,
          first_seen: agent.firstSeen || new Date(),
          last_seen: agent.lastSeen || new Date(),
          configuration: JSON.stringify(agent.configuration),
          metrics: JSON.stringify(agent.metrics),
          groups: JSON.stringify(agent.groups || []),
          tags: JSON.stringify(agent.tags || {}),
          certificate: JSON.stringify(agent.certificate),
          security_policy: agent.securityPolicy,
          last_config_update: agent.lastConfigUpdate,
          created_at: new Date(),
          updated_at: new Date()
        })
        .onConflict('id')
        .merge({
          hostname: agent.hostname,
          ip_address: agent.ipAddress,
          status: agent.status,
          last_seen: new Date(),
          configuration: JSON.stringify(agent.configuration),
          metrics: JSON.stringify(agent.metrics),
          updated_at: new Date()
        })
        .returning('*');

      this.stats.totalQueries++;
      return this.mapAgentFromDb(result);

    } catch (error) {
      this.logger.error('Erreur lors de la création/mise à jour de l\'agent:', error);
      throw error;
    }
  }

  /**
   * Récupère un agent par ID
   */
  public async getAgent(id: string, options?: QueryOptions): Promise<Agent | null> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    // Vérification du cache
    if (options?.cache) {
      const cached = this.getFromCache(`agent:${id}`);
      if (cached) {
        return cached;
      }
    }

    const query = options?.transaction || this.db;
    
    try {
      const result = await query('agents')
        .where('id', id)
        .first();

      this.stats.totalQueries++;
      
      if (!result) {
        return null;
      }

      const agent = this.mapAgentFromDb(result);
      
      // Mise en cache
      if (options?.cache) {
        this.setCache(`agent:${id}`, agent, options.cacheTTL || 300);
      }

      return agent;

    } catch (error) {
      this.logger.error('Erreur lors de la récupération de l\'agent:', error);
      throw error;
    }
  }

  /**
   * Récupère tous les agents avec pagination
   */
  public async getAgents(
    page: number = 1,
    pageSize: number = 50,
    filters?: any,
    options?: QueryOptions
  ): Promise<PaginatedResult<Agent>> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    const query = options?.transaction || this.db;
    const offset = (page - 1) * pageSize;

    try {
      let baseQuery = query('agents');

      // Application des filtres
      if (filters) {
        if (filters.status) {
          baseQuery = baseQuery.where('status', filters.status);
        }
        if (filters.hostname) {
          baseQuery = baseQuery.where('hostname', 'like', `%${filters.hostname}%`);
        }
        if (filters.groups) {
          baseQuery = baseQuery.whereRaw('JSON_CONTAINS(groups, ?)', [JSON.stringify(filters.groups)]);
        }
      }

      // Récupération du total
      const [{ count }] = await baseQuery.clone().count('* as count');
      const total = parseInt(count as string);

      // Récupération des données
      const results = await baseQuery
        .orderBy('last_seen', 'desc')
        .limit(pageSize)
        .offset(offset);

      this.stats.totalQueries += 2;

      const agents = results.map(result => this.mapAgentFromDb(result));

      return {
        data: agents,
        total,
        page,
        pageSize,
        totalPages: Math.ceil(total / pageSize)
      };

    } catch (error) {
      this.logger.error('Erreur lors de la récupération des agents:', error);
      throw error;
    }
  }

  // ==================== OPÉRATIONS MENACES ====================

  /**
   * Crée une nouvelle menace
   */
  public async createThreat(threat: Partial<Threat>, options?: QueryOptions): Promise<Threat> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    const query = options?.transaction || this.db;
    
    try {
      const [result] = await query('threats')
        .insert({
          id: threat.id,
          agent_id: threat.agentId,
          type: threat.type,
          category: threat.category,
          severity: threat.severity,
          name: threat.name,
          description: threat.description,
          file_path: threat.filePath,
          file_hash: threat.fileHash,
          process_name: threat.processName,
          process_id: threat.processId,
          source_ip: threat.sourceIP,
          source_port: threat.sourcePort,
          destination_ip: threat.destinationIP,
          destination_port: threat.destinationPort,
          detection_rule: threat.detectionRule,
          confidence_score: threat.confidenceScore,
          detected_at: threat.detectedAt || new Date(),
          status: threat.status,
          actions: JSON.stringify(threat.actions || []),
          context: JSON.stringify(threat.context || {}),
          metadata: JSON.stringify(threat.metadata || {}),
          created_at: new Date(),
          updated_at: new Date()
        })
        .returning('*');

      this.stats.totalQueries++;
      return this.mapThreatFromDb(result);

    } catch (error) {
      this.logger.error('Erreur lors de la création de la menace:', error);
      throw error;
    }
  }

  /**
   * Met à jour une menace
   */
  public async updateThreat(
    id: string,
    updates: Partial<Threat>,
    options?: QueryOptions
  ): Promise<Threat | null> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    const query = options?.transaction || this.db;
    
    try {
      const [result] = await query('threats')
        .where('id', id)
        .update({
          status: updates.status,
          actions: JSON.stringify(updates.actions),
          metadata: JSON.stringify(updates.metadata),
          updated_at: new Date()
        })
        .returning('*');

      this.stats.totalQueries++;
      
      if (!result) {
        return null;
      }

      return this.mapThreatFromDb(result);

    } catch (error) {
      this.logger.error('Erreur lors de la mise à jour de la menace:', error);
      throw error;
    }
  }

  /**
   * Récupère les menaces avec pagination
   */
  public async getThreats(
    page: number = 1,
    pageSize: number = 50,
    filters?: any,
    options?: QueryOptions
  ): Promise<PaginatedResult<Threat>> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    const query = options?.transaction || this.db;
    const offset = (page - 1) * pageSize;

    try {
      let baseQuery = query('threats');

      // Application des filtres
      if (filters) {
        if (filters.severity) {
          baseQuery = baseQuery.where('severity', filters.severity);
        }
        if (filters.status) {
          baseQuery = baseQuery.where('status', filters.status);
        }
        if (filters.agentId) {
          baseQuery = baseQuery.where('agent_id', filters.agentId);
        }
        if (filters.dateFrom) {
          baseQuery = baseQuery.where('detected_at', '>=', filters.dateFrom);
        }
        if (filters.dateTo) {
          baseQuery = baseQuery.where('detected_at', '<=', filters.dateTo);
        }
      }

      // Récupération du total
      const [{ count }] = await baseQuery.clone().count('* as count');
      const total = parseInt(count as string);

      // Récupération des données
      const results = await baseQuery
        .orderBy('detected_at', 'desc')
        .limit(pageSize)
        .offset(offset);

      this.stats.totalQueries += 2;

      const threats = results.map(result => this.mapThreatFromDb(result));

      return {
        data: threats,
        total,
        page,
        pageSize,
        totalPages: Math.ceil(total / pageSize)
      };

    } catch (error) {
      this.logger.error('Erreur lors de la récupération des menaces:', error);
      throw error;
    }
  }

  // ==================== OPÉRATIONS ÉVÉNEMENTS ====================

  /**
   * Crée un nouvel événement système
   */
  public async createEvent(event: Partial<SystemEvent>, options?: QueryOptions): Promise<SystemEvent> {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }

    const query = options?.transaction || this.db;
    
    try {
      const [result] = await query('events')
        .insert({
          id: event.id,
          agent_id: event.agentId,
          type: event.type,
          category: event.category,
          timestamp: event.timestamp || new Date(),
          source: event.source,
          message: event.message,
          data: JSON.stringify(event.data || {}),
          severity: event.severity,
          tags: JSON.stringify(event.tags || []),
          correlation_id: event.correlationId,
          created_at: new Date()
        })
        .returning('*');

      this.stats.totalQueries++;
      return this.mapEventFromDb(result);

    } catch (error) {
      this.logger.error('Erreur lors de la création de l\'événement:', error);
      throw error;
    }
  }

  // ==================== MÉTHODES UTILITAIRES ====================

  /**
   * Retourne le type de client de base de données
   */
  private getClientType(): string {
    switch (this.config.type) {
      case 'postgresql':
        return 'pg';
      case 'mysql':
        return 'mysql2';
      case 'sqlite':
        return 'sqlite3';
      default:
        throw new Error(`Type de base de données non supporté: ${this.config.type}`);
    }
  }

  /**
   * Retourne la configuration de connexion
   */
  private getConnectionConfig(): any {
    if (this.config.type === 'sqlite') {
      return {
        filename: this.config.database
      };
    }

    return {
      host: this.config.host,
      port: this.config.port,
      database: this.config.database,
      user: this.config.username,
      password: this.config.password,
      ssl: this.config.ssl
    };
  }

  /**
   * Retourne la configuration du pool de connexions
   */
  private getPoolConfig(): any {
    const pool = this.config.pool;
    return {
      min: pool.min,
      max: pool.max,
      acquireTimeoutMillis: pool.acquireTimeoutMillis,
      idleTimeoutMillis: pool.idleTimeoutMillis,
      reapIntervalMillis: pool.reapIntervalMillis
    };
  }

  /**
   * Test la connexion à la base de données
   */
  private async testConnection(): Promise<void> {
    if (!this.db) {
      throw new Error('Instance de base de données non initialisée');
    }

    try {
      await this.db.raw('SELECT 1');
      this.logger.info('Test de connexion réussi');
    } catch (error) {
      this.logger.error('Échec du test de connexion:', error);
      throw error;
    }
  }

  /**
   * Configure les écouteurs d'événements
   */
  private setupEventListeners(): void {
    if (!this.db) return;

    // Événements de connexion
    this.db.on('query', (query) => {
      this.stats.totalQueries++;
      if (query.sql) {
        const startTime = Date.now();
        query.response = query.response || {};
        query.response.startTime = startTime;
      }
    });

    this.db.on('query-response', (response, query) => {
      if (query.response && query.response.startTime) {
        const duration = Date.now() - query.response.startTime;
        if (duration > 1000) { // Requêtes lentes > 1s
          this.stats.slowQueries++;
          this.logger.warn(`Requête lente détectée (${duration}ms):`, query.sql);
        }
      }
    });

    this.db.on('query-error', (error, query) => {
      this.logger.error('Erreur de requête:', error, query.sql);
    });
  }

  /**
   * Démarre le monitoring de la base de données
   */
  private startMonitoring(): void {
    setInterval(async () => {
      try {
        await this.updateStats();
      } catch (error) {
        this.logger.error('Erreur lors de la mise à jour des statistiques:', error);
      }
    }, 60000); // Toutes les minutes
  }

  /**
   * Met à jour les statistiques de la base de données
   */
  private async updateStats(): Promise<void> {
    if (!this.db) return;

    try {
      // Mise à jour des statistiques de pool
      const pool = (this.db as any).client.pool;
      if (pool) {
        this.stats.activeConnections = pool.numUsed();
        this.stats.idleConnections = pool.numFree();
        this.stats.totalConnections = pool.numUsed() + pool.numFree();
      }

      // Calcul de la taille de la base de données (PostgreSQL)
      if (this.config.type === 'postgresql') {
        const result = await this.db.raw(
          "SELECT pg_size_pretty(pg_database_size(?)) as size",
          [this.config.database]
        );
        if (result.rows && result.rows[0]) {
          this.stats.databaseSize = result.rows[0].size;
        }
      }

    } catch (error) {
      this.logger.debug('Erreur lors de la mise à jour des statistiques:', error);
    }
  }

  /**
   * Mappe un agent depuis la base de données
   */
  private mapAgentFromDb(row: any): Agent {
    return {
      id: row.id,
      hostname: row.hostname,
      ipAddress: row.ip_address,
      macAddress: row.mac_address,
      version: row.version,
      operatingSystem: JSON.parse(row.operating_system || '{}'),
      status: row.status,
      firstSeen: new Date(row.first_seen),
      lastSeen: new Date(row.last_seen),
      configuration: JSON.parse(row.configuration || '{}'),
      metrics: JSON.parse(row.metrics || '{}'),
      groups: JSON.parse(row.groups || '[]'),
      tags: JSON.parse(row.tags || '{}'),
      certificate: JSON.parse(row.certificate || '{}'),
      securityPolicy: row.security_policy,
      lastConfigUpdate: row.last_config_update ? new Date(row.last_config_update) : new Date(),
      recentErrors: JSON.parse(row.recent_errors || '[]')
    };
  }

  /**
   * Mappe une menace depuis la base de données
   */
  private mapThreatFromDb(row: any): Threat {
    return {
      id: row.id,
      agentId: row.agent_id,
      type: row.type,
      category: row.category,
      severity: row.severity,
      name: row.name,
      description: row.description,
      filePath: row.file_path,
      fileHash: row.file_hash,
      processName: row.process_name,
      processId: row.process_id,
      sourceIP: row.source_ip,
      sourcePort: row.source_port,
      destinationIP: row.destination_ip,
      destinationPort: row.destination_port,
      detectionRule: row.detection_rule,
      confidenceScore: row.confidence_score,
      detectedAt: new Date(row.detected_at),
      status: row.status,
      actions: JSON.parse(row.actions || '[]'),
      context: JSON.parse(row.context || '{}'),
      metadata: JSON.parse(row.metadata || '{}')
    };
  }

  /**
   * Mappe un événement depuis la base de données
   */
  private mapEventFromDb(row: any): SystemEvent {
    return {
      id: row.id,
      agentId: row.agent_id,
      type: row.type,
      category: row.category,
      timestamp: new Date(row.timestamp),
      source: row.source,
      message: row.message,
      data: JSON.parse(row.data || '{}'),
      severity: row.severity,
      tags: JSON.parse(row.tags || '[]'),
      correlationId: row.correlation_id
    };
  }

  /**
   * Récupère une valeur du cache
   */
  private getFromCache(key: string): any {
    const cached = this.queryCache.get(key);
    if (cached && cached.expiry > Date.now()) {
      return cached.data;
    }
    this.queryCache.delete(key);
    return null;
  }

  /**
   * Met une valeur en cache
   */
  private setCache(key: string, data: any, ttlSeconds: number): void {
    this.queryCache.set(key, {
      data,
      expiry: Date.now() + (ttlSeconds * 1000)
    });
  }

  /**
   * Vide le cache
   */
  public clearCache(): void {
    this.queryCache.clear();
    this.logger.info('Cache de requêtes vidé');
  }

  /**
   * Retourne les statistiques de la base de données
   */
  public getStats(): DatabaseStats {
    return { ...this.stats };
  }

  /**
   * Vérifie si la base de données est connectée
   */
  public isConnected(): boolean {
    return this.connected && this.db !== null;
  }

  /**
   * Retourne l'instance Knex (pour les requêtes avancées)
   */
  public getKnex(): Knex {
    if (!this.db) {
      throw new Error('Base de données non connectée');
    }
    return this.db;
  }
}

export default DatabaseManager;