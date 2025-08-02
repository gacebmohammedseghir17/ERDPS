/**
 * ERDPS Enterprise Server - Point d'entrée principal
 * Serveur central de gestion des agents de sécurité avec architecture haute disponibilité
 * 
 * @author ERDPS Security Team
 * @version 1.0.0
 * @license Proprietary
 */

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import { createServer } from 'https';
import { readFileSync } from 'fs';
import { join } from 'path';
import dotenv from 'dotenv';
import config from 'config';

// Modules de sécurité et monitoring
import { SecurityManager } from './security/SecurityManager';
import { Logger } from './utils/Logger';
import { DatabaseManager } from './database/DatabaseManager';
import { RedisManager } from './cache/RedisManager';
import { MetricsCollector } from './monitoring/MetricsCollector';
import { AlertManager } from './alerts/AlertManager';

// Routes et middlewares
import { authRoutes } from './routes/auth';
import { agentRoutes } from './routes/agents';
import { threatRoutes } from './routes/threats';
import { dashboardRoutes } from './routes/dashboard';
import { adminRoutes } from './routes/admin';
import { apiRoutes } from './routes/api';
import { webhookRoutes } from './routes/webhooks';

// Middlewares personnalisés
import { authMiddleware } from './middleware/auth';
import { validationMiddleware } from './middleware/validation';
import { auditMiddleware } from './middleware/audit';
import { errorHandler } from './middleware/errorHandler';
import { securityHeaders } from './middleware/security';

// Services
import { AgentManager } from './services/AgentManager';
import { ThreatAnalysisService } from './services/ThreatAnalysisService';
import { NotificationService } from './services/NotificationService';
import { ReportingService } from './services/ReportingService';
import { BackupService } from './services/BackupService';

// WebSocket et gRPC
import { WebSocketManager } from './websocket/WebSocketManager';
import { GrpcServer } from './grpc/GrpcServer';

// Types
import { ServerConfig, SecurityConfig } from './types/config';
import { ServerStatus } from './types/server';

// Configuration de l'environnement
dotenv.config();

/**
 * Classe principale du serveur ERDPS
 * Gère l'initialisation, la configuration et le cycle de vie du serveur
 */
class ERDPSServer {
    private app: express.Application;
    private server: any;
    private config: ServerConfig;
    private securityManager: SecurityManager;
    private logger: Logger;
    private dbManager: DatabaseManager;
    private redisManager: RedisManager;
    private metricsCollector: MetricsCollector;
    private alertManager: AlertManager;
    private agentManager: AgentManager;
    private threatAnalysisService: ThreatAnalysisService;
    private notificationService: NotificationService;
    private reportingService: ReportingService;
    private backupService: BackupService;
    private webSocketManager: WebSocketManager;
    private grpcServer: GrpcServer;
    private status: ServerStatus;
    private startTime: Date;

    constructor() {
        this.app = express();
        this.config = config.get('server');
        this.status = ServerStatus.INITIALIZING;
        this.startTime = new Date();
        this.logger = new Logger('ERDPSServer');
        
        this.logger.info('Initialisation du serveur ERDPS Enterprise...');
    }

    /**
     * Initialise tous les composants du serveur
     */
    public async initialize(): Promise<void> {
        try {
            this.logger.info('Démarrage de l\'initialisation des composants...');

            // 1. Initialisation de la sécurité (priorité absolue)
            await this.initializeSecurity();

            // 2. Initialisation de la base de données
            await this.initializeDatabase();

            // 3. Initialisation du cache Redis
            await this.initializeCache();

            // 4. Initialisation des services métier
            await this.initializeServices();

            // 5. Configuration des middlewares Express
            this.configureMiddlewares();

            // 6. Configuration des routes
            this.configureRoutes();

            // 7. Initialisation WebSocket et gRPC
            await this.initializeProtocols();

            // 8. Initialisation du monitoring
            await this.initializeMonitoring();

            // 9. Configuration de la gestion d'erreurs
            this.configureErrorHandling();

            this.status = ServerStatus.READY;
            this.logger.info('Initialisation terminée avec succès');

        } catch (error) {
            this.logger.error('Erreur lors de l\'initialisation:', error);
            this.status = ServerStatus.ERROR;
            throw error;
        }
    }

    /**
     * Initialise le gestionnaire de sécurité et les certificats TLS
     */
    private async initializeSecurity(): Promise<void> {
        this.logger.info('Initialisation du gestionnaire de sécurité...');
        
        const securityConfig: SecurityConfig = config.get('security');
        this.securityManager = new SecurityManager(securityConfig);
        
        await this.securityManager.initialize();
        await this.securityManager.loadCertificates();
        await this.securityManager.validateConfiguration();
        
        this.logger.info('Gestionnaire de sécurité initialisé');
    }

    /**
     * Initialise la connexion à la base de données
     */
    private async initializeDatabase(): Promise<void> {
        this.logger.info('Initialisation de la base de données...');
        
        this.dbManager = new DatabaseManager(config.get('database'));
        await this.dbManager.connect();
        await this.dbManager.runMigrations();
        await this.dbManager.validateSchema();
        
        this.logger.info('Base de données initialisée');
    }

    /**
     * Initialise la connexion Redis pour le cache
     */
    private async initializeCache(): Promise<void> {
        this.logger.info('Initialisation du cache Redis...');
        
        this.redisManager = new RedisManager(config.get('redis'));
        await this.redisManager.connect();
        await this.redisManager.validateConnection();
        
        this.logger.info('Cache Redis initialisé');
    }

    /**
     * Initialise tous les services métier
     */
    private async initializeServices(): Promise<void> {
        this.logger.info('Initialisation des services métier...');

        // Gestionnaire d'agents
        this.agentManager = new AgentManager(
            this.dbManager,
            this.redisManager,
            this.securityManager
        );
        await this.agentManager.initialize();

        // Service d'analyse des menaces
        this.threatAnalysisService = new ThreatAnalysisService(
            this.dbManager,
            this.redisManager
        );
        await this.threatAnalysisService.initialize();

        // Service de notifications
        this.notificationService = new NotificationService(
            config.get('notifications')
        );
        await this.notificationService.initialize();

        // Service de rapports
        this.reportingService = new ReportingService(
            this.dbManager,
            this.threatAnalysisService
        );
        await this.reportingService.initialize();

        // Service de sauvegarde
        this.backupService = new BackupService(
            this.dbManager,
            config.get('backup')
        );
        await this.backupService.initialize();

        // Gestionnaire d'alertes
        this.alertManager = new AlertManager(
            this.notificationService,
            this.threatAnalysisService
        );
        await this.alertManager.initialize();

        this.logger.info('Services métier initialisés');
    }

    /**
     * Configure tous les middlewares Express
     */
    private configureMiddlewares(): void {
        this.logger.info('Configuration des middlewares...');

        // Sécurité de base
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'"],
                    fontSrc: ["'self'"],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'self'"],
                    frameSrc: ["'none'"]
                }
            },
            hsts: {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: true
            }
        }));

        // Headers de sécurité personnalisés
        this.app.use(securityHeaders);

        // CORS configuré de manière restrictive
        this.app.use(cors({
            origin: this.config.allowedOrigins,
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
        }));

        // Compression
        this.app.use(compression());

        // Rate limiting global
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 1000, // limite par IP
            message: 'Trop de requêtes depuis cette IP',
            standardHeaders: true,
            legacyHeaders: false
        });
        this.app.use(limiter);

        // Logging des requêtes
        this.app.use(morgan('combined', {
            stream: {
                write: (message: string) => {
                    this.logger.info(message.trim());
                }
            }
        }));

        // Parsing JSON avec limite de taille
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

        // Middleware d'audit
        this.app.use(auditMiddleware);

        // Middleware de validation
        this.app.use(validationMiddleware);

        this.logger.info('Middlewares configurés');
    }

    /**
     * Configure toutes les routes de l'API
     */
    private configureRoutes(): void {
        this.logger.info('Configuration des routes...');

        // Route de santé (sans authentification)
        this.app.get('/health', (req, res) => {
            res.json({
                status: this.status,
                uptime: Date.now() - this.startTime.getTime(),
                version: process.env.npm_package_version || '1.0.0',
                timestamp: new Date().toISOString()
            });
        });

        // Routes d'authentification
        this.app.use('/api/auth', authRoutes);

        // Routes protégées (nécessitent une authentification)
        this.app.use('/api/agents', authMiddleware, agentRoutes);
        this.app.use('/api/threats', authMiddleware, threatRoutes);
        this.app.use('/api/dashboard', authMiddleware, dashboardRoutes);
        this.app.use('/api/admin', authMiddleware, adminRoutes);
        this.app.use('/api/v1', authMiddleware, apiRoutes);
        
        // Routes de webhooks (authentification par token)
        this.app.use('/webhooks', webhookRoutes);

        // Route par défaut
        this.app.get('/', (req, res) => {
            res.json({
                name: 'ERDPS Enterprise Server',
                version: '1.0.0',
                status: 'operational',
                documentation: '/api/docs'
            });
        });

        this.logger.info('Routes configurées');
    }

    /**
     * Initialise WebSocket et gRPC
     */
    private async initializeProtocols(): Promise<void> {
        this.logger.info('Initialisation des protocoles de communication...');

        // WebSocket pour les communications temps réel
        this.webSocketManager = new WebSocketManager(
            this.server,
            this.securityManager,
            this.agentManager
        );
        await this.webSocketManager.initialize();

        // gRPC pour les communications avec les agents
        this.grpcServer = new GrpcServer(
            this.securityManager,
            this.agentManager,
            this.threatAnalysisService
        );
        await this.grpcServer.initialize();
        await this.grpcServer.start();

        this.logger.info('Protocoles de communication initialisés');
    }

    /**
     * Initialise le système de monitoring
     */
    private async initializeMonitoring(): Promise<void> {
        this.logger.info('Initialisation du monitoring...');

        this.metricsCollector = new MetricsCollector(
            this.app,
            this.dbManager,
            this.redisManager
        );
        await this.metricsCollector.initialize();
        await this.metricsCollector.startCollection();

        this.logger.info('Monitoring initialisé');
    }

    /**
     * Configure la gestion d'erreurs
     */
    private configureErrorHandling(): void {
        this.logger.info('Configuration de la gestion d\'erreurs...');

        // Gestionnaire d'erreurs global
        this.app.use(errorHandler);

        // Gestion des erreurs non capturées
        process.on('uncaughtException', (error) => {
            this.logger.error('Exception non capturée:', error);
            this.gracefulShutdown('uncaughtException');
        });

        process.on('unhandledRejection', (reason, promise) => {
            this.logger.error('Promesse rejetée non gérée:', reason);
            this.gracefulShutdown('unhandledRejection');
        });

        // Gestion des signaux système
        process.on('SIGTERM', () => this.gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => this.gracefulShutdown('SIGINT'));

        this.logger.info('Gestion d\'erreurs configurée');
    }

    /**
     * Démarre le serveur HTTPS
     */
    public async start(): Promise<void> {
        try {
            const tlsOptions = {
                key: readFileSync(join(process.cwd(), this.config.ssl.keyPath)),
                cert: readFileSync(join(process.cwd(), this.config.ssl.certPath)),
                ca: this.config.ssl.caPath ? 
                    readFileSync(join(process.cwd(), this.config.ssl.caPath)) : undefined,
                requestCert: true,
                rejectUnauthorized: true,
                secureProtocol: 'TLSv1_3_method',
                ciphers: [
                    'TLS_AES_256_GCM_SHA384',
                    'TLS_CHACHA20_POLY1305_SHA256',
                    'TLS_AES_128_GCM_SHA256'
                ].join(':')
            };

            this.server = createServer(tlsOptions, this.app);

            this.server.listen(this.config.port, this.config.host, () => {
                this.status = ServerStatus.RUNNING;
                this.logger.info(
                    `Serveur ERDPS démarré sur https://${this.config.host}:${this.config.port}`
                );
                this.logger.info('Serveur prêt à recevoir les connexions des agents');
            });

            this.server.on('error', (error: any) => {
                this.logger.error('Erreur du serveur:', error);
                this.status = ServerStatus.ERROR;
            });

        } catch (error) {
            this.logger.error('Erreur lors du démarrage du serveur:', error);
            this.status = ServerStatus.ERROR;
            throw error;
        }
    }

    /**
     * Arrêt gracieux du serveur
     */
    private async gracefulShutdown(signal: string): Promise<void> {
        this.logger.info(`Signal ${signal} reçu, arrêt gracieux en cours...`);
        this.status = ServerStatus.SHUTTING_DOWN;

        try {
            // Arrêt des nouveaux connexions
            if (this.server) {
                this.server.close();
            }

            // Arrêt des services
            if (this.grpcServer) {
                await this.grpcServer.stop();
            }

            if (this.webSocketManager) {
                await this.webSocketManager.shutdown();
            }

            if (this.metricsCollector) {
                await this.metricsCollector.stop();
            }

            if (this.backupService) {
                await this.backupService.stop();
            }

            // Fermeture des connexions
            if (this.redisManager) {
                await this.redisManager.disconnect();
            }

            if (this.dbManager) {
                await this.dbManager.disconnect();
            }

            this.logger.info('Arrêt gracieux terminé');
            process.exit(0);

        } catch (error) {
            this.logger.error('Erreur lors de l\'arrêt gracieux:', error);
            process.exit(1);
        }
    }

    /**
     * Retourne le statut actuel du serveur
     */
    public getStatus(): ServerStatus {
        return this.status;
    }

    /**
     * Retourne les métriques du serveur
     */
    public getMetrics(): any {
        return this.metricsCollector ? this.metricsCollector.getMetrics() : null;
    }
}

/**
 * Point d'entrée principal
 */
async function main(): Promise<void> {
    const server = new ERDPSServer();
    
    try {
        await server.initialize();
        await server.start();
    } catch (error) {
        console.error('Erreur fatale lors du démarrage:', error);
        process.exit(1);
    }
}

// Démarrage du serveur si ce fichier est exécuté directement
if (require.main === module) {
    main().catch((error) => {
        console.error('Erreur lors du démarrage:', error);
        process.exit(1);
    });
}

export { ERDPSServer };
export default ERDPSServer;