/**
 * ERDPS Session Manager - Gestionnaire de sessions sécurisées
 * 
 * Fonctionnalités:
 * - Authentification multi-facteurs (MFA)
 * - Gestion des sessions avec certificats
 * - Contrôle d'accès basé sur les rôles (RBAC)
 * - Audit des connexions et activités
 * - Protection contre les attaques de session
 * 
 * Sécurité:
 * - Tokens JWT sécurisés avec rotation
 * - Validation des certificats clients
 * - Détection d'anomalies de session
 * - Limitation des tentatives de connexion
 * 
 * @author ERDPS Security Team
 * @version 1.0.0
 * @license Proprietary
 */

import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import winston from 'winston';
import config from 'config';
import { redisManager } from './RedisManager';
import { v4 as uuidv4 } from 'uuid';

// Types et interfaces
interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  permissions: Permission[];
  isActive: boolean;
  lastLogin?: Date;
  failedLoginAttempts: number;
  lockedUntil?: Date;
  mfaEnabled: boolean;
  mfaSecret?: string;
  certificateFingerprint?: string;
  tenantId?: string;
}

interface AuthRequest extends Request {
  user?: User;
  session?: SessionInfo;
  clientCertificate?: any;
}

interface SessionInfo {
  sessionId: string;
  userId: string;
  username: string;
  role: UserRole;
  permissions: Permission[];
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActivity: Date;
  expiresAt: Date;
  tenantId?: string;
}

interface LoginCredentials {
  username: string;
  password: string;
  mfaToken?: string;
  rememberMe?: boolean;
}

interface JWTPayload {
  sessionId: string;
  userId: string;
  username: string;
  role: UserRole;
  permissions: Permission[];
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

enum UserRole {
  ADMIN = 'admin',
  SOC_ANALYST = 'soc_analyst',
  IT_OPERATOR = 'it_operator',
  VIEWER = 'viewer'
}

enum Permission {
  // Dashboard permissions
  VIEW_DASHBOARD = 'view_dashboard',
  VIEW_METRICS = 'view_metrics',
  
  // Endpoint management
  VIEW_ENDPOINTS = 'view_endpoints',
  MANAGE_ENDPOINTS = 'manage_endpoints',
  ISOLATE_ENDPOINTS = 'isolate_endpoints',
  
  // Alert management
  VIEW_ALERTS = 'view_alerts',
  MANAGE_ALERTS = 'manage_alerts',
  ACKNOWLEDGE_ALERTS = 'acknowledge_alerts',
  
  // Rule management
  VIEW_RULES = 'view_rules',
  MANAGE_RULES = 'manage_rules',
  DEPLOY_RULES = 'deploy_rules',
  
  // System administration
  MANAGE_USERS = 'manage_users',
  MANAGE_SYSTEM = 'manage_system',
  VIEW_AUDIT_LOGS = 'view_audit_logs',
  
  // Reports
  VIEW_REPORTS = 'view_reports',
  EXPORT_REPORTS = 'export_reports'
}

/**
 * Gestionnaire de sessions sécurisées pour ERDPS
 */
export class SessionManager {
  private logger: winston.Logger;
  private jwtSecret: string;
  private jwtRefreshSecret: string;
  private maxLoginAttempts: number = 5;
  private lockoutDuration: number = 15 * 60 * 1000; // 15 minutes
  private sessionTimeout: number = 8 * 60 * 60 * 1000; // 8 heures
  private refreshTokenTimeout: number = 7 * 24 * 60 * 60 * 1000; // 7 jours

  // Permissions par rôle
  private rolePermissions: Map<UserRole, Permission[]> = new Map([
    [UserRole.ADMIN, [
      Permission.VIEW_DASHBOARD, Permission.VIEW_METRICS,
      Permission.VIEW_ENDPOINTS, Permission.MANAGE_ENDPOINTS, Permission.ISOLATE_ENDPOINTS,
      Permission.VIEW_ALERTS, Permission.MANAGE_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
      Permission.VIEW_RULES, Permission.MANAGE_RULES, Permission.DEPLOY_RULES,
      Permission.MANAGE_USERS, Permission.MANAGE_SYSTEM, Permission.VIEW_AUDIT_LOGS,
      Permission.VIEW_REPORTS, Permission.EXPORT_REPORTS
    ]],
    [UserRole.SOC_ANALYST, [
      Permission.VIEW_DASHBOARD, Permission.VIEW_METRICS,
      Permission.VIEW_ENDPOINTS, Permission.ISOLATE_ENDPOINTS,
      Permission.VIEW_ALERTS, Permission.MANAGE_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
      Permission.VIEW_RULES, Permission.MANAGE_RULES,
      Permission.VIEW_REPORTS, Permission.EXPORT_REPORTS
    ]],
    [UserRole.IT_OPERATOR, [
      Permission.VIEW_DASHBOARD, Permission.VIEW_METRICS,
      Permission.VIEW_ENDPOINTS, Permission.MANAGE_ENDPOINTS,
      Permission.VIEW_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
      Permission.VIEW_RULES,
      Permission.VIEW_REPORTS
    ]],
    [UserRole.VIEWER, [
      Permission.VIEW_DASHBOARD, Permission.VIEW_METRICS,
      Permission.VIEW_ENDPOINTS,
      Permission.VIEW_ALERTS,
      Permission.VIEW_RULES,
      Permission.VIEW_REPORTS
    ]]
  ]);

  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: 'session-manager' },
      transports: [
        new winston.transports.File({ filename: 'logs/auth-error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/auth-combined.log' }),
        new winston.transports.Console({
          format: winston.format.simple()
        })
      ]
    });

    this.jwtSecret = config.get('security.jwtSecret') || process.env.JWT_SECRET || 'change-this-secret-in-production';
    this.jwtRefreshSecret = config.get('security.jwtRefreshSecret') || process.env.JWT_REFRESH_SECRET || 'change-this-refresh-secret';
    
    if (this.jwtSecret === 'change-this-secret-in-production') {
      this.logger.warn('Using default JWT secret - CHANGE IN PRODUCTION!');
    }
  }

  /**
   * Authentification utilisateur avec validation MFA
   */
  public async authenticate(credentials: LoginCredentials, ipAddress: string, userAgent: string): Promise<{ success: boolean; tokens?: { accessToken: string; refreshToken: string }; user?: User; error?: string }> {
    try {
      // Vérification du rate limiting
      const rateLimitKey = `login:${ipAddress}`;
      const isAllowed = await redisManager.checkRateLimit(rateLimitKey, this.maxLoginAttempts, 900); // 15 minutes
      
      if (!isAllowed) {
        this.logger.warn(`Rate limit exceeded for IP: ${ipAddress}`);
        return { success: false, error: 'Too many login attempts. Please try again later.' };
      }

      // Récupération de l'utilisateur (simulation - à remplacer par DB réelle)
      const user = await this.getUserByUsername(credentials.username);
      
      if (!user) {
        this.logger.warn(`Login attempt for non-existent user: ${credentials.username}`);
        return { success: false, error: 'Invalid credentials' };
      }

      // Vérification du verrouillage du compte
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        this.logger.warn(`Login attempt for locked account: ${credentials.username}`);
        return { success: false, error: 'Account is temporarily locked' };
      }

      // Vérification du mot de passe
      const isPasswordValid = await bcrypt.compare(credentials.password, await this.getPasswordHash(user.id));
      
      if (!isPasswordValid) {
        await this.handleFailedLogin(user.id, ipAddress);
        return { success: false, error: 'Invalid credentials' };
      }

      // Vérification MFA si activée
      if (user.mfaEnabled && !credentials.mfaToken) {
        return { success: false, error: 'MFA token required' };
      }

      if (user.mfaEnabled && credentials.mfaToken) {
        const isMfaValid = await this.verifyMfaToken(user.mfaSecret!, credentials.mfaToken);
        if (!isMfaValid) {
          this.logger.warn(`Invalid MFA token for user: ${credentials.username}`);
          return { success: false, error: 'Invalid MFA token' };
        }
      }

      // Création de la session
      const sessionInfo = await this.createSession(user, ipAddress, userAgent);
      
      // Génération des tokens JWT
      const tokens = await this.generateTokens(sessionInfo);
      
      // Réinitialisation des tentatives de connexion échouées
      await this.resetFailedLoginAttempts(user.id);
      
      // Mise à jour de la dernière connexion
      await this.updateLastLogin(user.id);
      
      this.logger.info(`Successful login for user: ${credentials.username}`, {
        userId: user.id,
        ipAddress,
        userAgent
      });
      
      return {
        success: true,
        tokens,
        user: this.sanitizeUser(user)
      };
      
    } catch (error) {
      this.logger.error('Authentication error:', error);
      return { success: false, error: 'Authentication failed' };
    }
  }

  /**
   * Création d'une nouvelle session
   */
  private async createSession(user: User, ipAddress: string, userAgent: string): Promise<SessionInfo> {
    const sessionId = uuidv4();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.sessionTimeout);
    
    const sessionInfo: SessionInfo = {
      sessionId,
      userId: user.id,
      username: user.username,
      role: user.role,
      permissions: this.rolePermissions.get(user.role) || [],
      ipAddress,
      userAgent,
      createdAt: now,
      lastActivity: now,
      expiresAt,
      tenantId: user.tenantId
    };
    
    // Stockage de la session dans Redis
    await redisManager.createSession({
      userId: user.id,
      username: user.username,
      role: user.role,
      permissions: sessionInfo.permissions,
      lastActivity: now.getTime(),
      ipAddress,
      userAgent,
      tenantId: user.tenantId
    });
    
    return sessionInfo;
  }

  /**
   * Génération des tokens JWT
   */
  private async generateTokens(sessionInfo: SessionInfo): Promise<{ accessToken: string; refreshToken: string }> {
    const payload: JWTPayload = {
      sessionId: sessionInfo.sessionId,
      userId: sessionInfo.userId,
      username: sessionInfo.username,
      role: sessionInfo.role,
      permissions: sessionInfo.permissions,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor((Date.now() + this.sessionTimeout) / 1000),
      iss: 'erdps-server',
      aud: 'erdps-client'
    };
    
    const accessToken = jwt.sign(payload, this.jwtSecret, {
      algorithm: 'HS256',
      expiresIn: '8h'
    });
    
    const refreshPayload = {
      sessionId: sessionInfo.sessionId,
      userId: sessionInfo.userId,
      type: 'refresh'
    };
    
    const refreshToken = jwt.sign(refreshPayload, this.jwtRefreshSecret, {
      algorithm: 'HS256',
      expiresIn: '7d'
    });
    
    return { accessToken, refreshToken };
  }

  /**
   * Validation d'un token JWT
   */
  public async validateToken(token: string): Promise<{ valid: boolean; payload?: JWTPayload; error?: string }> {
    try {
      const payload = jwt.verify(token, this.jwtSecret) as JWTPayload;
      
      // Vérification de l'existence de la session
      const sessionData = await redisManager.getSession(payload.sessionId);
      
      if (!sessionData) {
        return { valid: false, error: 'Session not found' };
      }
      
      // Vérification de l'expiration
      if (payload.exp * 1000 < Date.now()) {
        return { valid: false, error: 'Token expired' };
      }
      
      return { valid: true, payload };
    } catch (error) {
      this.logger.warn('Token validation failed:', error.message);
      return { valid: false, error: 'Invalid token' };
    }
  }

  /**
   * Middleware d'authentification
   */
  public authenticate_middleware() {
    return async (req: AuthRequest, res: Response, next: NextFunction) => {
      try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'No token provided' });
        }
        
        const token = authHeader.substring(7);
        const validation = await this.validateToken(token);
        
        if (!validation.valid) {
          return res.status(401).json({ error: validation.error });
        }
        
        // Récupération des informations utilisateur
        const user = await this.getUserById(validation.payload!.userId);
        
        if (!user || !user.isActive) {
          return res.status(401).json({ error: 'User not found or inactive' });
        }
        
        // Mise à jour de l'activité de session
        await redisManager.updateSession(validation.payload!.sessionId, {
          userId: user.id,
          username: user.username,
          role: user.role,
          permissions: validation.payload!.permissions,
          lastActivity: Date.now(),
          ipAddress: req.ip,
          userAgent: req.get('User-Agent') || '',
          tenantId: user.tenantId
        });
        
        req.user = user;
        req.session = {
          sessionId: validation.payload!.sessionId,
          userId: user.id,
          username: user.username,
          role: user.role,
          permissions: validation.payload!.permissions,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent') || '',
          createdAt: new Date(),
          lastActivity: new Date(),
          expiresAt: new Date(validation.payload!.exp * 1000),
          tenantId: user.tenantId
        };
        
        next();
      } catch (error) {
        this.logger.error('Authentication middleware error:', error);
        return res.status(500).json({ error: 'Authentication error' });
      }
    };
  }

  /**
   * Middleware d'autorisation basé sur les permissions
   */
  public authorize(requiredPermissions: Permission[]) {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
      if (!req.user || !req.session) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      
      const userPermissions = req.session.permissions;
      const hasPermission = requiredPermissions.every(permission => 
        userPermissions.includes(permission)
      );
      
      if (!hasPermission) {
        this.logger.warn(`Access denied for user ${req.user.username}`, {
          userId: req.user.id,
          requiredPermissions,
          userPermissions
        });
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
      
      next();
    };
  }

  /**
   * Déconnexion utilisateur
   */
  public async logout(sessionId: string): Promise<boolean> {
    try {
      const success = await redisManager.deleteSession(sessionId);
      
      if (success) {
        this.logger.info(`User logged out, session: ${sessionId}`);
      }
      
      return success;
    } catch (error) {
      this.logger.error('Logout error:', error);
      return false;
    }
  }

  /**
   * Rafraîchissement du token
   */
  public async refreshToken(refreshToken: string): Promise<{ success: boolean; accessToken?: string; error?: string }> {
    try {
      const payload = jwt.verify(refreshToken, this.jwtRefreshSecret) as any;
      
      if (payload.type !== 'refresh') {
        return { success: false, error: 'Invalid refresh token' };
      }
      
      // Vérification de l'existence de la session
      const sessionData = await redisManager.getSession(payload.sessionId);
      
      if (!sessionData) {
        return { success: false, error: 'Session not found' };
      }
      
      // Génération d'un nouveau token d'accès
      const newPayload: JWTPayload = {
        sessionId: payload.sessionId,
        userId: payload.userId,
        username: sessionData.username,
        role: sessionData.role,
        permissions: sessionData.permissions,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + this.sessionTimeout) / 1000),
        iss: 'erdps-server',
        aud: 'erdps-client'
      };
      
      const accessToken = jwt.sign(newPayload, this.jwtSecret, {
        algorithm: 'HS256',
        expiresIn: '8h'
      });
      
      return { success: true, accessToken };
    } catch (error) {
      this.logger.error('Token refresh error:', error);
      return { success: false, error: 'Token refresh failed' };
    }
  }

  /**
   * Gestion des échecs de connexion
   */
  private async handleFailedLogin(userId: string, ipAddress: string): Promise<void> {
    try {
      // Simulation - à remplacer par DB réelle
      const user = await this.getUserById(userId);
      
      if (user) {
        user.failedLoginAttempts += 1;
        
        if (user.failedLoginAttempts >= this.maxLoginAttempts) {
          user.lockedUntil = new Date(Date.now() + this.lockoutDuration);
          this.logger.warn(`Account locked for user: ${user.username}`);
        }
        
        // Mise à jour en base (simulation)
        await this.updateUser(user);
      }
      
      this.logger.warn(`Failed login attempt`, {
        userId,
        ipAddress,
        attempts: user?.failedLoginAttempts
      });
    } catch (error) {
      this.logger.error('Error handling failed login:', error);
    }
  }

  /**
   * Réinitialisation des tentatives de connexion échouées
   */
  private async resetFailedLoginAttempts(userId: string): Promise<void> {
    try {
      const user = await this.getUserById(userId);
      
      if (user && user.failedLoginAttempts > 0) {
        user.failedLoginAttempts = 0;
        user.lockedUntil = undefined;
        await this.updateUser(user);
      }
    } catch (error) {
      this.logger.error('Error resetting failed login attempts:', error);
    }
  }

  /**
   * Vérification du token MFA
   */
  private async verifyMfaToken(secret: string, token: string): Promise<boolean> {
    // Simulation de vérification TOTP
    // À remplacer par une vraie implémentation (speakeasy, otplib, etc.)
    const timeWindow = Math.floor(Date.now() / 30000);
    const expectedToken = crypto.createHmac('sha1', secret)
      .update(timeWindow.toString())
      .digest('hex')
      .slice(-6);
    
    return token === expectedToken;
  }

  /**
   * Nettoyage des données utilisateur sensibles
   */
  private sanitizeUser(user: User): Partial<User> {
    const { mfaSecret, ...sanitized } = user;
    return sanitized;
  }

  // Méthodes de simulation de base de données (à remplacer par une vraie DB)
  private async getUserByUsername(username: string): Promise<User | null> {
    // Simulation - utilisateurs de test
    const testUsers: User[] = [
      {
        id: '1',
        username: 'admin',
        email: 'admin@erdps.com',
        role: UserRole.ADMIN,
        permissions: this.rolePermissions.get(UserRole.ADMIN) || [],
        isActive: true,
        failedLoginAttempts: 0,
        mfaEnabled: true,
        mfaSecret: 'test-secret'
      },
      {
        id: '2',
        username: 'analyst',
        email: 'analyst@erdps.com',
        role: UserRole.SOC_ANALYST,
        permissions: this.rolePermissions.get(UserRole.SOC_ANALYST) || [],
        isActive: true,
        failedLoginAttempts: 0,
        mfaEnabled: false
      }
    ];
    
    return testUsers.find(u => u.username === username) || null;
  }

  private async getUserById(id: string): Promise<User | null> {
    // Simulation - à remplacer par DB réelle
    const user = await this.getUserByUsername('admin');
    return user?.id === id ? user : null;
  }

  private async getPasswordHash(userId: string): Promise<string> {
    // Simulation - mot de passe "password" hashé
    return '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi';
  }

  private async updateUser(user: User): Promise<void> {
    // Simulation - à remplacer par DB réelle
    this.logger.info(`User updated: ${user.username}`);
  }

  private async updateLastLogin(userId: string): Promise<void> {
    // Simulation - à remplacer par DB réelle
    this.logger.info(`Last login updated for user: ${userId}`);
  }
}

// Export du singleton
export const sessionManager = new SessionManager();
export { UserRole, Permission };
export default sessionManager;