/**
 * Gestionnaire de sécurité principal pour le serveur ERDPS
 * Gère l'authentification, l'autorisation, le chiffrement et les certificats
 * 
 * @author ERDPS Security Team
 * @version 1.0.0
 */

import { createHash, createCipher, createDecipher, randomBytes, pbkdf2Sync } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import * as forge from 'node-forge';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { SecurityConfig, JWTConfig, EncryptionConfig, CertificateConfig } from '../types/config';
import { Logger } from '../utils/Logger';

/**
 * Interface pour les informations d'authentification
 */
export interface AuthInfo {
  userId: string;
  username: string;
  roles: string[];
  permissions: string[];
  sessionId: string;
  ipAddress: string;
  userAgent: string;
  loginTime: Date;
  lastActivity: Date;
  mfaVerified: boolean;
}

/**
 * Interface pour les tokens JWT
 */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

/**
 * Interface pour les données chiffrées
 */
export interface EncryptedData {
  data: string;
  iv: string;
  tag: string;
  algorithm: string;
}

/**
 * Interface pour les informations de certificat
 */
export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  fingerprint: string;
  publicKey: string;
  isValid: boolean;
}

/**
 * Gestionnaire de sécurité principal
 */
export class SecurityManager {
  private config: SecurityConfig;
  private logger: Logger;
  private activeSessions: Map<string, AuthInfo>;
  private revokedTokens: Set<string>;
  private certificateStore: Map<string, forge.pki.Certificate>;
  private privateKey: forge.pki.PrivateKey | null;
  private publicKey: forge.pki.PublicKey | null;
  private caCertificate: forge.pki.Certificate | null;
  private encryptionKey: Buffer;
  private initialized: boolean;

  constructor(config: SecurityConfig) {
    this.config = config;
    this.logger = new Logger('SecurityManager');
    this.activeSessions = new Map();
    this.revokedTokens = new Set();
    this.certificateStore = new Map();
    this.privateKey = null;
    this.publicKey = null;
    this.caCertificate = null;
    this.encryptionKey = Buffer.alloc(0);
    this.initialized = false;
  }

  /**
   * Initialise le gestionnaire de sécurité
   */
  public async initialize(): Promise<void> {
    try {
      this.logger.info('Initialisation du gestionnaire de sécurité...');

      // Génération de la clé de chiffrement principale
      await this.generateEncryptionKey();

      // Chargement des certificats
      await this.loadCertificates();

      // Validation de la configuration
      await this.validateConfiguration();

      // Nettoyage périodique des sessions expirées
      this.startSessionCleanup();

      // Nettoyage périodique des tokens révoqués
      this.startTokenCleanup();

      this.initialized = true;
      this.logger.info('Gestionnaire de sécurité initialisé avec succès');

    } catch (error) {
      this.logger.error('Erreur lors de l\'initialisation du gestionnaire de sécurité:', error);
      throw error;
    }
  }

  /**
   * Génère ou charge la clé de chiffrement principale
   */
  private async generateEncryptionKey(): Promise<void> {
    const keyPath = join(process.cwd(), 'keys', 'encryption.key');
    
    if (existsSync(keyPath)) {
      this.logger.info('Chargement de la clé de chiffrement existante');
      this.encryptionKey = readFileSync(keyPath);
    } else {
      this.logger.info('Génération d\'une nouvelle clé de chiffrement');
      this.encryptionKey = randomBytes(32); // 256 bits
      
      // Sauvegarde sécurisée de la clé
      writeFileSync(keyPath, this.encryptionKey, { mode: 0o600 });
    }
  }

  /**
   * Charge les certificats depuis le magasin
   */
  public async loadCertificates(): Promise<void> {
    try {
      this.logger.info('Chargement des certificats...');

      const certConfig = this.config.certificates;
      
      // Chargement du certificat CA
      const caCertPath = join(certConfig.storePath, 'ca.crt');
      if (existsSync(caCertPath)) {
        const caCertPem = readFileSync(caCertPath, 'utf8');
        this.caCertificate = forge.pki.certificateFromPem(caCertPem);
        this.logger.info('Certificat CA chargé');
      }

      // Chargement de la clé privée du serveur
      const serverKeyPath = join(certConfig.storePath, 'server.key');
      if (existsSync(serverKeyPath)) {
        const serverKeyPem = readFileSync(serverKeyPath, 'utf8');
        this.privateKey = forge.pki.privateKeyFromPem(serverKeyPem);
        this.publicKey = forge.pki.rsa.setPublicKey(
          (this.privateKey as any).n,
          (this.privateKey as any).e
        );
        this.logger.info('Clés du serveur chargées');
      }

      // Chargement des certificats clients
      await this.loadClientCertificates();

      this.logger.info('Certificats chargés avec succès');

    } catch (error) {
      this.logger.error('Erreur lors du chargement des certificats:', error);
      throw error;
    }
  }

  /**
   * Charge les certificats clients autorisés
   */
  private async loadClientCertificates(): Promise<void> {
    // Implémentation du chargement des certificats clients
    // depuis le magasin de certificats
    this.logger.info('Chargement des certificats clients...');
    // TODO: Implémenter le chargement depuis le magasin
  }

  /**
   * Valide la configuration de sécurité
   */
  public async validateConfiguration(): Promise<void> {
    this.logger.info('Validation de la configuration de sécurité...');

    // Validation de la configuration JWT
    if (!this.config.jwt.secret || this.config.jwt.secret.length < 32) {
      throw new Error('La clé secrète JWT doit faire au moins 32 caractères');
    }

    // Validation de la configuration de chiffrement
    if (this.config.encryption.keySize < 256) {
      throw new Error('La taille de clé de chiffrement doit être d\'au moins 256 bits');
    }

    // Validation des certificats
    if (this.caCertificate) {
      const now = new Date();
      if (now > this.caCertificate.validity.notAfter) {
        throw new Error('Le certificat CA a expiré');
      }
    }

    this.logger.info('Configuration de sécurité validée');
  }

  /**
   * Authentifie un utilisateur avec nom d'utilisateur et mot de passe
   */
  public async authenticateUser(
    username: string,
    password: string,
    ipAddress: string,
    userAgent: string
  ): Promise<TokenPair> {
    try {
      this.logger.info(`Tentative d'authentification pour l'utilisateur: ${username}`);

      // Vérification des informations d'identification
      const user = await this.validateCredentials(username, password);
      if (!user) {
        throw new Error('Informations d\'identification invalides');
      }

      // Génération de l'ID de session
      const sessionId = this.generateSessionId();

      // Création des informations d'authentification
      const authInfo: AuthInfo = {
        userId: user.id,
        username: user.username,
        roles: user.roles,
        permissions: user.permissions,
        sessionId,
        ipAddress,
        userAgent,
        loginTime: new Date(),
        lastActivity: new Date(),
        mfaVerified: false
      };

      // Stockage de la session
      this.activeSessions.set(sessionId, authInfo);

      // Génération des tokens JWT
      const tokens = this.generateTokenPair(authInfo);

      this.logger.info(`Utilisateur ${username} authentifié avec succès`);
      return tokens;

    } catch (error) {
      this.logger.error(`Erreur d'authentification pour ${username}:`, error);
      throw error;
    }
  }

  /**
   * Authentifie un agent avec certificat client
   */
  public async authenticateAgent(certificate: string): Promise<AuthInfo> {
    try {
      this.logger.info('Authentification d\'agent par certificat');

      // Validation du certificat
      const cert = forge.pki.certificateFromPem(certificate);
      const isValid = await this.validateCertificate(cert);
      
      if (!isValid) {
        throw new Error('Certificat invalide');
      }

      // Extraction des informations de l'agent
      const agentId = this.extractAgentIdFromCertificate(cert);
      const sessionId = this.generateSessionId();

      const authInfo: AuthInfo = {
        userId: agentId,
        username: `agent-${agentId}`,
        roles: ['agent'],
        permissions: ['agent:report', 'agent:update'],
        sessionId,
        ipAddress: '',
        userAgent: 'ERDPS-Agent',
        loginTime: new Date(),
        lastActivity: new Date(),
        mfaVerified: true // Les agents sont considérés comme pré-authentifiés
      };

      this.activeSessions.set(sessionId, authInfo);
      this.logger.info(`Agent ${agentId} authentifié avec succès`);
      
      return authInfo;

    } catch (error) {
      this.logger.error('Erreur d\'authentification d\'agent:', error);
      throw error;
    }
  }

  /**
   * Valide un token JWT
   */
  public async validateToken(token: string): Promise<AuthInfo | null> {
    try {
      // Vérification si le token est révoqué
      if (this.revokedTokens.has(token)) {
        return null;
      }

      // Décodage et validation du token
      const decoded = jwt.verify(token, this.config.jwt.secret, {
        algorithms: [this.config.jwt.algorithm],
        issuer: this.config.jwt.issuer,
        audience: this.config.jwt.audience
      }) as any;

      // Récupération des informations de session
      const authInfo = this.activeSessions.get(decoded.sessionId);
      if (!authInfo) {
        return null;
      }

      // Mise à jour de la dernière activité
      authInfo.lastActivity = new Date();
      this.activeSessions.set(decoded.sessionId, authInfo);

      return authInfo;

    } catch (error) {
      this.logger.debug('Token invalide:', error.message);
      return null;
    }
  }

  /**
   * Révoque un token
   */
  public async revokeToken(token: string): Promise<void> {
    this.revokedTokens.add(token);
    this.logger.info('Token révoqué');
  }

  /**
   * Révoque une session
   */
  public async revokeSession(sessionId: string): Promise<void> {
    this.activeSessions.delete(sessionId);
    this.logger.info(`Session ${sessionId} révoquée`);
  }

  /**
   * Chiffre des données sensibles
   */
  public encrypt(data: string): EncryptedData {
    const algorithm = this.config.encryption.algorithm;
    const iv = randomBytes(this.config.encryption.ivSize);
    
    const cipher = createCipher(algorithm, this.encryptionKey);
    cipher.setAAD(Buffer.from('ERDPS-Security'));
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();

    return {
      data: encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      algorithm
    };
  }

  /**
   * Déchiffre des données
   */
  public decrypt(encryptedData: EncryptedData): string {
    const decipher = createDecipher(encryptedData.algorithm, this.encryptionKey);
    decipher.setAAD(Buffer.from('ERDPS-Security'));
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Génère un hash sécurisé
   */
  public generateHash(data: string, salt?: string): string {
    const actualSalt = salt || randomBytes(16).toString('hex');
    return bcrypt.hashSync(data, 12);
  }

  /**
   * Vérifie un hash
   */
  public verifyHash(data: string, hash: string): boolean {
    return bcrypt.compareSync(data, hash);
  }

  /**
   * Génère une signature numérique
   */
  public signData(data: string): string {
    if (!this.privateKey) {
      throw new Error('Clé privée non disponible pour la signature');
    }

    const md = forge.md.sha256.create();
    md.update(data, 'utf8');
    
    return forge.util.encode64(
      (this.privateKey as any).sign(md)
    );
  }

  /**
   * Vérifie une signature numérique
   */
  public verifySignature(data: string, signature: string, publicKey?: string): boolean {
    try {
      const key = publicKey ? 
        forge.pki.publicKeyFromPem(publicKey) : 
        this.publicKey;
      
      if (!key) {
        return false;
      }

      const md = forge.md.sha256.create();
      md.update(data, 'utf8');
      
      return (key as any).verify(
        md.digest().bytes(),
        forge.util.decode64(signature)
      );
    } catch (error) {
      this.logger.error('Erreur de vérification de signature:', error);
      return false;
    }
  }

  /**
   * Valide un certificat
   */
  private async validateCertificate(certificate: forge.pki.Certificate): Promise<boolean> {
    try {
      // Vérification de la validité temporelle
      const now = new Date();
      if (now < certificate.validity.notBefore || now > certificate.validity.notAfter) {
        return false;
      }

      // Vérification de la signature par le CA
      if (this.caCertificate) {
        try {
          const verified = this.caCertificate.publicKey.verify(
            certificate.md.digest().bytes(),
            certificate.signature
          );
          if (!verified) {
            return false;
          }
        } catch (error) {
          return false;
        }
      }

      // Vérification de révocation (OCSP/CRL)
      const isRevoked = await this.checkRevocationStatus(certificate);
      if (isRevoked) {
        return false;
      }

      return true;

    } catch (error) {
      this.logger.error('Erreur de validation de certificat:', error);
      return false;
    }
  }

  /**
   * Vérifie le statut de révocation d'un certificat
   */
  private async checkRevocationStatus(certificate: forge.pki.Certificate): Promise<boolean> {
    // TODO: Implémenter la vérification OCSP/CRL
    // Pour l'instant, on considère que le certificat n'est pas révoqué
    return false;
  }

  /**
   * Extrait l'ID de l'agent depuis le certificat
   */
  private extractAgentIdFromCertificate(certificate: forge.pki.Certificate): string {
    // Extraction de l'ID depuis le CN du sujet
    const subject = certificate.subject;
    const cnAttribute = subject.getField('CN');
    
    if (cnAttribute && cnAttribute.value) {
      // Format attendu: "ERDPS-Agent-{ID}"
      const match = cnAttribute.value.match(/ERDPS-Agent-(.+)/);
      if (match) {
        return match[1];
      }
    }

    throw new Error('ID d\'agent non trouvé dans le certificat');
  }

  /**
   * Valide les informations d'identification utilisateur
   */
  private async validateCredentials(username: string, password: string): Promise<any> {
    // TODO: Implémenter la validation contre la base de données
    // ou le système d'authentification externe (LDAP, AD, etc.)
    
    // Exemple temporaire
    if (username === 'admin' && password === 'admin123') {
      return {
        id: '1',
        username: 'admin',
        roles: ['admin'],
        permissions: ['*']
      };
    }
    
    return null;
  }

  /**
   * Génère un ID de session unique
   */
  private generateSessionId(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Génère une paire de tokens JWT
   */
  private generateTokenPair(authInfo: AuthInfo): TokenPair {
    const jwtConfig = this.config.jwt;
    
    const accessTokenPayload = {
      userId: authInfo.userId,
      username: authInfo.username,
      roles: authInfo.roles,
      permissions: authInfo.permissions,
      sessionId: authInfo.sessionId,
      type: 'access'
    };

    const refreshTokenPayload = {
      userId: authInfo.userId,
      sessionId: authInfo.sessionId,
      type: 'refresh'
    };

    const accessToken = jwt.sign(accessTokenPayload, jwtConfig.secret, {
      algorithm: jwtConfig.algorithm,
      expiresIn: jwtConfig.accessTokenExpiry,
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience
    });

    const refreshToken = jwt.sign(refreshTokenPayload, jwtConfig.secret, {
      algorithm: jwtConfig.algorithm,
      expiresIn: jwtConfig.refreshTokenExpiry,
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience
    });

    return {
      accessToken,
      refreshToken,
      expiresIn: this.parseExpiryToSeconds(jwtConfig.accessTokenExpiry),
      tokenType: 'Bearer'
    };
  }

  /**
   * Convertit une durée d'expiration en secondes
   */
  private parseExpiryToSeconds(expiry: string): number {
    const match = expiry.match(/(\d+)([smhd])/);
    if (!match) return 3600; // 1 heure par défaut

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 3600;
      case 'd': return value * 86400;
      default: return 3600;
    }
  }

  /**
   * Démarre le nettoyage périodique des sessions expirées
   */
  private startSessionCleanup(): void {
    setInterval(() => {
      const now = new Date();
      const expiredSessions: string[] = [];

      for (const [sessionId, authInfo] of this.activeSessions) {
        const inactiveTime = now.getTime() - authInfo.lastActivity.getTime();
        if (inactiveTime > 24 * 60 * 60 * 1000) { // 24 heures
          expiredSessions.push(sessionId);
        }
      }

      expiredSessions.forEach(sessionId => {
        this.activeSessions.delete(sessionId);
      });

      if (expiredSessions.length > 0) {
        this.logger.info(`${expiredSessions.length} sessions expirées nettoyées`);
      }
    }, 60 * 60 * 1000); // Toutes les heures
  }

  /**
   * Démarre le nettoyage périodique des tokens révoqués
   */
  private startTokenCleanup(): void {
    setInterval(() => {
      // Nettoyage des tokens révoqués expirés
      // TODO: Implémenter la logique de nettoyage basée sur l'expiration
      this.logger.debug('Nettoyage des tokens révoqués');
    }, 6 * 60 * 60 * 1000); // Toutes les 6 heures
  }

  /**
   * Retourne les informations de session active
   */
  public getActiveSession(sessionId: string): AuthInfo | undefined {
    return this.activeSessions.get(sessionId);
  }

  /**
   * Retourne le nombre de sessions actives
   */
  public getActiveSessionCount(): number {
    return this.activeSessions.size;
  }

  /**
   * Vérifie si le gestionnaire est initialisé
   */
  public isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Arrêt propre du gestionnaire
   */
  public async shutdown(): Promise<void> {
    this.logger.info('Arrêt du gestionnaire de sécurité...');
    
    // Révocation de toutes les sessions actives
    this.activeSessions.clear();
    
    // Nettoyage des tokens révoqués
    this.revokedTokens.clear();
    
    this.initialized = false;
    this.logger.info('Gestionnaire de sécurité arrêté');
  }
}

export default SecurityManager;