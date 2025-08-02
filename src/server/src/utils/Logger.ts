/**
 * Système de logging sécurisé pour ERDPS
 * Gère les logs avec chiffrement, intégrité et audit trail
 * 
 * @author ERDPS Security Team
 * @version 1.0.0
 */

import winston, { Logger as WinstonLogger, format, transports } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import { createHash, createCipher, createDecipher, randomBytes } from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';
import { gzip, gunzip } from 'zlib';
import { promisify } from 'util';

const gzipAsync = promisify(gzip);
const gunzipAsync = promisify(gunzip);

/**
 * Niveaux de log
 */
export enum LogLevel {
  ERROR = 'error',
  WARN = 'warn',
  INFO = 'info',
  HTTP = 'http',
  VERBOSE = 'verbose',
  DEBUG = 'debug',
  SILLY = 'silly'
}

/**
 * Catégories de log
 */
export enum LogCategory {
  SECURITY = 'security',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  AUDIT = 'audit',
  THREAT = 'threat',
  SYSTEM = 'system',
  NETWORK = 'network',
  DATABASE = 'database',
  CACHE = 'cache',
  API = 'api',
  AGENT = 'agent',
  PERFORMANCE = 'performance',
  ERROR = 'error',
  DEBUG = 'debug'
}

/**
 * Interface pour les métadonnées de log
 */
export interface LogMetadata {
  userId?: string;
  sessionId?: string;
  agentId?: string;
  ipAddress?: string;
  userAgent?: string;
  requestId?: string;
  correlationId?: string;
  component?: string;
  action?: string;
  resource?: string;
  duration?: number;
  statusCode?: number;
  errorCode?: string;
  threatId?: string;
  severity?: string;
  tags?: string[];
  [key: string]: any;
}

/**
 * Interface pour l'entrée de log
 */
export interface LogEntry {
  timestamp: Date;
  level: LogLevel;
  category: LogCategory;
  message: string;
  metadata?: LogMetadata;
  hash?: string;
  encrypted?: boolean;
  compressed?: boolean;
}

/**
 * Interface pour les statistiques de logging
 */
export interface LoggingStats {
  totalLogs: number;
  logsByLevel: Record<LogLevel, number>;
  logsByCategory: Record<LogCategory, number>;
  errorsCount: number;
  warningsCount: number;
  securityEventsCount: number;
  averageLogSize: number;
  compressionRatio: number;
  lastLogTime: Date;
  uptime: number;
}

/**
 * Configuration du logger
 */
export interface LoggerConfig {
  level: LogLevel;
  enableConsole: boolean;
  enableFile: boolean;
  enableSecurity: boolean;
  enableCompression: boolean;
  enableEncryption: boolean;
  logDirectory: string;
  maxFileSize: string;
  maxFiles: string;
  datePattern: string;
  encryptionKey?: string;
  auditRetentionDays: number;
  securityRetentionDays: number;
  compressionThreshold: number;
}

/**
 * Gestionnaire de logs sécurisé
 */
export class Logger {
  private winston: WinstonLogger;
  private config: LoggerConfig;
  private component: string;
  private stats: LoggingStats;
  private encryptionKey: Buffer;
  private integrityChain: string[];
  private startTime: Date;

  constructor(component: string, config?: Partial<LoggerConfig>) {
    this.component = component;
    this.startTime = new Date();
    this.integrityChain = [];
    
    // Configuration par défaut
    this.config = {
      level: LogLevel.INFO,
      enableConsole: true,
      enableFile: true,
      enableSecurity: true,
      enableCompression: true,
      enableEncryption: true,
      logDirectory: './logs',
      maxFileSize: '20m',
      maxFiles: '14d',
      datePattern: 'YYYY-MM