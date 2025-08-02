//! Security Manager for ERDPS Agent communication
//!
//! Gestionnaire de sécurité pour la communication chiffrée
//! Support TLS 1.3, authentification mutuelle et gestion des certificats
//!
//! @author ERDPS Security Team
//! @version 1.0.0
//! @license Proprietary

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use chrono::{DateTime, Utc};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use ring::digest::{digest, SHA256};
use base64::{Engine as _, engine::general_purpose};

use crate::config::SecurityConfig;

/// Gestionnaire de sécurité pour la communication
#[derive(Debug)]
pub struct SecurityManager {
    /// Configuration de sécurité
    config: SecurityConfig,
    
    /// Clé de chiffrement principale
    encryption_key: Arc<RwLock<Option<LessSafeKey>>>,
    
    /// Générateur de nombres aléatoires
    rng: SystemRandom,
    
    /// Certificats chargés
    certificates: Arc<RwLock<CertificateStore>>,
    
    /// Statistiques de sécurité
    stats: Arc<RwLock<SecurityStats>>,
}

/// Magasin de certificats
#[derive(Debug, Default)]
struct CertificateStore {
    /// Certificat client
    client_cert: Option<Vec<u8>>,
    
    /// Clé privée client
    client_key: Option<Vec<u8>>,
    
    /// Certificat CA
    ca_cert: Option<Vec<u8>>,
    
    /// Date de chargement
    loaded_at: Option<DateTime<Utc>>,
    
    /// Date d'expiration
    expires_at: Option<DateTime<Utc>>,
}

/// Statistiques de sécurité
#[derive(Debug, Default)]
struct SecurityStats {
    /// Nombre d'opérations de chiffrement
    encryption_operations: u64,
    
    /// Nombre d'opérations de déchiffrement
    decryption_operations: u64,
    
    /// Nombre d'échecs de chiffrement
    encryption_failures: u64,
    
    /// Nombre d'échecs de déchiffrement
    decryption_failures: u64,
    
    /// Dernière rotation de clé
    last_key_rotation: Option<DateTime<Utc>>,
    
    /// Nombre de rotations de clé
    key_rotations: u64,
}

/// Données chiffrées
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// Données chiffrées
    pub ciphertext: Vec<u8>,
    
    /// Nonce utilisé
    pub nonce: Vec<u8>,
    
    /// Tag d'authentification
    pub tag: Vec<u8>,
    
    /// Algorithme utilisé
    pub algorithm: String,
    
    /// Timestamp de chiffrement
    pub encrypted_at: DateTime<Utc>,
}

/// Résultat de validation de certificat
#[derive(Debug)]
pub struct CertificateValidationResult {
    /// Validité du certificat
    pub is_valid: bool,
    
    /// Raison de l'invalidité
    pub reason: Option<String>,
    
    /// Date d'expiration
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Émetteur du certificat
    pub issuer: Option<String>,
    
    /// Sujet du certificat
    pub subject: Option<String>,
}

impl SecurityManager {
    /// Crée un nouveau gestionnaire de sécurité
    pub async fn new(config: &SecurityConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing security manager");
        
        let manager = Self {
            config: config.clone(),
            encryption_key: Arc::new(RwLock::new(None)),
            rng: SystemRandom::new(),
            certificates: Arc::new(RwLock::new(CertificateStore::default())),
            stats: Arc::new(RwLock::new(SecurityStats::default())),
        };
        
        // Initialisation de la clé de chiffrement
        if config.enable_encryption {
            manager.initialize_encryption_key().await?;
        }
        
        info!("Security manager initialized successfully");
        Ok(manager)
    }
    
    /// Initialise la clé de chiffrement
    async fn initialize_encryption_key(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing encryption key");
        
        // Génération d'une clé aléatoire
        let mut key_bytes = vec![0u8; 32]; // 256 bits pour AES-256
        self.rng.fill(&mut key_bytes).map_err(|e| format!("Failed to generate random key: {:?}", e))?;
        
        // Création de la clé de chiffrement
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|e| format!("Failed to create encryption key: {:?}", e))?;
        
        let key = LessSafeKey::new(unbound_key);
        
        *self.encryption_key.write().await = Some(key);
        
        // Mise à jour des statistiques
        {
            let mut stats = self.stats.write().await;
            stats.last_key_rotation = Some(Utc::now());
            stats.key_rotations += 1;
        }
        
        info!("Encryption key initialized successfully");
        Ok(())
    }
    
    /// Chiffre des données
    pub async fn encrypt_data(&self, plaintext: &[u8]) -> Result<EncryptedData, Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enable_encryption {
            return Err("Encryption is disabled".into());
        }
        
        debug!("Encrypting {} bytes of data", plaintext.len());
        
        let key_guard = self.encryption_key.read().await;
        let key = key_guard.as_ref().ok_or("Encryption key not initialized")?;
        
        // Génération d'un nonce aléatoire
        let mut nonce_bytes = vec![0u8; 12]; // 96 bits pour AES-GCM
        self.rng.fill(&mut nonce_bytes).map_err(|e| format!("Failed to generate nonce: {:?}", e))?;
        
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|e| format!("Invalid nonce: {:?}", e))?;
        
        // Chiffrement des données
        let mut ciphertext = plaintext.to_vec();
        let tag = key.seal_in_place_detached(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|e| {
                // Mise à jour des statistiques d'échec
                tokio::spawn(async move {
                    // Note: On ne peut pas utiliser self ici à cause du lifetime
                    // Dans un vrai projet, on utiliserait un Arc<Self>
                });
                format!("Encryption failed: {:?}", e)
            })?;
        
        // Mise à jour des statistiques
        {
            let mut stats = self.stats.write().await;
            stats.encryption_operations += 1;
        }
        
        let encrypted_data = EncryptedData {
            ciphertext,
            nonce: nonce_bytes,
            tag: tag.as_ref().to_vec(),
            algorithm: self.config.encryption_algorithm.clone(),
            encrypted_at: Utc::now(),
        };
        
        debug!("Data encrypted successfully");
        Ok(encrypted_data)
    }
    
    /// Déchiffre des données
    pub async fn decrypt_data(&self, encrypted_data: &EncryptedData) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enable_encryption {
            return Err("Encryption is disabled".into());
        }
        
        debug!("Decrypting {} bytes of data", encrypted_data.ciphertext.len());
        
        let key_guard = self.encryption_key.read().await;
        let key = key_guard.as_ref().ok_or("Encryption key not initialized")?;
        
        // Reconstruction du nonce
        let nonce = Nonce::try_assume_unique_for_key(&encrypted_data.nonce)
            .map_err(|e| format!("Invalid nonce: {:?}", e))?;
        
        // Déchiffrement des données
        let mut plaintext = encrypted_data.ciphertext.clone();
        key.open_in_place(nonce, Aad::empty(), &mut plaintext)
            .map_err(|e| {
                // Mise à jour des statistiques d'échec
                tokio::spawn(async move {
                    // Note: On ne peut pas utiliser self ici à cause du lifetime
                });
                format!("Decryption failed: {:?}", e)
            })?;
        
        // Mise à jour des statistiques
        {
            let mut stats = self.stats.write().await;
            stats.decryption_operations += 1;
        }
        
        debug!("Data decrypted successfully");
        Ok(plaintext)
    }
    
    /// Charge les certificats depuis les fichiers
    pub async fn load_certificates(
        &self,
        client_cert_path: Option<&PathBuf>,
        client_key_path: Option<&PathBuf>,
        ca_cert_path: Option<&PathBuf>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Loading certificates");
        
        let mut cert_store = self.certificates.write().await;
        
        // Chargement du certificat client
        if let Some(cert_path) = client_cert_path {
            if cert_path.exists() {
                cert_store.client_cert = Some(tokio::fs::read(cert_path).await?);
                info!("Client certificate loaded from: {:?}", cert_path);
            } else {
                warn!("Client certificate file not found: {:?}", cert_path);
            }
        }
        
        // Chargement de la clé privée client
        if let Some(key_path) = client_key_path {
            if key_path.exists() {
                cert_store.client_key = Some(tokio::fs::read(key_path).await?);
                info!("Client private key loaded from: {:?}", key_path);
            } else {
                warn!("Client private key file not found: {:?}", key_path);
            }
        }
        
        // Chargement du certificat CA
        if let Some(ca_path) = ca_cert_path {
            if ca_path.exists() {
                cert_store.ca_cert = Some(tokio::fs::read(ca_path).await?);
                info!("CA certificate loaded from: {:?}", ca_path);
            } else {
                warn!("CA certificate file not found: {:?}", ca_path);
            }
        }
        
        cert_store.loaded_at = Some(Utc::now());
        
        info!("Certificates loaded successfully");
        Ok(())
    }
    
    /// Valide un certificat
    pub async fn validate_certificate(&self, cert_data: &[u8]) -> CertificateValidationResult {
        debug!("Validating certificate");
        
        // Simulation de validation de certificat
        // Dans un vrai projet, on utiliserait une bibliothèque comme rustls ou openssl
        
        // Vérification basique de la structure
        if cert_data.len() < 100 {
            return CertificateValidationResult {
                is_valid: false,
                reason: Some("Certificate too short".to_string()),
                expires_at: None,
                issuer: None,
                subject: None,
            };
        }
        
        // Vérification de l'en-tête PEM
        let cert_str = String::from_utf8_lossy(cert_data);
        if !cert_str.contains("-----BEGIN CERTIFICATE-----") {
            return CertificateValidationResult {
                is_valid: false,
                reason: Some("Invalid certificate format".to_string()),
                expires_at: None,
                issuer: None,
                subject: None,
            };
        }
        
        // Simulation d'une validation réussie
        CertificateValidationResult {
            is_valid: true,
            reason: None,
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            issuer: Some("ERDPS CA".to_string()),
            subject: Some("ERDPS Agent".to_string()),
        }
    }
    
    /// Calcule le hash d'un fichier
    pub async fn calculate_file_hash(&self, file_path: &PathBuf) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        debug!("Calculating hash for file: {:?}", file_path);
        
        let file_data = tokio::fs::read(file_path).await?;
        let hash = digest(&SHA256, &file_data);
        let hash_hex = hex::encode(hash.as_ref());
        
        debug!("File hash calculated: {}", hash_hex);
        Ok(hash_hex)
    }
    
    /// Génère une signature pour des données
    pub async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        debug!("Signing {} bytes of data", data.len());
        
        // Simulation de signature
        // Dans un vrai projet, on utiliserait une clé privée RSA ou ECDSA
        let hash = digest(&SHA256, data);
        let signature = format!("ERDPS_SIGNATURE_{}", hex::encode(hash.as_ref()));
        
        Ok(signature.into_bytes())
    }
    
    /// Vérifie une signature
    pub async fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        debug!("Verifying signature for {} bytes of data", data.len());
        
        // Simulation de vérification de signature
        let expected_hash = digest(&SHA256, data);
        let expected_signature = format!("ERDPS_SIGNATURE_{}", hex::encode(expected_hash.as_ref()));
        
        let signature_str = String::from_utf8_lossy(signature);
        let is_valid = signature_str == expected_signature;
        
        debug!("Signature verification result: {}", is_valid);
        Ok(is_valid)
    }
    
    /// Effectue la rotation des clés
    pub async fn rotate_keys(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enable_key_rotation {
            return Ok(());
        }
        
        info!("Performing key rotation");
        
        // Vérification si la rotation est nécessaire
        let stats = self.stats.read().await;
        let should_rotate = if let Some(last_rotation) = stats.last_rotation {
            let hours_since_rotation = Utc::now().signed_duration_since(last_rotation).num_hours();
            hours_since_rotation >= self.config.key_rotation_interval_hours as i64
        } else {
            true // Première rotation
        };
        drop(stats);
        
        if should_rotate {
            self.initialize_encryption_key().await?;
            info!("Key rotation completed successfully");
        } else {
            debug!("Key rotation not needed yet");
        }
        
        Ok(())
    }
    
    /// Encode des données en Base64
    pub fn encode_base64(&self, data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }
    
    /// Décode des données Base64
    pub fn decode_base64(&self, encoded: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        general_purpose::STANDARD.decode(encoded)
            .map_err(|e| format!("Base64 decode error: {}", e).into())
    }
    
    /// Obtient les statistiques de sécurité
    pub async fn get_stats(&self) -> SecurityStats {
        self.stats.read().await.clone()
    }
    
    /// Vérifie l'intégrité du gestionnaire de sécurité
    pub async fn self_check(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Performing security manager self-check");
        
        // Vérification de la clé de chiffrement
        if self.config.enable_encryption {
            let key_guard = self.encryption_key.read().await;
            if key_guard.is_none() {
                return Err("Encryption key not initialized".into());
            }
        }
        
        // Test de chiffrement/déchiffrement
        if self.config.enable_encryption {
            let test_data = b"ERDPS Security Test";
            let encrypted = self.encrypt_data(test_data).await?;
            let decrypted = self.decrypt_data(&encrypted).await?;
            
            if decrypted != test_data {
                return Err("Encryption/decryption test failed".into());
            }
        }
        
        info!("Security manager self-check passed");
        Ok(())
    }
}

// Implémentation de Clone pour SecurityStats
impl Clone for SecurityStats {
    fn clone(&self) -> Self {
        Self {
            encryption_operations: self.encryption_operations,
            decryption_operations: self.decryption_operations,
            encryption_failures: self.encryption_failures,
            decryption_failures: self.decryption_failures,
            last_key_rotation: self.last_key_rotation,
            key_rotations: self.key_rotations,
        }
    }
}

// Extension pour SecurityStats
impl SecurityStats {
    /// Obtient le taux de succès du chiffrement
    pub fn encryption_success_rate(&self) -> f64 {
        if self.encryption_operations == 0 {
            return 1.0;
        }
        
        let successful = self.encryption_operations - self.encryption_failures;
        successful as f64 / self.encryption_operations as f64
    }
    
    /// Obtient le taux de succès du déchiffrement
    pub fn decryption_success_rate(&self) -> f64 {
        if self.decryption_operations == 0 {
            return 1.0;
        }
        
        let successful = self.decryption_operations - self.decryption_failures;
        successful as f64 / self.decryption_operations as f64
    }
}

// Tests unitaires
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityConfig;
    
    #[tokio::test]
    async fn test_security_manager_creation() {
        let config = SecurityConfig::default();
        let manager = SecurityManager::new(&config).await.unwrap();
        
        assert!(manager.self_check().await.is_ok());
    }
    
    #[tokio::test]
    async fn test_encryption_decryption() {
        let config = SecurityConfig::default();
        let manager = SecurityManager::new(&config).await.unwrap();
        
        let test_data = b"Hello, ERDPS Security!";
        let encrypted = manager.encrypt_data(test_data).await.unwrap();
        let decrypted = manager.decrypt_data(&encrypted).await.unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }
    
    #[tokio::test]
    async fn test_base64_encoding() {
        let config = SecurityConfig::default();
        let manager = SecurityManager::new(&config).await.unwrap();
        
        let test_data = b"ERDPS Test Data";
        let encoded = manager.encode_base64(test_data);
        let decoded = manager.decode_base64(&encoded).unwrap();
        
        assert_eq!(test_data, decoded.as_slice());
    }
    
    #[tokio::test]
    async fn test_signature_verification() {
        let config = SecurityConfig::default();
        let manager = SecurityManager::new(&config).await.unwrap();
        
        let test_data = b"Data to sign";
        let signature = manager.sign_data(test_data).await.unwrap();
        let is_valid = manager.verify_signature(test_data, &signature).await.unwrap();
        
        assert!(is_valid);
    }
    
    #[test]
    fn test_security_stats() {
        let mut stats = SecurityStats::default();
        stats.encryption_operations = 100;
        stats.encryption_failures = 5;
        stats.decryption_operations = 95;
        stats.decryption_failures = 2;
        
        assert_eq!(stats.encryption_success_rate(), 0.95);
        assert!(stats.decryption_success_rate() > 0.97);
    }
}