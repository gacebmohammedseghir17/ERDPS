# Guide d'Installation ERDPS

## 🚀 Installation Enterprise

### Prérequis Système

#### Serveur ERDPS
- **OS**: Windows Server 2019/2022 ou Linux (Ubuntu 20.04+, CentOS 8+)
- **CPU**: 4 cœurs minimum (8 cœurs recommandés)
- **RAM**: 8 GB minimum (16 GB recommandés)
- **Stockage**: 100 GB SSD minimum
- **Réseau**: Connexion Internet stable, ports 443/8443 ouverts

#### Endpoints (Agents)
- **OS**: Windows 10/11 Pro/Enterprise
- **CPU**: 2 cœurs minimum
- **RAM**: 4 GB minimum
- **Stockage**: 1 GB d'espace libre
- **Réseau**: Accès HTTPS au serveur ERDPS

#### Base de Données
- **Redis**: Version 6.0+ pour le cache et les sessions
- **PostgreSQL**: Version 12+ pour les données persistantes (optionnel)

### 🔧 Installation du Serveur

#### 1. Préparation de l'environnement

```bash
# Installation des dépendances (Ubuntu/Debian)
sudo apt update
sudo apt install -y nodejs npm redis-server postgresql-client

# Installation des dépendances (CentOS/RHEL)
sudo yum install -y nodejs npm redis postgresql
```

#### 2. Configuration Redis

```bash
# Édition de la configuration Redis
sudo nano /etc/redis/redis.conf

# Paramètres recommandés:
# bind 127.0.0.1
# port 6379
# requirepass your_secure_password
# maxmemory 2gb
# maxmemory-policy allkeys-lru

# Redémarrage du service
sudo systemctl restart redis-server
sudo systemctl enable redis-server
```

#### 3. Installation du serveur ERDPS

```bash
# Clonage du repository
git clone https://github.com/your-org/erdps.git
cd erdps

# Installation des dépendances
cd src/server
npm install

# Configuration
cp config/config.example.json config/config.json
nano config/config.json
```

#### 4. Configuration du serveur

```json
{
  "server": {
    "port": 8443,
    "host": "0.0.0.0",
    "ssl": {
      "enabled": true,
      "cert": "/path/to/certificate.crt",
      "key": "/path/to/private.key"
    }
  },
  "redis": {
    "host": "localhost",
    "port": 6379,
    "password": "your_secure_password",
    "db": 0
  },
  "security": {
    "jwt_secret": "your_jwt_secret_key",
    "encryption_key": "your_32_char_encryption_key",
    "session_timeout": 3600
  },
  "logging": {
    "level": "info",
    "file": "/var/log/erdps/server.log"
  }
}
```

#### 5. Génération des certificats SSL

```bash
# Création du répertoire des certificats
sudo mkdir -p /etc/erdps/certs
cd /etc/erdps/certs

# Génération de la clé privée
sudo openssl genrsa -out erdps-server.key 4096

# Génération du certificat auto-signé (pour test)
sudo openssl req -new -x509 -key erdps-server.key -out erdps-server.crt -days 365

# Pour un environnement de production, utilisez un certificat signé par une CA
```

#### 6. Démarrage du serveur

```bash
# Démarrage en mode développement
npm run dev

# Démarrage en mode production
npm run build
npm start

# Installation comme service systemd
sudo cp scripts/erdps-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable erdps-server
sudo systemctl start erdps-server
```

### 🖥️ Installation de la Console Web

#### 1. Build de l'interface

```bash
# Retour au répertoire racine
cd ../../

# Installation des dépendances
npm install

# Build de production
npm run build

# Déploiement sur serveur web (nginx/apache)
sudo cp -r dist/* /var/www/erdps/
```

#### 2. Configuration Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name erdps.your-domain.com;
    
    ssl_certificate /etc/erdps/certs/erdps-server.crt;
    ssl_certificate_key /etc/erdps/certs/erdps-server.key;
    
    root /var/www/erdps;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api/ {
        proxy_pass https://localhost:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 🛡️ Installation des Agents

#### 1. Installation manuelle

```powershell
# Téléchargement du script de déploiement
Invoke-WebRequest -Uri "https://erdps.your-domain.com/scripts/deploy-agent.ps1" -OutFile "deploy-agent.ps1"

# Exécution avec privilèges administrateur
.\deploy-agent.ps1 -ServerUrl "https://erdps.your-domain.com" -InstallPath "C:\Program Files\ERDPS"
```

#### 2. Déploiement via GPO

```powershell
# Sur un contrôleur de domaine
.\scripts\gpo-deployment.ps1 -Domain "your-domain.local" -ServerUrl "https://erdps.your-domain.com"
```

#### 3. Déploiement via SCCM

1. Créer un package SCCM avec les fichiers de l'agent
2. Utiliser le script `deploy-agent.ps1` comme programme d'installation
3. Déployer sur les collections d'ordinateurs cibles

### 🔍 Vérification de l'Installation

#### 1. Vérification du serveur

```bash
# Statut du service
sudo systemctl status erdps-server

# Logs du serveur
sudo journalctl -u erdps-server -f

# Test de connectivité
curl -k https://localhost:8443/api/health
```

#### 2. Vérification des agents

```powershell
# Statut du service agent
Get-Service -Name "ERDPSAgent"

# Logs de l'agent
Get-EventLog -LogName "Application" -Source "ERDPSAgent" -Newest 10

# Test de communication
Test-NetConnection -ComputerName "erdps.your-domain.com" -Port 8443
```

#### 3. Vérification de la console

1. Ouvrir un navigateur web
2. Naviguer vers `https://erdps.your-domain.com`
3. Se connecter avec les identifiants administrateur
4. Vérifier que les agents apparaissent dans le dashboard

### 🔧 Configuration Post-Installation

#### 1. Création du compte administrateur

```bash
# Via l'API du serveur
curl -X POST https://localhost:8443/api/admin/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePassword123!",
    "email": "admin@your-domain.com",
    "role": "administrator"
  }'
```

#### 2. Configuration des politiques de sécurité

1. Accéder à la console web
2. Naviguer vers "Configuration" > "Politiques"
3. Configurer les règles de détection
4. Définir les actions automatiques

#### 3. Configuration des alertes

1. Configurer les notifications email/SMS
2. Définir les seuils d'alerte
3. Configurer l'intégration SIEM

### 🚨 Dépannage

#### Problèmes courants

**Serveur ne démarre pas**
```bash
# Vérifier les logs
sudo journalctl -u erdps-server -n 50

# Vérifier la configuration
npm run config:validate

# Vérifier les ports
sudo netstat -tlnp | grep 8443
```

**Agent ne se connecte pas**
```powershell
# Vérifier la connectivité réseau
Test-NetConnection -ComputerName "erdps.your-domain.com" -Port 8443

# Vérifier les certificats
Get-ChildItem -Path "C:\Program Files\ERDPS\certs"

# Redémarrer le service
Restart-Service -Name "ERDPSAgent"
```

**Console web inaccessible**
```bash
# Vérifier nginx
sudo systemctl status nginx

# Vérifier les logs nginx
sudo tail -f /var/log/nginx/error.log

# Vérifier les permissions
sudo chown -R www-data:www-data /var/www/erdps/
```

### 📋 Checklist Post-Installation

- [ ] Serveur ERDPS démarré et accessible
- [ ] Redis configuré et fonctionnel
- [ ] Console web accessible via HTTPS
- [ ] Certificats SSL installés et valides
- [ ] Compte administrateur créé
- [ ] Au moins un agent connecté
- [ ] Politiques de sécurité configurées
- [ ] Alertes configurées
- [ ] Logs fonctionnels
- [ ] Sauvegarde configurée
- [ ] Monitoring configuré
- [ ] Documentation utilisateur distribuée

### 📞 Support

Pour toute assistance lors de l'installation :
- **Documentation**: [docs.erdps.com](https://docs.erdps.com)
- **Support technique**: support@erdps.com
- **Urgences**: +33 1 XX XX XX XX

---

**Note**: Cette installation crée un environnement ERDPS complet et sécurisé. Assurez-vous de suivre les bonnes pratiques de sécurité et de maintenir le système à jour.