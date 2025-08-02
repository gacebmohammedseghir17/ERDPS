# Guide de Configuration ERDPS

## 🔧 Configuration du Serveur

### Fichier de configuration principal

Le fichier `config/config.json` contient tous les paramètres du serveur ERDPS :

```json
{
  "server": {
    "port": 8443,
    "host": "0.0.0.0",
    "workers": 4,
    "max_connections": 1000,
    "ssl": {
      "enabled": true,
      "cert": "/etc/erdps/certs/server.crt",
      "key": "/etc/erdps/certs/server.key",
      "ca": "/etc/erdps/certs/ca.crt",
      "protocols": ["TLSv1.2", "TLSv1.3"],
      "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    }
  },
  "database": {
    "redis": {
      "host": "localhost",
      "port": 6379,
      "password": "your_secure_redis_password",
      "db": 0,
      "max_connections": 100,
      "timeout": 5000
    },
    "postgresql": {
      "enabled": false,
      "host": "localhost",
      "port": 5432,
      "database": "erdps",
      "username": "erdps_user",
      "password": "your_secure_db_password",
      "ssl": true,
      "pool_size": 20
    }
  },
  "security": {
    "jwt_secret": "your_256_bit_secret_key_here",
    "jwt_expiration": 3600,
    "encryption_key": "your_32_character_encryption_key",
    "password_policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_symbols": true,
      "max_age_days": 90
    },
    "session_timeout": 1800,
    "max_login_attempts": 5,
    "lockout_duration": 900,
    "two_factor_auth": {
      "enabled": true,
      "issuer": "ERDPS Security",
      "window": 1
    }
  },
  "logging": {
    "level": "info",
    "file": "/var/log/erdps/server.log",
    "max_size": "100MB",
    "max_files": 10,
    "format": "json",
    "audit_log": "/var/log/erdps/audit.log",
    "syslog": {
      "enabled": false,
      "facility": "local0",
      "tag": "erdps-server"
    }
  },
  "monitoring": {
    "metrics_enabled": true,
    "metrics_port": 9090,
    "health_check_interval": 30,
    "performance_monitoring": true
  },
  "integrations": {
    "siem": {
      "enabled": false,
      "type": "splunk",
      "endpoint": "https://splunk.company.com:8088/services/collector",
      "token": "your_splunk_hec_token",
      "index": "erdps"
    },
    "email": {
      "enabled": true,
      "smtp_host": "smtp.company.com",
      "smtp_port": 587,
      "username": "erdps@company.com",
      "password": "your_email_password",
      "from_address": "ERDPS Security <erdps@company.com>",
      "tls": true
    },
    "webhook": {
      "enabled": false,
      "url": "https://your-webhook-endpoint.com/erdps",
      "secret": "your_webhook_secret",
      "timeout": 10
    }
  }
}
```

### Variables d'environnement

Pour la sécurité, utilisez des variables d'environnement pour les données sensibles :

```bash
# Fichier .env
ERDPS_JWT_SECRET=your_256_bit_secret_key_here
ERDPS_ENCRYPTION_KEY=your_32_character_encryption_key
ERDPS_REDIS_PASSWORD=your_secure_redis_password
ERDPS_DB_PASSWORD=your_secure_db_password
ERDPS_EMAIL_PASSWORD=your_email_password
ERDPS_WEBHOOK_SECRET=your_webhook_secret
```

## 🛡️ Configuration des Agents

### Fichier de configuration agent

Chaque agent utilise le fichier `agent-config.json` :

```json
{
  "server": {
    "url": "https://erdps.company.com:8443",
    "verify_ssl": true,
    "ca_cert": "C:\\Program Files\\ERDPS\\certs\\ca.crt",
    "client_cert": "C:\\Program Files\\ERDPS\\certs\\client.crt",
    "client_key": "C:\\Program Files\\ERDPS\\certs\\client.key",
    "heartbeat_interval": 30,
    "reconnect_interval": 60,
    "max_reconnect_attempts": 10
  },
  "agent": {
    "id": "auto-generated",
    "name": "auto-detected",
    "group": "default",
    "tags": ["production", "windows"],
    "update_channel": "stable"
  },
  "monitoring": {
    "real_time_protection": true,
    "file_system_monitoring": true,
    "process_monitoring": true,
    "network_monitoring": true,
    "registry_monitoring": true,
    "performance_monitoring": true,
    "scan_frequency": "daily",
    "scan_time": "02:00",
    "cpu_limit": 25,
    "memory_limit": 512
  },
  "detection": {
    "signature_updates": {
      "auto_update": true,
      "update_interval": 3600,
      "update_server": "https://updates.erdps.com"
    },
    "heuristic_analysis": true,
    "behavioral_analysis": true,
    "cloud_lookup": true,
    "machine_learning": true,
    "custom_rules": []
  },
  "response": {
    "auto_quarantine": true,
    "auto_remediation": false,
    "isolation_on_threat": false,
    "notification_level": "medium",
    "actions": {
      "malware": "quarantine",
      "suspicious": "alert",
      "pua": "log"
    }
  },
  "exclusions": {
    "paths": [
      "C:\\Windows\\System32\\",
      "C:\\Program Files\\TrustedApp\\"
    ],
    "processes": [
      "trusted-process.exe"
    ],
    "extensions": [
      ".tmp",
      ".log"
    ],
    "registry_keys": [
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\TrustedSoftware"
    ]
  },
  "logging": {
    "level": "info",
    "file": "C:\\Program Files\\ERDPS\\logs\\agent.log",
    "max_size": "50MB",
    "max_files": 5,
    "syslog_enabled": false,
    "event_log_enabled": true
  }
}
```

## 🔐 Configuration de Sécurité

### Génération des certificats

#### Autorité de certification (CA)

```bash
# Création de la clé privée de la CA
openssl genrsa -aes256 -out ca-key.pem 4096

# Création du certificat de la CA
openssl req -new -x509 -days 3650 -key ca-key.pem -sha256 -out ca.pem -subj "/C=FR/ST=IDF/L=Paris/O=Company/OU=IT/CN=ERDPS-CA"
```

#### Certificat serveur

```bash
# Clé privée du serveur
openssl genrsa -out server-key.pem 4096

# Demande de signature de certificat
openssl req -subj "/C=FR/ST=IDF/L=Paris/O=Company/OU=IT/CN=erdps.company.com" -sha256 -new -key server-key.pem -out server.csr

# Extensions pour le certificat serveur
echo "subjectAltName = DNS:erdps.company.com,DNS:*.erdps.company.com,IP:192.168.1.100" > server-extfile.cnf
echo "extendedKeyUsage = serverAuth" >> server-extfile.cnf

# Signature du certificat serveur
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem -extfile server-extfile.cnf -CAcreateserial
```

#### Certificats clients

```bash
# Clé privée du client
openssl genrsa -out client-key.pem 4096

# Demande de signature de certificat client
openssl req -subj "/C=FR/ST=IDF/L=Paris/O=Company/OU=IT/CN=erdps-client" -new -key client-key.pem -out client.csr

# Extensions pour le certificat client
echo "extendedKeyUsage = clientAuth" > client-extfile.cnf

# Signature du certificat client
openssl x509 -req -days 365 -in client.csr -CA ca.pem -CAkey ca-key.pem -out client-cert.pem -extfile client-extfile.cnf -CAcreateserial
```

### Configuration du pare-feu

#### Windows (Agent)

```powershell
# Règles de pare-feu pour l'agent
New-NetFirewallRule -DisplayName "ERDPS Agent Outbound" -Direction Outbound -Protocol TCP -RemotePort 8443 -Action Allow
New-NetFirewallRule -DisplayName "ERDPS Agent Updates" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow
```

#### Linux (Serveur)

```bash
# UFW (Ubuntu)
sudo ufw allow 8443/tcp comment "ERDPS Server"
sudo ufw allow 443/tcp comment "ERDPS Web Console"
sudo ufw allow 22/tcp comment "SSH"

# iptables
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

## 📊 Configuration du Monitoring

### Prometheus

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'erdps-server'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 30s
    
  - job_name: 'erdps-agents'
    consul_sd_configs:
      - server: 'localhost:8500'
        services: ['erdps-agent']
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "ERDPS Monitoring",
    "panels": [
      {
        "title": "Agents Status",
        "type": "stat",
        "targets": [
          {
            "expr": "erdps_agents_total",
            "legendFormat": "Total Agents"
          }
        ]
      },
      {
        "title": "Threats Detected",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(erdps_threats_total[5m])",
            "legendFormat": "Threats/sec"
          }
        ]
      }
    ]
  }
}
```

## 🔗 Configuration des Intégrations

### Splunk

```json
{
  "integrations": {
    "siem": {
      "enabled": true,
      "type": "splunk",
      "endpoint": "https://splunk.company.com:8088/services/collector",
      "token": "your_splunk_hec_token",
      "index": "erdps",
      "source": "erdps:security",
      "sourcetype": "erdps:json",
      "batch_size": 100,
      "flush_interval": 30
    }
  }
}
```

### Microsoft Sentinel

```json
{
  "integrations": {
    "siem": {
      "enabled": true,
      "type": "sentinel",
      "workspace_id": "your_workspace_id",
      "shared_key": "your_shared_key",
      "log_type": "ERDPSSecurityEvents",
      "time_generated_field": "timestamp"
    }
  }
}
```

### Slack

```json
{
  "integrations": {
    "slack": {
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
      "channel": "#security-alerts",
      "username": "ERDPS",
      "icon_emoji": ":shield:",
      "alert_levels": ["high", "critical"]
    }
  }
}
```

## 🎯 Configuration des Politiques

### Politique de détection

```json
{
  "detection_policies": {
    "malware_policy": {
      "name": "Politique Anti-Malware Standard",
      "enabled": true,
      "rules": [
        {
          "id": "malware_001",
          "name": "Détection signature",
          "type": "signature",
          "action": "quarantine",
          "severity": "high"
        },
        {
          "id": "malware_002",
          "name": "Analyse heuristique",
          "type": "heuristic",
          "action": "alert",
          "severity": "medium",
          "threshold": 75
        }
      ]
    },
    "ransomware_policy": {
      "name": "Protection Ransomware",
      "enabled": true,
      "behavioral_detection": true,
      "file_backup": true,
      "network_isolation": true,
      "rules": [
        {
          "id": "ransomware_001",
          "name": "Chiffrement massif de fichiers",
          "type": "behavioral",
          "action": "isolate",
          "severity": "critical",
          "parameters": {
            "file_encryption_threshold": 10,
            "time_window": 60
          }
        }
      ]
    }
  }
}
```

### Politique de réponse

```json
{
  "response_policies": {
    "auto_response": {
      "enabled": true,
      "rules": [
        {
          "condition": "threat_level >= critical",
          "actions": [
            "isolate_endpoint",
            "notify_admin",
            "create_incident"
          ]
        },
        {
          "condition": "threat_type == ransomware",
          "actions": [
            "isolate_endpoint",
            "backup_files",
            "notify_ciso",
            "escalate_to_soc"
          ]
        }
      ]
    }
  }
}
```

## 🔄 Configuration de la Sauvegarde

### Sauvegarde automatique

```bash
#!/bin/bash
# backup-erdps.sh

BACKUP_DIR="/backup/erdps"
DATE=$(date +%Y%m%d_%H%M%S)

# Sauvegarde de la configuration
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" /etc/erdps/

# Sauvegarde de la base de données Redis
redis-cli --rdb "$BACKUP_DIR/redis_$DATE.rdb"

# Sauvegarde des logs
tar -czf "$BACKUP_DIR/logs_$DATE.tar.gz" /var/log/erdps/

# Nettoyage des anciennes sauvegardes (> 30 jours)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.rdb" -mtime +30 -delete
```

### Crontab pour automatisation

```bash
# Sauvegarde quotidienne à 2h du matin
0 2 * * * /usr/local/bin/backup-erdps.sh

# Vérification de l'état du service toutes les 5 minutes
*/5 * * * * systemctl is-active --quiet erdps-server || systemctl restart erdps-server
```

## 📋 Validation de la Configuration

### Script de validation

```bash
#!/bin/bash
# validate-config.sh

echo "Validation de la configuration ERDPS..."

# Vérification des certificats
if openssl x509 -in /etc/erdps/certs/server.crt -text -noout > /dev/null 2>&1; then
    echo "✓ Certificat serveur valide"
else
    echo "✗ Certificat serveur invalide"
fi

# Vérification de la connectivité Redis
if redis-cli ping > /dev/null 2>&1; then
    echo "✓ Redis accessible"
else
    echo "✗ Redis inaccessible"
fi

# Vérification des ports
if netstat -tlnp | grep :8443 > /dev/null; then
    echo "✓ Port 8443 ouvert"
else
    echo "✗ Port 8443 fermé"
fi

# Vérification des permissions
if [ -r /etc/erdps/config.json ]; then
    echo "✓ Configuration lisible"
else
    echo "✗ Configuration non lisible"
fi

echo "Validation terminée."
```

## 🚨 Dépannage Configuration

### Problèmes courants

#### Certificats SSL

```bash
# Vérifier l'expiration du certificat
openssl x509 -in /etc/erdps/certs/server.crt -text -noout | grep "Not After"

# Vérifier la chaîne de certificats
openssl verify -CAfile /etc/erdps/certs/ca.crt /etc/erdps/certs/server.crt

# Tester la connectivité SSL
openssl s_client -connect erdps.company.com:8443 -CAfile /etc/erdps/certs/ca.crt
```

#### Configuration Redis

```bash
# Tester la connectivité
redis-cli -h localhost -p 6379 -a your_password ping

# Vérifier la configuration
redis-cli CONFIG GET "*"

# Monitorer les performances
redis-cli --latency-history
```

#### Logs de débogage

```bash
# Activer le mode debug
sed -i 's/"level": "info"/"level": "debug"/' /etc/erdps/config.json
systemctl restart erdps-server

# Suivre les logs en temps réel
tail -f /var/log/erdps/server.log | jq .
```

---

**Note**: Adaptez ces configurations selon votre environnement spécifique. Testez toujours les modifications dans un environnement de développement avant la production.