# Référence API ERDPS

## 🔗 Vue d'ensemble

L'API ERDPS fournit une interface RESTful complète pour la gestion des agents, la surveillance des menaces, et l'administration du système. Toutes les communications utilisent HTTPS avec authentification JWT.

**URL de base**: `https://your-erdps-server.com/api/v1`

## 🔐 Authentification

### Obtenir un token JWT

```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

**Réponse**:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "user": {
    "id": "user_123",
    "username": "admin",
    "role": "administrator"
  }
}
```

### Utilisation du token

Tous les appels API nécessitent le header d'autorisation :
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 👥 Gestion des Agents

### Lister tous les agents

```http
GET /agents
Authorization: Bearer {token}
```

**Paramètres de requête**:
- `status` (optionnel): `online`, `offline`, `error`
- `page` (optionnel): Numéro de page (défaut: 1)
- `limit` (optionnel): Éléments par page (défaut: 50)
- `search` (optionnel): Recherche par nom ou IP

**Réponse**:
```json
{
  "success": true,
  "data": {
    "agents": [
      {
        "id": "agent_123",
        "hostname": "DESKTOP-ABC123",
        "ip_address": "192.168.1.100",
        "os": "Windows 11 Pro",
        "version": "1.2.3",
        "status": "online",
        "last_seen": "2024-01-15T10:30:00Z",
        "cpu_usage": 15.2,
        "memory_usage": 45.8,
        "disk_usage": 67.3,
        "threats_detected": 5,
        "location": {
          "country": "France",
          "city": "Paris"
        }
      }
    ],
    "pagination": {
      "current_page": 1,
      "total_pages": 10,
      "total_items": 500,
      "items_per_page": 50
    }
  }
}
```

### Obtenir les détails d'un agent

```http
GET /agents/{agent_id}
Authorization: Bearer {token}
```

**Réponse**:
```json
{
  "success": true,
  "data": {
    "id": "agent_123",
    "hostname": "DESKTOP-ABC123",
    "ip_address": "192.168.1.100",
    "mac_address": "00:11:22:33:44:55",
    "os": "Windows 11 Pro",
    "os_version": "22H2",
    "architecture": "x64",
    "version": "1.2.3",
    "status": "online",
    "installed_at": "2024-01-01T00:00:00Z",
    "last_seen": "2024-01-15T10:30:00Z",
    "performance": {
      "cpu_usage": 15.2,
      "memory_usage": 45.8,
      "disk_usage": 67.3,
      "network_io": {
        "bytes_sent": 1048576,
        "bytes_received": 2097152
      }
    },
    "security": {
      "threats_detected": 5,
      "threats_blocked": 3,
      "last_scan": "2024-01-15T09:00:00Z",
      "quarantine_items": 2
    },
    "configuration": {
      "real_time_protection": true,
      "auto_quarantine": true,
      "scan_frequency": "daily"
    }
  }
}
```

### Mettre à jour la configuration d'un agent

```http
PUT /agents/{agent_id}/config
Authorization: Bearer {token}
Content-Type: application/json

{
  "real_time_protection": true,
  "auto_quarantine": false,
  "scan_frequency": "weekly",
  "exclusions": [
    "C:\\Program Files\\TrustedApp\\",
    "*.tmp"
  ]
}
```

### Exécuter une action sur un agent

```http
POST /agents/{agent_id}/actions
Authorization: Bearer {token}
Content-Type: application/json

{
  "action": "scan",
  "parameters": {
    "type": "full",
    "priority": "high"
  }
}
```

**Actions disponibles**:
- `scan`: Lancer un scan
- `isolate`: Isoler l'agent du réseau
- `unisolate`: Lever l'isolation
- `restart`: Redémarrer l'agent
- `update`: Mettre à jour l'agent

## 🚨 Gestion des Alertes

### Lister les alertes

```http
GET /alerts
Authorization: Bearer {token}
```

**Paramètres de requête**:
- `severity` (optionnel): `low`, `medium`, `high`, `critical`
- `status` (optionnel): `open`, `investigating`, `resolved`
- `agent_id` (optionnel): Filtrer par agent
- `from_date` (optionnel): Date de début (ISO 8601)
- `to_date` (optionnel): Date de fin (ISO 8601)

**Réponse**:
```json
{
  "success": true,
  "data": {
    "alerts": [
      {
        "id": "alert_456",
        "title": "Malware détecté",
        "description": "Trojan.Win32.Generic détecté dans C:\\Users\\user\\Downloads\\file.exe",
        "severity": "high",
        "status": "open",
        "agent_id": "agent_123",
        "agent_hostname": "DESKTOP-ABC123",
        "created_at": "2024-01-15T10:30:00Z",
        "updated_at": "2024-01-15T10:30:00Z",
        "threat_type": "malware",
        "file_path": "C:\\Users\\user\\Downloads\\file.exe",
        "file_hash": "a1b2c3d4e5f6...",
        "action_taken": "quarantined",
        "ioc": {
          "ip_addresses": ["192.168.1.100"],
          "domains": ["malicious-domain.com"],
          "file_hashes": ["a1b2c3d4e5f6..."]
        }
      }
    ],
    "summary": {
      "total": 150,
      "open": 45,
      "investigating": 12,
      "resolved": 93
    }
  }
}
```

### Mettre à jour le statut d'une alerte

```http
PUT /alerts/{alert_id}
Authorization: Bearer {token}
Content-Type: application/json

{
  "status": "investigating",
  "assignee": "analyst_john",
  "notes": "Investigation en cours, analyse du fichier suspect"
}
```

## 📊 Rapports et Statistiques

### Obtenir le dashboard

```http
GET /dashboard
Authorization: Bearer {token}
```

**Réponse**:
```json
{
  "success": true,
  "data": {
    "summary": {
      "total_agents": 500,
      "online_agents": 487,
      "offline_agents": 13,
      "total_threats": 1250,
      "threats_today": 15,
      "critical_alerts": 3
    },
    "threat_trends": {
      "last_24h": [
        {"hour": "00", "count": 2},
        {"hour": "01", "count": 1},
        {"hour": "02", "count": 0}
      ]
    },
    "top_threats": [
      {
        "name": "Trojan.Win32.Generic",
        "count": 45,
        "percentage": 35.2
      }
    ],
    "agent_status_distribution": {
      "online": 487,
      "offline": 13,
      "error": 0
    }
  }
}
```

### Générer un rapport

```http
POST /reports
Authorization: Bearer {token}
Content-Type: application/json

{
  "type": "security_summary",
  "period": "last_30_days",
  "format": "pdf",
  "filters": {
    "agent_groups": ["production", "development"],
    "severity": ["high", "critical"]
  }
}
```

**Réponse**:
```json
{
  "success": true,
  "data": {
    "report_id": "report_789",
    "status": "generating",
    "estimated_completion": "2024-01-15T10:35:00Z"
  }
}
```

### Télécharger un rapport

```http
GET /reports/{report_id}/download
Authorization: Bearer {token}
```

## ⚙️ Configuration Système

### Obtenir la configuration

```http
GET /config
Authorization: Bearer {token}
```

### Mettre à jour la configuration

```http
PUT /config
Authorization: Bearer {token}
Content-Type: application/json

{
  "global_settings": {
    "auto_quarantine": true,
    "real_time_scanning": true,
    "cloud_lookup": true
  },
  "notification_settings": {
    "email_alerts": true,
    "sms_alerts": false,
    "webhook_url": "https://your-siem.com/webhook"
  },
  "retention_policy": {
    "logs_retention_days": 90,
    "alerts_retention_days": 365
  }
}
```

## 👤 Gestion des Utilisateurs

### Lister les utilisateurs

```http
GET /users
Authorization: Bearer {token}
```

### Créer un utilisateur

```http
POST /users
Authorization: Bearer {token}
Content-Type: application/json

{
  "username": "analyst_jane",
  "email": "jane@company.com",
  "password": "SecurePassword123!",
  "role": "analyst",
  "permissions": [
    "view_alerts",
    "manage_alerts",
    "view_agents"
  ]
}
```

## 🔍 Recherche et Filtrage

### Recherche globale

```http
GET /search
Authorization: Bearer {token}
```

**Paramètres de requête**:
- `q`: Terme de recherche
- `type`: `agents`, `alerts`, `threats`, `files`
- `limit`: Nombre de résultats (défaut: 20)

## 📡 WebSocket pour les mises à jour en temps réel

### Connexion WebSocket

```javascript
const ws = new WebSocket('wss://your-erdps-server.com/ws');

// Authentification
ws.send(JSON.stringify({
  type: 'auth',
  token: 'your_jwt_token'
}));

// Écouter les événements
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Événement reçu:', data);
};
```

**Types d'événements**:
- `agent_status_changed`
- `new_alert`
- `threat_detected`
- `system_update`

## 🚫 Codes d'erreur

| Code | Description |
|------|-------------|
| 400 | Requête invalide |
| 401 | Non authentifié |
| 403 | Accès refusé |
| 404 | Ressource non trouvée |
| 429 | Trop de requêtes |
| 500 | Erreur serveur interne |

**Format des erreurs**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Nom d'utilisateur ou mot de passe incorrect",
    "details": {
      "field": "password",
      "reason": "invalid"
    }
  }
}
```

## 📝 Limites de l'API

- **Limite de taux**: 1000 requêtes par heure par utilisateur
- **Taille maximale des requêtes**: 10 MB
- **Timeout**: 30 secondes
- **Connexions WebSocket simultanées**: 10 par utilisateur

## 🔒 Sécurité

- Toutes les communications doivent utiliser HTTPS
- Les tokens JWT expirent après 1 heure
- Authentification à deux facteurs supportée
- Audit complet de toutes les actions API
- Chiffrement AES-256 pour les données sensibles

## 📚 Exemples d'intégration

### Python

```python
import requests
import json

class ERDPSClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.token = self._authenticate(username, password)
        
    def _authenticate(self, username, password):
        response = requests.post(f"{self.base_url}/auth/login", 
                               json={"username": username, "password": password})
        return response.json()["token"]
        
    def get_agents(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(f"{self.base_url}/agents", headers=headers)
        return response.json()

# Utilisation
client = ERDPSClient("https://erdps.company.com/api/v1", "admin", "password")
agents = client.get_agents()
print(f"Nombre d'agents: {len(agents['data']['agents'])}")
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

class ERDPSClient {
  constructor(baseUrl, username, password) {
    this.baseUrl = baseUrl;
    this.authenticate(username, password);
  }
  
  async authenticate(username, password) {
    const response = await axios.post(`${this.baseUrl}/auth/login`, {
      username,
      password
    });
    this.token = response.data.token;
  }
  
  async getAlerts(filters = {}) {
    const response = await axios.get(`${this.baseUrl}/alerts`, {
      headers: { Authorization: `Bearer ${this.token}` },
      params: filters
    });
    return response.data;
  }
}

// Utilisation
const client = new ERDPSClient('https://erdps.company.com/api/v1', 'admin', 'password');
const alerts = await client.getAlerts({ severity: 'high' });
console.log(`Alertes critiques: ${alerts.data.alerts.length}`);
```

---

**Note**: Cette API est en constante évolution. Consultez la documentation en ligne pour les dernières mises à jour : [api.erdps.com](https://api.erdps.com)