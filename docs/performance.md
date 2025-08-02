# Métriques de Performance ERDPS

## 📊 Vue d'ensemble des Performances

ERDPS est conçu pour offrir des performances optimales tout en maintenant une sécurité maximale. Ce document détaille les métriques de performance, les benchmarks et les recommandations d'optimisation.

## 🎯 Objectifs de Performance

### Serveur ERDPS

| Métrique | Objectif | Seuil Critique |
|----------|----------|----------------|
| Temps de réponse API | < 200ms | > 1000ms |
| Débit de traitement | > 10,000 événements/sec | < 1,000 événements/sec |
| Utilisation CPU | < 70% | > 90% |
| Utilisation mémoire | < 80% | > 95% |
| Disponibilité | > 99.9% | < 99% |
| Latence réseau | < 50ms | > 200ms |

### Agents ERDPS

| Métrique | Objectif | Seuil Critique |
|----------|----------|----------------|
| Impact CPU | < 5% | > 15% |
| Utilisation mémoire | < 256MB | > 512MB |
| Temps de scan | < 30min (complet) | > 2h |
| Détection en temps réel | < 1sec | > 5sec |
| Taille des logs | < 100MB/jour | > 500MB/jour |
| Heartbeat | 30sec | > 300sec |

## 📈 Métriques Détaillées

### Métriques Serveur

#### Performance API

```json
{
  "api_metrics": {
    "endpoints": {
      "/api/v1/agents": {
        "avg_response_time": "145ms",
        "95th_percentile": "280ms",
        "99th_percentile": "450ms",
        "requests_per_second": 1250,
        "error_rate": "0.02%"
      },
      "/api/v1/alerts": {
        "avg_response_time": "89ms",
        "95th_percentile": "180ms",
        "99th_percentile": "320ms",
        "requests_per_second": 850,
        "error_rate": "0.01%"
      },
      "/api/v1/dashboard": {
        "avg_response_time": "234ms",
        "95th_percentile": "420ms",
        "99th_percentile": "680ms",
        "requests_per_second": 450,
        "error_rate": "0.05%"
      }
    },
    "overall": {
      "total_requests": 2550,
      "avg_response_time": "156ms",
      "throughput": "2.55K req/sec",
      "concurrent_connections": 125
    }
  }
}
```

#### Utilisation des Ressources

```json
{
  "system_metrics": {
    "cpu": {
      "usage_percent": 45.2,
      "load_average": {
        "1min": 2.1,
        "5min": 1.8,
        "15min": 1.6
      },
      "cores": 8,
      "frequency": "3.2GHz"
    },
    "memory": {
      "total": "16GB",
      "used": "8.2GB",
      "usage_percent": 51.3,
      "available": "7.8GB",
      "swap_used": "0MB"
    },
    "disk": {
      "total": "500GB",
      "used": "180GB",
      "usage_percent": 36.0,
      "iops": {
        "read": 1250,
        "write": 850
      },
      "latency": {
        "read": "2.1ms",
        "write": "3.4ms"
      }
    },
    "network": {
      "bandwidth_in": "125Mbps",
      "bandwidth_out": "89Mbps",
      "packets_per_second": 15000,
      "connections": {
        "active": 245,
        "established": 198,
        "time_wait": 47
      }
    }
  }
}
```

### Métriques Base de Données

#### Redis Performance

```json
{
  "redis_metrics": {
    "memory": {
      "used": "2.1GB",
      "peak": "2.8GB",
      "fragmentation_ratio": 1.15,
      "evicted_keys": 0
    },
    "operations": {
      "ops_per_sec": 8500,
      "hit_rate": "98.5%",
      "miss_rate": "1.5%",
      "avg_ttl": "3600s"
    },
    "connections": {
      "connected_clients": 45,
      "max_clients": 10000,
      "rejected_connections": 0
    },
    "persistence": {
      "last_save_time": "2024-01-15T10:30:00Z",
      "changes_since_last_save": 1250,
      "rdb_size": "1.2GB"
    }
  }
}
```

### Métriques Agents

#### Performance par Agent

```json
{
  "agent_metrics": {
    "agent_123": {
      "system_impact": {
        "cpu_usage": "3.2%",
        "memory_usage": "185MB",
        "disk_io": {
          "read_bytes_per_sec": "2.1MB",
          "write_bytes_per_sec": "0.8MB"
        },
        "network_io": {
          "bytes_sent_per_sec": "15KB",
          "bytes_received_per_sec": "8KB"
        }
      },
      "detection_performance": {
        "files_scanned_per_sec": 1250,
        "detection_latency": "0.8ms",
        "false_positive_rate": "0.01%",
        "threats_detected": 5,
        "threats_blocked": 3
      },
      "communication": {
        "heartbeat_interval": "30s",
        "last_heartbeat": "2024-01-15T10:29:45Z",
        "connection_uptime": "99.8%",
        "data_compression_ratio": 0.65
      }
    }
  }
}
```

## 🔍 Monitoring et Alertes

### Configuration Prometheus

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "erdps_alerts.yml"

scrape_configs:
  - job_name: 'erdps-server'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
    metrics_path: '/metrics'
    
  - job_name: 'erdps-agents'
    consul_sd_configs:
      - server: 'localhost:8500'
        services: ['erdps-agent']
    scrape_interval: 60s
    
  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']
```

### Règles d'Alerte

```yaml
# erdps_alerts.yml
groups:
  - name: erdps_server
    rules:
      - alert: ERDPSServerDown
        expr: up{job="erdps-server"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Serveur ERDPS indisponible"
          description: "Le serveur ERDPS est indisponible depuis plus d'1 minute"
          
      - alert: ERDPSHighCPU
        expr: erdps_cpu_usage_percent > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Utilisation CPU élevée sur le serveur ERDPS"
          description: "CPU à {{ $value }}% depuis 5 minutes"
          
      - alert: ERDPSHighMemory
        expr: erdps_memory_usage_percent > 85
        for: 3m
        labels:
          severity: warning
        annotations:
          summary: "Utilisation mémoire élevée"
          description: "Mémoire à {{ $value }}% depuis 3 minutes"
          
      - alert: ERDPSSlowAPI
        expr: erdps_api_response_time_95th > 1000
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "API ERDPS lente"
          description: "95e percentile à {{ $value }}ms depuis 2 minutes"
          
  - name: erdps_agents
    rules:
      - alert: ERDPSAgentOffline
        expr: erdps_agent_last_seen > 300
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Agent ERDPS hors ligne"
          description: "Agent {{ $labels.hostname }} hors ligne depuis {{ $value }}s"
          
      - alert: ERDPSAgentHighCPU
        expr: erdps_agent_cpu_usage > 10
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Agent ERDPS utilise trop de CPU"
          description: "Agent {{ $labels.hostname }} utilise {{ $value }}% CPU"
          
      - alert: ERDPSManyThreats
        expr: increase(erdps_threats_detected_total[1h]) > 50
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Nombreuses menaces détectées"
          description: "{{ $value }} menaces détectées en 1 heure"
```

### Dashboard Grafana

```json
{
  "dashboard": {
    "id": null,
    "title": "ERDPS Performance Dashboard",
    "tags": ["erdps", "security", "performance"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Agents Status Overview",
        "type": "stat",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "targets": [
          {
            "expr": "erdps_agents_total",
            "legendFormat": "Total Agents"
          },
          {
            "expr": "erdps_agents_online",
            "legendFormat": "Online"
          },
          {
            "expr": "erdps_agents_offline",
            "legendFormat": "Offline"
          }
        ]
      },
      {
        "id": 2,
        "title": "API Response Times",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "targets": [
          {
            "expr": "erdps_api_response_time_avg",
            "legendFormat": "Average"
          },
          {
            "expr": "erdps_api_response_time_95th",
            "legendFormat": "95th Percentile"
          }
        ],
        "yAxes": [