import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import LoadingSpinner, { CardSkeleton } from '../components/UI/LoadingSpinner';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Users, 
  TrendingUp, 
  TrendingDown,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  BarChart3,
  PieChart,
  RefreshCw
} from 'lucide-react';

interface DashboardStats {
  totalEndpoints: number;
  activeEndpoints: number;
  totalAlerts: number;
  criticalAlerts: number;
  detectionRate: number;
  responseTime: number;
  lastUpdate: string;
}

interface RecentAlert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  endpoint: string;
  timestamp: string;
  status: 'new' | 'investigating' | 'resolved';
}

interface ThreatTrend {
  date: string;
  threats: number;
  blocked: number;
}

export default function Dashboard() {
  const { state } = useAuth();
  const { isDark } = useTheme();
  const [isLoading, setIsLoading] = useState(true);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<RecentAlert[]>([]);
  const [threatTrends, setThreatTrends] = useState<ThreatTrend[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  // Simulation de données
  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setIsLoading(true);
    
    // Simulation d'un appel API
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    setStats({
      totalEndpoints: 1247,
      activeEndpoints: 1198,
      totalAlerts: 23,
      criticalAlerts: 3,
      detectionRate: 99.2,
      responseTime: 1.8,
      lastUpdate: new Date().toISOString(),
    });

    setRecentAlerts([
      {
        id: '1',
        severity: 'critical',
        type: 'Ransomware détecté',
        endpoint: 'WS-FINANCE-01',
        timestamp: new Date(Date.now() - 300000).toISOString(),
        status: 'investigating'
      },
      {
        id: '2',
        severity: 'high',
        type: 'Activité suspecte',
        endpoint: 'WS-HR-15',
        timestamp: new Date(Date.now() - 900000).toISOString(),
        status: 'new'
      },
      {
        id: '3',
        severity: 'medium',
        type: 'Règle YARA déclenchée',
        endpoint: 'SRV-WEB-02',
        timestamp: new Date(Date.now() - 1800000).toISOString(),
        status: 'resolved'
      }
    ]);

    setThreatTrends([
      { date: '2024-01-15', threats: 45, blocked: 43 },
      { date: '2024-01-16', threats: 52, blocked: 50 },
      { date: '2024-01-17', threats: 38, blocked: 38 },
      { date: '2024-01-18', threats: 61, blocked: 59 },
      { date: '2024-01-19', threats: 29, blocked: 29 },
    ]);

    setIsLoading(false);
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadDashboardData();
    setRefreshing(false);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100 dark:bg-red-900/20';
      case 'high': return 'text-orange-600 bg-orange-100 dark:bg-orange-900/20';
      case 'medium': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/20';
      case 'low': return 'text-blue-600 bg-blue-100 dark:bg-blue-900/20';
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-900/20';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'new': return 'text-red-600';
      case 'investigating': return 'text-yellow-600';
      case 'resolved': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `il y a ${hours}h ${minutes % 60}m`;
    }
    return `il y a ${minutes}m`;
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {Array.from({ length: 4 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <CardSkeleton />
          <CardSkeleton />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Tableau de bord
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Bienvenue, {state.user?.name || state.user?.username}
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
          Actualiser
        </button>
      </div>

      {/* Statistiques principales */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Endpoints actifs */}
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Users className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Endpoints actifs
                  </dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900 dark:text-white">
                      {stats?.activeEndpoints}
                    </div>
                    <div className="ml-2 text-sm text-gray-600 dark:text-gray-400">
                      / {stats?.totalEndpoints}
                    </div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 px-5 py-3">
            <div className="text-sm">
              <span className="text-green-600 dark:text-green-400 font-medium flex items-center">
                <TrendingUp className="h-4 w-4 mr-1" />
                96.1% en ligne
              </span>
            </div>
          </div>
        </div>

        {/* Alertes critiques */}
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <AlertTriangle className="h-6 w-6 text-red-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Alertes critiques
                  </dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900 dark:text-white">
                      {stats?.criticalAlerts}
                    </div>
                    <div className="ml-2 text-sm text-gray-600 dark:text-gray-400">
                      / {stats?.totalAlerts}
                    </div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 px-5 py-3">
            <div className="text-sm">
              <span className="text-red-600 dark:text-red-400 font-medium">
                Attention requise
              </span>
            </div>
          </div>
        </div>

        {/* Taux de détection */}
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Shield className="h-6 w-6 text-green-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Taux de détection
                  </dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900 dark:text-white">
                      {stats?.detectionRate}%
                    </div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 px-5 py-3">
            <div className="text-sm">
              <span className="text-green-600 dark:text-green-400 font-medium flex items-center">
                <TrendingUp className="h-4 w-4 mr-1" />
                +0.3% ce mois
              </span>
            </div>
          </div>
        </div>

        {/* Temps de réponse */}
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Clock className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Temps de réponse
                  </dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900 dark:text-white">
                      {stats?.responseTime}s
                    </div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 px-5 py-3">
            <div className="text-sm">
              <span className="text-green-600 dark:text-green-400 font-medium flex items-center">
                <TrendingDown className="h-4 w-4 mr-1" />
                -0.2s amélioration
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Contenu principal */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alertes récentes */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Alertes récentes
            </h3>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {recentAlerts.map((alert) => (
              <div key={alert.id} className="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                      {alert.severity.toUpperCase()}
                    </span>
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {alert.type}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {alert.endpoint} • {formatTime(alert.timestamp)}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {alert.status === 'new' && <AlertCircle className={`h-4 w-4 ${getStatusColor(alert.status)}`} />}
                    {alert.status === 'investigating' && <Clock className={`h-4 w-4 ${getStatusColor(alert.status)}`} />}
                    {alert.status === 'resolved' && <CheckCircle className={`h-4 w-4 ${getStatusColor(alert.status)}`} />}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="px-6 py-3 bg-gray-50 dark:bg-gray-700">
            <a href="/alerts" className="text-sm font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400">
              Voir toutes les alertes →
            </a>
          </div>
        </div>

        {/* Tendances des menaces */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Tendances des menaces (5 derniers jours)
            </h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {threatTrends.map((trend, index) => (
                <div key={trend.date} className="flex items-center justify-between">
                  <div className="text-sm text-gray-600 dark:text-gray-400">
                    {new Date(trend.date).toLocaleDateString('fr-FR', { 
                      month: 'short', 
                      day: 'numeric' 
                    })}
                  </div>
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      <span className="text-sm text-gray-900 dark:text-white">
                        {trend.threats} menaces
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                      <span className="text-sm text-gray-900 dark:text-white">
                        {trend.blocked} bloquées
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="px-6 py-3 bg-gray-50 dark:bg-gray-700">
            <a href="/reports" className="text-sm font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400">
              Voir les rapports détaillés →
            </a>
          </div>
        </div>
      </div>

      {/* Statut du système */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Statut du système
          </h3>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-white">Moteur YARA</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">Opérationnel</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-white">Analyse comportementale</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">Opérationnel</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-white">Base de données</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">Opérationnel</p>
              </div>
            </div>
          </div>
          <div className="mt-4 text-sm text-gray-500 dark:text-gray-400">
            Dernière mise à jour: {stats && new Date(stats.lastUpdate).toLocaleString('fr-FR')}
          </div>
        </div>
      </div>
    </div>
  );
}