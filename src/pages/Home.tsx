import React, { useState, useEffect } from 'react';
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
  RefreshCw,
  Menu,
  Bell,
  Search,
  Settings,
  LogOut,
  User,
  Monitor,
  FileText
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

export default function Home() {
  const [isLoading, setIsLoading] = useState(true);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<RecentAlert[]>([]);
  const [threatTrends, setThreatTrends] = useState<ThreatTrend[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Load dashboard data
  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setIsLoading(true);
    
    // Simulate API call
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
        type: 'Ransomware detected',
        endpoint: 'WS-FINANCE-01',
        timestamp: new Date(Date.now() - 300000).toISOString(),
        status: 'investigating'
      },
      {
        id: '2',
        severity: 'high',
        type: 'Suspicious activity',
        endpoint: 'WS-HR-15',
        timestamp: new Date(Date.now() - 900000).toISOString(),
        status: 'new'
      },
      {
        id: '3',
        severity: 'medium',
        type: 'YARA rule triggered',
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
      return `${hours}h ${minutes % 60}m ago`;
    }
    return `${minutes}m ago`;
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
          <p className="mt-4 text-gray-400">Loading ERDPS Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Sidebar */}
      <div className={`fixed inset-y-0 left-0 z-50 w-64 bg-gray-800 transform transition-transform duration-300 ease-in-out ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      } lg:translate-x-0`}>
        <div className="flex items-center justify-between h-16 px-6 border-b border-gray-700">
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8 text-blue-400" />
            <span className="text-xl font-bold">ERDPS</span>
          </div>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden p-1 rounded-md text-gray-400 hover:text-white hover:bg-gray-700"
          >
            <XCircle className="w-6 h-6" />
          </button>
        </div>

        <nav className="mt-6 px-3">
          <div className="space-y-1">
            <a href="#" className="bg-blue-900 text-blue-200 group flex items-center px-3 py-2 text-sm font-medium rounded-md">
              <BarChart3 className="mr-3 h-5 w-5 text-blue-400" />
              Dashboard
            </a>
            <a href="#" className="text-gray-300 hover:bg-gray-700 hover:text-white group flex items-center px-3 py-2 text-sm font-medium rounded-md">
              <Monitor className="mr-3 h-5 w-5 text-gray-400 group-hover:text-gray-300" />
              Endpoints
            </a>
            <a href="#" className="text-gray-300 hover:bg-gray-700 hover:text-white group flex items-center justify-between px-3 py-2 text-sm font-medium rounded-md">
              <div className="flex items-center">
                <AlertTriangle className="mr-3 h-5 w-5 text-gray-400 group-hover:text-gray-300" />
                Alerts
              </div>
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                3
              </span>
            </a>
            <a href="#" className="text-gray-300 hover:bg-gray-700 hover:text-white group flex items-center px-3 py-2 text-sm font-medium rounded-md">
              <Settings className="mr-3 h-5 w-5 text-gray-400 group-hover:text-gray-300" />
              Rules
            </a>
            <a href="#" className="text-gray-300 hover:bg-gray-700 hover:text-white group flex items-center px-3 py-2 text-sm font-medium rounded-md">
              <FileText className="mr-3 h-5 w-5 text-gray-400 group-hover:text-gray-300" />
              Reports
            </a>
            <a href="#" className="text-gray-300 hover:bg-gray-700 hover:text-white group flex items-center px-3 py-2 text-sm font-medium rounded-md">
              <Users className="mr-3 h-5 w-5 text-gray-400 group-hover:text-gray-300" />
              Administration
            </a>
          </div>
        </nav>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top navigation */}
        <div className="sticky top-0 z-40 bg-gray-800 shadow-sm border-b border-gray-700">
          <div className="flex items-center justify-between h-16 px-4 sm:px-6 lg:px-8">
            <div className="flex items-center">
              <button
                onClick={() => setSidebarOpen(true)}
                className="lg:hidden p-2 rounded-md text-gray-400 hover:text-white hover:bg-gray-700"
              >
                <Menu className="w-6 h-6" />
              </button>
              <h1 className="ml-4 lg:ml-0 text-xl font-semibold">Security Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <button className="p-2 rounded-md text-gray-400 hover:text-white hover:bg-gray-700">
                <Search className="w-5 h-5" />
              </button>
              <button className="p-2 rounded-md text-gray-400 hover:text-white hover:bg-gray-700 relative">
                <Bell className="w-5 h-5" />
                <span className="absolute top-0 right-0 block h-2 w-2 rounded-full bg-red-400"></span>
              </button>
              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="inline-flex items-center px-3 py-2 border border-gray-600 rounded-md text-sm font-medium text-gray-300 bg-gray-700 hover:bg-gray-600 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <button className="p-2 rounded-md text-gray-400 hover:text-white hover:bg-gray-700">
                <User className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>

        {/* Dashboard content */}
        <div className="p-6 space-y-6">
          {/* Stats grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* Active Endpoints */}
            <div className="bg-gray-800 overflow-hidden shadow rounded-lg border border-gray-700">
              <div className="p-5">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Users className="h-6 w-6 text-blue-400" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-400 truncate">
                        Active Endpoints
                      </dt>
                      <dd className="flex items-baseline">
                        <div className="text-2xl font-semibold text-white">
                          {stats?.activeEndpoints}
                        </div>
                        <div className="ml-2 text-sm text-gray-400">
                          / {stats?.totalEndpoints}
                        </div>
                      </dd>
                    </dl>
                  </div>
                </div>
              </div>
              <div className="bg-gray-700 px-5 py-3">
                <div className="text-sm">
                  <span className="text-green-400 font-medium flex items-center">
                    <TrendingUp className="h-4 w-4 mr-1" />
                    96.1% online
                  </span>
                </div>
              </div>
            </div>

            {/* Critical Alerts */}
            <div className="bg-gray-800 overflow-hidden shadow rounded-lg border border-gray-700">
              <div className="p-5">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <AlertTriangle className="h-6 w-6 text-red-400" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-400 truncate">
                        Critical Alerts
                      </dt>
                      <dd className="flex items-baseline">
                        <div className="text-2xl font-semibold text-white">
                          {stats?.criticalAlerts}
                        </div>
                        <div className="ml-2 text-sm text-gray-400">
                          / {stats?.totalAlerts}
                        </div>
                      </dd>
                    </dl>
                  </div>
                </div>
              </div>
              <div className="bg-gray-700 px-5 py-3">
                <div className="text-sm">
                  <span className="text-red-400 font-medium">
                    Requires attention
                  </span>
                </div>
              </div>
            </div>

            {/* Detection Rate */}
            <div className="bg-gray-800 overflow-hidden shadow rounded-lg border border-gray-700">
              <div className="p-5">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Shield className="h-6 w-6 text-green-400" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-400 truncate">
                        Detection Rate
                      </dt>
                      <dd className="flex items-baseline">
                        <div className="text-2xl font-semibold text-white">
                          {stats?.detectionRate}%
                        </div>
                      </dd>
                    </dl>
                  </div>
                </div>
              </div>
              <div className="bg-gray-700 px-5 py-3">
                <div className="text-sm">
                  <span className="text-green-400 font-medium flex items-center">
                    <TrendingUp className="h-4 w-4 mr-1" />
                    +0.3% this month
                  </span>
                </div>
              </div>
            </div>

            {/* Response Time */}
            <div className="bg-gray-800 overflow-hidden shadow rounded-lg border border-gray-700">
              <div className="p-5">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Clock className="h-6 w-6 text-blue-400" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-400 truncate">
                        Response Time
                      </dt>
                      <dd className="flex items-baseline">
                        <div className="text-2xl font-semibold text-white">
                          {stats?.responseTime}s
                        </div>
                      </dd>
                    </dl>
                  </div>
                </div>
              </div>
              <div className="bg-gray-700 px-5 py-3">
                <div className="text-sm">
                  <span className="text-green-400 font-medium flex items-center">
                    <TrendingDown className="h-4 w-4 mr-1" />
                    -0.2s improvement
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Main content grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Recent Alerts */}
            <div className="bg-gray-800 shadow rounded-lg border border-gray-700">
              <div className="px-6 py-4 border-b border-gray-700">
                <h3 className="text-lg font-medium text-white">
                  Recent Alerts
                </h3>
              </div>
              <div className="divide-y divide-gray-700">
                {recentAlerts.map((alert) => (
                  <div key={alert.id} className="px-6 py-4 hover:bg-gray-700">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                          {alert.severity.toUpperCase()}
                        </span>
                        <div>
                          <p className="text-sm font-medium text-white">
                            {alert.type}
                          </p>
                          <p className="text-sm text-gray-400">
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
              <div className="px-6 py-3 bg-gray-700">
                <a href="#" className="text-sm font-medium text-blue-400 hover:text-blue-300">
                  View all alerts →
                </a>
              </div>
            </div>

            {/* Threat Trends */}
            <div className="bg-gray-800 shadow rounded-lg border border-gray-700">
              <div className="px-6 py-4 border-b border-gray-700">
                <h3 className="text-lg font-medium text-white">
                  Threat Trends (Last 5 days)
                </h3>
              </div>
              <div className="p-6">
                <div className="space-y-4">
                  {threatTrends.map((trend, index) => (
                    <div key={trend.date} className="flex items-center justify-between">
                      <div className="text-sm text-gray-400">
                        {new Date(trend.date).toLocaleDateString('en-US', { 
                          month: 'short', 
                          day: 'numeric' 
                        })}
                      </div>
                      <div className="flex items-center space-x-4">
                        <div className="flex items-center space-x-2">
                          <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                          <span className="text-sm text-white">
                            {trend.threats} threats
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                          <span className="text-sm text-white">
                            {trend.blocked} blocked
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="px-6 py-3 bg-gray-700">
                <a href="#" className="text-sm font-medium text-blue-400 hover:text-blue-300">
                  View detailed reports →
                </a>
              </div>
            </div>
          </div>

          {/* System Status */}
          <div className="bg-gray-800 shadow rounded-lg border border-gray-700">
            <div className="px-6 py-4 border-b border-gray-700">
              <h3 className="text-lg font-medium text-white">
                System Status
              </h3>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="flex items-center space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-400" />
                  <div>
                    <p className="text-sm font-medium text-white">YARA Engine</p>
                    <p className="text-sm text-gray-400">Operational</p>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-400" />
                  <div>
                    <p className="text-sm font-medium text-white">Behavioral Analysis</p>
                    <p className="text-sm text-gray-400">Operational</p>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-400" />
                  <div>
                    <p className="text-sm font-medium text-white">Database</p>
                    <p className="text-sm text-gray-400">Operational</p>
                  </div>
                </div>
              </div>
              <div className="mt-4 text-sm text-gray-400">
                Last updated: {stats && new Date(stats.lastUpdate).toLocaleString()}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 bg-gray-600 bg-opacity-75 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
}