import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import LoadingSpinner, { TableSkeleton } from '../components/UI/LoadingSpinner';
import { PermissionGate } from '../components/Auth/ProtectedRoute';
import { 
  Search, 
  Filter, 
  Download, 
  RefreshCw, 
  MoreVertical,
  AlertTriangle,
  Shield,
  Clock,
  CheckCircle,
  XCircle,
  Eye,
  UserCheck,
  Archive,
  Flag,
  FileText,
  ExternalLink
} from 'lucide-react';

interface Alert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  description: string;
  endpoint: string;
  user: string;
  timestamp: string;
  status: 'new' | 'investigating' | 'resolved' | 'false_positive';
  assignedTo?: string;
  ruleId?: string;
  filePath?: string;
  processName?: string;
  hash?: string;
  tags: string[];
}

type SortField = 'timestamp' | 'severity' | 'status' | 'endpoint';
type SortDirection = 'asc' | 'desc';

export default function Alerts() {
  const { hasPermission } = useAuth();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filteredAlerts, setFilteredAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [selectedAlerts, setSelectedAlerts] = useState<string[]>([]);
  const [showActions, setShowActions] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  useEffect(() => {
    loadAlerts();
  }, []);

  useEffect(() => {
    filterAndSortAlerts();
  }, [alerts, searchTerm, severityFilter, statusFilter, typeFilter, sortField, sortDirection]);

  const loadAlerts = async () => {
    setIsLoading(true);
    
    // Simulation d'un appel API
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const mockAlerts: Alert[] = [
      {
        id: '1',
        severity: 'critical',
        type: 'Ransomware détecté',
        description: 'Activité de chiffrement suspecte détectée - Possible ransomware WannaCry',
        endpoint: 'WS-FINANCE-01',
        user: 'marie.dupont',
        timestamp: new Date(Date.now() - 300000).toISOString(),
        status: 'investigating',
        assignedTo: 'admin',
        ruleId: 'YARA_WANNACRY_001',
        filePath: 'C:\\Users\\marie.dupont\\Documents\\suspicious.exe',
        processName: 'suspicious.exe',
        hash: 'a1b2c3d4e5f6789012345678901234567890abcd',
        tags: ['ransomware', 'encryption', 'wannacry']
      },
      {
        id: '2',
        severity: 'high',
        type: 'Activité suspecte',
        description: 'Tentative de modification massive de fichiers',
        endpoint: 'WS-HR-15',
        user: 'jean.martin',
        timestamp: new Date(Date.now() - 900000).toISOString(),
        status: 'new',
        filePath: 'C:\\Users\\jean.martin\\Desktop\\',
        processName: 'powershell.exe',
        tags: ['behavioral', 'file_modification']
      },
      {
        id: '3',
        severity: 'medium',
        type: 'Règle YARA déclenchée',
        description: 'Signature malware détectée dans un fichier téléchargé',
        endpoint: 'SRV-WEB-02',
        user: 'system',
        timestamp: new Date(Date.now() - 1800000).toISOString(),
        status: 'resolved',
        assignedTo: 'analyst',
        ruleId: 'YARA_TROJAN_GENERIC',
        filePath: 'C:\\temp\\download.tmp',
        hash: 'b2c3d4e5f6789012345678901234567890abcdef',
        tags: ['yara', 'trojan', 'download']
      },
      {
        id: '4',
        severity: 'low',
        type: 'Connexion réseau suspecte',
        description: 'Connexion vers une IP blacklistée',
        endpoint: 'WS-SALES-08',
        user: 'pierre.bernard',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        status: 'false_positive',
        tags: ['network', 'blacklist']
      },
      {
        id: '5',
        severity: 'high',
        type: 'Processus malveillant',
        description: 'Exécution d\'un processus connu malveillant',
        endpoint: 'WS-FINANCE-01',
        user: 'marie.dupont',
        timestamp: new Date(Date.now() - 7200000).toISOString(),
        status: 'resolved',
        assignedTo: 'admin',
        processName: 'malware.exe',
        hash: 'c3d4e5f6789012345678901234567890abcdef12',
        tags: ['process', 'malware', 'execution']
      }
    ];
    
    setAlerts(mockAlerts);
    setIsLoading(false);
  };

  const filterAndSortAlerts = () => {
    let filtered = alerts.filter(alert => {
      const matchesSearch = alert.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           alert.endpoint.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           alert.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           alert.type.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
      const matchesStatus = statusFilter === 'all' || alert.status === statusFilter;
      const matchesType = typeFilter === 'all' || alert.type === typeFilter;
      
      return matchesSearch && matchesSeverity && matchesStatus && matchesType;
    });

    // Tri
    filtered.sort((a, b) => {
      let aValue: any = a[sortField];
      let bValue: any = b[sortField];
      
      if (sortField === 'timestamp') {
        aValue = new Date(aValue).getTime();
        bValue = new Date(bValue).getTime();
      } else if (sortField === 'severity') {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        aValue = severityOrder[a.severity];
        bValue = severityOrder[b.severity];
      }
      
      if (typeof aValue === 'string') {
        aValue = aValue.toLowerCase();
        bValue = bValue.toLowerCase();
      }
      
      if (sortDirection === 'asc') {
        return aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
      } else {
        return aValue > bValue ? -1 : aValue < bValue ? 1 : 0;
      }
    });

    setFilteredAlerts(filtered);
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const handleSelectAlert = (alertId: string) => {
    setSelectedAlerts(prev => 
      prev.includes(alertId) 
        ? prev.filter(id => id !== alertId)
        : [...prev, alertId]
    );
  };

  const handleSelectAll = () => {
    if (selectedAlerts.length === filteredAlerts.length) {
      setSelectedAlerts([]);
    } else {
      setSelectedAlerts(filteredAlerts.map(a => a.id));
    }
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
      case 'false_positive': return 'text-gray-600';
      default: return 'text-gray-600';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'new': return <AlertTriangle className="h-4 w-4" />;
      case 'investigating': return <Clock className="h-4 w-4" />;
      case 'resolved': return <CheckCircle className="h-4 w-4" />;
      case 'false_positive': return <XCircle className="h-4 w-4" />;
      default: return <AlertTriangle className="h-4 w-4" />;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) {
      return `il y a ${days}j`;
    } else if (hours > 0) {
      return `il y a ${hours}h`;
    }
    return `il y a ${minutes}m`;
  };

  const alertTypes = [...new Set(alerts.map(a => a.type))];

  if (isLoading) {
    return <TableSkeleton rows={8} columns={7} />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Centre d'alertes
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            {filteredAlerts.length} alerte(s) sur {alerts.length}
          </p>
        </div>
        <div className="flex space-x-3">
          <PermissionGate permission="alerts:export">
            <button className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700">
              <Download className="h-4 w-4 mr-2" />
              Exporter
            </button>
          </PermissionGate>
          <button 
            onClick={loadAlerts}
            className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Actualiser
          </button>
        </div>
      </div>

      {/* Statistiques rapides */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow">
          <div className="flex items-center">
            <AlertTriangle className="h-8 w-8 text-red-500" />
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Critiques</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                {alerts.filter(a => a.severity === 'critical').length}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow">
          <div className="flex items-center">
            <Clock className="h-8 w-8 text-yellow-500" />
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">En cours</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                {alerts.filter(a => a.status === 'investigating').length}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow">
          <div className="flex items-center">
            <CheckCircle className="h-8 w-8 text-green-500" />
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Résolues</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                {alerts.filter(a => a.status === 'resolved').length}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow">
          <div className="flex items-center">
            <XCircle className="h-8 w-8 text-gray-500" />
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Faux positifs</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                {alerts.filter(a => a.status === 'false_positive').length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Filtres et recherche */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {/* Recherche */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Rechercher..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          {/* Filtre par sévérité */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">Toutes les sévérités</option>
            <option value="critical">Critique</option>
            <option value="high">Élevée</option>
            <option value="medium">Moyenne</option>
            <option value="low">Faible</option>
          </select>

          {/* Filtre par statut */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">Tous les statuts</option>
            <option value="new">Nouvelle</option>
            <option value="investigating">En cours</option>
            <option value="resolved">Résolue</option>
            <option value="false_positive">Faux positif</option>
          </select>

          {/* Filtre par type */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">Tous les types</option>
            {alertTypes.map(type => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>

          {/* Actions groupées */}
          {selectedAlerts.length > 0 && (
            <div className="flex space-x-2">
              <PermissionGate permission="alerts:manage">
                <button className="flex-1 inline-flex items-center justify-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
                  <UserCheck className="h-4 w-4 mr-1" />
                  Assigner
                </button>
                <button className="flex-1 inline-flex items-center justify-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700">
                  <CheckCircle className="h-4 w-4 mr-1" />
                  Résoudre
                </button>
              </PermissionGate>
            </div>
          )}
        </div>
      </div>

      {/* Tableau des alertes */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th className="px-6 py-3 text-left">
                <input
                  type="checkbox"
                  checked={selectedAlerts.length === filteredAlerts.length && filteredAlerts.length > 0}
                  onChange={handleSelectAll}
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                onClick={() => handleSort('severity')}
              >
                Sévérité
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Type & Description
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                onClick={() => handleSort('endpoint')}
              >
                Endpoint
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                onClick={() => handleSort('status')}
              >
                Statut
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Assigné à
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                onClick={() => handleSort('timestamp')}
              >
                Horodatage
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            {filteredAlerts.map((alert) => (
              <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                <td className="px-6 py-4 whitespace-nowrap">
                  <input
                    type="checkbox"
                    checked={selectedAlerts.includes(alert.id)}
                    onChange={() => handleSelectAlert(alert.id)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                    {alert.severity.toUpperCase()}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <div className="max-w-xs">
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {alert.type}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400 truncate">
                      {alert.description}
                    </div>
                    {alert.tags.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {alert.tags.slice(0, 3).map(tag => (
                          <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300">
                            {tag}
                          </span>
                        ))}
                        {alert.tags.length > 3 && (
                          <span className="text-xs text-gray-500 dark:text-gray-400">+{alert.tags.length - 3}</span>
                        )}
                      </div>
                    )}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {alert.endpoint}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      {alert.user}
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className={`flex items-center space-x-2 ${getStatusColor(alert.status)}`}>
                    {getStatusIcon(alert.status)}
                    <span className="text-sm capitalize">
                      {alert.status === 'new' ? 'Nouvelle' :
                       alert.status === 'investigating' ? 'En cours' :
                       alert.status === 'resolved' ? 'Résolue' : 'Faux positif'}
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                  {alert.assignedTo || '-'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  {formatTimestamp(alert.timestamp)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <div className="relative">
                    <button
                      onClick={() => setShowActions(showActions === alert.id ? null : alert.id)}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <MoreVertical className="h-4 w-4" />
                    </button>
                    {showActions === alert.id && (
                      <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-md shadow-lg z-10 border border-gray-200 dark:border-gray-700">
                        <div className="py-1">
                          <button 
                            onClick={() => setSelectedAlert(alert)}
                            className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 w-full text-left"
                          >
                            <Eye className="h-4 w-4 mr-2" />
                            Voir les détails
                          </button>
                          <PermissionGate permission="alerts:manage">
                            <button className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 w-full text-left">
                              <UserCheck className="h-4 w-4 mr-2" />
                              Assigner
                            </button>
                            <button className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 w-full text-left">
                              <CheckCircle className="h-4 w-4 mr-2" />
                              Marquer comme résolue
                            </button>
                            <button className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 w-full text-left">
                              <XCircle className="h-4 w-4 mr-2" />
                              Faux positif
                            </button>
                          </PermissionGate>
                          <button className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 w-full text-left">
                            <FileText className="h-4 w-4 mr-2" />
                            Générer rapport
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        
        {filteredAlerts.length === 0 && (
          <div className="text-center py-12">
            <AlertTriangle className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">
              Aucune alerte trouvée
            </h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Aucune alerte ne correspond aux critères de recherche.
            </p>
          </div>
        )}
      </div>

      {/* Modal de détails d'alerte */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white dark:bg-gray-800">
            <div className="mt-3">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                  Détails de l'alerte
                </h3>
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  <XCircle className="h-6 w-6" />
                </button>
              </div>
              
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Sévérité</label>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(selectedAlert.severity)}`}>
                      {selectedAlert.severity.toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Statut</label>
                    <div className={`flex items-center space-x-2 ${getStatusColor(selectedAlert.status)}`}>
                      {getStatusIcon(selectedAlert.status)}
                      <span className="text-sm capitalize">
                        {selectedAlert.status === 'new' ? 'Nouvelle' :
                         selectedAlert.status === 'investigating' ? 'En cours' :
                         selectedAlert.status === 'resolved' ? 'Résolue' : 'Faux positif'}
                      </span>
                    </div>
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Description</label>
                  <p className="mt-1 text-sm text-gray-900 dark:text-white">{selectedAlert.description}</p>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Endpoint</label>
                    <p className="mt-1 text-sm text-gray-900 dark:text-white">{selectedAlert.endpoint}</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Utilisateur</label>
                    <p className="mt-1 text-sm text-gray-900 dark:text-white">{selectedAlert.user}</p>
                  </div>
                </div>
                
                {selectedAlert.filePath && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Chemin du fichier</label>
                    <p className="mt-1 text-sm text-gray-900 dark:text-white font-mono">{selectedAlert.filePath}</p>
                  </div>
                )}
                
                {selectedAlert.hash && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Hash</label>
                    <p className="mt-1 text-sm text-gray-900 dark:text-white font-mono">{selectedAlert.hash}</p>
                  </div>
                )}
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Tags</label>
                  <div className="mt-1 flex flex-wrap gap-2">
                    {selectedAlert.tags.map(tag => (
                      <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Horodatage</label>
                  <p className="mt-1 text-sm text-gray-900 dark:text-white">
                    {new Date(selectedAlert.timestamp).toLocaleString('fr-FR')}
                  </p>
                </div>
              </div>
              
              <div className="mt-6 flex justify-end space-x-3">
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  Fermer
                </button>
                <PermissionGate permission="alerts:manage">
                  <button className="px-4 py-2 border border-transparent rounded-md text-sm font-medium text-white bg-blue-600 hover:bg-blue-700">
                    Prendre en charge
                  </button>
                </PermissionGate>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}