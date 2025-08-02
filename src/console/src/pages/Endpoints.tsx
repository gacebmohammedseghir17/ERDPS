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
  Monitor,
  Wifi,
  WifiOff,
  Shield,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Clock,
  Settings,
  Eye,
  Play,
  Square,
  Trash2
} from 'lucide-react';

interface Endpoint {
  id: string;
  hostname: string;
  ipAddress: string;
  osVersion: string;
  agentVersion: string;
  status: 'online' | 'offline' | 'warning';
  lastSeen: string;
  protectionStatus: 'enabled' | 'disabled' | 'partial';
  threatsBlocked: number;
  department: string;
  user: string;
  riskScore: number;
}

type SortField = 'hostname' | 'status' | 'lastSeen' | 'riskScore' | 'threatsBlocked';
type SortDirection = 'asc' | 'desc';

export default function Endpoints() {
  const { hasPermission } = useAuth();
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [filteredEndpoints, setFilteredEndpoints] = useState<Endpoint[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [departmentFilter, setDepartmentFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('hostname');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
  const [selectedEndpoints, setSelectedEndpoints] = useState<string[]>([]);
  const [showActions, setShowActions] = useState<string | null>(null);

  useEffect(() => {
    loadEndpoints();
  }, []);

  useEffect(() => {
    filterAndSortEndpoints();
  }, [endpoints, searchTerm, statusFilter, departmentFilter, sortField, sortDirection]);

  const loadEndpoints = async () => {
    setIsLoading(true);
    
    // Simulation d'un appel API
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const mockEndpoints: Endpoint[] = [
      {
        id: '1',
        hostname: 'WS-FINANCE-01',
        ipAddress: '192.168.1.101',
        osVersion: 'Windows 11 Pro',
        agentVersion: '2.1.0',
        status: 'online',
        lastSeen: new Date(Date.now() - 300000).toISOString(),
        protectionStatus: 'enabled',
        threatsBlocked: 12,
        department: 'Finance',
        user: 'marie.dupont',
        riskScore: 2
      },
      {
        id: '2',
        hostname: 'WS-HR-15',
        ipAddress: '192.168.1.115',
        osVersion: 'Windows 10 Pro',
        agentVersion: '2.0.8',
        status: 'warning',
        lastSeen: new Date(Date.now() - 900000).toISOString(),
        protectionStatus: 'partial',
        threatsBlocked: 5,
        department: 'RH',
        user: 'jean.martin',
        riskScore: 7
      },
      {
        id: '3',
        hostname: 'SRV-WEB-02',
        ipAddress: '192.168.1.202',
        osVersion: 'Windows Server 2022',
        agentVersion: '2.1.0',
        status: 'online',
        lastSeen: new Date(Date.now() - 60000).toISOString(),
        protectionStatus: 'enabled',
        threatsBlocked: 28,
        department: 'IT',
        user: 'system',
        riskScore: 1
      },
      {
        id: '4',
        hostname: 'WS-SALES-08',
        ipAddress: '192.168.1.108',
        osVersion: 'Windows 11 Pro',
        agentVersion: '2.0.5',
        status: 'offline',
        lastSeen: new Date(Date.now() - 7200000).toISOString(),
        protectionStatus: 'disabled',
        threatsBlocked: 0,
        department: 'Ventes',
        user: 'pierre.bernard',
        riskScore: 9
      }
    ];
    
    setEndpoints(mockEndpoints);
    setIsLoading(false);
  };

  const filterAndSortEndpoints = () => {
    let filtered = endpoints.filter(endpoint => {
      const matchesSearch = endpoint.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           endpoint.ipAddress.includes(searchTerm) ||
                           endpoint.user.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesStatus = statusFilter === 'all' || endpoint.status === statusFilter;
      const matchesDepartment = departmentFilter === 'all' || endpoint.department === departmentFilter;
      
      return matchesSearch && matchesStatus && matchesDepartment;
    });

    // Tri
    filtered.sort((a, b) => {
      let aValue: any = a[sortField];
      let bValue: any = b[sortField];
      
      if (sortField === 'lastSeen') {
        aValue = new Date(aValue).getTime();
        bValue = new Date(bValue).getTime();
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

    setFilteredEndpoints(filtered);
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const handleSelectEndpoint = (endpointId: string) => {
    setSelectedEndpoints(prev => 
      prev.includes(endpointId) 
        ? prev.filter(id => id !== endpointId)
        : [...prev, endpointId]
    );
  };

  const handleSelectAll = () => {
    if (selectedEndpoints.length === filteredEndpoints.length) {
      setSelectedEndpoints([]);
    } else {
      setSelectedEndpoints(filteredEndpoints.map(e => e.id));
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online': return <Wifi className="h-4 w-4 text-green-500" />;
      case 'offline': return <WifiOff className="h-4 w-4 text-red-500" />;
      case 'warning': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default: return <Monitor className="h-4 w-4 text-gray-500" />;
    }
  };

  const getProtectionIcon = (status: string) => {
    switch (status) {
      case 'enabled': return <Shield className="h-4 w-4 text-green-500" />;
      case 'disabled': return <ShieldAlert className="h-4 w-4 text-red-500" />;
      case 'partial': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default: return <Shield className="h-4 w-4 text-gray-500" />;
    }
  };

  const getRiskColor = (score: number) => {
    if (score <= 3) return 'text-green-600 bg-green-100 dark:bg-green-900/20';
    if (score <= 6) return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/20';
    return 'text-red-600 bg-red-100 dark:bg-red-900/20';
  };

  const formatLastSeen = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `il y a ${hours}h`;
    }
    return `il y a ${minutes}m`;
  };

  const departments = [...new Set(endpoints.map(e => e.department))];

  if (isLoading) {
    return <TableSkeleton rows={8} columns={8} />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Gestion des endpoints
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            {filteredEndpoints.length} endpoint(s) sur {endpoints.length}
          </p>
        </div>
        <div className="flex space-x-3">
          <PermissionGate permission="endpoints:export">
            <button className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700">
              <Download className="h-4 w-4 mr-2" />
              Exporter
            </button>
          </PermissionGate>
          <button 
            onClick={loadEndpoints}
            className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Actualiser
          </button>
        </div>
      </div>

      {/* Filtres et recherche */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
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

          {/* Filtre par statut */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">Tous les statuts</option>
            <option value="online">En ligne</option>
            <option value="offline">Hors ligne</option>
            <option value="warning">Avertissement</option>
          </select>

          {/* Filtre par département */}
          <select
            value={departmentFilter}
            onChange={(e) => setDepartmentFilter(e.target.value)}
            className="rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">Tous les départements</option>
            {departments.map(dept => (
              <option key={dept} value={dept}>{dept}</option>
            ))}
          </select>

          {/* Actions groupées */}
          {selectedEndpoints.length > 0 && (
            <div className="flex space-x-2">
              <PermissionGate permission="endpoints:control">
                <button className="flex-1 inline-flex items-center justify-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
                  <Play className="h-4 w-4 mr-1" />
                  Démarrer
                </button>
                <button className="flex-1 inline-flex items-center justify-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700">
                  <Square className="h-4 w-4 mr-1" />
                  Arrêter
                </button>
              </PermissionGate>
            </div>
          )}
        </div>
      </div>

      {/* Tableau des endpoints */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th className="px-6 py-3 text-left">
                <input
                  type="checkbox"
                  checked={selectedEndpoints.length === filteredEndpoints.length && filteredEndpoints.length > 0}
                  onChange={handleSelectAll}
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                onClick={() => handleSort('hostname')}
              >
                Hostname
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                onClick={() => handleSort('status')}
              >
                Statut
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Protection
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Utilisateur
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Département
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                onClick={() => handleSort('threatsBlocked')}
              >
                Menaces bloquées
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                onClick={() => handleSort('riskScore')}
              >
                Risque
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                onClick={() => handleSort('lastSeen')}
              >
                Dernière activité
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            {filteredEndpoints.map((endpoint) => (
              <tr key={endpoint.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                <td className="px-6 py-4 whitespace-nowrap">
                  <input
                    type="checkbox"
                    checked={selectedEndpoints.includes(endpoint.id)}
                    onChange={() => handleSelectEndpoint(endpoint.id)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {endpoint.hostname}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      {endpoint.ipAddress}
                    </div>
                    <div className="text-xs text-gray-400 dark:text-gray-500">
                      {endpoint.osVersion} • Agent v{endpoint.agentVersion}
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(endpoint.status)}
                    <span className="text-sm text-gray-900 dark:text-white capitalize">
                      {endpoint.status === 'online' ? 'En ligne' : 
                       endpoint.status === 'offline' ? 'Hors ligne' : 'Avertissement'}
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center space-x-2">
                    {getProtectionIcon(endpoint.protectionStatus)}
                    <span className="text-sm text-gray-900 dark:text-white capitalize">
                      {endpoint.protectionStatus === 'enabled' ? 'Activée' :
                       endpoint.protectionStatus === 'disabled' ? 'Désactivée' : 'Partielle'}
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                  {endpoint.user}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                  {endpoint.department}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                  {endpoint.threatsBlocked}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRiskColor(endpoint.riskScore)}`}>
                    {endpoint.riskScore}/10
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  {formatLastSeen(endpoint.lastSeen)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <div className="relative">
                    <button
                      onClick={() => setShowActions(showActions === endpoint.id ? null : endpoint.id)}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <MoreVertical className="h-4 w-4" />
                    </button>
                    {showActions === endpoint.id && (
                      <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-md shadow-lg z-10 border border-gray-200 dark:border-gray-700">
                        <div className="py-1">
                          <PermissionGate permission="endpoints:view">
                            <button className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 w-full text-left">
                              <Eye className="h-4 w-4 mr-2" />
                              Voir les détails
                            </button>
                          </PermissionGate>
                          <PermissionGate permission="endpoints:configure">
                            <button className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 w-full text-left">
                              <Settings className="h-4 w-4 mr-2" />
                              Configurer
                            </button>
                          </PermissionGate>
                          <PermissionGate permission="endpoints:control">
                            <button className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 w-full text-left">
                              <Play className="h-4 w-4 mr-2" />
                              Redémarrer agent
                            </button>
                          </PermissionGate>
                          <PermissionGate permission="endpoints:delete">
                            <button className="flex items-center px-4 py-2 text-sm text-red-700 dark:text-red-400 hover:bg-gray-100 dark:hover:bg-gray-700 w-full text-left">
                              <Trash2 className="h-4 w-4 mr-2" />
                              Supprimer
                            </button>
                          </PermissionGate>
                        </div>
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        
        {filteredEndpoints.length === 0 && (
          <div className="text-center py-12">
            <Monitor className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">
              Aucun endpoint trouvé
            </h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Aucun endpoint ne correspond aux critères de recherche.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}