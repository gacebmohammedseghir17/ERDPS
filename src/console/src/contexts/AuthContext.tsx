import React, { createContext, useContext, useReducer, useEffect, ReactNode } from 'react';
import { toast } from 'sonner';

// Types pour l'authentification
export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  permissions: Permission[];
  lastLogin: string;
  isActive: boolean;
  certificateId?: string;
  mfaEnabled: boolean;
}

export enum UserRole {
  SOC_ADMIN = 'soc_admin',
  IT_OPERATOR = 'it_operator',
  ANALYST = 'analyst',
  VIEWER = 'viewer'
}

export enum Permission {
  // Dashboard
  VIEW_DASHBOARD = 'view_dashboard',
  
  // Endpoints
  VIEW_ENDPOINTS = 'view_endpoints',
  MANAGE_ENDPOINTS = 'manage_endpoints',
  ISOLATE_ENDPOINTS = 'isolate_endpoints',
  
  // Alertes
  VIEW_ALERTS = 'view_alerts',
  MANAGE_ALERTS = 'manage_alerts',
  ACKNOWLEDGE_ALERTS = 'acknowledge_alerts',
  
  // Règles
  VIEW_RULES = 'view_rules',
  MANAGE_RULES = 'manage_rules',
  DEPLOY_RULES = 'deploy_rules',
  
  // Rapports
  VIEW_REPORTS = 'view_reports',
  GENERATE_REPORTS = 'generate_reports',
  EXPORT_REPORTS = 'export_reports',
  
  // Administration
  VIEW_ADMIN = 'view_admin',
  MANAGE_USERS = 'manage_users',
  MANAGE_SYSTEM = 'manage_system',
  VIEW_LOGS = 'view_logs'
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

type AuthAction =
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_SUCCESS'; payload: { user: User; token: string } }
  | { type: 'LOGIN_FAILURE'; payload: string }
  | { type: 'LOGOUT' }
  | { type: 'REFRESH_TOKEN_SUCCESS'; payload: string }
  | { type: 'UPDATE_USER'; payload: User }
  | { type: 'CLEAR_ERROR' };

interface AuthContextType {
  state: AuthState;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<void>;
  hasPermission: (permission: Permission) => boolean;
  hasRole: (role: UserRole) => boolean;
  clearError: () => void;
}

interface LoginCredentials {
  username: string;
  password: string;
  certificateFile?: File;
  mfaCode?: string;
}

const initialState: AuthState = {
  user: null,
  token: null,
  isAuthenticated: false,
  isLoading: false,
  error: null,
};

function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'LOGIN_START':
      return {
        ...state,
        isLoading: true,
        error: null,
      };
    
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        user: action.payload.user,
        token: action.payload.token,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      };
    
    case 'LOGIN_FAILURE':
      return {
        ...state,
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: false,
        error: action.payload,
      };
    
    case 'LOGOUT':
      return {
        ...initialState,
      };
    
    case 'REFRESH_TOKEN_SUCCESS':
      return {
        ...state,
        token: action.payload,
      };
    
    case 'UPDATE_USER':
      return {
        ...state,
        user: action.payload,
      };
    
    case 'CLEAR_ERROR':
      return {
        ...state,
        error: null,
      };
    
    default:
      return state;
  }
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Vérifier le token au chargement
  useEffect(() => {
    const token = localStorage.getItem('erdps_token');
    const userData = localStorage.getItem('erdps_user');
    
    if (token && userData) {
      try {
        const user = JSON.parse(userData);
        dispatch({ type: 'LOGIN_SUCCESS', payload: { user, token } });
      } catch (error) {
        console.error('Failed to parse stored user data:', error);
        localStorage.removeItem('erdps_token');
        localStorage.removeItem('erdps_user');
      }
    }
  }, []);

  // Auto-refresh du token
  useEffect(() => {
    if (state.isAuthenticated && state.token) {
      const interval = setInterval(() => {
        refreshToken();
      }, 15 * 60 * 1000); // Refresh toutes les 15 minutes
      
      return () => clearInterval(interval);
    }
  }, [state.isAuthenticated, state.token]);

  const login = async (credentials: LoginCredentials): Promise<void> => {
    dispatch({ type: 'LOGIN_START' });
    
    try {
      // Simuler l'appel API d'authentification
      const response = await mockAuthAPI(credentials);
      
      if (response.success) {
        const { user, token } = response.data;
        
        // Stocker les données d'authentification
        localStorage.setItem('erdps_token', token);
        localStorage.setItem('erdps_user', JSON.stringify(user));
        
        dispatch({ type: 'LOGIN_SUCCESS', payload: { user, token } });
        
        toast.success(`Bienvenue, ${user.username}!`);
      } else {
        throw new Error(response.error || 'Échec de l\'authentification');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Erreur de connexion';
      dispatch({ type: 'LOGIN_FAILURE', payload: errorMessage });
      toast.error(errorMessage);
    }
  };

  const logout = (): void => {
    // Nettoyer le stockage local
    localStorage.removeItem('erdps_token');
    localStorage.removeItem('erdps_user');
    
    dispatch({ type: 'LOGOUT' });
    toast.info('Déconnexion réussie');
  };

  const refreshToken = async (): Promise<void> => {
    try {
      if (!state.token) return;
      
      // Simuler le refresh du token
      const response = await mockRefreshTokenAPI(state.token);
      
      if (response.success) {
        const newToken = response.data.token;
        localStorage.setItem('erdps_token', newToken);
        dispatch({ type: 'REFRESH_TOKEN_SUCCESS', payload: newToken });
      } else {
        // Token invalide, déconnecter l'utilisateur
        logout();
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
      logout();
    }
  };

  const hasPermission = (permission: Permission): boolean => {
    return state.user?.permissions.includes(permission) || false;
  };

  const hasRole = (role: UserRole): boolean => {
    return state.user?.role === role;
  };

  const clearError = (): void => {
    dispatch({ type: 'CLEAR_ERROR' });
  };

  const contextValue: AuthContextType = {
    state,
    login,
    logout,
    refreshToken,
    hasPermission,
    hasRole,
    clearError,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// Mock API pour l'authentification (à remplacer par de vrais appels API)
async function mockAuthAPI(credentials: LoginCredentials): Promise<{
  success: boolean;
  data?: { user: User; token: string };
  error?: string;
}> {
  // Simuler un délai réseau
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Utilisateurs de test
  const testUsers: Record<string, { password: string; user: User }> = {
    'admin': {
      password: 'admin123',
      user: {
        id: '1',
        username: 'admin',
        email: 'admin@erdps.local',
        role: UserRole.SOC_ADMIN,
        permissions: Object.values(Permission),
        lastLogin: new Date().toISOString(),
        isActive: true,
        mfaEnabled: true,
      }
    },
    'operator': {
      password: 'operator123',
      user: {
        id: '2',
        username: 'operator',
        email: 'operator@erdps.local',
        role: UserRole.IT_OPERATOR,
        permissions: [
          Permission.VIEW_DASHBOARD,
          Permission.VIEW_ENDPOINTS,
          Permission.MANAGE_ENDPOINTS,
          Permission.VIEW_ALERTS,
          Permission.ACKNOWLEDGE_ALERTS,
          Permission.VIEW_REPORTS,
        ],
        lastLogin: new Date().toISOString(),
        isActive: true,
        mfaEnabled: false,
      }
    },
    'analyst': {
      password: 'analyst123',
      user: {
        id: '3',
        username: 'analyst',
        email: 'analyst@erdps.local',
        role: UserRole.ANALYST,
        permissions: [
          Permission.VIEW_DASHBOARD,
          Permission.VIEW_ENDPOINTS,
          Permission.VIEW_ALERTS,
          Permission.MANAGE_ALERTS,
          Permission.VIEW_RULES,
          Permission.VIEW_REPORTS,
          Permission.GENERATE_REPORTS,
        ],
        lastLogin: new Date().toISOString(),
        isActive: true,
        mfaEnabled: true,
      }
    }
  };
  
  const testUser = testUsers[credentials.username];
  
  if (!testUser || testUser.password !== credentials.password) {
    return {
      success: false,
      error: 'Nom d\'utilisateur ou mot de passe incorrect'
    };
  }
  
  // Simuler la vérification MFA si activée
  if (testUser.user.mfaEnabled && !credentials.mfaCode) {
    return {
      success: false,
      error: 'Code MFA requis'
    };
  }
  
  const token = `erdps_token_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  return {
    success: true,
    data: {
      user: testUser.user,
      token
    }
  };
}

async function mockRefreshTokenAPI(token: string): Promise<{
  success: boolean;
  data?: { token: string };
}> {
  // Simuler un délai réseau
  await new Promise(resolve => setTimeout(resolve, 500));
  
  // Vérifier si le token est valide (simulation)
  if (token.startsWith('erdps_token_')) {
    const newToken = `erdps_token_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    return {
      success: true,
      data: { token: newToken }
    };
  }
  
  return { success: false };
}

// Permissions par rôle
export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  [UserRole.SOC_ADMIN]: Object.values(Permission),
  [UserRole.IT_OPERATOR]: [
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_ENDPOINTS,
    Permission.MANAGE_ENDPOINTS,
    Permission.ISOLATE_ENDPOINTS,
    Permission.VIEW_ALERTS,
    Permission.ACKNOWLEDGE_ALERTS,
    Permission.VIEW_REPORTS,
    Permission.VIEW_LOGS,
  ],
  [UserRole.ANALYST]: [
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_ENDPOINTS,
    Permission.VIEW_ALERTS,
    Permission.MANAGE_ALERTS,
    Permission.ACKNOWLEDGE_ALERTS,
    Permission.VIEW_RULES,
    Permission.VIEW_REPORTS,
    Permission.GENERATE_REPORTS,
    Permission.EXPORT_REPORTS,
  ],
  [UserRole.VIEWER]: [
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_ENDPOINTS,
    Permission.VIEW_ALERTS,
    Permission.VIEW_REPORTS,
  ],
};