import React, { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth, Permission } from '../../contexts/AuthContext';
import LoadingSpinner from '../UI/LoadingSpinner';

interface ProtectedRouteProps {
  children: ReactNode;
  requiredPermission?: Permission;
  fallback?: ReactNode;
}

export default function ProtectedRoute({ 
  children, 
  requiredPermission,
  fallback 
}: ProtectedRouteProps) {
  const { state, hasPermission } = useAuth();
  const location = useLocation();

  // Afficher le spinner pendant le chargement
  if (state.isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  // Rediriger vers la page de connexion si non authentifié
  if (!state.isAuthenticated) {
    return (
      <Navigate 
        to="/login" 
        state={{ from: location }} 
        replace 
      />
    );
  }

  // Vérifier les permissions si requises
  if (requiredPermission && !hasPermission(requiredPermission)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="max-w-md w-full bg-white dark:bg-gray-800 shadow-lg rounded-lg p-6">
          <div className="text-center">
            <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 dark:bg-red-900">
              <svg 
                className="h-6 w-6 text-red-600 dark:text-red-400" 
                fill="none" 
                viewBox="0 0 24 24" 
                stroke="currentColor"
              >
                <path 
                  strokeLinecap="round" 
                  strokeLinejoin="round" 
                  strokeWidth={2} 
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" 
                />
              </svg>
            </div>
            <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-white">
              Accès refusé
            </h3>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              Vous n'avez pas les permissions nécessaires pour accéder à cette page.
            </p>
            <div className="mt-6">
              <button
                onClick={() => window.history.back()}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Retour
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Afficher le contenu protégé
  return <>{children}</>;
}

// Hook pour vérifier les permissions dans les composants
export function useRequirePermission(permission: Permission): boolean {
  const { hasPermission } = useAuth();
  return hasPermission(permission);
}

// Composant pour afficher du contenu conditionnel basé sur les permissions
interface PermissionGateProps {
  permission: Permission;
  children: ReactNode;
  fallback?: ReactNode;
}

export function PermissionGate({ 
  permission, 
  children, 
  fallback = null 
}: PermissionGateProps) {
  const { hasPermission } = useAuth();
  
  if (!hasPermission(permission)) {
    return <>{fallback}</>;
  }
  
  return <>{children}</>;
}

// Composant pour afficher du contenu basé sur le rôle
interface RoleGateProps {
  roles: string[];
  children: ReactNode;
  fallback?: ReactNode;
}

export function RoleGate({ 
  roles, 
  children, 
  fallback = null 
}: RoleGateProps) {
  const { state } = useAuth();
  
  if (!state.user || !roles.includes(state.user.role)) {
    return <>{fallback}</>;
  }
  
  return <>{children}</>;
}

// Hook pour vérifier si l'utilisateur a un rôle spécifique
export function useHasRole(role: string): boolean {
  const { state } = useAuth();
  return state.user?.role === role || false;
}

// Hook pour vérifier si l'utilisateur a l'un des rôles spécifiés
export function useHasAnyRole(roles: string[]): boolean {
  const { state } = useAuth();
  return state.user ? roles.includes(state.user.role) : false;
}