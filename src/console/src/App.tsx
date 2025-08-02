import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import { AuthProvider } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import Layout from './components/Layout/Layout';
import ProtectedRoute from './components/Auth/ProtectedRoute';

// Pages
import Dashboard from './pages/Dashboard';
import Endpoints from './pages/Endpoints';
import Alerts from './pages/Alerts';
import Login from './pages/Login';

// Pages à créer
const Rules = () => <div>Rules</div>;
const Reports = () => <div>Reports</div>;
const Administration = () => <div>Administration</div>;

import './App.css';

// Configuration du client React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 3,
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
      staleTime: 5 * 60 * 1000, // 5 minutes
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 1,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <Router>
            <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
              <Routes>
                {/* Route de connexion */}
                <Route path="/login" element={<Login />} />
                
                {/* Routes protégées */}
                <Route
                  path="/*"
                  element={
                    <ProtectedRoute>
                      <Layout>
                        <Routes>
                          {/* Dashboard principal */}
                          <Route path="/" element={<Navigate to="/dashboard" replace />} />
                          <Route path="/dashboard" element={<Dashboard />} />
                          
                          {/* Gestion des endpoints */}
                          <Route path="/endpoints" element={<Endpoints />} />
                          
                          {/* Centre d'alertes */}
                          <Route path="/alerts" element={<Alerts />} />
                          
                          {/* Configuration des règles */}
                          <Route path="/rules" element={<Rules />} />
                          
                          {/* Rapports et audit */}
                          <Route path="/reports" element={<Reports />} />
                          
                          {/* Administration système */}
                          <Route path="/admin" element={<Administration />} />
                          
                          {/* Route par défaut */}
                          <Route path="*" element={<Navigate to="/dashboard" replace />} />
                        </Routes>
                      </Layout>
                    </ProtectedRoute>
                  }
                />
              </Routes>
              
              {/* Notifications toast */}
              <Toaster
                position="top-right"
                expand={true}
                richColors
                closeButton
                toastOptions={{
                  duration: 5000,
                  style: {
                    background: 'var(--background)',
                    color: 'var(--foreground)',
                    border: '1px solid var(--border)',
                  },
                }}
              />
            </div>
          </Router>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;