import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'react-hot-toast';
import { store, persistor } from './store';

// Layout
import MainLayout from './components/common/Layout/MainLayout';

// WebSocket Provider
import { WebSocketProvider } from './contexts/WebSocketContext';

// Auth Pages
import LoginPage from './pages/Auth/LoginPage';
import RegisterPage from './pages/Auth/RegisterPage';

// Main Pages
import DashboardPage from './pages/Dashboard/DashboardPage';
import InvestigationsListPage from './pages/Investigations/InvestigationsListPage';
import InvestigationDetailPage from './pages/Investigations/InvestigationDetailPage';
import TargetsListPage from './pages/Targets/TargetsListPage';
import TargetDetailPage from './pages/Targets/TargetDetailPage';
import EvidenceListPage from './pages/Evidence/EvidenceListPage';
import IntelligenceListPage from './pages/Intelligence/IntelligenceListPage';
import OperationsListPage from './pages/Operations/OperationsListPage';
import OperationDetailPage from './pages/Operations/OperationDetailPage';
import BlockchainPage from './pages/Blockchain/BlockchainPage';
import FacialRecognitionPage from './pages/FacialRecognition/FacialRecognitionPage';
import GeolocationPage from './pages/Geolocation/GeolocationPage';
import AnalyticsPage from './pages/Analytics/AnalyticsPage';
import SettingsPage from './pages/Settings/SettingsPage';
import AdminPage from './pages/Administration/AdminPage';

// Protected Route Component
import ProtectedRoute from './components/common/ProtectedRoute';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000,
    },
  },
});

function App() {
  return (
    <Provider store={store}>
      <PersistGate loading={<div>Loading...</div>} persistor={persistor}>
        <QueryClientProvider client={queryClient}>
          <WebSocketProvider autoConnect={true}>
            <BrowserRouter>
              <Routes>
              {/* Public Routes */}
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />

              {/* Protected Routes */}
              <Route element={<ProtectedRoute />}>
                <Route element={<MainLayout />}>
                  <Route path="/dashboard" element={<DashboardPage />} />
                  <Route path="/investigations" element={<InvestigationsListPage />} />
                  <Route path="/investigations/:id" element={<InvestigationDetailPage />} />
                  <Route path="/targets" element={<TargetsListPage />} />
                  <Route path="/targets/:id" element={<TargetDetailPage />} />
                  <Route path="/evidence" element={<EvidenceListPage />} />
                  <Route path="/intelligence" element={<IntelligenceListPage />} />
                  <Route path="/operations" element={<OperationsListPage />} />
                  <Route path="/operations/:id" element={<OperationDetailPage />} />
                  <Route path="/blockchain" element={<BlockchainPage />} />
                  <Route path="/facial-recognition" element={<FacialRecognitionPage />} />
                  <Route path="/geolocation" element={<GeolocationPage />} />
                  <Route path="/analytics" element={<AnalyticsPage />} />
                  <Route path="/settings" element={<SettingsPage />} />
                  <Route path="/admin" element={<AdminPage />} />
                </Route>
              </Route>

              {/* Default Route */}
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </BrowserRouter>
            <Toaster position="top-right" />
          </WebSocketProvider>
        </QueryClientProvider>
      </PersistGate>
    </Provider>
  );
}

export default App;
