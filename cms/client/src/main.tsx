import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ToastProvider } from '@ui/toast';
import { PageSkeleton } from '@ui/feedback';
import { AuthProvider, useAuth } from '@/auth';
import { Shell } from '@/components/Shell';
import { ApplicationPage } from '@/pages/ApplicationPage';
import { ApplicationsPage } from '@/pages/ApplicationsPage';
import { AuditPage } from '@/pages/AuditPage';
import { CatalogPage } from '@/pages/CatalogPage';
import { LoginPage } from '@/pages/LoginPage';
import { VersionPage } from '@/pages/VersionPage';
import './index.css';

function App() {
  const { user, loading } = useAuth();
  if (loading) return <PageSkeleton />;
  if (!user) return <LoginPage />;
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route path="/applications" element={<ApplicationsPage key="provider" />} />
        <Route path="/applications/:key" element={<ApplicationPage key="provider" />} />
        <Route path="/applications/:key/versions/:version" element={<VersionPage key="provider" />} />
        <Route path="/secret-types" element={<ApplicationsPage key="secret_type" kind="secret_type" />} />
        <Route path="/secret-types/:key" element={<ApplicationPage key="secret_type" kind="secret_type" />} />
        <Route path="/secret-types/:key/versions/:version" element={<VersionPage key="secret_type" kind="secret_type" />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/catalog" element={<CatalogPage />} />
        <Route path="*" element={<Navigate to="/applications" replace />} />
      </Route>
    </Routes>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ToastProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
