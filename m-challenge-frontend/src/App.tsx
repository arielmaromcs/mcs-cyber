import ClientIpBadge from "./components/ClientIpBadge";
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './hooks/useAuth';
import { Layout } from './components/Layout';
import WebScanPage from './pages/WebScan';
import EmailScanPage from './pages/EmailScan';
import ThreatIntelPage from './pages/ThreatIntel';
import MitrePage from './pages/Mitre';
import SchedulesPage from './pages/Schedules';
import AdminPage from './pages/Admin';
import AboutPage from './pages/About';
import LoginPage from './pages/Login';

export default function App() {
  return (
    <AuthProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<Navigate to="/about" replace />} />
          <Route path="/web" element={<WebScanPage />} />
          <Route path="/email" element={<EmailScanPage />} />
          <Route path="/threat" element={<ThreatIntelPage />} />
          <Route path="/mitre" element={<MitrePage />} />
          <Route path="/schedules" element={<SchedulesPage />} />
          <Route path="/admin" element={<AdminPage />} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="/login" element={<LoginPage />} />
        </Routes>
      </Layout>
    </AuthProvider>
  );
}
