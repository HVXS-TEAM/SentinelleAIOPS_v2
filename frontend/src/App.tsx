import { useState, useEffect } from 'react';
import { ThemeProvider, useTheme } from './context/ThemeContext';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { DashboardPage } from './pages/DashboardPage';
import { SupervisionPage } from './pages/SupervisionPage';
import { SecuritePage } from './pages/SecuritePage';
import { NetDevOpsPage } from './pages/NetDevOpsPage';
import { ParcPage } from './pages/ParcPage';
import { AssistantPage } from './pages/AssistantPage';
import { AdminPage } from './pages/AdminPage';
import { LoginPage, type AuthenticatedUser } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { authService, clearSession, SESSION_EXPIRED_EVENT, SESSION_KEYS } from './services/api';

function MainApp() {
  const { activeTheme } = useTheme();
  const [currentUser, setCurrentUser] = useState<AuthenticatedUser | null>(() => {
    try {
      const stored = localStorage.getItem(SESSION_KEYS.authUser);
      const hasToken = Boolean(localStorage.getItem(SESSION_KEYS.token));
      return stored && hasToken ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  const [authView, setAuthView] = useState<'login' | 'register'>('login');
  const [currentTab, setCurrentTab] = useState<string>('dashboard');

  useEffect(() => {
    // Si l'utilisateur n'est pas connecté, réinitialiser l'onglet
    if (!currentUser) {
      setCurrentTab('dashboard');
    }
  }, [currentUser]);

  // Une session restaurée depuis le stockage local doit être confirmée par le serveur.
  useEffect(() => {
    if (!currentUser) return;
    authService.validateSession().then(isValid => {
      if (!isValid) {
        clearSession();
        setCurrentUser(null);
      }
    });
    // Vérification unique au montage : les expirations ultérieures passent par l'événement.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const onExpired = () => setCurrentUser(null);
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired);
  }, []);

  const handleLoginSuccess = (user: AuthenticatedUser) => {
    setCurrentUser(user);
    setCurrentTab('dashboard');
  };

  const handleLogout = () => {
    clearSession();
    setCurrentUser(null);
  };

  /* Si non authentifié, afficher l'écran de Login ou de Création de compte */
  if (!currentUser) {
    if (authView === 'register') {
      return (
        <RegisterPage
          onRegisterSuccess={handleLoginSuccess}
          onSwitchToLogin={() => setAuthView('login')}
        />
      );
    }
    return (
      <LoginPage
        onLoginSuccess={handleLoginSuccess}
        onSwitchToRegister={() => setAuthView('register')}
      />
    );
  }

  const renderPage = () => {
    switch (currentTab) {
      case 'dashboard':   return <DashboardPage onNavigateTab={setCurrentTab} />;
      case 'supervision': return <SupervisionPage />;
      case 'securite':    return <SecuritePage />;
      case 'netdevops':   return <NetDevOpsPage />;
      case 'parc':        return <ParcPage />;
      case 'assistant':   return <AssistantPage currentUser={currentUser} />;
      case 'admin':       return <AdminPage />;
      case 'rapports':    return <AdminPage />;
      default:            return <DashboardPage onNavigateTab={setCurrentTab} />;
    }
  };

  return (
    <div className={`flex h-screen w-screen overflow-hidden bg-[#101416] text-[#e0e3e6] font-sans ${activeTheme === 'night' ? 'theme-night' : 'theme-day'}`}>
      <Sidebar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        currentUser={currentUser}
        onLogout={handleLogout}
      />

      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        <Header
          currentUser={currentUser}
          onNavigateTab={setCurrentTab}
          onLogout={handleLogout}
        />

        <main className="flex-1 min-h-0 overflow-y-auto overflow-x-hidden">
          {renderPage()}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <MainApp />
    </ThemeProvider>
  );
}
