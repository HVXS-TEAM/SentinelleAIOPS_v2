import { lazy, Suspense, useState, useEffect } from 'react';
import { ThemeProvider, useTheme } from './context/ThemeContext';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { LoginPage, type AuthenticatedUser } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { SetupPage } from './pages/SetupPage';
import { ForgotPasswordPage } from './pages/ForgotPasswordPage';
import { ResetPasswordPage } from './pages/ResetPasswordPage';
import { authService, clearSession, SESSION_EXPIRED_EVENT, SESSION_KEYS } from './services/api';

// Pages de l'application chargées à la demande : le bundle initial ne contient que la connexion et la coque.
const DashboardPage = lazy(() => import('./pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const SupervisionPage = lazy(() => import('./pages/SupervisionPage').then(m => ({ default: m.SupervisionPage })));
const SecuritePage = lazy(() => import('./pages/SecuritePage').then(m => ({ default: m.SecuritePage })));
const NetDevOpsPage = lazy(() => import('./pages/NetDevOpsPage').then(m => ({ default: m.NetDevOpsPage })));
const ParcPage = lazy(() => import('./pages/ParcPage').then(m => ({ default: m.ParcPage })));
const AssistantPage = lazy(() => import('./pages/AssistantPage').then(m => ({ default: m.AssistantPage })));
const AdminPage = lazy(() => import('./pages/AdminPage').then(m => ({ default: m.AdminPage })));

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

  const [authView, setAuthView] = useState<'checking' | 'setup' | 'login' | 'register' | 'forgot' | 'reset'>('checking');
  const [allowRegistration, setAllowRegistration] = useState(false);
  const [rolesDisponibles, setRolesDisponibles] = useState<string[]>(['Visiteur']);
  // Lien de réinitialisation reçu par e-mail : /?reset=<jeton>&u=<identifiant>
  const [lienReset] = useState(() => {
    const p = new URLSearchParams(window.location.search);
    return { code: p.get('reset') ?? '', identifiant: p.get('u') ?? '' };
  });
  const [currentTab, setCurrentTab] = useState<string>('dashboard');

  // Base vide ? Le serveur l'indique : on propose alors la création du premier administrateur.
  useEffect(() => {
    if (currentUser) return;
    setAuthView('checking');
    let actif = true;
    authService
      .getSetupStatus()
      .then(status => {
        if (!actif) return;
        setAllowRegistration(status.allow_registration || status.local_creation);
        setRolesDisponibles(status.roles_disponibles?.length ? status.roles_disponibles : ['Visiteur']);
        if (status.needs_setup) setAuthView('setup');
        else setAuthView(lienReset.code ? 'reset' : 'login');
      })
      .catch(() => {
        // Serveur injoignable : l'écran de connexion affiche l'erreur explicite.
        if (actif) setAuthView('login');
      });
    return () => {
      actif = false;
    };
    // Revérifié à chaque déconnexion : l'écran proposé (connexion, création de compte) vient du serveur.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUser]);

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
    if (authView === 'checking') {
      return <div className="h-screen w-screen bg-[#101416]" role="status" aria-label="Chargement" />;
    }
    if (authView === 'setup') {
      return <SetupPage onSetupSuccess={handleLoginSuccess} />;
    }
    if (authView === 'register' && allowRegistration) {
      return (
        <RegisterPage
          onRegisterSuccess={handleLoginSuccess}
          onSwitchToLogin={() => setAuthView('login')}
          rolesDisponibles={rolesDisponibles}
        />
      );
    }
    if (authView === 'forgot') {
      return <ForgotPasswordPage onBackToLogin={() => setAuthView('login')} onHaveCode={() => setAuthView('reset')} />;
    }
    if (authView === 'reset') {
      const retourConnexion = () => {
        window.history.replaceState({}, '', window.location.pathname);
        setAuthView('login');
      };
      return (
        <ResetPasswordPage
          identifiantInitial={lienReset.identifiant}
          codeInitial={lienReset.code}
          onDone={retourConnexion}
          onBackToLogin={retourConnexion}
        />
      );
    }
    return (
      <LoginPage
        onLoginSuccess={handleLoginSuccess}
        onSwitchToRegister={allowRegistration ? () => setAuthView('register') : undefined}
        onForgotPassword={() => setAuthView('forgot')}
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
      case 'assistant':   return <AssistantPage currentUser={currentUser} onNavigateTab={setCurrentTab} />;
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
          <Suspense
            fallback={<div className="p-6 text-xs font-mono text-[#87938e]" role="status">Chargement du module…</div>}
          >
            {renderPage()}
          </Suspense>
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
