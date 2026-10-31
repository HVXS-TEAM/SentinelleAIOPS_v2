import React, { useState } from 'react';
import { Icon } from '../components/ui/Icon';
import { authService } from '../services/api';
import { useTheme } from '../context/ThemeContext';

/* ── Types ───────────────────────────────────────────────────────────────── */
export interface AuthenticatedUser {
  identifiant: string;
  nom_complet: string;
  role: 'Administrateur' | 'Technicien' | 'Visiteur';
  email: string;
  token?: string;
}

interface LoginPageProps {
  onLoginSuccess: (user: AuthenticatedUser) => void;
  onSwitchToRegister?: () => void;
}

/* ── Comptes de Démo ─────────────────────────────────────────────────────── */
const DEMO_CREDENTIALS: Record<string, { username: string; pass: string; name: string; role: 'Administrateur' | 'Technicien' | 'Visiteur'; email: string }> = {
  admin: {
    username: 'admin',
    pass: 'AdminPassword2026!',
    name: 'Sarah Connor',
    role: 'Administrateur',
    email: 'admin@sentinelle.local',
  },
  tech: {
    username: 'tech',
    pass: 'TechPassword2026!',
    name: 'David Bowman',
    role: 'Technicien',
    email: 'technicien@sentinelle.local',
  },
  visiteur: {
    username: 'visiteur',
    pass: 'VisiteurPassword2026!',
    name: 'Ellen Ripley',
    role: 'Visiteur',
    email: 'visiteur@sentinelle.local',
  },
};

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess, onSwitchToRegister }) => {
  const { activeTheme, preference, currentHour, cycleTheme } = useTheme();
  const [profile, setProfile] = useState<'admin' | 'tech' | 'visiteur'>('admin');
  const [username, setUsername] = useState(DEMO_CREDENTIALS.admin.username);
  const [password, setPassword] = useState(DEMO_CREDENTIALS.admin.pass);
  const [mfaCode, setMfaCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  /* Changement de profil pré-remplissant automatiquement les champs */
  const handleProfileChange = (newProfile: 'admin' | 'tech' | 'visiteur') => {
    setProfile(newProfile);
    setUsername(DEMO_CREDENTIALS[newProfile].username);
    setPassword(DEMO_CREDENTIALS[newProfile].pass);
    setErrorMsg(null);
    setFieldErrors({});
  };

  /* Soumission de la connexion réelle avec fallback sécurisé */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const errors: Record<string, string> = {};
    const trimmedUser = username.trim();
    const trimmedPass = password.trim();

    if (!trimmedUser) {
      errors.username = "L'identifiant est requis.";
    }
    if (!trimmedPass) {
      errors.password = 'Le mot de passe est requis.';
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }
    setFieldErrors({});
    setIsLoading(true);

    try {
      // Appel API réel vers FastAPI /api/v1/auth/login
      const authData = await authService.login(trimmedUser, trimmedPass);
      const user: AuthenticatedUser = {
        identifiant: authData.identifiant,
        nom_complet: authData.nom_complet,
        role: authData.role as 'Administrateur' | 'Technicien' | 'Visiteur',
        email: `${authData.identifiant}@sentinelle.local`,
        token: authData.access_token,
      };

      localStorage.setItem('sentinelle_auth_user', JSON.stringify(user));
      onLoginSuccess(user);
    } catch (err: unknown) {
      let errorDetail: string | null = null;
      let hasResponse = false;
      if (err && typeof err === 'object' && 'response' in err) {
        const resp = (err as { response?: { status?: number; data?: { detail?: string } } }).response;
        if (resp) {
          hasResponse = true;
          if (resp.data?.detail && typeof resp.data.detail === 'string') {
            errorDetail = resp.data.detail;
          }
        }
      }
      if (!hasResponse) {
        setErrorMsg('Serveur API local injoignable. Relancez le lanceur Sentinelle AIOps.');
      } else {
        setErrorMsg(errorDetail ?? 'Identifiant ou mot de passe incorrect.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const [activeLegalModal, setActiveLegalModal] = useState<'privacy' | 'terms' | 'security' | null>(null);

  return (
    <div
      className="h-screen w-full flex flex-col items-center justify-start overflow-y-auto overflow-x-hidden p-4 sm:p-6 md:p-8 relative scroll-smooth font-sans text-[#dae3ee]"
      style={
        activeTheme === 'night'
          ? {
              backgroundColor: '#0D1117',
              backgroundImage: 'radial-gradient(#161B22 1.5px, transparent 1.5px)',
              backgroundSize: '20px 20px',
            }
          : {
              backgroundColor: '#f4f6f8',
              backgroundImage: 'radial-gradient(#cbd5e1 1.2px, transparent 1.2px)',
              backgroundSize: '20px 20px',
            }
      }
    >
      {/* Badge de Thème Horaire Automatique (Haut-Droite) */}
      <div className="fixed top-4 right-4 z-30">
        <button
          type="button"
          onClick={cycleTheme}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-[11px] font-mono transition-all cursor-pointer shadow-sm ${
            activeTheme === 'night'
              ? 'bg-[#14181b] border-[#252c32] text-[#78d8ba] hover:border-[#78d8ba]'
              : 'bg-white border-slate-200 text-slate-700 hover:border-teal-600'
          }`}
          title="Cliquer pour basculer entre Mode Horaire Auto (07h-19h Jour / 19h-07h Nuit), Mode Nuit forcé et Mode Jour forcé"
        >
          <Icon name={activeTheme === 'night' ? 'dark_mode' : 'light_mode'} size="xs" />
          <span>
            {preference === 'auto'
              ? `Auto (${currentHour}h • ${activeTheme === 'night' ? 'Nuit' : 'Jour'})`
              : preference === 'night'
              ? 'Thème : Nuit'
              : 'Thème : Jour'}
          </span>
        </button>
      </div>

      {/* ── Carte Centrale en Glassmorphism (Maquette Stitch) ─────────── */}
      <div className="w-full max-w-[420px] my-auto py-6 sm:py-8 px-6 sm:px-8 bg-[#161c22] border border-[#30363d]/60 rounded-2xl flex flex-col items-center shadow-[0_8px_32px_rgba(0,0,0,0.6)] relative z-10 shrink-0 animate-in zoom-in-95 duration-200">

        {/* Logo Sentinelle au centre avec Halo lumineux (Conforme maquette Stitch) */}
        <div className="mb-6 w-24 h-24 relative flex items-center justify-center">
          <div className="absolute inset-0 bg-[#00f2c3]/25 blur-xl rounded-2xl animate-pulse" />
          <div className="w-24 h-24 rounded-2xl bg-[#0b0f11] border border-[#00f2c3]/40 overflow-hidden relative shadow-[0_0_25px_rgba(0,242,195,0.25)] flex items-center justify-center p-2">
            <img
              src="/sentinelle_logo.png"
              alt="Sentinelle AIOps"
              className="w-full h-full object-contain scale-110 drop-shadow-[0_0_8px_rgba(0,242,195,0.4)]"
              onError={(e) => {
                e.currentTarget.style.display = 'none';
              }}
            />
          </div>
        </div>

        {/* Titre & Sous-titre */}
        <div className="text-center mb-6 w-full">
          <h1 className="text-2xl font-bold text-[#dae3ee] tracking-tight mb-1">
            Connexion à Sentinelle
          </h1>
          <p className="text-xs text-[#b9cac2]">
            Accédez à votre centre de commande AIOps
          </p>
        </div>

        {/* Message d'erreur éventuel */}
        {errorMsg && (
          <div className="w-full mb-4 p-2.5 rounded bg-[#ffb4ab]/10 border border-[#ffb4ab]/30 flex items-center gap-2 text-xs text-[#ffb4ab]">
            <Icon name="error" size="sm" className="shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Formulaire de Connexion Libre & Réel avec validation sans infobulles natives */}
        <form onSubmit={handleSubmit} noValidate className="w-full space-y-4 text-xs">

          {/* Raccourcis de test démo optionnels */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="block font-mono text-[10px] font-semibold text-[#b9cac2] uppercase tracking-wider">
                COMPTES DE DÉMONSTRATION
              </label>
              <span className="text-[9px] text-[#00f2c3] font-mono">1 clic</span>
            </div>
            <div className="grid grid-cols-3 gap-1.5">
              {(['admin', 'tech', 'visiteur'] as const).map((key) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => handleProfileChange(key)}
                  className={`py-1.5 px-2 rounded-lg border font-mono text-[10px] transition-all cursor-pointer text-center ${
                    profile === key
                      ? 'bg-[#00f2c3]/20 border-[#00f2c3] text-[#00f2c3] font-bold shadow-[0_0_8px_rgba(0,242,195,0.2)]'
                      : 'bg-[#222b33]/80 border-[#3a4a44] text-[#b9cac2] hover:border-[#b9cac2]/50 hover:text-white'
                  }`}
                >
                  {key === 'admin' ? 'Admin' : key === 'tech' ? 'Tech' : 'Visiteur'}
                </button>
              ))}
            </div>
          </div>

          {/* 1. IDENTIFIANT */}
          <div className="space-y-1.5">
            <label className="block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider">
              IDENTIFIANT
            </label>
            <div className={`relative rounded-lg bg-[#222b33] border transition-all ${
              fieldErrors.username
                ? 'border-[#ffb4ab] shadow-[0_0_8px_rgba(255,180,171,0.25)]'
                : 'border-[#3a4a44] focus-within:border-[#00f2c3] focus-within:shadow-[0_0_12px_rgba(0,242,195,0.2)]'
            }`}>
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#b9cac2]">
                <Icon name="person" size="sm" />
              </div>
              <input
                id="login-username-input"
                type="text"
                value={username}
                onChange={e => {
                  setUsername(e.target.value);
                  if (fieldErrors.username) setFieldErrors(prev => ({ ...prev, username: '' }));
                }}
                placeholder="Votre identifiant (ex: edwin, admin)"
                className="w-full pl-9 pr-3 py-2.5 bg-transparent text-[#dae3ee] focus:outline-none placeholder-[#b9cac2]/40 font-mono text-xs"
              />
            </div>
            {fieldErrors.username && (
              <span className="text-[11px] font-mono text-[#ffb4ab] flex items-center gap-1 mt-0.5 animate-in fade-in">
                <Icon name="error" size="xs" />
                <span>{fieldErrors.username}</span>
              </span>
            )}
          </div>

          {/* 2. MOT DE PASSE + Lien Oublié ? */}
          <div className="space-y-1.5">
            <div className="flex justify-between items-center">
              <label className="block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider">
                MOT DE PASSE
              </label>
              <button
                type="button"
                onClick={() => setShowForgotModal(true)}
                className="font-mono text-[11px] text-[#00f2c3] hover:underline"
              >
                Oublié ?
              </button>
            </div>
            <div className={`relative rounded-lg bg-[#222b33] border transition-all ${
              fieldErrors.password
                ? 'border-[#ffb4ab] shadow-[0_0_8px_rgba(255,180,171,0.25)]'
                : 'border-[#3a4a44] focus-within:border-[#00f2c3] focus-within:shadow-[0_0_12px_rgba(0,242,195,0.2)]'
            }`}>
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#b9cac2]">
                <Icon name="lock" size="sm" />
              </div>
              <input
                id="login-password-input"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={e => {
                  setPassword(e.target.value);
                  if (fieldErrors.password) setFieldErrors(prev => ({ ...prev, password: '' }));
                }}
                placeholder="••••••••"
                className="w-full pl-9 pr-9 py-2.5 bg-transparent text-[#dae3ee] focus:outline-none placeholder-[#b9cac2]/40 font-mono text-xs"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-[#b9cac2] hover:text-[#dae3ee]"
              >
                {showPassword ? <Icon name="visibility_off" size="sm" /> : <Icon name="visibility" size="sm" />}
              </button>
            </div>
            {fieldErrors.password && (
              <span className="text-[11px] font-mono text-[#ffb4ab] flex items-center gap-1 mt-0.5 animate-in fade-in">
                <Icon name="error" size="xs" />
                <span>{fieldErrors.password}</span>
              </span>
            )}
          </div>

          {/* 3. CODE MFA (Si Administrateur) */}
          {profile === 'admin' && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="block font-mono text-[10px] font-semibold text-[#00f2c3] uppercase tracking-wider flex items-center gap-1">
                  <Icon name="key" size="xs" />
                  <span>CODE MFA (FACULTATIF DÉMO)</span>
                </label>
              </div>
              <div className="relative rounded-lg bg-[#222b33] border border-[#3a4a44] focus-within:border-[#00f2c3] focus-within:shadow-[0_0_12px_rgba(0,242,195,0.2)] transition-all">
                <input
                  id="login-mfa-input"
                  type="text"
                  maxLength={6}
                  value={mfaCode}
                  onChange={e => setMfaCode(e.target.value)}
                  placeholder="123456 (ou laissez vide)"
                  className="w-full px-3 py-2 bg-transparent text-[#dae3ee] focus:outline-none placeholder-[#b9cac2]/40 font-mono text-center tracking-widest text-xs"
                />
              </div>
            </div>
          )}

          {/* Bouton Se connecter ➔ */}
          <button
            id="login-submit-btn"
            type="submit"
            disabled={isLoading}
            className="w-full mt-2 py-3 px-4 rounded-xl bg-[#00f2c3] hover:bg-[#00e0b4] text-[#002118] font-bold text-sm tracking-wide shadow-[0_0_15px_rgba(0,242,195,0.3)] hover:shadow-[0_0_25px_rgba(0,242,195,0.5)] transition-all duration-300 flex justify-center items-center gap-2 cursor-pointer disabled:opacity-60"
          >
            {isLoading ? (
              <span className="inline-block w-4 h-4 border-2 border-[#002118] border-t-transparent rounded-full animate-spin" />
            ) : (
              <>
                <span>Se connecter</span>
                <Icon name="login" size="sm" />
              </>
            )}
          </button>
        </form>

        {/* Bouton Créer un compte */}
        {onSwitchToRegister && (
          <div className="mt-4 pt-4 border-t border-[#3a4a44]/40 w-full text-center">
            <p className="text-xs text-[#b9cac2]">
              Pas encore de compte ?{' '}
              <button
                id="login-switch-to-register-btn"
                type="button"
                onClick={onSwitchToRegister}
                className="text-[#00f2c3] font-bold hover:underline inline-flex items-center gap-1 ml-1 cursor-pointer"
              >
                <span>Créer un compte</span>
                <Icon name="person_add" size="xs" />
              </button>
            </p>
          </div>
        )}

        {/* Badge Système Opérationnel */}
        <div className="mt-6 pt-5 border-t border-[#3a4a44]/40 w-full text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#222b33]/60 border border-[#3a4a44]/50">
            <span className="w-2 h-2 rounded-full bg-[#00f2c3] animate-pulse" />
            <span className="font-mono text-[11px] text-[#b9cac2]">
              Système Opérationnel
            </span>
          </div>
        </div>
      </div>

      {/* ── Footer Légal (Discret) ────────────────────────────────────── */}
      <footer className="mt-8 mb-6 text-center text-[11px] font-mono text-[#b9cac2]/60 z-10 space-y-1 shrink-0">
        <div>© 2026 Sentinelle AIOps Command. Tous droits réservés.</div>
        <div className="flex gap-4 justify-center text-[10px]">
          <button
            type="button"
            onClick={() => setActiveLegalModal('privacy')}
            className="hover:text-[#00f2c3] cursor-pointer"
          >
            Politique de Confidentialité
          </button>
          <span>•</span>
          <button
            type="button"
            onClick={() => setActiveLegalModal('terms')}
            className="hover:text-[#00f2c3] cursor-pointer"
          >
            Conditions d'Utilisation
          </button>
          <span>•</span>
          <button
            type="button"
            onClick={() => setActiveLegalModal('security')}
            className="hover:text-[#00f2c3] cursor-pointer"
          >
            Centre de Sécurité
          </button>
        </div>
      </footer>

      {/* ── Modales Légales / RGPD / Sécurité ─────────────────────────── */}
      {activeLegalModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-[#161b22] border border-[#30363d] rounded-xl shadow-2xl p-6 text-xs text-[#dae3ee] animate-in zoom-in-95 duration-150">
            <div className="flex justify-between items-center mb-3">
              <h3 className="font-bold text-sm text-[#00f2c3]">
                {activeLegalModal === 'privacy' && 'Politique de Confidentialité (RGPD)'}
                {activeLegalModal === 'terms' && "Conditions d'Utilisation AIOps"}
                {activeLegalModal === 'security' && 'Centre de Sécurité & Conformité SOC2'}
              </h3>
              <button
                onClick={() => setActiveLegalModal(null)}
                className="text-[#b9cac2] hover:text-white cursor-pointer"
              >
                <Icon name="close" size="sm" />
              </button>
            </div>
            <div className="text-[#b9cac2] space-y-2.5 leading-relaxed text-[11px]">
              {activeLegalModal === 'privacy' && (
                <>
                  <p>
                    Conformément au RGPD (Règlement Général sur la Protection des Données), Sentinelle AIOps applique une politique de minimisation stricte.
                  </p>
                  <p>
                    Les adresses IP collectées dans les journaux d'audit et Syslog sont automatiquement anonymisées (hachage SHA-256 ou masquage subnet /24) à des fins d'analyse d'anomalies par Isolation Forest.
                  </p>
                </>
              )}
              {activeLegalModal === 'terms' && (
                <>
                  <p>
                    L'utilisation de la plateforme de supervision prédictive Sentinelle AIOps est réservée aux opérateurs, administrateurs et auditeurs habilités du réseau.
                  </p>
                  <p>
                    Toutes les actions d'orchestration (scans SNMP, blocages au pare-feu, exécution de scripts NetDevOps et sauvegardes PRA) sont journalisées de façon inaltérable dans la base SQLite.
                  </p>
                </>
              )}
              {activeLegalModal === 'security' && (
                <>
                  <p>
                    Conformité CIS Benchmark Level 1, chiffrement des secrets par clé Fernet AES-128-CBC et hachage des identifiants d'accès par bcrypt.
                  </p>
                  <p>
                    En cas d'incident critique, un Plan de Reprise d'Activité (PRA) à chaud peut être déclenché depuis le module d'administration.
                  </p>
                </>
              )}
            </div>
            <button
              onClick={() => setActiveLegalModal(null)}
              className="w-full mt-4 py-2 rounded-lg bg-[#00f2c3] text-[#002118] font-bold cursor-pointer hover:bg-[#00e0b4] transition-colors"
            >
              Compris
            </button>
          </div>
        </div>
      )}

      {/* ── Modal Mot de Passe Oublié ─────────────────────────────────── */}
      {showForgotModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-sm bg-[#161b22] border border-[#30363d] rounded-xl shadow-2xl p-5 text-xs text-[#dae3ee]">
            <div className="flex justify-between items-center mb-3">
              <h3 className="font-bold text-sm text-[#00f2c3]">Réinitialisation d'accès</h3>
              <button
                onClick={() => setShowForgotModal(false)}
                className="text-[#b9cac2] hover:text-white cursor-pointer"
              >
                <Icon name="close" size="sm" />
              </button>
            </div>
            <p className="text-[#b9cac2] mb-3 leading-relaxed">
              Pour des raisons de conformité SOC2 et de durcissement CIS, contactez le Responsable de la Sécurité des Systèmes d'Information (RSSI) ou utilisez votre clé de secours YubiKey.
            </p>
            <div className="p-2.5 rounded bg-[#222b33] border border-[#3a4a44] font-mono text-[11px] text-[#00f2c3] mb-4">
              Comptes démo préconfigurés :<br />
              • Admin: <span className="text-white">admin / AdminPassword2026!</span><br />
              • Tech: <span className="text-white">tech / TechPassword2026!</span><br />
              • Visiteur: <span className="text-white">visiteur / VisiteurPassword2026!</span>
            </div>
            <button
              onClick={() => setShowForgotModal(false)}
              className="w-full py-2 rounded bg-[#00f2c3] text-[#002118] font-bold cursor-pointer"
            >
              Fermer
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
