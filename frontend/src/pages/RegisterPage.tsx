import React, { useState } from 'react';
import {
  User,
  Mail,
  Lock,
  Eye,
  EyeOff,
  Shield,
  Wrench,
  BarChart3,
  UserPlus,
  LogIn,
  CheckCircle2,
  AlertCircle,
  Sparkles,
} from 'lucide-react';
import { authService } from '../services/api';
import type { AuthenticatedUser } from './LoginPage';

interface RegisterPageProps {
  onRegisterSuccess: (user: AuthenticatedUser) => void;
  onSwitchToLogin: () => void;
}

type UserRole = 'Administrateur' | 'Technicien' | 'Visiteur';

interface RoleOption {
  id: UserRole;
  title: string;
  subtitle: string;
  icon: React.ComponentType<{ className?: string }>;
  badge: string;
}

const ROLE_OPTIONS: RoleOption[] = [
  {
    id: 'Administrateur',
    title: 'Administrateur',
    subtitle: 'Accès complet, PRA & gestion des comptes',
    icon: Shield,
    badge: 'Contrôle Total',
  },
  {
    id: 'Technicien',
    title: 'Technicien N2/N3',
    subtitle: 'Supervision live, scans SNMP & audits CIS',
    icon: Wrench,
    badge: 'Opérationnel',
  },
  {
    id: 'Visiteur',
    title: 'Visiteur',
    subtitle: 'Consultation lecture seule & indicateurs',
    icon: BarChart3,
    badge: 'Lecture seule',
  },
];

export const RegisterPage: React.FC<RegisterPageProps> = ({
  onRegisterSuccess,
  onSwitchToLogin,
}) => {
  const [identifiant, setIdentifiant] = useState('');
  const [nomComplet, setNomComplet] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<UserRole>('Technicien');
  const [motDePasse, setMotDePasse] = useState('');
  const [confirmationPasse, setConfirmationPasse] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Évaluation de la robustesse du mot de passe
  const getPasswordStrength = (pwd: string) => {
    if (!pwd) return { score: 0, label: 'Vide', color: 'bg-zinc-700' };
    let score = 0;
    if (pwd.length >= 6) score++;
    if (pwd.length >= 10) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;

    if (score <= 2) return { score: 1, label: 'Faible', color: 'bg-rose-500' };
    if (score <= 4) return { score: 2, label: 'Correct', color: 'bg-amber-400' };
    return { score: 3, label: 'Fort', color: 'bg-[#00f2c3]' };
  };

  const strength = getPasswordStrength(motDePasse);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    const trimmedId = identifiant.trim();
    const trimmedNom = nomComplet.trim();
    const trimmedEmail = email.trim();

    if (!trimmedId || trimmedId.length < 3) {
      setErrorMsg("L'identifiant doit comporter au moins 3 caractères.");
      return;
    }

    if (!trimmedNom) {
      setErrorMsg('Veuillez renseigner votre nom complet.');
      return;
    }

    if (!trimmedEmail || !trimmedEmail.includes('@')) {
      setErrorMsg('Veuillez renseigner une adresse email valide.');
      return;
    }

    if (motDePasse.length < 6) {
      setErrorMsg('Le mot de passe doit contenir au moins 6 caractères.');
      return;
    }

    if (motDePasse !== confirmationPasse) {
      setErrorMsg('Les deux mots de passe ne correspondent pas.');
      return;
    }

    setIsLoading(true);

    try {
      // 1. Appel API réel vers FastAPI /api/v1/auth/register
      const res = await authService.register({
        identifiant: trimmedId,
        nom_complet: trimmedNom,
        email: trimmedEmail,
        mot_de_passe: motDePasse,
        role: role,
      });

      const user: AuthenticatedUser = {
        identifiant: res.identifiant,
        nom_complet: res.nom_complet,
        role: res.role as UserRole,
        email: res.email || trimmedEmail,
        token: res.access_token,
      };

      setSuccessMsg(`Compte « ${user.identifiant} » créé avec succès ! Connexion en cours...`);
      localStorage.setItem('sentinelle_auth_user', JSON.stringify(user));

      // Redirection après léger délai pour feedback utilisateur
      setTimeout(() => {
        onRegisterSuccess(user);
      }, 900);
    } catch (err: unknown) {
      const errDetail =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
          : null;

      setErrorMsg(
        errDetail ||
          'Erreur lors de la création du compte. Vérifiez que cet identifiant ou email n\'est pas déjà utilisé.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      className="h-screen w-full flex flex-col items-center justify-start overflow-y-auto overflow-x-hidden p-4 sm:p-6 md:p-8 relative scroll-smooth"
      style={{
        backgroundColor: '#0D1117',
        backgroundImage: 'radial-gradient(#161B22 1.5px, transparent 1.5px)',
        backgroundSize: '20px 20px',
      }}
    >
      {/* Carte Centrale Glassmorphism responsive avec défilement fluide */}
      <div className="w-full max-w-[520px] my-auto py-6 sm:py-8 px-5 sm:px-8 bg-[rgba(22,27,34,0.85)] backdrop-blur-xl border border-[#30363d]/70 rounded-2xl flex flex-col items-center shadow-[0_8px_32px_rgba(0,0,0,0.6)] relative z-10 shrink-0 animate-in zoom-in-95 duration-200">
        {/* Header avec Logo Sentinelle */}
        <div className="mb-4 w-20 h-20 relative flex items-center justify-center">
          <div className="absolute inset-0 bg-[#00f2c3]/20 blur-lg rounded-2xl animate-pulse" />
          <div className="w-20 h-20 rounded-2xl bg-[#0b0f11] border border-[#00f2c3]/40 overflow-hidden relative shadow-[0_0_20px_rgba(0,242,195,0.25)] flex items-center justify-center p-2">
            <img
              src="/sentinelle_logo.png"
              alt="Sentinelle AIOps Logo"
              className="w-full h-full object-contain scale-110 drop-shadow-[0_0_8px_rgba(0,242,195,0.4)]"
            />
          </div>
        </div>

        {/* Titre & Sous-titre */}
        <div className="text-center mb-5 w-full">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#00f2c3]/10 border border-[#00f2c3]/30 text-[#00f2c3] text-[10px] font-mono font-semibold uppercase tracking-wider mb-2">
            <Sparkles className="w-3 h-3" />
            <span>Gestion Réelle des Comptes</span>
          </div>
          <h1 className="text-2xl font-bold text-[#dae3ee] tracking-tight mb-1">
            Créer un compte Sentinelle
          </h1>
          <p className="text-xs text-[#b9cac2]">
            Enregistrez votre profil pour accéder à la plateforme AIOps
          </p>
        </div>

        {/* Messages d'alerte / succès */}
        {errorMsg && (
          <div className="w-full mb-4 p-3 rounded-lg bg-[#ffb4ab]/10 border border-[#ffb4ab]/30 flex items-center gap-2.5 text-xs text-[#ffb4ab] animate-in fade-in">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {successMsg && (
          <div className="w-full mb-4 p-3 rounded-lg bg-[#00f2c3]/10 border border-[#00f2c3]/30 flex items-center gap-2.5 text-xs text-[#00f2c3] animate-in fade-in">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Formulaire d'inscription */}
        <form onSubmit={handleSubmit} className="w-full space-y-4 text-xs">
          {/* 1. Sélection du Profil / Rôle */}
          <div className="space-y-1.5">
            <label className="block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider">
              1. CHOISIR VOTRE PROFIL & RÔLE
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {ROLE_OPTIONS.map((opt) => {
                const IconComponent = opt.icon;
                const isSelected = role === opt.id;
                return (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setRole(opt.id)}
                    className={`p-3 rounded-xl border text-left transition-all duration-200 cursor-pointer flex flex-col justify-between ${
                      isSelected
                        ? 'bg-[#00f2c3]/15 border-[#00f2c3] shadow-[0_0_12px_rgba(0,242,195,0.25)] text-[#dae3ee]'
                        : 'bg-[#1c242c] border-[#3a4a44]/60 hover:border-[#b9cac2]/40 text-[#b9cac2]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div
                        className={`p-1.5 rounded-lg ${
                          isSelected ? 'bg-[#00f2c3] text-[#002118]' : 'bg-[#222b33] text-[#b9cac2]'
                        }`}
                      >
                        <IconComponent className="w-4 h-4" />
                      </div>
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.5 rounded-full ${
                          isSelected
                            ? 'bg-[#00f2c3]/20 text-[#00f2c3] font-bold'
                            : 'bg-black/30 text-[#b9cac2]/70'
                        }`}
                      >
                        {opt.badge}
                      </span>
                    </div>
                    <div>
                      <div className="font-bold text-xs text-white leading-tight">
                        {opt.title}
                      </div>
                      <div className="text-[10px] text-[#b9cac2]/80 mt-1 line-clamp-2">
                        {opt.subtitle}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* 2. Nom Complet & Identifiant */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider">
                NOM COMPLET
              </label>
              <div className="relative rounded-lg bg-[#222b33] border border-[#3a4a44] focus-within:border-[#00f2c3] focus-within:shadow-[0_0_12px_rgba(0,242,195,0.2)] transition-all">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#b9cac2]">
                  <User className="w-4 h-4" />
                </div>
                <input
                  id="register-nom-complet-input"
                  type="text"
                  required
                  value={nomComplet}
                  onChange={(e) => setNomComplet(e.target.value)}
                  placeholder="Ex: Edwin Jamel"
                  className="w-full pl-9 pr-3 py-2 bg-transparent text-[#dae3ee] focus:outline-none placeholder-[#b9cac2]/40 text-xs"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider">
                IDENTIFIANT UNIQUE
              </label>
              <div className="relative rounded-lg bg-[#222b33] border border-[#3a4a44] focus-within:border-[#00f2c3] focus-within:shadow-[0_0_12px_rgba(0,242,195,0.2)] transition-all">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#b9cac2]">
                  <User className="w-4 h-4" />
                </div>
                <input
                  id="register-identifiant-input"
                  type="text"
                  required
                  value={identifiant}
                  onChange={(e) => setIdentifiant(e.target.value)}
                  placeholder="Ex: edwin"
                  className="w-full pl-9 pr-3 py-2 bg-transparent text-[#dae3ee] focus:outline-none placeholder-[#b9cac2]/40 font-mono text-xs"
                />
              </div>
            </div>
          </div>

          {/* 3. Adresse E-mail Professionnelle */}
          <div className="space-y-1.5">
            <label className="block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider">
              EMAIL PROFESSIONNEL
            </label>
            <div className="relative rounded-lg bg-[#222b33] border border-[#3a4a44] focus-within:border-[#00f2c3] focus-within:shadow-[0_0_12px_rgba(0,242,195,0.2)] transition-all">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#b9cac2]">
                <Mail className="w-4 h-4" />
              </div>
              <input
                id="register-email-input"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="edwin@sentinelle.local"
                className="w-full pl-9 pr-3 py-2 bg-transparent text-[#dae3ee] focus:outline-none placeholder-[#b9cac2]/40 font-mono text-xs"
              />
            </div>
          </div>

          {/* 4. Mot de passe & Confirmation */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider">
                MOT DE PASSE
              </label>
              <div className="relative rounded-lg bg-[#222b33] border border-[#3a4a44] focus-within:border-[#00f2c3] focus-within:shadow-[0_0_12px_rgba(0,242,195,0.2)] transition-all">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#b9cac2]">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  id="register-password-input"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={motDePasse}
                  onChange={(e) => setMotDePasse(e.target.value)}
                  placeholder="Min. 6 caractères"
                  className="w-full pl-9 pr-8 py-2 bg-transparent text-[#dae3ee] focus:outline-none placeholder-[#b9cac2]/40 font-mono text-xs"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-2.5 flex items-center text-[#b9cac2] hover:text-[#dae3ee]"
                >
                  {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider">
                CONFIRMATION
              </label>
              <div className="relative rounded-lg bg-[#222b33] border border-[#3a4a44] focus-within:border-[#00f2c3] focus-within:shadow-[0_0_12px_rgba(0,242,195,0.2)] transition-all">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#b9cac2]">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  id="register-confirm-password-input"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={confirmationPasse}
                  onChange={(e) => setConfirmationPasse(e.target.value)}
                  placeholder="Répétez le passe"
                  className="w-full pl-9 pr-3 py-2 bg-transparent text-[#dae3ee] focus:outline-none placeholder-[#b9cac2]/40 font-mono text-xs"
                />
              </div>
            </div>
          </div>

          {/* Jauge de sécurité */}
          {motDePasse && (
            <div className="space-y-1 pt-0.5">
              <div className="flex justify-between items-center text-[10px] font-mono">
                <span className="text-[#b9cac2]">Force du mot de passe :</span>
                <span className="text-white font-semibold">{strength.label}</span>
              </div>
              <div className="h-1.5 w-full bg-[#222b33] rounded-full overflow-hidden flex gap-1">
                <div
                  className={`h-full transition-all duration-300 ${
                    strength.score >= 1 ? strength.color : 'bg-transparent'
                  }`}
                  style={{ width: '33.3%' }}
                />
                <div
                  className={`h-full transition-all duration-300 ${
                    strength.score >= 2 ? strength.color : 'bg-transparent'
                  }`}
                  style={{ width: '33.3%' }}
                />
                <div
                  className={`h-full transition-all duration-300 ${
                    strength.score >= 3 ? strength.color : 'bg-transparent'
                  }`}
                  style={{ width: '33.4%' }}
                />
              </div>
            </div>
          )}

          {/* Bouton de soumission */}
          <button
            id="register-submit-btn"
            type="submit"
            disabled={isLoading}
            className="w-full mt-3 py-3 px-4 rounded-xl bg-[#00f2c3] hover:bg-[#00e0b4] text-[#002118] font-bold text-sm tracking-wide shadow-[0_0_15px_rgba(0,242,195,0.3)] hover:shadow-[0_0_25px_rgba(0,242,195,0.5)] transition-all duration-300 flex justify-center items-center gap-2 cursor-pointer disabled:opacity-60"
          >
            {isLoading ? (
              <span className="inline-block w-4 h-4 border-2 border-[#002118] border-t-transparent rounded-full animate-spin" />
            ) : (
              <>
                <span>Créer mon compte & Accéder</span>
                <UserPlus className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Bascule vers la page de connexion */}
        <div className="mt-5 pt-4 border-t border-[#3a4a44]/40 w-full text-center">
          <p className="text-xs text-[#b9cac2]">
            Vous possédez déjà un compte enregistré ?{' '}
            <button
              id="register-switch-to-login-btn"
              type="button"
              onClick={onSwitchToLogin}
              className="text-[#00f2c3] font-bold hover:underline inline-flex items-center gap-1 ml-1 cursor-pointer"
            >
              <span>Se connecter</span>
              <LogIn className="w-3.5 h-3.5" />
            </button>
          </p>
        </div>
      </div>

      {/* Footer Sentinelle */}
      <footer className="text-center text-[11px] font-mono text-[#b9cac2]/60 z-10 space-y-1">
        <div>© 2026 Sentinelle AIOps Platform. Gestion des identités sécurisée.</div>
      </footer>
    </div>
  );
};
