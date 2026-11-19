import React, { useState } from 'react';
import axios from 'axios';
import { Icon } from '../components/ui/Icon';
import { authService } from '../services/api';
import { useTheme } from '../context/ThemeContext';
import type { AuthenticatedUser } from './LoginPage';
import { PROFILS, RoleChoice, type Profil } from '../components/auth/RoleChoice';

interface SetupPageProps {
  onSetupSuccess: (user: AuthenticatedUser) => void;
}

/** Poste neuf (base vide) : choix du profil de ce poste, puis création du premier compte. */
export const SetupPage: React.FC<SetupPageProps> = ({ onSetupSuccess }) => {
  const { activeTheme } = useTheme();
  const [etape, setEtape] = useState<'profil' | 'compte'>('profil');
  const [role, setRole] = useState<Profil>('Administrateur');
  const [identifiant, setIdentifiant] = useState('');
  const [nomComplet, setNomComplet] = useState('');
  const [email, setEmail] = useState('');
  const [motDePasse, setMotDePasse] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const erreurs: string[] = [];
  if (identifiant.trim().length < 3) erreurs.push("Identifiant : 3 caractères minimum.");
  if (!nomComplet.trim()) erreurs.push('Nom complet requis.');
  if (!email.includes('@')) erreurs.push('Adresse email invalide.');
  if (motDePasse.length < 12) erreurs.push('Mot de passe : 12 caractères minimum.');
  else if (!/[A-Za-z]/.test(motDePasse) || !/[0-9]/.test(motDePasse)) erreurs.push('Mot de passe : lettres et chiffres requis.');
  if (motDePasse !== confirmation) erreurs.push('Les deux mots de passe ne correspondent pas.');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (erreurs.length > 0) return;
    setErrorMsg(null);
    setIsLoading(true);
    try {
      const res = await authService.setup({
        identifiant: identifiant.trim(),
        email: email.trim(),
        nom_complet: nomComplet.trim(),
        mot_de_passe: motDePasse,
        role,
      });
      const user: AuthenticatedUser = {
        identifiant: res.identifiant,
        nom_complet: res.nom_complet,
        role: res.role as AuthenticatedUser['role'],
        email: email.trim(),
        token: res.access_token,
      };
      localStorage.setItem('sentinelle_auth_user', JSON.stringify(user));
      onSetupSuccess(user);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response) {
        const detail = err.response.data?.detail;
        setErrorMsg(typeof detail === 'string' ? detail : 'Configuration impossible.');
      } else {
        setErrorMsg('Serveur API local injoignable. Relancez le lanceur Sentinelle AIOps.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const champ = 'w-full px-3 py-2.5 rounded-lg bg-[#222b33] border border-[#3a4a44] focus:border-[#00f2c3] focus:outline-none text-[#dae3ee] font-mono text-xs';
  const etiquette = 'block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider mb-1';

  return (
    <div
      className="min-h-screen w-full flex items-center justify-center p-4 font-sans text-[#dae3ee]"
      style={{ backgroundColor: activeTheme === 'night' ? '#0D1117' : '#f4f6f8' }}
    >
      <div className="w-full max-w-[460px] py-8 px-8 bg-[#161c22] border border-[#30363d]/60 rounded-2xl shadow-[0_8px_32px_rgba(0,0,0,0.6)]">
        <h1 className="text-2xl font-bold tracking-tight mb-1">Première configuration</h1>
        {etape === 'profil' ? (
          <div data-testid="setup-choix-profil">
            <p className="text-xs text-[#b9cac2] mb-4">
              Ce poste n'a encore aucun compte. Choisissez le profil avec lequel vous allez l'utiliser.
            </p>
            <RoleChoice roles={PROFILS.map(p => p.role)} value={role} onChange={setRole} />
            {role !== 'Administrateur' && (
              <p className="mt-3 text-[11px] font-mono text-[#ffb95c]">
                Aucun administrateur n'existera : vous pourrez en créer un depuis « Créer un nouveau compte » sur ce poste.
              </p>
            )}
            <button
              id="setup-continue-btn"
              type="button"
              onClick={() => setEtape('compte')}
              className="w-full mt-5 py-3 rounded-xl bg-[#00f2c3] hover:bg-[#00e0b4] text-[#002118] font-bold text-sm cursor-pointer"
            >
              Continuer
            </button>
          </div>
        ) : (
        <>
        <p className="text-xs text-[#b9cac2] mb-5">
          Création du compte <strong className="text-white">{role}</strong> de ce poste.{' '}
          <button type="button" onClick={() => setEtape('profil')} className="text-[#00f2c3] hover:underline cursor-pointer">
            Changer de profil
          </button>
        </p>

        {errorMsg && (
          <div role="alert" className="mb-4 p-2.5 rounded bg-[#ffb4ab]/10 border border-[#ffb4ab]/30 flex items-center gap-2 text-xs text-[#ffb4ab]">
            <Icon name="error" size="sm" className="shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} noValidate className="space-y-3.5">
          <div>
            <label htmlFor="setup-identifiant" className={etiquette}>Identifiant</label>
            <input id="setup-identifiant" className={champ} value={identifiant} onChange={e => setIdentifiant(e.target.value)} autoComplete="username" />
          </div>
          <div>
            <label htmlFor="setup-nom" className={etiquette}>Nom complet</label>
            <input id="setup-nom" className={champ} value={nomComplet} onChange={e => setNomComplet(e.target.value)} autoComplete="name" />
          </div>
          <div>
            <label htmlFor="setup-email" className={etiquette}>Email</label>
            <input id="setup-email" type="email" className={champ} value={email} onChange={e => setEmail(e.target.value)} autoComplete="email" />
          </div>
          <div>
            <label htmlFor="setup-password" className={etiquette}>Mot de passe</label>
            <input id="setup-password" type="password" className={champ} value={motDePasse} onChange={e => setMotDePasse(e.target.value)} autoComplete="new-password" placeholder="12 caractères min., lettres et chiffres" />
          </div>
          <div>
            <label htmlFor="setup-confirm" className={etiquette}>Confirmer le mot de passe</label>
            <input id="setup-confirm" type="password" className={champ} value={confirmation} onChange={e => setConfirmation(e.target.value)} autoComplete="new-password" />
          </div>

          {erreurs.length > 0 && (identifiant || motDePasse || email) && (
            <ul className="text-[11px] font-mono text-[#ffb4ab] space-y-0.5" data-testid="setup-erreurs">
              {erreurs.map(m => <li key={m}>• {m}</li>)}
            </ul>
          )}

          <button
            id="setup-submit-btn"
            type="submit"
            disabled={isLoading || erreurs.length > 0}
            className="w-full mt-1 py-3 rounded-xl bg-[#00f2c3] hover:bg-[#00e0b4] text-[#002118] font-bold text-sm disabled:opacity-50 cursor-pointer"
          >
            {isLoading ? 'Création…' : 'Créer le compte'}
          </button>
        </form>
        <p className="mt-4 text-[10px] font-mono text-[#87938e]">
          Activez ensuite le second facteur (MFA) depuis le menu du profil → Sécurité du compte.
        </p>
        </>
        )}
      </div>
    </div>
  );
};
