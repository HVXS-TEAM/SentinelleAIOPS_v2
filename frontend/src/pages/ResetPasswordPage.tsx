import React, { useState } from 'react';
import axios from 'axios';
import { Icon } from '../components/ui/Icon';
import { authService } from '../services/api';
import { useTheme } from '../context/ThemeContext';

interface ResetPasswordPageProps {
  identifiantInitial?: string;
  codeInitial?: string;
  onDone: () => void;
  onBackToLogin: () => void;
}

/** Choix d'un nouveau mot de passe avec le lien reçu par e-mail ou le code remis par l'administrateur. */
export const ResetPasswordPage: React.FC<ResetPasswordPageProps> = ({
  identifiantInitial = '',
  codeInitial = '',
  onDone,
  onBackToLogin,
}) => {
  const { activeTheme } = useTheme();
  const [identifiant, setIdentifiant] = useState(identifiantInitial);
  const [code, setCode] = useState(codeInitial);
  const [motDePasse, setMotDePasse] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [erreur, setErreur] = useState<string | null>(null);
  const [reussi, setReussi] = useState(false);
  const [enCours, setEnCours] = useState(false);

  const problemes: string[] = [];
  if (!identifiant.trim()) problemes.push('Identifiant requis.');
  if (!code.trim()) problemes.push('Code requis.');
  if (motDePasse.length < 12) problemes.push('Mot de passe : 12 caractères minimum.');
  else if (!/[A-Za-z]/.test(motDePasse) || !/[0-9]/.test(motDePasse)) problemes.push('Mot de passe : lettres et chiffres requis.');
  if (motDePasse !== confirmation) problemes.push('Les deux mots de passe ne correspondent pas.');

  const envoyer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (problemes.length > 0) return;
    setErreur(null);
    setEnCours(true);
    try {
      await authService.resetPassword(identifiant.trim(), code.trim(), motDePasse);
      setReussi(true);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response) {
        const detail = err.response.data?.detail;
        setErreur(typeof detail === 'string' ? detail : 'Réinitialisation impossible.');
      } else {
        setErreur('Serveur API local injoignable. Relancez le lanceur Sentinelle AIOps.');
      }
    } finally {
      setEnCours(false);
    }
  };

  const champ = 'w-full px-3 py-2.5 rounded-lg bg-[#222b33] border border-[#3a4a44] focus:border-[#00f2c3] focus:outline-none text-[#dae3ee] font-mono text-xs';
  const etiquette = 'block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider mb-1';

  return (
    <div
      className="min-h-screen w-full flex items-center justify-center p-4 font-sans text-[#dae3ee]"
      style={{ backgroundColor: activeTheme === 'night' ? '#0D1117' : '#f4f6f8' }}
    >
      <div className="w-full max-w-[440px] py-8 px-8 bg-[#161c22] border border-[#30363d]/60 rounded-2xl shadow-[0_8px_32px_rgba(0,0,0,0.6)]">
        <h1 className="text-2xl font-bold tracking-tight mb-1">Nouveau mot de passe</h1>

        {reussi ? (
          <div className="space-y-4" data-testid="reset-reussi">
            <p className="text-xs text-[#78d8ba]">Mot de passe modifié. Vous pouvez maintenant vous connecter.</p>
            <button
              id="reset-done-btn"
              type="button"
              onClick={onDone}
              className="w-full py-3 rounded-xl bg-[#00f2c3] hover:bg-[#00e0b4] text-[#002118] font-bold text-sm cursor-pointer"
            >
              Se connecter
            </button>
          </div>
        ) : (
          <form onSubmit={envoyer} noValidate className="space-y-3.5">
            <p className="text-xs text-[#b9cac2]">
              Saisissez le code reçu (ou ouvrez le lien de l'e-mail) puis choisissez un nouveau mot de passe.
            </p>
            {erreur && (
              <div role="alert" className="p-2.5 rounded bg-[#ffb4ab]/10 border border-[#ffb4ab]/30 flex items-center gap-2 text-xs text-[#ffb4ab]">
                <Icon name="error" size="sm" className="shrink-0" />
                <span>{erreur}</span>
              </div>
            )}
            <div>
              <label htmlFor="reset-identifiant" className={etiquette}>Identifiant</label>
              <input id="reset-identifiant" className={champ} value={identifiant} onChange={e => setIdentifiant(e.target.value)} autoComplete="username" />
            </div>
            <div>
              <label htmlFor="reset-code" className={etiquette}>Code de réinitialisation</label>
              <input id="reset-code" className={champ} value={code} onChange={e => setCode(e.target.value)} autoComplete="one-time-code" placeholder="XXXXX-XXXXX" />
            </div>
            <div>
              <label htmlFor="reset-password" className={etiquette}>Nouveau mot de passe</label>
              <input id="reset-password" type="password" className={champ} value={motDePasse} onChange={e => setMotDePasse(e.target.value)} autoComplete="new-password" placeholder="12 caractères min., lettres et chiffres" />
            </div>
            <div>
              <label htmlFor="reset-confirm" className={etiquette}>Confirmer le mot de passe</label>
              <input id="reset-confirm" type="password" className={champ} value={confirmation} onChange={e => setConfirmation(e.target.value)} autoComplete="new-password" />
            </div>
            {problemes.length > 0 && (motDePasse || confirmation) && (
              <ul className="text-[11px] font-mono text-[#ffb4ab] space-y-0.5" data-testid="reset-erreurs">
                {problemes.map(m => <li key={m}>• {m}</li>)}
              </ul>
            )}
            <button
              id="reset-submit-btn"
              type="submit"
              disabled={enCours || problemes.length > 0}
              className="w-full mt-1 py-3 rounded-xl bg-[#00f2c3] hover:bg-[#00e0b4] text-[#002118] font-bold text-sm disabled:opacity-50 cursor-pointer"
            >
              {enCours ? 'Enregistrement…' : 'Changer le mot de passe'}
            </button>
          </form>
        )}

        {!reussi && (
          <div className="mt-5 pt-4 border-t border-[#3a4a44]/40 text-xs">
            <button id="reset-back-btn" type="button" onClick={onBackToLogin} className="text-[#00f2c3] hover:underline cursor-pointer">
              Retour à la connexion
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
