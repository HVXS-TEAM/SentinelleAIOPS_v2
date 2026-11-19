import React, { useState } from 'react';
import axios from 'axios';
import { Icon } from '../components/ui/Icon';
import { authService } from '../services/api';
import { useTheme } from '../context/ThemeContext';
import type { ForgotPasswordResponse } from '../types';

interface ForgotPasswordPageProps {
  onBackToLogin: () => void;
  onHaveCode: () => void;
}

/** « Mot de passe oublié » : lien par e-mail si le serveur envoie des e-mails, sinon code de l'administrateur. */
export const ForgotPasswordPage: React.FC<ForgotPasswordPageProps> = ({ onBackToLogin, onHaveCode }) => {
  const { activeTheme } = useTheme();
  const [identifiant, setIdentifiant] = useState('');
  const [reponse, setReponse] = useState<ForgotPasswordResponse | null>(null);
  const [erreur, setErreur] = useState<string | null>(null);
  const [enCours, setEnCours] = useState(false);

  const envoyer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifiant.trim()) return;
    setErreur(null);
    setEnCours(true);
    try {
      setReponse(await authService.forgotPassword(identifiant.trim()));
    } catch (err: unknown) {
      setErreur(
        axios.isAxiosError(err) && err.response
          ? 'La demande a échoué. Réessayez dans un instant.'
          : 'Serveur API local injoignable. Relancez le lanceur Sentinelle AIOps.',
      );
    } finally {
      setEnCours(false);
    }
  };

  return (
    <div
      className="min-h-screen w-full flex items-center justify-center p-4 font-sans text-[#dae3ee]"
      style={{ backgroundColor: activeTheme === 'night' ? '#0D1117' : '#f4f6f8' }}
    >
      <div className="w-full max-w-[440px] py-8 px-8 bg-[#161c22] border border-[#30363d]/60 rounded-2xl shadow-[0_8px_32px_rgba(0,0,0,0.6)]">
        <h1 className="text-2xl font-bold tracking-tight mb-1">Mot de passe oublié</h1>

        {reponse ? (
          <div className="space-y-4" data-testid="oubli-reponse">
            <p className="text-xs text-[#b9cac2]">{reponse.message}</p>
            <button
              id="forgot-have-code-btn"
              type="button"
              onClick={onHaveCode}
              className="w-full py-3 rounded-xl bg-[#00f2c3] hover:bg-[#00e0b4] text-[#002118] font-bold text-sm cursor-pointer"
            >
              {reponse.mode === 'email' ? "J'ai reçu un lien ou un code" : "J'ai un code de mon administrateur"}
            </button>
          </div>
        ) : (
          <form onSubmit={envoyer} noValidate className="space-y-4">
            <p className="text-xs text-[#b9cac2]">
              Saisissez votre identifiant ou votre adresse e-mail. Si l'envoi d'e-mails est configuré, vous recevrez un lien ;
              sinon, votre administrateur vous remettra un code à usage unique.
            </p>
            {erreur && (
              <div role="alert" className="p-2.5 rounded bg-[#ffb4ab]/10 border border-[#ffb4ab]/30 flex items-center gap-2 text-xs text-[#ffb4ab]">
                <Icon name="error" size="sm" className="shrink-0" />
                <span>{erreur}</span>
              </div>
            )}
            <div>
              <label htmlFor="forgot-identifiant" className="block font-mono text-[11px] font-semibold text-[#b9cac2] uppercase tracking-wider mb-1">
                Identifiant ou e-mail
              </label>
              <input
                id="forgot-identifiant"
                value={identifiant}
                onChange={e => setIdentifiant(e.target.value)}
                autoComplete="username"
                className="w-full px-3 py-2.5 rounded-lg bg-[#222b33] border border-[#3a4a44] focus:border-[#00f2c3] focus:outline-none text-[#dae3ee] font-mono text-xs"
              />
            </div>
            <button
              id="forgot-submit-btn"
              type="submit"
              disabled={enCours || !identifiant.trim()}
              className="w-full py-3 rounded-xl bg-[#00f2c3] hover:bg-[#00e0b4] text-[#002118] font-bold text-sm disabled:opacity-50 cursor-pointer"
            >
              {enCours ? 'Envoi…' : 'Continuer'}
            </button>
          </form>
        )}

        <div className="mt-5 pt-4 border-t border-[#3a4a44]/40 flex justify-between text-xs">
          <button id="forgot-back-btn" type="button" onClick={onBackToLogin} className="text-[#00f2c3] hover:underline cursor-pointer">
            Retour à la connexion
          </button>
          {!reponse && (
            <button type="button" onClick={onHaveCode} className="text-[#b9cac2] hover:underline cursor-pointer">
              J'ai déjà un code
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
