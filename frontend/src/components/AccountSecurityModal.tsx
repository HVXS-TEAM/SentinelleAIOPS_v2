import React, { useEffect, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import axios from 'axios';
import { Icon } from './ui/Icon';
import { authService, mfaService } from '../services/api';
import type { MfaSetupResponse } from '../types';

type Phase = 'loading' | 'inactive' | 'enrolling' | 'codes' | 'active';

interface Props {
  onClose: () => void;
}

const errorText = (err: unknown, fallback: string): string => {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (!err.response) return 'Serveur injoignable.';
  }
  return fallback;
};

/** Gestion du second facteur (TOTP) du compte connecté : activation, codes de secours, désactivation. */
export const AccountSecurityModal: React.FC<Props> = ({ onClose }) => {
  const [phase, setPhase] = useState<Phase>('loading');
  const [setup, setSetup] = useState<MfaSetupResponse | null>(null);
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pwdActuel, setPwdActuel] = useState('');
  const [pwdNouveau, setPwdNouveau] = useState('');
  const [pwdConfirm, setPwdConfirm] = useState('');
  const [pwdMessage, setPwdMessage] = useState<string | null>(null);

  useEffect(() => {
    let actif = true;
    mfaService
      .me()
      .then(me => {
        if (actif) setPhase(me.mfa_active ? 'active' : 'inactive');
      })
      .catch(err => {
        if (!actif) return;
        setError(errorText(err, "Impossible de lire l'état du second facteur."));
        setPhase('inactive');
      });
    return () => {
      actif = false;
    };
  }, []);

  const run = async (action: () => Promise<void>, fallback: string) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(errorText(err, fallback));
    } finally {
      setBusy(false);
    }
  };

  const startEnrollment = () =>
    run(async () => {
      setSetup(await mfaService.setup());
      setCode('');
      setPhase('enrolling');
    }, "Impossible de démarrer l'activation.");

  const confirmEnrollment = () =>
    run(async () => {
      const res = await mfaService.enable(code.trim());
      setRecoveryCodes(res.recovery_codes);
      setSetup(null);
      setCode('');
      setSaved(false);
      setPhase('codes');
    }, 'Code invalide.');

  const disable = () =>
    run(async () => {
      await mfaService.disable(password, code.trim());
      setPassword('');
      setCode('');
      setPhase('inactive');
    }, 'Désactivation impossible.');

  const pwdTropCourt = pwdNouveau.length > 0 && pwdNouveau.length < 12;
  const pwdIncoherent = pwdConfirm.length > 0 && pwdConfirm !== pwdNouveau;

  const changePassword = () =>
    run(async () => {
      await authService.changePassword(pwdActuel, pwdNouveau);
      setPwdActuel('');
      setPwdNouveau('');
      setPwdConfirm('');
      setPwdMessage('Mot de passe modifié.');
    }, 'Modification impossible.');

  const copyCodes = () => {
    void navigator.clipboard?.writeText(recoveryCodes.join('\n'));
  };

  const inputClass =
    'w-full px-3 py-2 rounded-lg bg-[#222b33] border border-[#3a4a44] focus:border-[#00f2c3] focus:outline-none text-[#dae3ee] font-mono text-sm';

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Sécurité du compte"
    >
      <div className="w-full max-w-md bg-[#161c22] border border-[#272a2d] rounded-xl shadow-2xl p-5 space-y-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-sm font-mono font-bold uppercase tracking-wider text-[#78d8ba]">
            <Icon name="verified_user" size="sm" />
            <span>Sécurité du compte</span>
          </h2>
          <button onClick={onClose} aria-label="Fermer" className="text-[#87938e] hover:text-white cursor-pointer">
            <Icon name="close" size="sm" />
          </button>
        </div>

        {error && (
          <div role="alert" className="p-2.5 rounded bg-[#ffb4ab]/10 border border-[#ffb4ab]/30 text-xs text-[#ffb4ab]">
            {error}
          </div>
        )}

        <section className="space-y-2 text-xs text-[#bdc9c3]" aria-label="Changer le mot de passe">
          <h3 className="font-mono font-bold uppercase tracking-wider text-[#dfe4e0]">Mot de passe</h3>
          <input
            type="password"
            aria-label="Ancien mot de passe"
            autoComplete="current-password"
            value={pwdActuel}
            onChange={e => {
              setPwdActuel(e.target.value);
              setPwdMessage(null);
            }}
            placeholder="Mot de passe actuel"
            className={inputClass}
          />
          <input
            type="password"
            aria-label="Nouveau mot de passe"
            autoComplete="new-password"
            value={pwdNouveau}
            onChange={e => {
              setPwdNouveau(e.target.value);
              setPwdMessage(null);
            }}
            placeholder="Nouveau mot de passe (12 caractères min., lettres et chiffres)"
            className={inputClass}
          />
          <input
            type="password"
            aria-label="Confirmer le nouveau mot de passe"
            autoComplete="new-password"
            value={pwdConfirm}
            onChange={e => setPwdConfirm(e.target.value)}
            placeholder="Confirmer le nouveau mot de passe"
            className={inputClass}
          />
          {pwdTropCourt && <p className="text-[#ffb4ab]">12 caractères minimum.</p>}
          {pwdIncoherent && <p className="text-[#ffb4ab]">Les deux saisies ne correspondent pas.</p>}
          {pwdMessage && <p role="status" className="text-[#78d8ba]">{pwdMessage}</p>}
          <button
            onClick={changePassword}
            disabled={busy || !pwdActuel || pwdNouveau.length < 12 || pwdNouveau !== pwdConfirm}
            className="w-full py-2 rounded-lg bg-[#262b29] border border-[#3e4945] text-[#dfe4e0] font-bold hover:border-[#78d8ba] disabled:opacity-60 cursor-pointer"
          >
            Changer le mot de passe
          </button>
        </section>

        <hr className="border-[#272a2d]" />

        {phase === 'loading' && <p className="text-xs text-[#87938e] font-mono">Chargement…</p>}

        {phase === 'inactive' && (
          <div className="space-y-3 text-xs text-[#bdc9c3]">
            <p>
              <strong className="text-white">Authentification à deux facteurs : désactivée.</strong> Ajoutez une
              couche de protection : en plus du mot de passe, un code à 6 chiffres généré par une application
              (Google Authenticator, Microsoft Authenticator, Aegis…) sera demandé à chaque connexion.
            </p>
            <button
              onClick={startEnrollment}
              disabled={busy}
              className="w-full py-2 rounded-lg bg-[#00f2c3] text-[#002118] font-bold hover:bg-[#00e0b4] disabled:opacity-60 cursor-pointer"
            >
              Activer l'authentification à deux facteurs
            </button>
          </div>
        )}

        {phase === 'enrolling' && setup && (
          <div className="space-y-3 text-xs text-[#bdc9c3]">
            <p>1. Scannez ce QR code avec votre application d'authentification.</p>
            <div className="flex justify-center p-3 bg-white rounded-lg w-fit mx-auto">
              <QRCodeSVG value={setup.otpauth_uri} size={168} />
            </div>
            <p>
              Impossible de scanner ? Saisissez cette clé manuellement :
              <code data-testid="mfa-secret" className="block mt-1 p-2 rounded bg-[#0d1117] text-[#78d8ba] font-mono break-all select-all">
                {setup.secret}
              </code>
            </p>
            <p>2. Saisissez le code à 6 chiffres affiché pour confirmer.</p>
            <input
              aria-label="Code de confirmation"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={code}
              onChange={e => setCode(e.target.value)}
              placeholder="123456"
              className={`${inputClass} text-center tracking-widest`}
            />
            <div className="flex gap-2">
              <button
                onClick={() => {
                  setSetup(null);
                  setPhase('inactive');
                }}
                className="flex-1 py-2 rounded-lg bg-[#262b29] border border-[#3e4945] text-[#dfe4e0] cursor-pointer"
              >
                Annuler
              </button>
              <button
                onClick={confirmEnrollment}
                disabled={busy || code.trim().length !== 6}
                className="flex-1 py-2 rounded-lg bg-[#00f2c3] text-[#002118] font-bold disabled:opacity-60 cursor-pointer"
              >
                Confirmer
              </button>
            </div>
          </div>
        )}

        {phase === 'codes' && (
          <div className="space-y-3 text-xs text-[#bdc9c3]">
            <p className="text-[#78d8ba] font-bold">✓ Authentification à deux facteurs activée.</p>
            <p>
              Conservez ces <strong className="text-white">codes de secours</strong> en lieu sûr (gestionnaire de mots de
              passe, impression). Chacun ne sert qu'une fois si vous perdez votre téléphone.
              <strong className="text-white"> Ils ne seront plus jamais affichés.</strong>
            </p>
            <ul data-testid="recovery-codes" className="grid grid-cols-2 gap-1.5 font-mono text-[#e0e3e6]">
              {recoveryCodes.map(c => (
                <li key={c} className="px-2 py-1 rounded bg-[#0d1117] text-center select-all">
                  {c}
                </li>
              ))}
            </ul>
            <button onClick={copyCodes} className="text-[#78d8ba] hover:text-white font-mono cursor-pointer">
              Copier les codes
            </button>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={saved} onChange={e => setSaved(e.target.checked)} />
              <span>J'ai conservé mes codes de secours.</span>
            </label>
            <button
              onClick={() => {
                setPhase('active');
              }}
              disabled={!saved}
              className="w-full py-2 rounded-lg bg-[#00f2c3] text-[#002118] font-bold disabled:opacity-60 cursor-pointer"
            >
              Terminer
            </button>
          </div>
        )}

        {phase === 'active' && (
          <div className="space-y-3 text-xs text-[#bdc9c3]">
            <p>
              <strong className="text-[#78d8ba]">Authentification à deux facteurs : activée.</strong> Un code est demandé
              à chaque connexion.
            </p>
            <p className="text-[#87938e]">Pour la désactiver, confirmez avec votre mot de passe et un code (ou un code de secours).</p>
            <input
              type="password"
              aria-label="Mot de passe actuel"
              autoComplete="current-password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Mot de passe"
              className={inputClass}
            />
            <input
              aria-label="Code MFA"
              value={code}
              onChange={e => setCode(e.target.value)}
              placeholder="Code à 6 chiffres ou code de secours"
              className={inputClass}
            />
            <button
              onClick={disable}
              disabled={busy || !password || !code.trim()}
              className="w-full py-2 rounded-lg bg-[#ffb4ab]/15 border border-[#ffb4ab]/40 text-[#ffb4ab] font-bold hover:bg-[#ffb4ab]/25 disabled:opacity-60 cursor-pointer"
            >
              Désactiver l'authentification à deux facteurs
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
