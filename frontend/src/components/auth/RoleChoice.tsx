import React from 'react';
import { Icon } from '../ui/Icon';

export type Profil = 'Administrateur' | 'Technicien' | 'Visiteur';

export const PROFILS: { role: Profil; icone: string; description: string }[] = [
  { role: 'Administrateur', icone: 'shield', description: 'Accès complet : parc, sécurité, NetDevOps, comptes, sauvegardes.' },
  { role: 'Technicien', icone: 'build', description: "Exploitation : scans, audits, correctifs, terminal SSH. Ne gère pas les comptes." },
  { role: 'Visiteur', icone: 'visibility', description: 'Consultation en lecture seule des tableaux de bord et des alertes.' },
];

interface RoleChoiceProps {
  roles: string[];
  value: Profil;
  onChange: (role: Profil) => void;
}

/** Choix du profil d'un compte (groupe de boutons radio accessibles). */
export const RoleChoice: React.FC<RoleChoiceProps> = ({ roles, value, onChange }) => (
  <div role="radiogroup" aria-label="Profil du compte" className="space-y-2">
    {PROFILS.filter(p => roles.includes(p.role)).map(p => {
      const actif = p.role === value;
      return (
        <button
          key={p.role}
          type="button"
          role="radio"
          aria-checked={actif}
          onClick={() => onChange(p.role)}
          className={`w-full text-left p-3 rounded-xl border flex items-start gap-3 cursor-pointer transition-colors ${
            actif ? 'border-[#00f2c3] bg-[#00f2c3]/10' : 'border-[#3a4a44]/60 bg-[#1c242c] hover:border-[#00f2c3]/50'
          }`}
        >
          <Icon name={p.icone} size="sm" className={actif ? 'text-[#00f2c3] shrink-0 mt-0.5' : 'text-[#b9cac2] shrink-0 mt-0.5'} />
          <span>
            <span className="block text-sm font-bold text-white">{p.role}</span>
            <span className="block text-[11px] text-[#b9cac2]">{p.description}</span>
          </span>
        </button>
      );
    })}
  </div>
);
