import React, { useState } from 'react';
import { Icon } from './ui/Icon';

interface SidebarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  currentUser?: {
    nom_complet: string;
    role: string;
    identifiant: string;
  } | null;
  onLogout: () => void;
}

interface NavItem {
  id: string;
  label: string;
  iconName: string;
}

const NAV_ITEMS: readonly NavItem[] = [
  { id: 'dashboard',   label: 'DASHBOARD',         iconName: 'dashboard' },
  { id: 'supervision', label: 'SUPERVISION',       iconName: 'monitoring' },
  { id: 'securite',    label: 'SÉCURITÉ',          iconName: 'security' },
  { id: 'netdevops',   label: 'NETDEVOPS',         iconName: 'lan' },
  { id: 'parc',        label: 'PARC INFORMATIQUE', iconName: 'inventory_2' },
  { id: 'assistant',   label: 'ASSISTANT IA',      iconName: 'smart_toy' },
  { id: 'admin',       label: 'ADMIN & RAPPORTS',  iconName: 'settings' },
];

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  currentUser,
  onLogout,
}) => {
  const [isCollapsed, setIsCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem('sentinelle_sidebar_collapsed') === 'true';
    } catch {
      return false;
    }
  });

  const toggleCollapse = () => {
    setIsCollapsed(prev => {
      const next = !prev;
      try {
        localStorage.setItem('sentinelle_sidebar_collapsed', String(next));
      } catch {
        /* noop */
      }
      return next;
    });
  };

  const initials = (currentUser?.nom_complet ?? 'Administrateur')
    .split(' ')
    .map(w => w[0])
    .slice(0, 2)
    .join('')
    .toUpperCase();

  return (
    <aside
      className={`bg-[#0b0f11] border-r border-[#272a2d] flex flex-col shrink-0 select-none h-screen sticky top-0 overflow-hidden transition-all duration-300 ease-in-out relative ${
        isCollapsed ? 'w-[72px]' : 'w-[240px]'
      }`}
    >
      {/* ── Brand Logo & Titre (Fidèle à la maquette Stitch) ────────────────── */}
      <div
        className={`h-16 flex items-center border-b border-[#272a2d]/60 transition-all ${
          isCollapsed ? 'justify-center px-2' : 'justify-between px-4'
        }`}
      >
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={isCollapsed ? toggleCollapse : undefined}
            title={isCollapsed ? 'Déplier la barre de navigation' : 'Sentinelle AIOps'}
            className={`w-9 h-9 rounded-lg bg-[#0b0f11] border border-[#78d8ba]/30 overflow-hidden flex items-center justify-center shrink-0 shadow-[0_0_12px_rgba(120,216,186,0.18)] transition-transform ${
              isCollapsed ? 'hover:scale-105 cursor-pointer hover:border-[#78d8ba]' : ''
            }`}
          >
            <img
              src="/sentinelle_logo.png"
              alt="Sentinelle AIOps"
              className="w-full h-full object-cover object-left scale-[1.9] translate-x-1.5"
            />
          </button>

          {!isCollapsed && (
            <div className="min-w-0 animate-in fade-in duration-200">
              <div className="font-semibold text-[15px] tracking-wide text-[#78d8ba] leading-tight truncate">
                Sentinelle
              </div>
              <div className="text-[11px] font-mono text-[#87938e] tracking-tight truncate">
                AIOps Command
              </div>
            </div>
          )}
        </div>

        {/* Bouton Toggle replier / déplier */}
        <button
          id="btn-sidebar-toggle"
          onClick={toggleCollapse}
          title={isCollapsed ? 'Déplier la barre latérale' : 'Replier la barre latérale'}
          className={`text-[#87938e] hover:text-[#78d8ba] p-1.5 rounded-lg hover:bg-[#191c1e] transition-colors shrink-0 ${
            isCollapsed ? 'hidden' : 'block'
          }`}
        >
          <Icon name="menu_open" size="sm" />
        </button>
      </div>

      {/* Petit bouton toggle sous le logo en mode replié pour accessibilité directe */}
      {isCollapsed && (
        <div className="pt-2 flex justify-center">
          <button
            onClick={toggleCollapse}
            title="Déplier la barre de navigation"
            className="w-8 h-8 rounded-lg bg-[#14191c] hover:bg-[#1f262b] border border-[#272a2d] hover:border-[#78d8ba]/40 flex items-center justify-center text-[#87938e] hover:text-[#78d8ba] transition-all"
          >
            <Icon name="menu" size="sm" />
          </button>
        </div>
      )}

      {/* ── Navigation ──────────────────────────────────────────────────────── */}
      <nav className="flex-1 py-3 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map(({ id, label, iconName }) => {
          const active = currentTab === id;
          return (
            <button
              key={id}
              id={`nav-${id}`}
              onClick={() => onTabChange(id)}
              title={isCollapsed ? label : undefined}
              className={`w-full flex items-center transition-colors text-left ${
                isCollapsed
                  ? 'justify-center py-3.5 px-0 border-l-[3px]'
                  : 'gap-3.5 px-5 py-3 text-[11px] font-mono font-medium tracking-wider border-l-[3px]'
              } ${
                active
                  ? 'sidebar-nav-active bg-[#15231f] text-[#78d8ba] border-[#78d8ba]'
                  : 'sidebar-nav-inactive text-[#87938e] hover:text-[#e0e3e6] hover:bg-[#191c1e] border-transparent'
              }`}
            >
              <Icon
                name={iconName}
                size={isCollapsed ? 20 : 18}
                fill={active}
                className={`shrink-0 transition-transform ${active ? 'text-[#78d8ba]' : 'text-[#87938e]'}`}
              />
              {!isCollapsed && <span className="truncate">{label}</span>}
            </button>
          );
        })}
      </nav>

      {/* ── Pied de Sidebar : Aide + Déconnexion + User Card ───────────────── */}
      <div className={`p-3 border-t border-[#272a2d]/60 space-y-2 shrink-0 ${isCollapsed ? 'px-2' : ''}`}>
        {!isCollapsed ? (
          <>
            <div className="flex items-center justify-between px-2 text-xs text-[#87938e]">
              <button
                onClick={() => alert('Documentation en ligne Sentinelle AIOps v2.')}
                className="flex items-center gap-1.5 hover:text-[#e0e3e6] transition-colors font-mono text-[11px]"
              >
                <Icon name="help" size="xs" />
                Aide
              </button>
              <button
                onClick={onLogout}
                className="flex items-center gap-1.5 text-error hover:text-error/80 transition-colors font-mono text-[11px]"
              >
                <Icon name="logout" size="xs" />
                Quitter
              </button>
            </div>

            <div className="bg-[#191c1e] border border-[#272a2d] rounded-lg p-2.5 flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-full bg-[#14231f] border border-[#78d8ba]/40 flex items-center justify-center text-[11px] font-mono font-bold text-[#78d8ba] shrink-0">
                {initials}
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium text-[#e0e3e6] truncate">
                  {currentUser?.nom_complet ?? 'J. Doe (Admin)'}
                </div>
                <div className="text-[10px] font-mono text-[#87938e] truncate">
                  {currentUser?.role ?? 'Administrateur'}
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="flex flex-col items-center gap-3 py-1">
            {/* Avatar seul avec initiales */}
            <div
              title={`${currentUser?.nom_complet ?? 'Administrateur'} (${currentUser?.role ?? 'Admin'})`}
              className="w-9 h-9 rounded-full bg-[#14231f] border border-[#78d8ba]/40 flex items-center justify-center text-[12px] font-mono font-bold text-[#78d8ba] cursor-pointer shadow-[0_0_8px_rgba(120,216,186,0.2)] hover:scale-105 transition-transform"
            >
              {initials}
            </div>

            {/* Bouton Quitter icône seule */}
            <button
              onClick={onLogout}
              title="Quitter la session"
              className="w-9 h-9 rounded-lg bg-[#191c1e] hover:bg-error/20 border border-[#272a2d] hover:border-error/40 flex items-center justify-center text-error hover:text-error/90 transition-colors"
            >
              <Icon name="logout" size="sm" />
            </button>
          </div>
        )}
      </div>
    </aside>
  );
};
