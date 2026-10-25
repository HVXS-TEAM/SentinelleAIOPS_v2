import React, { useState } from 'react';
import {
  Search,
  Bell,
  Moon,
  Sun,
  Settings,
  LogOut,
  Check,
  Sliders,
  Shield,
  X,
  Radio,
  Volume2,
  Clock,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

import type { AuthenticatedUser } from '../pages/LoginPage';

interface Notification {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'WARNING' | 'INFO';
  time: string;
  module: string;
}

interface HeaderProps {
  title?: string;
  subtitle?: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  actions?: React.ReactNode;
  currentUser?: AuthenticatedUser | null;
  onNavigateTab?: (tab: string) => void;
  onLogout?: () => void;
}

const NOTIFICATIONS: Notification[] = [
  {
    id: 'n1',
    title: 'Surcharge CPU détectée',
    description: 'Switch-Core-01 atteint 98% d\'utilisation.',
    severity: 'CRITICAL',
    time: 'Il y a 2m',
    module: 'NetDevOps',
  },
  {
    id: 'n2',
    title: 'Latence réseau anomale',
    description: 'Lien vers Datacenter B > 50ms.',
    severity: 'WARNING',
    time: 'Il y a 15m',
    module: 'Supervision',
  },
  {
    id: 'n3',
    title: 'Tentative d\'intrusion bloquée',
    description: 'IP suspecte détectée sur Firewall-Edge.',
    severity: 'CRITICAL',
    time: 'Il y a 1h',
    module: 'Sécurité',
  },
];

export const Header: React.FC<HeaderProps> = ({
  actions,
  currentUser,
  onNavigateTab,
  onLogout,
}) => {
  const { preference, activeTheme, currentHour, cycleTheme } = useTheme();
  const [showNotifs, setShowNotifs] = useState(false);
  const [search, setSearch] = useState('');
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [telemetryInterval, setTelemetryInterval] = useState('5s');
  const [soundAlerts, setSoundAlerts] = useState(true);
  const [compactMode, setCompactMode] = useState(false);
  const [settingsSavedToast, setSettingsSavedToast] = useState(false);

  const criticalCount = NOTIFICATIONS.filter(n => n.severity === 'CRITICAL').length;

  const getInitials = (name?: string) => {
    if (!name) return 'AD';
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
    return name.slice(0, 2).toUpperCase();
  };

  return (
    <header className="h-16 px-6 border-b border-[#272a2d] bg-[#101416] flex items-center justify-between gap-4 shrink-0 sticky top-0 z-30">
      {/* ── Barre de recherche arrondie (Stitch design) ──────────────────────── */}
      <div className="w-[420px] max-w-lg relative">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[#87938e]" />
        <input
          id="header-search"
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Rechercher IP, appareil, alerte..."
          className="w-full pl-10 pr-4 py-2 rounded-full bg-[#181f26] border border-[#272a2d] text-sm text-[#e0e3e6] placeholder:text-[#87938e] focus:outline-none focus:border-[#78d8ba]/60 transition-all font-sans"
        />
      </div>

      {/* ── Actions contextuelles injectées ─────────────────────────────────── */}
      {actions && <div className="flex items-center gap-2">{actions}</div>}

      {/* ── Outils droite : Notifications + Thème + Paramètres + Avatar ─────── */}
      <div className="flex items-center gap-3">
        {/* Cloche avec badge vert de la maquette */}
        <div className="relative">
          <button
            id="header-notifications-btn"
            onClick={() => setShowNotifs(v => !v)}
            className="w-9 h-9 rounded-full bg-[#181f26] border border-[#272a2d] hover:border-[#78d8ba]/40 flex items-center justify-center text-[#bdc9c3] hover:text-[#e0e3e6] transition-colors relative cursor-pointer"
            title="Notifications"
          >
            <Bell className="w-4 h-4" />
            {criticalCount > 0 && (
              <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-[#78d8ba]" />
            )}
          </button>

          {/* Panneau de notification dropdown */}
          {showNotifs && (
            <div className="absolute right-0 top-full mt-2 w-80 bg-[#161c22] border border-[#272a2d] rounded-xl shadow-2xl z-50 overflow-hidden animate-in fade-in zoom-in-95 duration-100">
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#272a2d]">
                <span className="text-xs font-semibold text-[#e0e3e6] uppercase font-mono tracking-wider">Flux d'alertes</span>
                <span className="text-[11px] font-mono text-[#ffb4ab]">{criticalCount} actives</span>
              </div>
              <div className="divide-y divide-[#272a2d]/60">
                {NOTIFICATIONS.map(n => (
                  <div
                    key={n.id}
                    onClick={() => {
                      setShowNotifs(false);
                      onNavigateTab?.('supervision');
                    }}
                    className="p-3.5 hover:bg-[#1d2022] cursor-pointer transition-colors"
                  >
                    <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                      <span className={`px-1.5 py-0.5 rounded font-bold ${
                        n.severity === 'CRITICAL' ? 'bg-[#ffb4ab]/15 text-[#ffb4ab]' : 'bg-orange-500/15 text-orange-400'
                      }`}>
                        {n.severity}
                      </span>
                      <span className="text-[#87938e]">{n.time}</span>
                    </div>
                    <p className="text-xs font-medium text-[#e0e3e6]">{n.title}</p>
                    <p className="text-[11px] text-[#87938e] mt-0.5">{n.description}</p>
                  </div>
                ))}
              </div>
              <div className="p-2.5 border-t border-[#272a2d] text-center bg-[#101416]">
                <button
                  id="header-view-all-alerts-btn"
                  onClick={() => {
                    setShowNotifs(false);
                    onNavigateTab?.('supervision');
                  }}
                  className="text-[11px] font-mono font-bold text-[#78d8ba] hover:underline uppercase tracking-wider cursor-pointer"
                >
                  VOIR TOUTES LES ALERTES
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Toggle Thème Temporel (Auto / Nuit / Jour) */}
        <button
          id="header-darkmode-btn"
          onClick={cycleTheme}
          className={`w-9 h-9 rounded-full border flex items-center justify-center transition-all relative cursor-pointer ${
            activeTheme === 'night'
              ? 'bg-[#181f26] border-[#78d8ba]/40 text-[#78d8ba] shadow-[0_0_10px_rgba(120,216,186,0.25)] hover:border-[#78d8ba]'
              : 'bg-white border-amber-300 text-amber-500 shadow-sm hover:border-amber-400'
          }`}
          title={
            preference === 'auto'
              ? `Thème Automatique (${activeTheme === 'night' ? 'Nocturne actif' : 'Jour actif'} - ${currentHour}h) — Cliquer pour forcer Nocturne`
              : preference === 'night'
              ? 'Thème Forcé : Nocturne (Night Ops) — Cliquer pour forcer Jour'
              : 'Thème Forcé : Jour (Haute luminosité) — Cliquer pour passer en Automatique'
          }
        >
          {preference === 'auto' ? (
            <div className="relative flex items-center justify-center">
              {activeTheme === 'night' ? (
                <Moon className="w-4 h-4" />
              ) : (
                <Sun className="w-4 h-4 text-amber-500" />
              )}
              <span className="absolute -bottom-1 -right-1.5 text-[8px] font-mono font-bold px-0.5 rounded bg-[#0b0f11] text-[#78d8ba] border border-[#78d8ba]/40 leading-none">
                A
              </span>
            </div>
          ) : preference === 'night' ? (
            <Moon className="w-4 h-4" />
          ) : (
            <Sun className="w-4 h-4 text-amber-500" />
          )}
        </button>

        {/* Paramètres rapides */}
        <button
          id="header-settings-btn"
          onClick={() => setShowSettingsModal(true)}
          className="w-9 h-9 rounded-full bg-[#181f26] border border-[#272a2d] hover:border-[#78d8ba]/40 flex items-center justify-center text-[#bdc9c3] hover:text-[#e0e3e6] transition-colors cursor-pointer"
          title="Paramètres de supervision & Préférences"
        >
          <Settings className="w-4 h-4" />
        </button>

        {/* Avatar avec cercle stylisé et menu dropdown */}
        <div className="relative">
          <button
            id="header-avatar-btn"
            onClick={() => setShowProfileMenu(v => !v)}
            className="w-9 h-9 rounded-full bg-[#162320] border-2 border-[#78d8ba]/60 hover:border-[#78d8ba] flex items-center justify-center font-mono font-bold text-xs text-[#78d8ba] transition-colors shrink-0 cursor-pointer"
            title={`Profil : ${currentUser?.nom_complet || 'Administrateur'}`}
          >
            {getInitials(currentUser?.nom_complet)}
          </button>

          {showProfileMenu && (
            <div className="absolute right-0 top-full mt-2 w-64 bg-[#161c22] border border-[#272a2d] rounded-xl shadow-2xl z-50 overflow-hidden animate-in fade-in zoom-in-95 duration-100">
              <div className="p-3.5 border-b border-[#272a2d] bg-[#12161a]">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-full bg-[#78d8ba]/15 border border-[#78d8ba]/40 flex items-center justify-center font-mono font-bold text-xs text-[#78d8ba]">
                    {getInitials(currentUser?.nom_complet)}
                  </div>
                  <div className="min-w-0">
                    <div className="text-xs font-bold text-[#e0e3e6] truncate">
                      {currentUser?.nom_complet || 'Administrateur'}
                    </div>
                    <div className="text-[10px] text-[#87938e] font-mono truncate">
                      {currentUser?.email || 'admin@sentinelle.local'}
                    </div>
                  </div>
                </div>
                <div className="mt-2.5 flex items-center gap-1.5">
                  <span className="px-2 py-0.5 rounded bg-[#78d8ba]/10 text-[#78d8ba] font-mono font-bold text-[9px] uppercase tracking-wider border border-[#78d8ba]/30">
                    {currentUser?.role || 'ADMINISTRATEUR'}
                  </span>
                  <span className="text-[10px] text-[#87938e] font-mono">• Session active</span>
                </div>
              </div>

              <div className="p-1.5 space-y-0.5 text-xs font-mono">
                <button
                  id="header-menu-admin-btn"
                  onClick={() => {
                    setShowProfileMenu(false);
                    onNavigateTab?.('admin');
                  }}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-[#bdc9c3] hover:text-[#e0e3e6] hover:bg-[#1d2022] transition-colors text-left cursor-pointer"
                >
                  <Shield className="w-3.5 h-3.5 text-[#78d8ba]" />
                  <span>Gestion Utilisateurs & RBAC</span>
                </button>
                <button
                  id="header-menu-supervision-btn"
                  onClick={() => {
                    setShowProfileMenu(false);
                    onNavigateTab?.('supervision');
                  }}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-[#bdc9c3] hover:text-[#e0e3e6] hover:bg-[#1d2022] transition-colors text-left cursor-pointer"
                >
                  <Radio className="w-3.5 h-3.5 text-[#81d0f8]" />
                  <span>Supervision Métriques Live</span>
                </button>
              </div>

              <div className="p-1.5 border-t border-[#272a2d] bg-[#12161a]">
                <button
                  id="header-menu-logout-btn"
                  onClick={() => {
                    setShowProfileMenu(false);
                    onLogout?.();
                  }}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-[#ffb4ab] hover:bg-[#ffb4ab]/10 transition-colors text-left font-mono text-xs cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Se déconnecter</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Backdrop de fermeture pour les menus volants */}
      {(showNotifs || showProfileMenu) && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => {
            setShowNotifs(false);
            setShowProfileMenu(false);
          }}
        />
      )}

      {/* ── Modal : Préférences & Paramètres Rapides ───────────────────────── */}
      {showSettingsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-150">
          <div className="w-full max-w-md bg-[#181d1b] border border-[#3e4945] rounded-xl shadow-2xl overflow-hidden">
            <div className="px-4 py-3 bg-[#1c211e] border-b border-[#3e4945] flex items-center justify-between">
              <div className="flex items-center gap-2 text-[#78d8ba]">
                <Settings className="w-4 h-4" />
                <h3 className="text-sm font-bold font-mono">Préférences & Paramètres Rapides</h3>
              </div>
              <button
                onClick={() => setShowSettingsModal(false)}
                className="text-[#bdc9c3] hover:text-[#dfe4e0] p-1 rounded hover:bg-[#262b29] transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4 text-xs font-mono">
              <div>
                <label className="block text-[11px] font-semibold text-[#bdc9c3] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-[#78d8ba]" />
                  <span>Intervalle de rafraîchissement Télémétrie</span>
                </label>
                <div className="grid grid-cols-3 gap-2">
                  {['2s', '5s', '30s'].map(val => {
                    const label = val === '2s' ? '2s (Live)' : val === '5s' ? '5s (Std)' : '30s (Éco)';
                    const isSel = telemetryInterval === val;
                    return (
                      <button
                        key={val}
                        type="button"
                        onClick={() => setTelemetryInterval(val)}
                        className={`py-2 px-2 rounded border text-center transition-all cursor-pointer text-[11px] ${
                          isSel
                            ? 'border-[#78d8ba] bg-[#78d8ba]/10 text-[#78d8ba] font-bold'
                            : 'border-[#3e4945] bg-[#262b29] text-[#bdc9c3] hover:border-white/20'
                        }`}
                      >
                        {label}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="flex items-center justify-between p-3 rounded bg-[#12161a] border border-[#3e4945]/50">
                <div className="flex items-center gap-2">
                  <Volume2 className="w-4 h-4 text-[#81d0f8]" />
                  <div>
                    <div className="text-[#dfe4e0] font-semibold">Alertes sonores critiques</div>
                    <div className="text-[10px] text-[#87938e]">Bip sonore à chaque incident sévérité CRITICAL</div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSoundAlerts(!soundAlerts)}
                  className={`relative w-8 h-4.5 rounded-full transition-colors cursor-pointer ${
                    soundAlerts ? 'bg-[#78d8ba]' : 'bg-[#272a2d]'
                  }`}
                >
                  <span
                    className={`absolute top-0.5 w-3.5 h-3.5 rounded-full bg-white transition-all shadow ${
                      soundAlerts ? 'left-4' : 'left-0.5'
                    }`}
                  />
                </button>
              </div>

              <div className="flex items-center justify-between p-3 rounded bg-[#12161a] border border-[#3e4945]/50">
                <div className="flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-[#78d8ba]" />
                  <div>
                    <div className="text-[#dfe4e0] font-semibold">Mode d'affichage compact</div>
                    <div className="text-[10px] text-[#87938e]">Densité accrue sur les tables et graphes d'infrastructure</div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setCompactMode(!compactMode)}
                  className={`relative w-8 h-4.5 rounded-full transition-colors cursor-pointer ${
                    compactMode ? 'bg-[#78d8ba]' : 'bg-[#272a2d]'
                  }`}
                >
                  <span
                    className={`absolute top-0.5 w-3.5 h-3.5 rounded-full bg-white transition-all shadow ${
                      compactMode ? 'left-4' : 'left-0.5'
                    }`}
                  />
                </button>
              </div>

              {settingsSavedToast && (
                <div className="p-2.5 rounded bg-[#78d8ba]/10 border border-[#78d8ba]/30 text-[#78d8ba] text-[11px] flex items-center gap-1.5 animate-in fade-in">
                  <Check className="w-3.5 h-3.5" />
                  <span>Préférences enregistrées avec succès.</span>
                </div>
              )}

              <div className="flex justify-end gap-2 pt-3 border-t border-[#3e4945]/60">
                <button
                  type="button"
                  onClick={() => setShowSettingsModal(false)}
                  className="px-3.5 py-1.5 rounded bg-[#262b29] border border-[#3e4945] text-[#dfe4e0] hover:bg-[#313633] transition-colors cursor-pointer"
                >
                  Fermer
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSettingsSavedToast(true);
                    setTimeout(() => {
                      setSettingsSavedToast(false);
                      setShowSettingsModal(false);
                    }, 800);
                  }}
                  className="px-4 py-1.5 rounded bg-[#78d8ba] text-[#00382b] font-bold transition-colors cursor-pointer hover:bg-[#78d8ba]/90"
                >
                  Appliquer
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};

