import React, { useState, useEffect, useCallback } from 'react';
import { Icon } from '../components/ui/Icon';
import { securiteService, parcService } from '../services/api';
import type { Equipement } from '../types';

interface SecStats {
  total_evenements: number;
  total_anomalies: number;
  attaques_critiques: number;
  ips_bloquees: number;
  modele_actif: string;
  echantillons_baseline: number;
  echantillons_requis: number;
  evenements_par_source: Record<string, number>;
  derniere_observation: string | null;
  syslog_actif: boolean;
  syslog_datagrammes_recus: number;
  syslog_ignores_source_inconnue: number;
}

/* ── Types ───────────────────────────────────────────────────────────────── */
interface Incident {
  id: string;
  dbId?: number;
  equipementId?: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  timestamp: string;
  type: string;
  sourceIp: string;
  rawIp?: string;
  target: string;
  action: 'Investigate' | 'Blocked' | 'Review';
  details?: string;
  /** Score de l'Isolation Forest ; 0 = détection par règle statique uniquement. */
  score: number;
}

const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-[#ffb4ab]/15 text-[#ffb4ab] border border-[#ffb4ab]/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  MEDIUM:   'bg-[#81d0f8]/15 text-[#81d0f8] border border-[#81d0f8]/30',
};

export const SecuritePage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [showIsolateDrawer, setShowIsolateDrawer] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [equipementsList, setEquipementsList] = useState<Equipement[]>([]);
  const [secStats, setSecStats] = useState<SecStats | null>(null);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3500);
  };

  const loadSecurityData = useCallback(async () => {
    try {
      const [events, stats, eqs] = await Promise.all([
        securiteService.getEvents(false),
        securiteService.getStats(),
        parcService.getEquipements(),
      ]);

      if (eqs && Array.isArray(eqs)) {
        setEquipementsList(eqs);
      }
      if (stats) {
        setSecStats(stats as SecStats);
      }

      if (events && Array.isArray(events)) {
        const mapped: Incident[] = events.map((e: any) => {
          const isBlocked = String(e.explication || '').startsWith('[BLOQUÉ]');
          const sev: 'CRITICAL' | 'HIGH' | 'MEDIUM' =
            e.severite === 'CRITICAL' ? 'CRITICAL' : e.severite === 'HIGH' ? 'HIGH' : 'MEDIUM';
          return {
            id: `inc-${e.id}`,
            dbId: e.id,
            equipementId: e.equipement_id,
            severity: sev,
            timestamp: e.horodatage
              ? new Date(e.horodatage).toLocaleTimeString('fr-FR', {
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                }) + ' UTC'
              : 'Temps réel',
            type: e.type_evenement,
            sourceIp: e.source_ip_anonymisee || e.source_ip,
            rawIp: e.source_ip || e.source_ip_anonymisee,
            target: e.utilisateur_cible ? `Compte ${e.utilisateur_cible}` : 'Sonde Hôte / Passerelle',
            action: isBlocked ? 'Blocked' : sev === 'CRITICAL' ? 'Investigate' : 'Review',
            details:
              e.explication ||
              `Fréquence mesurée : ${e.tentatives_minute}/min.`,
            score: typeof e.score_anomalie === 'number' ? e.score_anomalie : 0,
          };
        });
        setIncidents(mapped);
      }
    } catch {
      showToast('Impossible de charger les données de sécurité : le serveur ne répond pas.');
    }
  }, []);

  useEffect(() => {
    loadSecurityData();
  }, [loadSecurityData]);

  const handleFullScan = async () => {
    setIsScanning(true);
    showToast('Lecture des journaux d\'authentification de l\'hôte...');
    try {
      const scanRes = await securiteService.scanRealSecurity();
      await loadSecurityData();
      if (scanRes?.aucune_source_lisible) {
        const raison = (scanRes?.sources ?? []).map((x: any) => `${x.source} : ${x.detail}`).join(' ; ');
        showToast(`Aucun journal d'authentification lisible sur l'hôte (${raison || 'aucune source'}).`);
      } else {
        showToast(
          `Scan terminé : ${scanRes?.nouveaux_evenements ?? 0} nouvel(s) événement(s), ${scanRes?.evenements_analyses ?? 0} analysé(s), ${scanRes?.anomalies_detectees ?? 0} anomalie(s).`,
        );
      }
    } catch {
      showToast('Erreur lors du scan de sécurité.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleBlockIncident = async (inc: Incident) => {
    const ipToBlock = (inc.rawIp || inc.sourceIp).split(' ')[0];
    showToast(`Application de la règle pare-feu pour bloquer ${ipToBlock}...`);
    try {
      const res = await securiteService.blockIp(
        ipToBlock,
        inc.dbId,
        `Blocage SOC suite à ${inc.type}`,
      );
      await loadSecurityData();
      setSelectedIncident(prev => (prev && prev.id === inc.id ? { ...prev, action: 'Blocked' } : prev));
      showToast(res?.message || `IP ${ipToBlock} bloquée (${res?.firewall_mode || 'pare-feu'}).`);
    } catch (err: any) {
      const d = err?.response?.data?.detail;
      showToast(typeof d === 'string' ? d : `Blocage de ${ipToBlock} impossible.`);
    }
  };

  const handleIsolateEquipment = async (eq: Equipement) => {
    showToast(`Marquage en quarantaine de ${eq.nom} (${eq.ip})...`);
    try {
      const res = await securiteService.isolateDevice(eq.id, eq.nom, 'Isolation manuelle SOC');
      setShowIsolateDrawer(false);
      await loadSecurityData();
      showToast(res?.message || `${eq.nom} marqué en quarantaine (aucune action réseau).`);
    } catch {
      showToast(`Marquage en quarantaine de ${eq.nom} impossible.`);
    }
  };

  const criticalCount = incidents.filter(i => i.severity === 'CRITICAL' && i.action !== 'Blocked').length;
  const anomalyCount = incidents.filter(i => i.severity !== 'CRITICAL' && i.action !== 'Blocked').length;

  return (
    <div className="p-6 lg:p-8 space-y-6 bg-[#101416] min-h-screen text-[#e0e3e6] font-sans">
      {/* ── Toast de notification ─────────────────────────────────────────── */}
      {toastMsg && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#1d2022] border border-[#78d8ba] text-[#78d8ba] px-4 py-2.5 rounded-lg shadow-xl font-mono text-xs flex items-center gap-2">
          <Icon name="check_circle" size="sm" className="text-[#78d8ba]" />
          {toastMsg}
        </div>
      )}

      {/* ── En-tête de page (Sécurité Overview + Boutons d'action) ─────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#e0e3e6]">
            Sécurité Overview
          </h1>
          <p className="text-sm text-[#87938e] mt-0.5">
            Détection d'intrusion sur journaux d'authentification réels (hôte, syslog des équipements) &amp; pare-feu.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            id="securite-isolate-btn"
            onClick={() => setShowIsolateDrawer(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#81d0f8]/60 bg-[#1d2022] hover:bg-[#272a2d] text-xs font-mono font-bold text-[#81d0f8] transition-colors cursor-pointer"
          >
            <Icon name="lock" size="xs" />
            ISOLATE DEVICE
          </button>
          <button
            id="securite-scan-btn"
            onClick={handleFullScan}
            disabled={isScanning}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#78d8ba] hover:bg-[#68c8aa] text-[#00382b] font-mono font-bold text-xs transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
          >
            <Icon name="security" size="xs" className={isScanning ? 'animate-spin' : ''} />
            {isScanning ? 'SCANNING...' : 'RUN FULL SCAN'}
          </button>
        </div>
      </div>

      {/* ── Disposition 2 Colonnes (Global Threat Map & Benchmarks) ────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ── Colonne Gauche (7 cols) : GLOBAL THREAT MAP ───────────────────── */}
        <div className="lg:col-span-7 bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider">
                <Icon name="public" size="sm" className="text-[#78d8ba]" />
                GLOBAL THREAT RADAR (SONDE SYSTÈME &amp; RÉSEAU)
              </div>
              <div className="flex items-center gap-4 text-xs font-mono">
                <span className="flex items-center gap-1.5 text-[#bdc9c3]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#ffb4ab]" />
                  Critical ({criticalCount})
                </span>
                <span className="flex items-center gap-1.5 text-[#bdc9c3]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#81d0f8]" />
                  Events ({anomalyCount})
                </span>
              </div>
            </div>

            {/* Radar Canvas avec grille matricielle & cercles de portée */}
            <div className="relative h-64 w-full bg-[#161c22] rounded-xl border border-[#272a2d] overflow-hidden flex items-center justify-center">
              <div className="absolute inset-0 opacity-20">
                <svg width="100%" height="100%">
                  <defs>
                    <pattern id="radarGrid" width="24" height="24" patternUnits="userSpaceOnUse">
                      <circle cx="12" cy="12" r="1.5" fill="#78d8ba" />
                    </pattern>
                  </defs>
                  <rect width="100%" height="100%" fill="url(#radarGrid)" />
                </svg>
              </div>

              <div className="absolute w-48 h-48 rounded-full border border-[#78d8ba]/20" />
              <div className="absolute w-32 h-32 rounded-full border border-[#78d8ba]/30" />
              <div className="absolute w-16 h-16 rounded-full border border-[#78d8ba]/40" />
              <div className="absolute w-full h-[1px] bg-[#78d8ba]/15" />
              <div className="absolute h-full w-[1px] bg-[#78d8ba]/15" />

              {incidents.slice(0, 5).map((inc, idx) => {
                const positions = [
                  'top-16 right-36',
                  'bottom-20 left-36',
                  'top-28 left-48',
                  'bottom-14 right-44',
                  'top-12 left-28',
                ];
                const isCrit = inc.severity === 'CRITICAL' && inc.action !== 'Blocked';
                return (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className={`absolute ${positions[idx % positions.length]} cursor-pointer group`}
                    title={`${inc.severity}: ${inc.type} (${inc.sourceIp})`}
                  >
                    {isCrit && (
                      <div className="w-3.5 h-3.5 rounded-full bg-[#ffb4ab] animate-ping opacity-75 absolute inset-0" />
                    )}
                    <div
                      className={`w-3.5 h-3.5 rounded-full border-2 border-white relative shadow-lg ${
                        inc.action === 'Blocked'
                          ? 'bg-[#78d8ba]'
                          : isCrit
                          ? 'bg-[#ffb4ab]'
                          : 'bg-[#81d0f8]'
                      }`}
                    />
                  </div>
                );
              })}
            </div>
          </div>

          {/* 3 Cartes de métriques en bas de la Threat Map */}
          <div className="grid grid-cols-3 gap-3.5 mt-5">
            <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-3.5">
              <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase block">
                ANOMALIES
              </span>
              <span className="text-2xl font-bold font-mono text-[#ffb4ab] mt-1 block">
                {secStats?.total_anomalies ?? 0}
              </span>
            </div>
            <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-3.5">
              <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase block">
                ÉVÉNEMENTS LUS
              </span>
              <span className="text-2xl font-bold font-mono text-[#78d8ba] mt-1 block">
                {secStats?.total_evenements ?? 0}
              </span>
            </div>
            <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-3.5">
              <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase block">
                IP BLOQUÉES
              </span>
              <span className="text-2xl font-bold font-mono text-[#81d0f8] mt-1 block">
                {secStats?.ips_bloquees ?? 0}
              </span>
            </div>
          </div>
        </div>

        {/* ── Colonne Droite (5 cols) : sources et moteur de détection (données réelles) ── */}
        <div className="lg:col-span-5 bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider mb-4">
              <Icon name="security" size="sm" className="text-[#78d8ba]" />
              SOURCES &amp; MOTEUR DE DÉTECTION
            </div>
            {!secStats ? (
              <p className="text-xs text-[#87938e] font-sans" data-testid="securite-stats-unavailable">
                Statistiques indisponibles.
              </p>
            ) : (
              <div className="space-y-4 text-xs font-mono" data-testid="securite-engine-panel">
                <div className="flex justify-between">
                  <span className="text-[#87938e]">Modèle actif</span>
                  <span className="text-[#e0e3e6] font-bold">
                    {secStats.modele_actif === 'regles_statiques' ? 'Règles statiques' : 'Isolation Forest + règles'}
                  </span>
                </div>
                <div>
                  <div className="flex justify-between mb-1.5">
                    <span className="text-[#87938e]">Historique d'apprentissage</span>
                    <span className="text-[#e0e3e6] font-bold">
                      {secStats.echantillons_baseline} / {secStats.echantillons_requis}
                    </span>
                  </div>
                  <div className="w-full bg-[#161c22] h-2 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[#78d8ba] rounded-full"
                      style={{
                        width: `${Math.min(100, secStats.echantillons_requis > 0 ? (secStats.echantillons_baseline / secStats.echantillons_requis) * 100 : 0)}%`,
                      }}
                    />
                  </div>
                  {secStats.modele_actif === 'regles_statiques' && (
                    <p className="text-[10px] text-[#87938e] mt-1.5 font-sans">
                      L'Isolation Forest s'active quand assez d'observations réelles sont collectées.
                    </p>
                  )}
                </div>
                <div className="pt-3 border-t border-[#272a2d] space-y-2">
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Événements par source</div>
                  {Object.keys(secStats.evenements_par_source).length === 0 ? (
                    <p className="text-[11px] text-[#87938e] font-sans">
                      Aucun événement d'authentification collecté. Lancez un scan ou activez le récepteur syslog.
                    </p>
                  ) : (
                    Object.entries(secStats.evenements_par_source).map(([src, n]) => (
                      <div key={src} className="flex justify-between">
                        <span className="text-[#bdc9c3]">{src}</span>
                        <span className="text-[#e0e3e6] font-bold">{n}</span>
                      </div>
                    ))
                  )}
                </div>
                <div className="pt-3 border-t border-[#272a2d] space-y-2">
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Récepteur syslog</span>
                    <span className={secStats.syslog_actif ? 'text-[#78d8ba] font-bold' : 'text-[#87938e]'}>
                      {secStats.syslog_actif ? `actif (${secStats.syslog_datagrammes_recus} reçus)` : 'désactivé'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Dernière observation</span>
                    <span className="text-[#e0e3e6]">
                      {secStats.derniere_observation
                        ? new Date(secStats.derniere_observation + 'Z').toLocaleString('fr-FR')
                        : 'aucune'}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Ligne Inférieure : RECENT SECURITY INCIDENTS ─────────────────────── */}
      <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider">
            <Icon name="warning" size="sm" className="text-orange-400" />
            RECENT SECURITY INCIDENTS ({incidents.length})
          </div>
          <button
            onClick={handleFullScan}
            className="text-xs font-mono font-bold text-[#78d8ba] hover:underline"
          >
            Actualiser les flux système &rsaquo;
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#272a2d] text-[10px] text-[#87938e] uppercase tracking-wider">
                <th className="pb-3 pl-2">SEVERITY</th>
                <th className="pb-3">TIMESTAMP</th>
                <th className="pb-3">TYPE</th>
                <th className="pb-3">SOURCE IP (RGPD)</th>
                <th className="pb-3">TARGET</th>
                <th className="pb-3 text-right pr-2">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#272a2d]/50">
              {incidents.map(inc => (
                <tr
                  key={inc.id}
                  className="hover:bg-[#272a2d]/40 transition-colors cursor-pointer group"
                  onClick={() => setSelectedIncident(inc)}
                >
                  <td className="py-3.5 pl-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${SEV_BADGE[inc.severity]}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="py-3.5 text-[#87938e]">{inc.timestamp}</td>
                  <td className="py-3.5 font-bold text-[#e0e3e6] group-hover:text-[#78d8ba] transition-colors">
                    {inc.type}
                  </td>
                  <td className="py-3.5 text-[#bdc9c3]">{inc.sourceIp}</td>
                  <td className="py-3.5 text-[#e0e3e6]">{inc.target}</td>
                  <td className="py-3.5 text-right pr-2" onClick={e => e.stopPropagation()}>
                    {inc.action === 'Blocked' ? (
                      <span className="inline-flex items-center gap-1.5 text-emerald-400 font-bold text-xs">
                        <Icon name="check_circle" size="xs" />
                        Blocked
                      </span>
                    ) : (
                      <button
                        onClick={() => setSelectedIncident(inc)}
                        className="px-3 py-1 rounded bg-[#161c22] border border-[#3e4945] hover:border-[#78d8ba] hover:text-[#78d8ba] text-[#e0e3e6] transition-colors text-xs font-mono"
                      >
                        {inc.action}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── TIROIR LATÉRAL : Investigation d'Incident & Blocage Pare-feu ─────── */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div>
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    Investigation Incident SOC
                  </h3>
                  <span className={`inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold ${SEV_BADGE[selectedIncident.severity]}`}>
                    {selectedIncident.severity}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <Icon name="close" size="md" />
                </button>
              </div>

              <div className="mt-5 space-y-4 font-mono text-xs">
                <div className="p-3.5 bg-[#1d2022] rounded-xl border border-[#272a2d] space-y-2">
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Détails de l'Anomalie</div>
                  <div className="text-sm font-bold text-[#e0e3e6]">{selectedIncident.type}</div>
                  <p className="text-xs text-[#bdc9c3] leading-relaxed">{selectedIncident.details}</p>
                </div>

                <div className="p-3.5 bg-[#1d2022] rounded-xl border border-[#272a2d] space-y-2">
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Vecteur d'Attaque</div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Source :</span>
                    <span className="text-[#ffb4ab] font-bold">{selectedIncident.sourceIp}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Cible réseau :</span>
                    <span className="text-[#e0e3e6]">{selectedIncident.target}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Méthode :</span>
                    <span className="text-[#ffb4ab] font-bold">
                      {selectedIncident.score > 0 ? `Isolation Forest (score ${selectedIncident.score.toFixed(2)})` : 'Règle statique'}
                    </span>
                  </div>
                </div>

                <div className="p-3.5 bg-[#1d2022] rounded-xl border border-[#272a2d] space-y-2">
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Blocage pare-feu</div>
                  <p className="text-[11px] text-[#bdc9c3] font-sans leading-relaxed">
                    Crée une règle de blocage entrant sur l'hôte de Sentinelle (netsh sous Windows, iptables sous Linux).
                    Si les droits sont insuffisants, aucune règle n'est créée et le serveur l'indique.
                  </p>
                </div>
              </div>
            </div>

            <div className="pt-6 border-t border-[#272a2d] flex gap-2">
              {selectedIncident.action !== 'Blocked' && (
                <button
                  onClick={() => handleBlockIncident(selectedIncident)}
                  className="flex-1 py-2.5 rounded-lg bg-[#ef4444] text-white font-mono font-bold text-xs hover:bg-[#dc2626] transition-colors shadow-sm"
                >
                  Bloquer l'IP Source (Pare-feu)
                </button>
              )}
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-2.5 rounded-lg border border-[#3e4945] text-xs font-mono text-[#e0e3e6] hover:bg-[#272a2d] transition-colors"
              >
                Fermer
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── TIROIR LATÉRAL : Isolation d'un équipement réel du parc ──────────── */}
      {showIsolateDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div className="flex items-center gap-2">
                  <Icon name="lock" size="md" className="text-[#81d0f8]" />
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    Isolation Réseau d'Urgence
                  </h3>
                </div>
                <button
                  onClick={() => setShowIsolateDrawer(false)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <Icon name="close" size="md" />
                </button>
              </div>

              <div className="mt-5 space-y-4 font-mono text-xs">
                <p className="text-xs text-[#bdc9c3]">
                  Sélectionnez l'équipement à marquer « Quarantaine SOC » dans Sentinelle. Aucune action réseau n'est exécutée : l'isolement effectif (VLAN, ACL, port) reste à faire sur l'équipement.
                </p>

                <div className="space-y-2">
                  {equipementsList.map(eq => (
                    <button
                      key={eq.id}
                      onClick={() => handleIsolateEquipment(eq)}
                      className="w-full p-3.5 rounded-xl bg-[#1d2022] hover:bg-[#272a2d] border border-[#3e4945] text-left transition-colors flex items-center justify-between group"
                    >
                      <div>
                        <div className="font-bold text-[#e0e3e6] group-hover:text-[#81d0f8]">{eq.nom}</div>
                        <div className="text-[10px] text-[#87938e] mt-0.5">{eq.ip} • {eq.groupe}</div>
                      </div>
                      <span className="text-[10px] text-[#ffb4ab] uppercase font-bold">Isoler &rsaquo;</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="pt-6 border-t border-[#272a2d]">
              <button
                onClick={() => setShowIsolateDrawer(false)}
                className="w-full py-2.5 rounded-lg border border-[#3e4945] text-xs font-mono text-[#e0e3e6] hover:bg-[#272a2d] transition-colors"
              >
                Annuler
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
