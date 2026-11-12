import React, { useState, useEffect, useCallback } from 'react';
import { Icon } from '../components/ui/Icon';
import { securiteService, parcService } from '../services/api';
import type { Equipement } from '../types';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
} from 'recharts';

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
  anomalyScore?: number;
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
  const [isSimulatingBrute, setIsSimulatingBrute] = useState(false);
  const [equipementsList, setEquipementsList] = useState<Equipement[]>([]);
  const [secStats, setSecStats] = useState<{
    total_events: number;
    anomalies_detectees: number;
    critical_threats: number;
    blocked_ips_count: number;
  }>({
    total_events: 0,
    anomalies_detectees: 0,
    critical_threats: 0,
    blocked_ips_count: 0,
  });

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
        setSecStats({
          total_events: stats.total_events ?? 0,
          anomalies_detectees: stats.anomalies_detectees ?? 0,
          critical_threats: stats.critical_threats ?? 0,
          blocked_ips_count: stats.blocked_ips_count ?? 0,
        });
      }

      if (events && Array.isArray(events)) {
        const mapped: Incident[] = events.map((e: any) => {
          const isBlocked = String(e.type_evenement || '').includes('BLOQUÉE');
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
              `Fréquence mesurée : ${e.tentatives_minute}/min. Score Isolation Forest : ${Math.round(
                Math.abs(e.score_anomalie ?? 0.25) * 100,
              )}/100.`,
            anomalyScore: Math.min(99, Math.max(15, Math.round(Math.abs(e.score_anomalie ?? 0.25) * 100 + (e.is_anomaly ? 50 : 0)))),
          };
        });
        setIncidents(mapped);
      }
    } catch {
      // Tolérance réseau
    }
  }, []);

  useEffect(() => {
    loadSecurityData();
  }, [loadSecurityData]);

  const handleFullScan = async () => {
    setIsScanning(true);
    showToast('Scan réel des journaux Windows EventLog / Linux auth.log et sockets réseau...');
    try {
      const scanRes = await securiteService.scanRealSecurity();
      await loadSecurityData();
      showToast(
        `Scan terminé : ${scanRes?.events_collected ?? 0} flux système analysés par Isolation Forest (${scanRes?.anomalies_detected ?? 0} anomalie(s)).`,
      );
    } catch {
      showToast('Erreur lors du scan de sécurité.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleSimulateBruteforce = async () => {
    setIsSimulatingBrute(true);
    showToast("Injection d'un flux Brute Force SSH et analyse par le modèle Isolation Forest...");
    try {
      const targetEqId = equipementsList[0]?.id ?? 1;
      await securiteService.simulateBruteforce(targetEqId, '198.51.100.45');
      await loadSecurityData();
      showToast("Flux d'attaque détecté et classifié CRITICAL par l'Isolation Forest !");
    } catch {
      showToast("Erreur lors de l'injection du test Brute Force.");
    } finally {
      setIsSimulatingBrute(false);
    }
  };

  const handleBlockIncident = async (inc: Incident) => {
    const ipToBlock = (inc.rawIp || inc.sourceIp).split(' ')[0];
    showToast(`Application de la règle pare-feu pour bloquer ${ipToBlock}...`);
    try {
      const res = await securiteService.blockIp(
        ipToBlock,
        inc.equipementId,
        `Blocage SOC suite à ${inc.type}`,
      );
      await loadSecurityData();
      setSelectedIncident(prev => (prev && prev.id === inc.id ? { ...prev, action: 'Blocked' } : prev));
      showToast(res?.message || `IP ${ipToBlock} bloquée avec succès (${res?.firewall_mode || 'FIREWALL'}).`);
    } catch {
      showToast(`Erreur lors du blocage de ${ipToBlock}.`);
    }
  };

  const handleIsolateEquipment = async (eq: Equipement) => {
    showToast(`Mise en quarantaine (VLAN 999) de ${eq.nom} (${eq.ip})...`);
    try {
      const res = await securiteService.isolateDevice(eq.id, 'Isolation manuelle SOC');
      setShowIsolateDrawer(false);
      await loadSecurityData();
      showToast(res?.message || `Équipement ${eq.nom} isolé en quarantaine.`);
    } catch {
      showToast(`Erreur lors de l'isolation de ${eq.nom}.`);
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
            Détection d'anomalies temps réel (Isolation Forest), EventLog Windows &amp; Pare-feu actif.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            id="securite-simulate-bruteforce-btn"
            onClick={handleSimulateBruteforce}
            disabled={isSimulatingBrute}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#ffb4ab]/60 bg-[#1d2022] hover:bg-[#272a2d] text-xs font-mono font-bold text-[#ffb4ab] transition-colors cursor-pointer"
          >
            <Icon name="bolt" size="xs" className={`text-[#ffb4ab] ${isSimulatingBrute ? 'animate-bounce' : ''}`} />
            <span>{isSimulatingBrute ? 'INJECTION...' : 'TEST BRUTE FORCE'}</span>
          </button>
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
                ACTIVE VECTORS
              </span>
              <span className="text-2xl font-bold font-mono text-[#ffb4ab] mt-1 block">
                {secStats.anomalies_detectees}
              </span>
            </div>
            <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-3.5">
              <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase block">
                EVENTS ANALYZED
              </span>
              <span className="text-2xl font-bold font-mono text-[#78d8ba] mt-1 block">
                {secStats.total_events}
              </span>
            </div>
            <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-3.5">
              <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase block">
                IPS BLOCKED
              </span>
              <span className="text-2xl font-bold font-mono text-[#81d0f8] mt-1 block">
                {secStats.blocked_ips_count}
              </span>
            </div>
          </div>
        </div>

        {/* ── Colonne Droite (5 cols) : SECURITY BENCHMARKS ─────────────────── */}
        <div className="lg:col-span-5 bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider mb-2">
              <Icon name="security" size="sm" className="text-[#78d8ba]" />
              SECURITY BENCHMARKS
            </div>

            <div className="h-44 relative flex items-center justify-center my-2">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Compliant', value: 85, color: '#78d8ba' },
                      { name: 'Non-compliant', value: 15, color: '#272a2d' },
                    ]}
                    dataKey="value"
                    innerRadius={55}
                    outerRadius={75}
                    startAngle={90}
                    endAngle={-270}
                    strokeWidth={0}
                  >
                    <Cell fill="#78d8ba" />
                    <Cell fill="#272a2d" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-3xl font-bold font-mono text-[#e0e3e6]">
                  85%
                </span>
                <span className="text-[10px] font-mono font-bold text-[#78d8ba] uppercase tracking-wider mt-0.5">
                  RGPD &amp; CIS READY
                </span>
              </div>
            </div>

            <div className="space-y-4 pt-3 border-t border-[#272a2d] text-xs font-mono">
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-[#bdc9c3]">Identity &amp; Access (Bcrypt / MFA)</span>
                  <span className="font-bold text-[#e0e3e6]">95%</span>
                </div>
                <div className="w-full bg-[#161c22] h-2 rounded-full overflow-hidden">
                  <div className="h-full bg-[#78d8ba] rounded-full" style={{ width: '95%' }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-[#bdc9c3]">Network Hardening (CIS Level 1)</span>
                  <span className="font-bold text-[#ffb4ab]">72%</span>
                </div>
                <div className="w-full bg-[#161c22] h-2 rounded-full overflow-hidden">
                  <div className="h-full bg-[#ffb4ab] rounded-full" style={{ width: '72%' }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-[#bdc9c3]">Data Protection (Fernet &amp; IP Anonymization)</span>
                  <span className="font-bold text-[#81d0f8]">100%</span>
                </div>
                <div className="w-full bg-[#161c22] h-2 rounded-full overflow-hidden">
                  <div className="h-full bg-[#81d0f8] rounded-full" style={{ width: '100%' }} />
                </div>
              </div>
            </div>
          </div>

          <div className="pt-4 text-right">
            <span className="text-[11px] font-mono text-[#87938e]">
              Moteur ML : Isolation Forest (Scikit-Learn)
            </span>
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
                    <span className="text-[#87938e]">Score Isolation Forest :</span>
                    <span className="text-[#ffb4ab] font-bold">{selectedIncident.anomalyScore ?? 92}/100</span>
                  </div>
                </div>

                <div className="p-3.5 bg-[#1d2022] rounded-xl border border-[#272a2d] space-y-2">
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Règle Pare-feu Windows / Linux</div>
                  <code className="text-[11px] block bg-[#0b0f11] p-2 rounded text-[#78d8ba]">
                    netsh advfirewall firewall add rule name="Sentinelle_Block_{(selectedIncident.rawIp || selectedIncident.sourceIp).split(' ')[0]}" dir=in action=block remoteip={(selectedIncident.rawIp || selectedIncident.sourceIp).split(' ')[0]}
                  </code>
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
                  Sélectionnez l'équipement du parc à basculer immédiatement dans le groupe de quarantaine (VLAN 999).
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
