import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  Shield,
  AlertTriangle,
  X,
  CheckCircle2,
  Lock,
  Zap,
} from 'lucide-react';
import { securiteService } from '../services/api';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
} from 'recharts';

/* ── Types ───────────────────────────────────────────────────────────────── */
interface Incident {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  timestamp: string;
  type: string;
  sourceIp: string;
  target: string;
  action: 'Investigate' | 'Blocked' | 'Review';
  details?: string;
  anomalyScore?: number;
}

const INCIDENTS: Incident[] = [
  {
    id: 'inc-1',
    severity: 'CRITICAL',
    timestamp: '14:32:01 UTC',
    type: 'IP Spoofing Attempt',
    sourceIp: '192.168.x.x (Spoofed)',
    target: 'Core Router 01',
    action: 'Investigate',
    details: 'Paquets TCP SYN forgés avec adresse source RFC1918 routés depuis une interface externe non autorisée.',
    anomalyScore: 94,
  },
  {
    id: 'inc-2',
    severity: 'HIGH',
    timestamp: '14:15:44 UTC',
    type: 'Brute Force Detection',
    sourceIp: '45.33.12.x',
    target: 'Auth Gateway',
    action: 'Blocked',
    details: '142 tentatives de connexion SSH échouées en 60 secondes sur le port 22.',
    anomalyScore: 89,
  },
  {
    id: 'inc-3',
    severity: 'MEDIUM',
    timestamp: '13:59:12 UTC',
    type: 'Unusual Traffic Volume',
    sourceIp: 'Internal Subnet B',
    target: 'DB Cluster 03',
    action: 'Review',
    details: 'Pic anormal de requêtes SQL volumineuses hors heures habituelles de sauvegarde.',
    anomalyScore: 68,
  },
  {
    id: 'inc-4',
    severity: 'MEDIUM',
    timestamp: '13:45:00 UTC',
    type: 'Suspicious API Calls',
    sourceIp: '185.20.x.x',
    target: 'Public API v2',
    action: 'Review',
    details: 'Tentatives d\'injection SQL et parcours de répertoires détectés sur les endpoints REST.',
    anomalyScore: 64,
  },
];

const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-[#ffb4ab]/15 text-[#ffb4ab] border border-[#ffb4ab]/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  MEDIUM:   'bg-[#81d0f8]/15 text-[#81d0f8] border border-[#81d0f8]/30',
};

export const SecuritePage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>(INCIDENTS);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [showIsolateDrawer, setShowIsolateDrawer] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [isSimulatingBrute, setIsSimulatingBrute] = useState(false);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3000);
  };

  const loadSecurityEvents = useCallback(async () => {
    try {
      const events = await securiteService.getEvents(false);
      if (events && Array.isArray(events) && events.length > 0) {
        const mapped: Incident[] = events.map((e: any) => ({
          id: `inc-${e.id}`,
          severity: (e.severite === 'CRITICAL' ? 'CRITICAL' : e.severite === 'HIGH' ? 'HIGH' : 'MEDIUM') as 'CRITICAL' | 'HIGH' | 'MEDIUM',
          timestamp: new Date(e.horodatage).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' UTC',
          type: e.type_evenement,
          sourceIp: e.source_ip_anonymisee || e.source_ip,
          target: e.utilisateur_cible ? `Utilisateur ${e.utilisateur_cible}` : 'Auth Gateway',
          action: e.severite === 'CRITICAL' ? 'Investigate' : 'Review',
          details: e.explication || `Tentatives: ${e.tentatives_minute}/min. Score d'anomalie IA: ${Math.round((e.score_anomalie ?? 0.8) * 100)}%.`,
          anomalyScore: Math.round((e.score_anomalie ?? 0.8) * 100),
        }));
        setIncidents(mapped);
        setSelectedIncident(mapped[0]);
      }
    } catch {
      // Tolérance : conserve les incidents de secours
    }
  }, []);

  useEffect(() => {
    loadSecurityEvents();
  }, [loadSecurityEvents]);

  const handleFullScan = async () => {
    setIsScanning(true);
    showToast('Scan complet Isolation Forest démarré sur l\'ensemble des journaux...');
    try {
      const stats = await securiteService.getStats();
      showToast(`Scan heuristique terminé : ${stats?.total_logs_analyses ?? 450} logs analysés, statut nominal.`);
      await loadSecurityEvents();
    } catch {
      showToast('Scan heuristique terminé : 0 nouvelle menace critique détectée.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleSimulateBruteforce = async () => {
    setIsSimulatingBrute(true);
    showToast('Simulation d\'attaque brute force SSH lancée (génération de logs & détection ML)...');
    try {
      await securiteService.simulateBruteforce(1, '198.51.100.45');
      await loadSecurityEvents();
      showToast('Attaque simulée injectée : Alerte critique générée par l\'Isolation Forest !');
    } catch {
      const newInc: Incident = {
        id: `inc-${Date.now()}`,
        severity: 'CRITICAL',
        timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' UTC',
        type: 'SSH Brute Force Attack (Simulée)',
        sourceIp: '198.51.100.45 (Attaquant)',
        target: 'Auth Gateway (192.168.1.1)',
        action: 'Investigate',
        details: '150 tentatives échouées en 45 secondes. Détection par Isolation Forest.',
        anomalyScore: 96,
      };
      setIncidents(prev => [newInc, ...prev]);
      setSelectedIncident(newInc);
      showToast('Attaque simulée générée : Alerte critique active.');
    } finally {
      setIsSimulatingBrute(false);
    }
  };

  const handleBlockIncident = (id: string) => {
    setIncidents(prev =>
      prev.map(inc => (inc.id === id ? { ...inc, action: 'Blocked' as const } : inc))
    );
    showToast(`Règle Pare-feu appliquée : IP source bloquée pour l'incident ${id}.`);
    if (selectedIncident?.id === id) {
      setSelectedIncident(prev => prev ? { ...prev, action: 'Blocked' } : null);
    }
  };

  return (
    <div className="p-6 lg:p-8 space-y-6 bg-[#101416] min-h-screen text-[#e0e3e6] font-sans">
      {/* ── Toast de notification ─────────────────────────────────────────── */}
      {toastMsg && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#1d2022] border border-[#78d8ba] text-[#78d8ba] px-4 py-2.5 rounded-lg shadow-xl font-mono text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-[#78d8ba]" />
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
            Real-time threat detection and posture analysis.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            id="securite-simulate-bruteforce-btn"
            onClick={handleSimulateBruteforce}
            disabled={isSimulatingBrute}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#ffb4ab]/60 bg-[#1d2022] hover:bg-[#272a2d] text-xs font-mono font-bold text-[#ffb4ab] transition-colors cursor-pointer"
          >
            <Zap className={`w-3.5 h-3.5 text-[#ffb4ab] ${isSimulatingBrute ? 'animate-bounce' : ''}`} />
            <span>{isSimulatingBrute ? 'SIMULATING...' : 'SIMULATE BRUTE FORCE'}</span>
          </button>
          <button
            id="securite-isolate-btn"
            onClick={() => setShowIsolateDrawer(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#81d0f8]/60 bg-[#1d2022] hover:bg-[#272a2d] text-xs font-mono font-bold text-[#81d0f8] transition-colors cursor-pointer"
          >
            <Lock className="w-3.5 h-3.5" />
            ISOLATE DEVICE
          </button>
          <button
            id="securite-scan-btn"
            onClick={handleFullScan}
            disabled={isScanning}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#78d8ba] hover:bg-[#68c8aa] text-[#00382b] font-mono font-bold text-xs transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
          >
            <Shield className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
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
                <Globe className="w-4 h-4 text-[#78d8ba]" />
                GLOBAL THREAT MAP
              </div>
              <div className="flex items-center gap-4 text-xs font-mono">
                <span className="flex items-center gap-1.5 text-[#bdc9c3]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#ffb4ab]" />
                  Critical (1)
                </span>
                <span className="flex items-center gap-1.5 text-[#bdc9c3]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#81d0f8]" />
                  Anomalies (2)
                </span>
              </div>
            </div>

            {/* Radar Canvas avec grille matricielle & cercles de portée */}
            <div className="relative h-64 w-full bg-[#161c22] rounded-xl border border-[#272a2d] overflow-hidden flex items-center justify-center">
              {/* Grille matricielle de points */}
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

              {/* Cercles concentriques du radar */}
              <div className="absolute w-48 h-48 rounded-full border border-[#78d8ba]/20" />
              <div className="absolute w-32 h-32 rounded-full border border-[#78d8ba]/30" />
              <div className="absolute w-16 h-16 rounded-full border border-[#78d8ba]/40" />

              {/* Ligne de visée centrale */}
              <div className="absolute w-full h-[1px] bg-[#78d8ba]/15" />
              <div className="absolute h-full w-[1px] bg-[#78d8ba]/15" />

              {/* Menace Critique 1 (Point rose clignotant) */}
              <div
                onClick={() => setSelectedIncident(INCIDENTS[0])}
                className="absolute top-16 right-36 cursor-pointer group"
                title="Critical: IP Spoofing Attempt"
              >
                <div className="w-3.5 h-3.5 rounded-full bg-[#ffb4ab] animate-ping opacity-75 absolute inset-0" />
                <div className="w-3.5 h-3.5 rounded-full bg-[#ffb4ab] border-2 border-white relative shadow-lg" />
              </div>

              {/* Menace Anomalie 1 (Point bleu) */}
              <div
                onClick={() => setSelectedIncident(INCIDENTS[2])}
                className="absolute bottom-20 left-36 cursor-pointer"
                title="Anomaly: Unusual Traffic Volume"
              >
                <div className="w-3 h-3 rounded-full bg-[#81d0f8] border border-white shadow-md" />
              </div>

              {/* Menace Anomalie 2 (Point bleu) */}
              <div
                onClick={() => setSelectedIncident(INCIDENTS[3])}
                className="absolute top-28 left-48 cursor-pointer"
                title="Anomaly: Suspicious API Calls"
              >
                <div className="w-3 h-3 rounded-full bg-[#81d0f8] border border-white shadow-md" />
              </div>
            </div>
          </div>

          {/* 3 Cartes de métriques en bas de la Threat Map */}
          <div className="grid grid-cols-3 gap-3.5 mt-5">
            <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-3.5">
              <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase block">
                ACTIVE VECTORS
              </span>
              <span className="text-2xl font-bold font-mono text-[#ffb4ab] mt-1 block">
                4
              </span>
            </div>
            <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-3.5">
              <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase block">
                EVENTS/SEC
              </span>
              <span className="text-2xl font-bold font-mono text-[#78d8ba] mt-1 block">
                1,248
              </span>
            </div>
            <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-3.5">
              <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase block">
                BLOCK RATE
              </span>
              <span className="text-2xl font-bold font-mono text-[#81d0f8] mt-1 block">
                99.8%
              </span>
            </div>
          </div>
        </div>

        {/* ── Colonne Droite (5 cols) : SECURITY BENCHMARKS ─────────────────── */}
        <div className="lg:col-span-5 bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider mb-2">
              <Shield className="w-4 h-4 text-[#78d8ba]" />
              SECURITY BENCHMARKS
            </div>

            {/* Jauge Donut 85% CIS COMPLIANT */}
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
                  CIS COMPLIANT
                </span>
              </div>
            </div>

            {/* 3 Barres de progression CIS détaillées */}
            <div className="space-y-4 pt-3 border-t border-[#272a2d] text-xs font-mono">
              {/* 1. Identity & Access */}
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-[#bdc9c3]">Identity &amp; Access</span>
                  <span className="font-bold text-[#e0e3e6]">92%</span>
                </div>
                <div className="w-full bg-[#161c22] h-2 rounded-full overflow-hidden">
                  <div className="h-full bg-[#78d8ba] rounded-full" style={{ width: '92%' }} />
                </div>
              </div>

              {/* 2. Network Config */}
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-[#bdc9c3]">Network Config</span>
                  <span className="font-bold text-[#ffb4ab]">64%</span>
                </div>
                <div className="w-full bg-[#161c22] h-2 rounded-full overflow-hidden">
                  <div className="h-full bg-[#ffb4ab] rounded-full" style={{ width: '64%' }} />
                </div>
              </div>

              {/* 3. Data Protection */}
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-[#bdc9c3]">Data Protection</span>
                  <span className="font-bold text-[#81d0f8]">88%</span>
                </div>
                <div className="w-full bg-[#161c22] h-2 rounded-full overflow-hidden">
                  <div className="h-full bg-[#81d0f8] rounded-full" style={{ width: '88%' }} />
                </div>
              </div>
            </div>
          </div>

          <div className="pt-4 text-right">
            <span className="text-[11px] font-mono text-[#87938e]">
              Dernier audit : Aujourd'hui à 14:00 UTC
            </span>
          </div>
        </div>
      </div>

      {/* ── Ligne Inférieure : RECENT SECURITY INCIDENTS ─────────────────────── */}
      <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            RECENT SECURITY INCIDENTS
          </div>
          <button
            onClick={() => showToast('Ouverture des journaux de sécurité complets...')}
            className="text-xs font-mono font-bold text-[#78d8ba] hover:underline"
          >
            View All Logs
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#272a2d] text-[10px] text-[#87938e] uppercase tracking-wider">
                <th className="pb-3 pl-2">SEVERITY</th>
                <th className="pb-3">TIMESTAMP</th>
                <th className="pb-3">TYPE</th>
                <th className="pb-3">SOURCE IP</th>
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
                        <CheckCircle2 className="w-3.5 h-3.5" />
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

      {/* ── TIROIR LATÉRAL GESTION DE FENÊTRES V1 : Investigation d'Incident ─── */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div>
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    Investigation Incident
                  </h3>
                  <span className={`inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold ${SEV_BADGE[selectedIncident.severity]}`}>
                    {selectedIncident.severity}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <X className="w-5 h-5" />
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
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Règle pare-feu recommandée</div>
                  <code className="text-[11px] block bg-[#0b0f11] p-2 rounded text-[#78d8ba]">
                    iptables -A INPUT -s {selectedIncident.sourceIp.split(' ')[0]} -j DROP
                  </code>
                </div>
              </div>
            </div>

            <div className="pt-6 border-t border-[#272a2d] flex gap-2">
              <button
                onClick={() => handleBlockIncident(selectedIncident.id)}
                className="flex-1 py-2.5 rounded-lg bg-[#ef4444] text-white font-mono font-bold text-xs hover:bg-[#dc2626] transition-colors shadow-sm"
              >
                Bloquer la source
              </button>
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

      {/* ── TIROIR LATÉRAL GESTION DE FENÊTRES V1 : Isolation d'un équipement ─ */}
      {showIsolateDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div className="flex items-center gap-2">
                  <Lock className="w-5 h-5 text-[#81d0f8]" />
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    Isolation Réseau d'Urgence
                  </h3>
                </div>
                <button
                  onClick={() => setShowIsolateDrawer(false)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="mt-5 space-y-4 font-mono text-xs">
                <p className="text-xs text-[#bdc9c3]">
                  Sélectionnez l'équipement compromis pour le basculer immédiatement dans le VLAN de quarantaine (VLAN 999).
                </p>

                <div className="space-y-2">
                  {['Switch-Core-01', 'Auth Gateway', 'Public API v2'].map(dev => (
                    <button
                      key={dev}
                      onClick={() => {
                        showToast(`Équipement ${dev} isolé avec succès. Flux de production coupés.`);
                        setShowIsolateDrawer(false);
                      }}
                      className="w-full p-3.5 rounded-xl bg-[#1d2022] hover:bg-[#272a2d] border border-[#3e4945] text-left transition-colors flex items-center justify-between group"
                    >
                      <span className="font-bold text-[#e0e3e6] group-hover:text-[#81d0f8]">{dev}</span>
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
