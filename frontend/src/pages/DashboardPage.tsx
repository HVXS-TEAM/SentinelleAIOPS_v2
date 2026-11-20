import React, { useState, useEffect, useCallback } from 'react';
import { Icon } from '../components/ui/Icon';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { dashboardService, parcService, supervisionService } from '../services/api';

/* ── Point télémétrique pour le graphique principal ───────────────────────── */
interface TelemetryPoint {
  day: string;
  cpu: number | null;
  ram: number | null;
  pred: number | null;
}

const DEFAULT_TELEMETRY_DATA: TelemetryPoint[] = [];

/* ── Équipements critiques du tableau ────────────────────────────────────── */
interface EquipmentRow {
  id: string;
  dbId?: number;
  nom: string;
  type: string;
  ip: string;
  statusColor: string;
  statusText: string;
  tendance: 'up' | 'stable' | 'down';
  cpu: number;
  ram: number;
  disk: number;
  uptime: string;
}

interface DonutSlice {
  name: string;
  value: number;
  color: string;
}

interface DashboardProps {
  onNavigateTab?: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardProps> = ({ onNavigateTab }) => {
  const [period, setPeriod] = useState('TEMPS RÉEL & PRÉDICTION');
  const [selectedEquipment, setSelectedEquipment] = useState<EquipmentRow | null>(null);
  const [showActionDrawer, setShowActionDrawer] = useState(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const [monitoredCount, setMonitoredCount] = useState<number>(0);
  const [criticalAlertsCount, setCriticalAlertsCount] = useState<number>(0);
  const [avgHealth, setAvgHealth] = useState<number>(100);
  const [predictedIncidents, setPredictedIncidents] = useState<number>(0);
  const [cisCompliance, setCisCompliance] = useState<number | null>(null);

  const [telemetryData, setTelemetryData] = useState<TelemetryPoint[]>(DEFAULT_TELEMETRY_DATA);
  const [donutData, setDonutData] = useState<DonutSlice[]>([
    { name: 'Switchs & Routeurs', value: 0, color: '#78d8ba' },
    { name: 'Serveurs & Hôtes',   value: 0, color: '#81d0f8' },
    { name: 'Pare-feux & Sécu',   value: 0, color: '#f59e0b' },
  ]);

  const [criticalEquipmentsList, setCriticalEquipmentsList] = useState<EquipmentRow[]>([]);
  const [recentAlertsList, setRecentAlertsList] = useState<any[]>([]);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3500);
  };

  /**
   * Rôle : Charge et synchronise l'ensemble des métriques réelles depuis le backend SQLite/psutil.
   */
  const loadDashboardData = useCallback(async () => {
    try {
      const [data, eqs] = await Promise.all([
        dashboardService.getSummary(),
        parcService.getEquipements(),
      ]);

      if (data?.kpis) {
        if (typeof data.kpis.total_equipements === 'number') {
          setMonitoredCount(data.kpis.total_equipements);
        }
        if (typeof data.kpis.alertes_critiques === 'number') {
          setCriticalAlertsCount(data.kpis.alertes_critiques);
        }
        if (typeof data.kpis.sante_moyenne === 'number') {
          setAvgHealth(data.kpis.sante_moyenne);
        }
        if (typeof data.kpis.ttf_imminents === 'number') {
          setPredictedIncidents(data.kpis.ttf_imminents);
        }
        if (typeof data.kpis.cis_conformite_moyenne === 'number' && data.kpis.cis_conformite_moyenne > 0) {
          setCisCompliance(Math.round(data.kpis.cis_conformite_moyenne));
        } else {
          setCisCompliance(null);
        }
      }

      const alertsFromApi = data?.alertes_recentes || data?.recent_alertes;
      if (Array.isArray(alertsFromApi)) {
        setRecentAlertsList(alertsFromApi.filter((a: any) => a.statut !== 'Résolue'));
      }

      if (Array.isArray(data?.telemetry_series) && data.telemetry_series.length > 0) {
        const mappedSeries: TelemetryPoint[] = data.telemetry_series.map((pt: any) => ({
          day: pt.time,
          cpu: typeof pt.cpu_actual === 'number' ? pt.cpu_actual : pt.actual ?? null,
          ram: typeof pt.ram_actual === 'number' ? pt.ram_actual : null,
          pred: typeof pt.cpu_predicted === 'number' ? pt.cpu_predicted : pt.predicted ?? null,
        }));
        setTelemetryData(mappedSeries);
      }

      if (eqs && eqs.length > 0) {
        if (!data?.kpis?.total_equipements) {
          setMonitoredCount(eqs.length);
        }

        let switchs = 0;
        let servers = 0;
        let firewalls = 0;
        let others = 0;

        eqs.forEach((eq: any) => {
          const t = (eq.type || '').toLowerCase();
          if (t.includes('switch') || t.includes('routeur') || t.includes('passerelle')) {
            switchs++;
          } else if (t.includes('serveur') || t.includes('hôte') || t.includes('linux') || t.includes('windows') || t.includes('vm')) {
            servers++;
          } else if (t.includes('firewall') || t.includes('pare-feu') || t.includes('sécu')) {
            firewalls++;
          } else {
            others++;
          }
        });

        const dynamicDonut: DonutSlice[] = [
          { name: 'Switchs & Routeurs', value: switchs, color: '#78d8ba' },
          { name: 'Serveurs & Hôtes',   value: servers, color: '#81d0f8' },
          { name: 'Pare-feux & Sécu',   value: firewalls, color: '#f59e0b' },
        ];
        if (others > 0) {
          dynamicDonut.push({ name: 'Autres équipements', value: others, color: '#3e4945' });
        }
        setDonutData(dynamicDonut);

        // Tri par criticité (équipements en alerte ou santé la plus basse en premier)
        const sortedEqs = [...eqs].sort((a, b) => a.score_sante - b.score_sante);
        const mappedRows: EquipmentRow[] = sortedEqs.slice(0, 6).map((eq, i) => {
          const isCrit = eq.score_sante < 50 || eq.statut_collecte !== 'OK';
          const isWarn = eq.score_sante < 80;
          const statusColor = isCrit ? '#ffb4ab' : isWarn ? '#f97316' : '#78d8ba';
          const statusText = eq.statut_collecte !== 'OK' ? 'Injoignable' : isCrit ? 'Critique' : isWarn ? 'Attention' : 'Normal';
          const days = Math.floor((eq.uptime_secondes || 0) / 86400);
          const hours = Math.floor(((eq.uptime_secondes || 0) % 86400) / 3600);

          const realCpu = typeof eq.cpu_percent === 'number' ? Math.round(eq.cpu_percent) : 0;
          const realRam = typeof eq.ram_percent === 'number' ? Math.round(eq.ram_percent) : 0;
          const realDisk = typeof eq.disk_percent === 'number' ? Math.round(eq.disk_percent) : 0;

          // Calcul de tendance basé sur l'historique réel CPU si disponible
          let tendance: 'up' | 'stable' | 'down' = 'stable';
          if (Array.isArray(eq.cpu_history) && eq.cpu_history.length >= 2) {
            const diff = eq.cpu_history[eq.cpu_history.length - 1] - eq.cpu_history[0];
            if (diff > 3) tendance = 'up';
            else if (diff < -3) tendance = 'down';
          }

          return {
            id: `eq-${eq.id || i}`,
            dbId: eq.id,
            nom: eq.nom,
            type: eq.type,
            ip: eq.ip,
            statusColor,
            statusText,
            tendance,
            cpu: realCpu,
            ram: realRam,
            disk: realDisk,
            uptime: `${days}j ${String(hours).padStart(2, '0')}h`,
          };
        });
        setCriticalEquipmentsList(mappedRows);
      }
    } catch {
      // Conservation de l'état courant en cas d'erreur réseau transitoire
    }
  }, []);

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 15000);
    return () => clearInterval(interval);
  }, [loadDashboardData]);

  const handlePeriodToggle = async () => {
    const options = ['TEMPS RÉEL & PRÉDICTION', '24 HEURES', '7 DERNIERS JOURS'];
    const next = (options.indexOf(period) + 1) % options.length;
    setPeriod(options[next]);
    showToast(`Synchronisation télémétrique (${options[next]})...`);
    await dashboardService.refreshSummary().catch(() => {});
    await loadDashboardData();
  };

  const handleScanGlobal = async () => {
    showToast('Sondage actif (ICMP/TCP/SSH) et scan réseau physique en cours...');
    setShowActionDrawer(false);
    try {
      const [scanRes, probeRes] = await Promise.all([
        parcService.scanRealNetwork(),
        supervisionService.probeAll(),
      ]);
      await loadDashboardData();
      showToast(
        `Scan terminé : ${scanRes?.devices_count ?? 0} hôtes LAN détectés, ${probeRes?.online ?? 0}/${probeRes?.total ?? 0} équipements en ligne.`
      );
    } catch {
      showToast('Erreur lors du scan réseau.');
    }
  };

  const handleRecalculatePredictions = async () => {
    showToast('Collecte live et recalcul des Time-To-Failure (régression linéaire)...');
    setShowActionDrawer(false);
    try {
      await dashboardService.refreshSummary();
      await parcService.recalculateScores();
      const preds = await supervisionService.getPredictions();
      await loadDashboardData();
      showToast(`Prédictions actualisées : ${preds?.length ?? 0} séries temporelles recalculées.`);
    } catch {
      showToast('Erreur lors du recalcul des prédictions.');
    }
  };

  const handleExportSynthesis = async () => {
    showToast('Génération et téléchargement de l\'inventaire CSV...');
    setShowActionDrawer(false);
    try {
      await parcService.exportCsv();
      showToast('Fichier inventaire_parc_sentinelle.csv téléchargé avec succès !');
    } catch {
      showToast('Erreur lors de l\'export CSV.');
    }
  };

  const handleAcknowledgeAlert = async (e: React.MouseEvent, alertId: number) => {
    e.stopPropagation();
    try {
      await supervisionService.acknowledgeAlert(alertId);
      showToast(`Alerte #${alertId} acquittée.`);
      await loadDashboardData();
    } catch {
      showToast(`Impossible d'acquitter l'alerte #${alertId}.`);
    }
  };

  const handleResolveAlert = async (e: React.MouseEvent, alertId: number) => {
    e.stopPropagation();
    try {
      await supervisionService.resolveAlert(alertId);
      showToast(`Alerte #${alertId} résolue et archivée.`);
      await loadDashboardData();
    } catch {
      showToast(`Impossible de résoudre l'alerte #${alertId}.`);
    }
  };

  return (
    <div className="p-6 lg:p-8 space-y-6 bg-[#101416] min-h-screen text-[#e0e3e6] font-sans">
      {/* ── Toast de feedback dynamique ───────────────────────────────────── */}
      {toastMsg && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#1d2022] border border-[#78d8ba] text-[#78d8ba] px-4 py-2.5 rounded-lg shadow-xl font-mono text-xs flex items-center gap-2">
          <Icon name="check_circle" size="sm" className="text-[#78d8ba]" />
          {toastMsg}
        </div>
      )}

      {/* ── En-tête de page (Dashboard Opérationnel) ────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#e0e3e6]">
            Dashboard Opérationnel
          </h1>
          <p className="text-sm text-[#87938e] mt-0.5">
            Vue d'ensemble temps réel de l'infrastructure AIOps
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            id="dashboard-period-btn"
            onClick={handlePeriodToggle}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-[#3e4945] bg-[#1d2022] text-xs font-mono text-[#e0e3e6] hover:bg-[#272a2d] transition-colors"
          >
            <Icon name="sync" size="xs" className="text-[#78d8ba]" />
            {period}
          </button>
          <button
            id="dashboard-action-btn"
            onClick={() => setShowActionDrawer(true)}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#78d8ba] hover:bg-[#68c8aa] text-[#00382b] font-mono font-bold text-xs transition-colors shadow-sm"
          >
            <Icon name="add" size="sm" />
            ACTION
          </button>
        </div>
      </div>

      {/* ── 5 Cartes KPI (Stitch Reference) ─────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Card 1 : Appareils surveillés */}
        <div
          onClick={() => onNavigateTab?.('parc')}
          className="bg-[#1d2022] border border-[#3e4945]/60 hover:border-[#78d8ba]/40 rounded-xl p-4 cursor-pointer transition-colors flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase">
            APPAREILS SURVEILLÉS
          </span>
          <div className="text-3xl font-bold font-mono text-[#e0e3e6] mt-2">
            {monitoredCount.toLocaleString('fr-FR')}
          </div>
          <div className="text-xs font-mono text-[#78d8ba] mt-2 flex items-center gap-1">
            <Icon name="sensors" size="xs" /> Sondes actives
          </div>
        </div>

        {/* Card 2 : Alertes critiques (liseré rouge distinctif) */}
        <div
          onClick={() => onNavigateTab?.('supervision')}
          className="bg-[#1d2022] border border-[#ef4444]/60 hover:border-[#ef4444] rounded-xl p-4 cursor-pointer transition-colors flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono tracking-widest text-[#ef4444] uppercase flex items-center gap-1.5 font-semibold">
            <Icon name="warning" size="xs" className="text-[#ef4444]" />
            ALERTES CRITIQUES
          </span>
          <div className="text-3xl font-bold font-mono text-[#ffb4ab] mt-2">
            {criticalAlertsCount}
          </div>
          <div className="text-xs font-mono text-[#bdc9c3] mt-2">
            {criticalAlertsCount > 0 ? 'Action requise' : 'Nominal'}
          </div>
        </div>

        {/* Card 3 : Score de santé (avec sparkline verte) */}
        <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase">
            SCORE DE SANTÉ
          </span>
          <div className="flex items-center justify-between mt-2">
            <div className="text-3xl font-bold font-mono text-[#78d8ba]">
              {avgHealth}%
            </div>
            <svg className="w-16 h-8 text-[#78d8ba]" viewBox="0 0 60 25" fill="none">
              <path
                d="M 2 20 Q 15 5, 25 18 T 45 10 T 58 8"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
              />
            </svg>
          </div>
          <div className="text-xs font-mono text-[#87938e] mt-2">
            Global infrastructure
          </div>
        </div>

        {/* Card 4 : Incidents prédits */}
        <div
          onClick={() => onNavigateTab?.('supervision')}
          className="bg-[#1d2022] border border-[#3e4945]/60 hover:border-[#81d0f8]/40 rounded-xl p-4 cursor-pointer transition-colors flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase">
            INCIDENTS PRÉDITS
          </span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-bold font-mono text-[#81d0f8]">{predictedIncidents}</span>
            <span className="text-xs font-mono text-[#87938e]">Prochains 7j</span>
          </div>
          <div className="text-xs font-mono text-[#81d0f8] mt-2">
            Modèle régression IA
          </div>
        </div>

        {/* Card 5 : Conformité réseau */}
        <div
          onClick={() => onNavigateTab?.('netdevops')}
          className="bg-[#1d2022] border border-[#3e4945]/60 hover:border-[#78d8ba]/40 rounded-xl p-4 cursor-pointer transition-colors flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono tracking-widest text-[#87938e] uppercase">
            CONFORMITÉ RÉSEAU
          </span>
          <div className="text-3xl font-bold font-mono text-[#e0e3e6] mt-2">
            {cisCompliance !== null ? `${cisCompliance}%` : '—'}
          </div>
          <div className="text-xs font-mono text-[#78d8ba] mt-2 flex items-center gap-1">
            <Icon name="check_circle" size="xs" /> {cisCompliance !== null ? 'Benchmark CIS' : 'Non audité'}
          </div>
        </div>
      </div>

      {/* ── Disposition 2 Colonnes (Graphe + Tableau / Alertes + Donut) ───────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ── Colonne Gauche (8 cols) : Télémétrie & Équipements critiques ─────── */}
        <div className="lg:col-span-8 space-y-6">
          {/* Bloc Graphique Tendances Ressources & Prédictions IA */}
          <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xs font-mono font-semibold tracking-wider text-[#e0e3e6] uppercase">
                TENDANCES RESSOURCES RÉELLES &amp; PRÉDICTIONS IA
              </h2>
              <div className="flex items-center gap-4 text-xs font-mono">
                <span className="flex items-center gap-1.5 text-[#bdc9c3]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#78d8ba]" /> CPU
                </span>
                <span className="flex items-center gap-1.5 text-[#bdc9c3]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#81d0f8]" /> RAM
                </span>
                <span className="flex items-center gap-1.5 text-[#bdc9c3]">
                  <span className="w-4 h-0.5 border-b-2 border-dashed border-[#78d8ba]" /> Prédictions IA
                </span>
              </div>
            </div>

            <div className="h-64 w-full">
              {telemetryData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={telemetryData} margin={{ top: 10, right: 15, left: -20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#272a2d" vertical={false} />
                    <XAxis
                      dataKey="day"
                      stroke="#87938e"
                      fontSize={11}
                      tickLine={false}
                      axisLine={{ stroke: '#272a2d' }}
                      tick={({ x, y, payload }) => (
                        <text
                          x={x}
                          y={Number(y) + 12}
                          textAnchor="middle"
                          fill={String(payload.value).includes('Préd') ? '#81d0f8' : '#87938e'}
                          fontSize={10}
                          fontFamily="JetBrains Mono"
                        >
                          {payload.value}
                        </text>
                      )}
                    />
                    <YAxis
                      stroke="#87938e"
                      fontSize={11}
                      tickLine={false}
                      axisLine={{ stroke: '#272a2d' }}
                      tickFormatter={v => `${v}%`}
                      domain={[0, 100]}
                      ticks={[0, 25, 50, 75, 100]}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#161c22',
                        borderColor: '#3e4945',
                        borderRadius: '8px',
                        fontSize: '12px',
                        color: '#e0e3e6',
                        fontFamily: 'JetBrains Mono',
                      }}
                    />
                    {/* Courbe CPU Réel */}
                    <Line
                      type="monotone"
                      dataKey="cpu"
                      name="CPU Réel (%)"
                      stroke="#78d8ba"
                      strokeWidth={2.5}
                      dot={{ r: 3, fill: '#78d8ba' }}
                      connectNulls={false}
                    />
                    {/* Courbe RAM Réelle */}
                    <Line
                      type="monotone"
                      dataKey="ram"
                      name="RAM Réelle (%)"
                      stroke="#81d0f8"
                      strokeWidth={2}
                      dot={{ r: 3, fill: '#81d0f8' }}
                      connectNulls={false}
                    />
                    {/* Courbe Prédiction IA pointillée */}
                    <Line
                      type="monotone"
                      dataKey="pred"
                      name="Projection IA (%)"
                      stroke="#78d8ba"
                      strokeWidth={2}
                      strokeDasharray="4 4"
                      dot={{ r: 3, fill: '#78d8ba' }}
                      connectNulls
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full w-full flex flex-col items-center justify-center text-center p-6 border border-dashed border-[#272a2d] rounded-lg bg-[#14181a]/50">
                  <Icon name="monitoring" size="lg" className="text-[#87938e] mb-2 opacity-40" />
                  <p className="text-sm text-[#e0e3e6] font-medium font-mono">Aucune métrique télémétrique disponible</p>
                  <p className="text-xs text-[#87938e] mt-1 max-w-sm">
                    Les métriques réelles de la machine hôte et du parc apparaîtront dès les premiers cycles de collecte.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Bloc Statut des Équipements (Tableau interactif avec vraies métriques) */}
          <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xs font-mono font-semibold tracking-wider text-[#e0e3e6] uppercase">
                STATUT DES ÉQUIPEMENTS SUPERVISÉS
              </h2>
              <button
                onClick={() => onNavigateTab?.('parc')}
                className="text-xs font-mono text-[#78d8ba] hover:underline"
              >
                Voir tout le parc &rsaquo;
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-[#272a2d] text-[10px] font-mono text-[#87938e] uppercase tracking-wider">
                    <th className="pb-3 pl-2">STATUT</th>
                    <th className="pb-3">ÉQUIPEMENT</th>
                    <th className="pb-3">TYPE</th>
                    <th className="pb-3">IP</th>
                    <th className="pb-3">CPU / RAM / DISQUE</th>
                    <th className="pb-3 text-right pr-2">TENDANCE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#272a2d]/50 text-xs font-mono">
                  {criticalEquipmentsList.length > 0 ? (
                    criticalEquipmentsList.map(eq => (
                      <tr
                        key={eq.id}
                        onClick={() => setSelectedEquipment(eq)}
                        className="hover:bg-[#272a2d]/50 cursor-pointer transition-colors group"
                      >
                        <td className="py-3.5 pl-2">
                          <span
                            className="w-2.5 h-2.5 rounded-full inline-block"
                            style={{ backgroundColor: eq.statusColor }}
                            title={eq.statusText}
                          />
                        </td>
                        <td className="py-3.5 font-bold text-[#e0e3e6] group-hover:text-[#78d8ba] transition-colors">
                          {eq.nom}
                        </td>
                        <td className="py-3.5 text-[#bdc9c3]">{eq.type}</td>
                        <td className="py-3.5 text-[#87938e]">{eq.ip}</td>
                        <td className="py-3.5 text-[#bdc9c3]">
                          <span className={eq.cpu > 80 ? 'text-[#ffb4ab] font-bold' : 'text-[#78d8ba]'}>{eq.cpu}%</span>
                          {' / '}
                          <span className="text-[#81d0f8]">{eq.ram}%</span>
                          {' / '}
                          <span className={eq.disk > 85 ? 'text-[#ffb4ab] font-bold' : 'text-[#bdc9c3]'}>{eq.disk}%</span>
                        </td>
                        <td className="py-3.5 text-right pr-2">
                          {eq.tendance === 'up' ? (
                            <span className="text-[#ffb4ab] inline-flex items-center gap-1 font-bold">
                              &uarr; Hausse
                            </span>
                          ) : eq.tendance === 'down' ? (
                            <span className="text-[#78d8ba] inline-flex items-center gap-1">
                              &darr; Baisse
                            </span>
                          ) : (
                            <span className="text-[#87938e]">~ Stable</span>
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-[#87938e] text-xs">
                        Aucun équipement supervisé pour le moment.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* ── Colonne Droite (4 cols) : Flux d'alertes & Donut du Parc ───────── */}
        <div className="lg:col-span-4 space-y-6">
          {/* Bloc Flux d'alertes actives */}
          <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xs font-mono font-semibold tracking-wider text-[#e0e3e6] uppercase">
                  FLUX D'ALERTES ACTIVES
                </h2>
                <span className="text-[10px] font-mono text-[#78d8ba] bg-[#78d8ba]/10 px-2 py-0.5 rounded">
                  {recentAlertsList.length} en cours
                </span>
              </div>

              <div className="space-y-3">
                {recentAlertsList.length > 0 ? (
                  recentAlertsList.slice(0, 4).map((al: any) => {
                    const isCrit = al.severite === 'CRITICAL';
                    const targetTab = al.module_origine === 'Sécurité' ? 'securite' : al.module_origine === 'NetDevOps' ? 'netdevops' : 'supervision';
                    return (
                      <div
                        key={al.id}
                        onClick={() => onNavigateTab?.(targetTab)}
                        className={`bg-[#161c22] border-l-4 ${
                          isCrit ? 'border-l-[#ef4444]' : 'border-l-orange-500'
                        } border border-[#272a2d] rounded-lg p-3.5 cursor-pointer hover:border-[#3e4945] transition-all`}
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <span className={`${
                            isCrit ? 'bg-[#ffb4ab]/15 text-[#ffb4ab]' : 'bg-orange-500/15 text-orange-400'
                          } px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider`}>
                            {al.severite} • {al.statut}
                          </span>
                          <span className="text-[10px] font-mono text-[#87938e]">
                            {al.equipement_nom || 'Système'}
                          </span>
                        </div>
                        <h3 className="text-xs font-semibold text-[#e0e3e6]">
                          {al.titre}
                        </h3>
                        <p className="text-[11px] text-[#87938e] mt-1 line-clamp-2">
                          {al.message}
                        </p>
                        <div className="mt-2.5 flex items-center justify-between gap-2">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#1d2022] border border-[#272a2d] text-[10px] font-mono text-[#bdc9c3]">
                            <Icon name="monitoring" size="xs" className="text-[#78d8ba]" /> {al.module_origine}
                          </span>
                          <div className="flex items-center gap-1.5">
                            {al.statut === 'Active' && (
                              <button
                                onClick={(e) => handleAcknowledgeAlert(e, al.id)}
                                className="px-2 py-0.5 rounded bg-[#272a2d] hover:bg-[#3e4945] text-[10px] font-mono text-[#81d0f8] transition-colors"
                                title="Acquitter l'alerte"
                              >
                                Acquitter
                              </button>
                            )}
                            <button
                              onClick={(e) => handleResolveAlert(e, al.id)}
                              className="px-2 py-0.5 rounded bg-[#78d8ba]/15 hover:bg-[#78d8ba]/30 text-[10px] font-mono text-[#78d8ba] transition-colors"
                              title="Marquer comme résolue"
                            >
                              Résoudre
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <div className="bg-[#161c22] border border-[#272a2d] rounded-lg p-5 text-center flex flex-col items-center justify-center">
                    <Icon name="verified_user" size={32} className="text-[#78d8ba] mb-2" />
                    <span className="text-xs font-mono font-semibold text-[#e0e3e6]">
                      Aucune alerte active
                    </span>
                    <span className="text-[11px] font-mono text-[#87938e] mt-1">
                      Tous les équipements opèrent en conditions nominales.
                    </span>
                  </div>
                )}
              </div>
            </div>

            <div className="pt-4 text-center border-t border-[#272a2d] mt-4">
              <button
                id="dashboard-all-alerts-btn"
                onClick={() => onNavigateTab?.('supervision')}
                className="text-xs font-mono font-bold text-[#78d8ba] hover:underline uppercase tracking-wider"
              >
                VOIR TOUTES LES ALERTES
              </button>
            </div>
          </div>

          {/* Bloc Répartition du Parc (Donut circulaire) */}
          <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5">
            <h2 className="text-xs font-mono font-semibold tracking-wider text-[#e0e3e6] uppercase mb-2">
              RÉPARTITION DU PARC
            </h2>

            <div className="h-48 relative flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={donutData}
                    dataKey="value"
                    innerRadius={55}
                    outerRadius={75}
                    startAngle={90}
                    endAngle={-270}
                    strokeWidth={0}
                  >
                    {donutData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-2xl font-bold font-mono text-[#e0e3e6]">
                  {monitoredCount}
                </span>
                <span className="text-[10px] font-mono text-[#87938e] uppercase tracking-wider">
                  TOTAL RÉEL
                </span>
              </div>
            </div>

            <div className="space-y-2 mt-2 pt-3 border-t border-[#272a2d] text-xs font-mono">
              {donutData.map(d => (
                <div key={d.name} className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-[#bdc9c3]">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                    {d.name}
                  </span>
                  <span className="font-bold text-[#e0e3e6]">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── TIROIR LATÉRAL : Fiche Équipement ────────────────────────────────── */}
      {selectedEquipment && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div className="flex items-center gap-2">
                  <span
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: selectedEquipment.statusColor }}
                  />
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    {selectedEquipment.nom}
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedEquipment(null)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <Icon name="close" size="md" />
                </button>
              </div>

              <div className="mt-5 space-y-4 font-mono text-xs">
                <div className="p-3 bg-[#1d2022] rounded-lg border border-[#272a2d] space-y-2">
                  <div className="text-[10px] text-[#87938e] uppercase">Identification</div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Adresse IP:</span>
                    <span className="text-[#e0e3e6] font-bold">{selectedEquipment.ip}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Type appareil:</span>
                    <span className="text-[#e0e3e6]">{selectedEquipment.type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Statut sonde:</span>
                    <span className="text-[#78d8ba]">{selectedEquipment.statusText}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Uptime:</span>
                    <span className="text-[#78d8ba]">{selectedEquipment.uptime}</span>
                  </div>
                </div>

                <div className="p-3 bg-[#1d2022] rounded-lg border border-[#272a2d] space-y-2.5">
                  <div className="text-[10px] text-[#87938e] uppercase">Métriques réelles collectées</div>
                  <div>
                    <div className="flex justify-between text-[11px] mb-1">
                      <span className="text-[#87938e]">Utilisation CPU:</span>
                      <span className="font-bold text-[#78d8ba]">{selectedEquipment.cpu}%</span>
                    </div>
                    <div className="w-full bg-[#0b0f11] h-2 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-[#78d8ba]"
                        style={{ width: `${selectedEquipment.cpu}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-[11px] mb-1">
                      <span className="text-[#87938e]">Utilisation RAM:</span>
                      <span className="font-bold text-[#81d0f8]">{selectedEquipment.ram}%</span>
                    </div>
                    <div className="w-full bg-[#0b0f11] h-2 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-[#81d0f8]"
                        style={{ width: `${selectedEquipment.ram}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-[11px] mb-1">
                      <span className="text-[#87938e]">Utilisation Disque:</span>
                      <span className="font-bold text-[#f59e0b]">{selectedEquipment.disk}%</span>
                    </div>
                    <div className="w-full bg-[#0b0f11] h-2 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-[#f59e0b]"
                        style={{ width: `${selectedEquipment.disk}%` }}
                      />
                    </div>
                  </div>
                </div>

                {selectedEquipment.dbId && (
                  <button
                    onClick={async () => {
                      if (!selectedEquipment.dbId) return;
                      showToast(`Sondage actif de ${selectedEquipment.nom} (${selectedEquipment.ip})...`);
                      const updated = await parcService.probeEquipement(selectedEquipment.dbId);
                      setSelectedEquipment({
                        ...selectedEquipment,
                        cpu: Math.round(updated.cpu_percent ?? selectedEquipment.cpu),
                        ram: Math.round(updated.ram_percent ?? selectedEquipment.ram),
                        disk: Math.round(updated.disk_percent ?? selectedEquipment.disk),
                        statusText: updated.statut_collecte === 'OK' ? 'Normal' : 'Injoignable',
                      });
                      await loadDashboardData();
                      showToast(`Sonde ${selectedEquipment.nom} actualisée (${updated.statut_collecte}).`);
                    }}
                    className="w-full py-2 rounded-lg bg-[#1d2022] hover:bg-[#272a2d] border border-[#78d8ba]/40 text-[#78d8ba] font-mono text-xs flex items-center justify-center gap-2 transition-colors"
                  >
                    <Icon name="radar" size="sm" />
                    Sonder cet équipement maintenant (ICMP / TCP / SSH)
                  </button>
                )}
              </div>
            </div>

            <div className="pt-6 border-t border-[#272a2d] flex gap-2">
              <button
                onClick={() => {
                  setSelectedEquipment(null);
                  onNavigateTab?.('parc');
                }}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg bg-[#78d8ba] text-[#00382b] font-mono font-bold text-xs hover:bg-[#68c8aa] transition-colors"
              >
                <Icon name="terminal" size="sm" />
                Ouvrir dans Parc &amp; SSH
              </button>
              <button
                onClick={() => setSelectedEquipment(null)}
                className="px-4 py-2.5 rounded-lg border border-[#3e4945] text-xs font-mono text-[#e0e3e6] hover:bg-[#272a2d] transition-colors"
              >
                Fermer
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── TIROIR LATÉRAL : Actions rapides ─────────────────────────────────── */}
      {showActionDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                  Opérations Rapides AIOps
                </h3>
                <button
                  onClick={() => setShowActionDrawer(false)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <Icon name="close" size="md" />
                </button>
              </div>

              <div className="mt-5 space-y-3 font-mono text-xs">
                <button
                  id="dashboard-action-scan-btn"
                  onClick={handleScanGlobal}
                  className="w-full p-4 rounded-xl bg-[#1d2022] hover:bg-[#272a2d] border border-[#3e4945] text-left transition-colors flex items-center justify-between group cursor-pointer"
                >
                  <div>
                    <div className="font-bold text-[#e0e3e6] group-hover:text-[#78d8ba]">
                      Lancer Scan Réel &amp; Sondage Global
                    </div>
                    <div className="text-[11px] text-[#87938e] mt-1">
                      Découverte ARP/ICMP/TCP et sondage de tous les nœuds
                    </div>
                  </div>
                  <Icon name="open_in_new" size="sm" className="text-[#87938e] group-hover:text-[#78d8ba]" />
                </button>

                <button
                  id="dashboard-action-predictions-btn"
                  onClick={handleRecalculatePredictions}
                  className="w-full p-4 rounded-xl bg-[#1d2022] hover:bg-[#272a2d] border border-[#3e4945] text-left transition-colors flex items-center justify-between group cursor-pointer"
                >
                  <div>
                    <div className="font-bold text-[#e0e3e6] group-hover:text-[#78d8ba]">
                      Recalculer Prédictions IA (TTF)
                    </div>
                    <div className="text-[11px] text-[#87938e] mt-1">
                      Collecte matérielle live et régression linéaire
                    </div>
                  </div>
                  <Icon name="open_in_new" size="sm" className="text-[#87938e] group-hover:text-[#78d8ba]" />
                </button>

                <button
                  id="dashboard-action-export-btn"
                  onClick={handleExportSynthesis}
                  className="w-full p-4 rounded-xl bg-[#1d2022] hover:bg-[#272a2d] border border-[#3e4945] text-left transition-colors flex items-center justify-between group cursor-pointer"
                >
                  <div>
                    <div className="font-bold text-[#e0e3e6] group-hover:text-[#78d8ba]">
                      Exporter Synthèse CSV / Inventaire
                    </div>
                    <div className="text-[11px] text-[#87938e] mt-1">
                      Téléchargement immédiat du parc horodaté
                    </div>
                  </div>
                  <Icon name="open_in_new" size="sm" className="text-[#87938e] group-hover:text-[#78d8ba]" />
                </button>
              </div>
            </div>

            <div className="pt-6 border-t border-[#272a2d]">
              <button
                onClick={() => setShowActionDrawer(false)}
                className="w-full py-2.5 rounded-lg border border-[#3e4945] text-xs font-mono text-[#e0e3e6] hover:bg-[#272a2d] transition-colors"
              >
                Fermer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
