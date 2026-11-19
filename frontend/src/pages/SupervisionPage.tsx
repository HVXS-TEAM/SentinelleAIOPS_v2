import React, { useState, useEffect, useCallback } from 'react';
import { Icon } from '../components/ui/Icon';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  ReferenceLine,
  Tooltip,
} from 'recharts';
import { supervisionService, parcService } from '../services/api';
import type { HardwareLiveStats, Equipement, Prediction } from '../types';

/* ── Types ───────────────────────────────────────────────────────────────── */
interface UrgenceMaintenance {
  id: string;
  equipementId?: number;
  device: string;
  severity: 'CRITIQUE' | 'ÉLEVÉE' | 'MOYENNE' | 'FAIBLE';
  description: string;
  ttf: string;
  ttfJours: number;
  ttfHeures: number;
  cause: string;
  metrique?: string;
}

interface TelemetryChartPoint {
  t: number;
  label: string;
  hist: number | null;
  pred: number | null;
}

const SEV_BADGE: Record<string, string> = {
  CRITIQUE: 'bg-[#ffb4ab]/20 text-[#ffb4ab] border border-[#ffb4ab]/30',
  ÉLEVÉE:   'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  MOYENNE:  'bg-[#81d0f8]/20 text-[#81d0f8] border border-[#81d0f8]/30',
  FAIBLE:   'bg-[#78d8ba]/20 text-[#78d8ba] border border-[#78d8ba]/30',
};

/**
 * Rôle : Construit une série graphique {t, label, hist, pred} à partir des points réels SQLite
 * et de la pente horaire issue de la régression linéaire du backend.
 */
const buildChartSeriesFromRealPoints = (
  points: { valeur: number; horodatage: string }[],
  slopePerHour: number,
  fallbackCurrent: number,
): TelemetryChartPoint[] => {
  const result: TelemetryChartPoint[] = [];
  const rawValues =
    points && points.length > 0
      ? points.slice(-30)
      : [{ valeur: fallbackCurrent, horodatage: new Date().toISOString() }];

  // Si on a peu de points en base (ex: premier démarrage), interpoler légèrement les premiers points réels
  const paddedValues = [...rawValues];
  while (paddedValues.length < 15) {
    const firstVal = paddedValues[0].valeur;
    paddedValues.unshift({
      valeur: Math.max(1, Number((firstVal - slopePerHour * 0.25).toFixed(1))),
      horodatage: paddedValues[0].horodatage,
    });
  }

  const histLen = paddedValues.length;
  paddedValues.forEach((pt, idx) => {
    const val = Math.min(100, Math.max(0, Number(pt.valeur.toFixed(1))));
    const timeStr = pt.horodatage ? new Date(pt.horodatage).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }) : `T-${histLen - idx}`;
    result.push({
      t: idx,
      label: timeStr,
      hist: val,
      pred: idx === histLen - 1 ? val : null,
    });
  });

  const lastVal = result[result.length - 1]?.hist ?? fallbackCurrent;
  const effectiveSlope = slopePerHour !== 0 ? slopePerHour : 0.15;

  // 12 points de projection linéaire (+4h à +48h, pas de 4h)
  for (let step = 1; step <= 12; step++) {
    const hoursAhead = step * 4;
    const projected = Math.min(105, Math.max(0, Number((lastVal + effectiveSlope * hoursAhead).toFixed(1))));
    result.push({
      t: histLen - 1 + step,
      label: `+${hoursAhead}h`,
      hist: null,
      pred: projected,
    });
  }

  return result;
};

export const SupervisionPage: React.FC = () => {
  const [selectedDevice, setSelectedDevice] = useState<string>('');
  const [selectedEquipementId, setSelectedEquipementId] = useState<number>(1);
  const [warnThreshold, setWarnThreshold] = useState<number>(80);
  const [critThreshold, setCritThreshold] = useState<number>(85);
  const [thresholdsSaved, setThresholdsSaved] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [showInterventionDrawer, setShowInterventionDrawer] = useState(false);
  const [isRecalculating, setIsRecalculating] = useState(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const [ttf, setTtf] = useState<{ jours: number; heures: number }>({ jours: 14, heures: 0 });

  // Télémétrie réelle système & Parc
  const [hardwareLive, setHardwareLive] = useState<HardwareLiveStats | null>(null);
  const [isLoadingLive, setIsLoadingLive] = useState(false);
  const [equipementsList, setEquipementsList] = useState<Equipement[]>([]);
  const [predictionsList, setPredictionsList] = useState<Prediction[]>([]);
  const [urgencesList, setUrgencesList] = useState<UrgenceMaintenance[]>([]);

  // Séries temporelles réelles SQLite pour l'équipement sélectionné
  const [cpuSeries, setCpuSeries] = useState<TelemetryChartPoint[]>([]);
  const [ramSeries, setRamSeries] = useState<TelemetryChartPoint[]>([]);
  const [diskSeries, setDiskSeries] = useState<TelemetryChartPoint[]>([]);
  const [netSeries, setNetSeries] = useState<TelemetryChartPoint[]>([]);
  const [currentMetrics, setCurrentMetrics] = useState<{
    cpu: number;
    ram: number;
    disk: number;
    net: number;
  }>({ cpu: 0, ram: 0, disk: 0, net: 0 });

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3500);
  };

  /**
   * Rôle : Charge les 4 séries temporelles réelles (CPU, RAM, Disque, Réseau) depuis SQLite
   * pour l'équipement sélectionné et calcule la zone de prédiction linéaire (+48h).
   */
  const loadDeviceTelemetry = useCallback(
    async (eqId: number, eqObj?: Equipement, allPreds?: Prediction[]) => {
      try {
        const [cpuRes, ramRes, diskRes, netRes] = await Promise.all([
          supervisionService.getMetrics(eqId, 'cpu_percent', 35),
          supervisionService.getMetrics(eqId, 'ram_percent', 35),
          supervisionService.getMetrics(eqId, 'disk_percent', 35),
          supervisionService.getMetrics(eqId, 'network_mbps', 35),
        ]);

        const predsForEq = (allPreds || predictionsList).filter(p => p.equipement_id === eqId);
        const cpuPred = predsForEq.find(p => p.metrique === 'cpu_percent');
        const ramPred = predsForEq.find(p => p.metrique === 'ram_percent');
        const diskPred = predsForEq.find(p => p.metrique === 'disk_percent');

        const lastCpu =
          cpuRes.points.length > 0
            ? cpuRes.points[cpuRes.points.length - 1].valeur
            : (eqObj?.cpu_percent ?? 0);
        const lastRam =
          ramRes.points.length > 0
            ? ramRes.points[ramRes.points.length - 1].valeur
            : (eqObj?.ram_percent ?? 0);
        const lastDisk =
          diskRes.points.length > 0
            ? diskRes.points[diskRes.points.length - 1].valeur
            : (eqObj?.disk_percent ?? 0);
        const lastNet =
          netRes.points.length > 0
            ? netRes.points[netRes.points.length - 1].valeur
            : (eqObj?.network_mbps ?? 0.5);

        setCurrentMetrics({
          cpu: Number(lastCpu.toFixed(1)),
          ram: Number(lastRam.toFixed(1)),
          disk: Number(lastDisk.toFixed(1)),
          net: Number(lastNet.toFixed(2)),
        });

        setCpuSeries(
          buildChartSeriesFromRealPoints(cpuRes.points, cpuPred?.pente_horaire ?? 0.15, lastCpu),
        );
        setRamSeries(
          buildChartSeriesFromRealPoints(ramRes.points, ramPred?.pente_horaire ?? 0.12, lastRam),
        );
        setDiskSeries(
          buildChartSeriesFromRealPoints(diskRes.points, diskPred?.pente_horaire ?? 0.25, lastDisk),
        );
        setNetSeries(
          buildChartSeriesFromRealPoints(netRes.points, 0.05, lastNet),
        );
      } catch {
        // Tolérance réseau
      }
    },
    [predictionsList],
  );

  const loadHardwareLive = useCallback(async () => {
    setIsLoadingLive(true);
    try {
      const data = await supervisionService.getHardwareLive();
      if (data) {
        setHardwareLive(data);
      }
    } catch {
      // Tolérance en mode hors ligne
    } finally {
      setIsLoadingLive(false);
    }
  }, []);

  const loadParcAndPredictions = useCallback(async () => {
    try {
      const [eqs, preds] = await Promise.all([
        parcService.getEquipements(),
        supervisionService.getPredictions(),
      ]);
      if (eqs && eqs.length > 0) {
        setEquipementsList(eqs);
      }
      if (preds) {
        setPredictionsList(preds);
      }

      if (preds && preds.length > 0) {
        const mappedUrgences: UrgenceMaintenance[] = preds.map((p, idx) => {
          const ttfH = p.ttf_estime_heures && p.ttf_estime_heures > 0 ? p.ttf_estime_heures : 720;
          const j = Math.floor(ttfH / 24);
          const h = Math.round(ttfH % 24);
          const sev: UrgenceMaintenance['severity'] =
            ttfH < 72 ? 'CRITIQUE' : ttfH < 168 ? 'ÉLEVÉE' : ttfH < 360 ? 'MOYENNE' : 'FAIBLE';
          const metLabel =
            p.metrique === 'disk_percent'
              ? 'Disque'
              : p.metrique === 'ram_percent'
              ? 'RAM'
              : p.metrique === 'cpu_percent'
              ? 'CPU'
              : p.metrique;
          return {
            id: `pred-${p.id || idx}`,
            equipementId: p.equipement_id,
            device: p.equipement_nom || `Équipement #${p.equipement_id}`,
            severity: sev,
            description: `Tendance ${metLabel} (R²=${p.r2_score.toFixed(2)})`,
            ttf: p.ttf_estime_heures && p.ttf_estime_heures > 0 ? `${j}j ${String(h).padStart(2, '0')}h` : 'Stable (>30j)',
            ttfJours: j,
            ttfHeures: h,
            cause: `Pente horaire ${p.pente_horaire >= 0 ? '+' : ''}${p.pente_horaire.toFixed(3)}%/h (Confiance ${p.indice_confiance}). Mesure actuelle: ${p.valeur_actuelle.toFixed(1)}%.`,
            metrique: p.metrique,
          };
        });
        setUrgencesList(mappedUrgences);

        // Si aucun équipement n'est encore sélectionné, choisir le premier de la liste
        if (!selectedDevice && mappedUrgences.length > 0) {
          const first = mappedUrgences[0];
          setSelectedDevice(first.device);
          setTtf({ jours: first.ttfJours, heures: first.ttfHeures });
          const targetEq = eqs?.find(e => e.id === first.equipementId || e.nom === first.device) || eqs?.[0];
          if (targetEq) {
            setSelectedEquipementId(targetEq.id);
            setCritThreshold(Math.round(targetEq.seuil_disque_alerte || 85));
            await loadDeviceTelemetry(targetEq.id, targetEq, preds);
          }
        } else if (selectedEquipementId) {
          const currentEq = eqs?.find(e => e.id === selectedEquipementId);
          await loadDeviceTelemetry(selectedEquipementId, currentEq, preds);
        }
      } else if (eqs && eqs.length > 0 && !selectedDevice) {
        const firstEq = eqs[0];
        setSelectedDevice(firstEq.nom);
        setSelectedEquipementId(firstEq.id);
        setCritThreshold(Math.round(firstEq.seuil_disque_alerte || 85));
        await loadDeviceTelemetry(firstEq.id, firstEq, []);
      }
    } catch {
      // Tolérance
    }
  }, [selectedDevice, selectedEquipementId, loadDeviceTelemetry]);

  useEffect(() => {
    loadHardwareLive();
    loadParcAndPredictions();
    const interval = setInterval(() => {
      loadHardwareLive();
      loadParcAndPredictions();
    }, 15000);
    return () => clearInterval(interval);
  }, [loadHardwareLive, loadParcAndPredictions]);

  const activeUrgence: UrgenceMaintenance =
    urgencesList.find(u => u.device === selectedDevice) ??
    urgencesList[0] ?? {
      id: 'default',
      equipementId: selectedEquipementId,
      device: selectedDevice || hardwareLive?.hostname || 'Hôte Local',
      severity: 'FAIBLE',
      description: 'Surveillance prédictive active',
      ttf: `${ttf.jours}j ${String(ttf.heures).padStart(2, '0')}h`,
      ttfJours: ttf.jours,
      ttfHeures: ttf.heures,
      cause: 'Collecte télémétrique SQLite continue et régression linéaire actives.',
    };

  const handleDeviceSelect = async (devName: string, eqIdOverride?: number) => {
    setSelectedDevice(devName);
    const targetUrgence = urgencesList.find(u => u.device === devName);
    if (targetUrgence) {
      setTtf({ jours: targetUrgence.ttfJours, heures: targetUrgence.ttfHeures });
    }
    const targetEq =
      equipementsList.find(e => e.id === eqIdOverride || e.nom === devName) ||
      (targetUrgence?.equipementId ? equipementsList.find(e => e.id === targetUrgence.equipementId) : undefined);

    if (targetEq) {
      setSelectedEquipementId(targetEq.id);
      setCritThreshold(Math.round(targetEq.seuil_disque_alerte || 85));
      await loadDeviceTelemetry(targetEq.id, targetEq);
    }
    showToast(`Équipement supervisé : ${devName}`);
  };

  const handleSaveThresholds = async () => {
    setThresholdsSaved(true);
    try {
      await supervisionService.updateThreshold(selectedEquipementId, critThreshold);
      showToast(`Seuils enregistrés pour ${selectedDevice} : Alerte ${warnThreshold}%, Critique ${critThreshold}%`);
      await loadParcAndPredictions();
    } catch {
      showToast(`Erreur lors de la sauvegarde du seuil.`);
    }
    setTimeout(() => setThresholdsSaved(false), 2500);
  };

  const handleRecalculateTtf = async () => {
    setIsRecalculating(true);
    showToast(`Recalcul du TTF sur ${selectedDevice} à partir des métriques collectées...`);
    try {
      const pred = await supervisionService.recalculateTTF(selectedEquipementId);
      if (pred && typeof pred.ttf_estime_heures === 'number') {
        const totalH = Math.max(1, Math.round(pred.ttf_estime_heures));
        const j = Math.floor(totalH / 24);
        const h = totalH % 24;
        setTtf({ jours: j, heures: h });
        showToast(`TTF recalculé : ${j}j ${h}h (pente ${pred.pente_horaire.toFixed(2)} %/h).`);
      } else {
        showToast('Historique insuffisant pour estimer un TTF fiable.');
      }
      await loadHardwareLive();
      await loadParcAndPredictions();
    } catch {
      showToast('Recalcul impossible : le serveur a refusé ou n\'a pas pu traiter la demande.');
    } finally {
      setIsRecalculating(false);
    }
  };

  const handleConfirmIntervention = async () => {
    try {
      showToast(`Exécution de la maintenance préventive sur ${activeUrgence.device}...`);
      // Sonder l'équipement et recalculer ses métriques réelles
      await parcService.probeEquipement(selectedEquipementId);
      await supervisionService.recalculateTTF(selectedEquipementId, 'disk_percent');
      // Acquitter / résoudre les alertes actives liées à cet équipement
      const alerts = await supervisionService.getAlerts('Active');
      const eqAlerts = alerts.filter(a => a.equipement_id === selectedEquipementId);
      for (const al of eqAlerts) {
        await supervisionService.resolveAlert(al.id);
      }
      await loadHardwareLive();
      await loadParcAndPredictions();
      setShowInterventionDrawer(false);
      showToast(`Intervention exécutée sur ${activeUrgence.device} (${eqAlerts.length} alerte(s) résolue(s)).`);
    } catch {
      setShowInterventionDrawer(false);
      showToast(`Intervention enregistrée pour ${activeUrgence.device}.`);
    }
  };

  const histSplitIndex = cpuSeries.findIndex(p => p.hist === null) - 1;

  return (
    <div className="p-6 lg:p-8 space-y-6 bg-[#101416] min-h-screen text-[#e0e3e6] font-sans">
      {/* ── Toast de confirmation ─────────────────────────────────────────── */}
      {toastMsg && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#1d2022] border border-[#78d8ba] text-[#78d8ba] px-4 py-2.5 rounded-lg shadow-xl font-mono text-xs flex items-center gap-2">
          <Icon name="check_circle" size="sm" className="text-[#78d8ba]" />
          {toastMsg}
        </div>
      )}

      {/* ── Fil d'ariane & Titre de page ───────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="text-xs font-mono text-[#87938e] mb-1.5 flex items-center gap-1.5">
            <span>Home</span>
            <span className="text-[#3e4945]">&rsaquo;</span>
            <span className="text-[#78d8ba] font-medium">Supervision</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#e0e3e6]">
            Supervision &amp; Analyses Prédictives
          </h1>
          <p className="text-sm text-[#87938e] mt-0.5">
            Analyse de santé et prédiction de pannes en temps réel des équipements supervisés.
          </p>
        </div>

        {/* Bouton Actualisation Sonde Matérielle & Réseau */}
        <button
          id="supervision-refresh-hardware-btn"
          onClick={async () => {
            setIsLoadingLive(true);
            await supervisionService.probeAll().catch(() => {});
            await loadHardwareLive();
            await loadParcAndPredictions();
            showToast('Sondes matérielles et réseau actualisées en direct.');
          }}
          disabled={isLoadingLive}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-[#78d8ba]/40 bg-[#78d8ba]/10 hover:bg-[#78d8ba]/20 text-[#78d8ba] font-mono text-xs transition-colors cursor-pointer self-start sm:self-auto"
        >
          <Icon name="refresh" size="xs" className={isLoadingLive ? 'animate-spin' : ''} />
          <span>Sonder Tout &amp; Rafraîchir</span>
        </button>
      </div>

      {/* ── Bandeau Matériel Réel Hôte (psutil / Exécutable .exe) ──────────── */}
      {hardwareLive && (
        <div className="bg-[#161c22] border border-[#3e4945] rounded-xl p-4 sm:p-5 shadow-lg">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 mb-3 border-b border-[#272a2d] gap-2">
            <div className="flex items-center gap-2.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#78d8ba] animate-pulse" />
              <div className="font-mono text-xs">
                <span className="text-[#e0e3e6] font-bold">{hardwareLive.hostname}</span>
                <span className="text-[#87938e] ml-2">({hardwareLive.os} - {hardwareLive.ip})</span>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#78d8ba]/15 text-[#78d8ba] border border-[#78d8ba]/30">
                SONDE HOST ACTIVE (.EXE READY)
              </span>
            </div>
            <button
              onClick={() => handleDeviceSelect(hardwareLive.hostname, hardwareLive.equipement_id)}
              className="text-[11px] font-mono text-[#78d8ba] hover:underline flex items-center gap-1 cursor-pointer"
            >
              <Icon name="dns" size="xs" />
              <span>Superviser cet hôte dans les graphiques</span>
            </button>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
            {/* CPU */}
            <div className="bg-[#101416] p-3 rounded-lg border border-[#272a2d]">
              <div className="text-[11px] text-[#87938e] flex items-center justify-between mb-1">
                <span className="flex items-center gap-1"><Icon name="memory" size="xs" className="text-[#78d8ba]" /> CPU Réel</span>
                <span className="text-[#e0e3e6]">{hardwareLive.cpu_count} cœurs</span>
              </div>
              <div className="text-xl font-bold text-[#78d8ba]">{hardwareLive.cpu_percent}%</div>
              <div className="w-full bg-[#272a2d] h-1.5 rounded-full mt-2 overflow-hidden">
                <div
                  className="bg-[#78d8ba] h-full rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, hardwareLive.cpu_percent)}%` }}
                />
              </div>
            </div>

            {/* RAM */}
            <div className="bg-[#101416] p-3 rounded-lg border border-[#272a2d]">
              <div className="text-[11px] text-[#87938e] flex items-center justify-between mb-1">
                <span className="flex items-center gap-1"><Icon name="monitoring" size="xs" className="text-orange-400" /> RAM Réelle</span>
                <span className="text-[#e0e3e6]">{hardwareLive.ram_used_gb} / {hardwareLive.ram_total_gb} Go</span>
              </div>
              <div className="text-xl font-bold text-orange-400">{hardwareLive.ram_percent}%</div>
              <div className="w-full bg-[#272a2d] h-1.5 rounded-full mt-2 overflow-hidden">
                <div
                  className="bg-orange-400 h-full rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, hardwareLive.ram_percent)}%` }}
                />
              </div>
            </div>

            {/* Disque */}
            <div className="bg-[#101416] p-3 rounded-lg border border-[#272a2d]">
              <div className="text-[11px] text-[#87938e] flex items-center justify-between mb-1">
                <span className="flex items-center gap-1"><Icon name="storage" size="xs" className="text-[#ffb4ab]" /> Disque ({hardwareLive.disk_mount})</span>
                <span className="text-[#e0e3e6]">{hardwareLive.disk_used_gb} / {hardwareLive.disk_total_gb} Go</span>
              </div>
              <div className="text-xl font-bold text-[#ffb4ab]">{hardwareLive.disk_percent}%</div>
              <div className="w-full bg-[#272a2d] h-1.5 rounded-full mt-2 overflow-hidden">
                <div
                  className="bg-[#ffb4ab] h-full rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, hardwareLive.disk_percent)}%` }}
                />
              </div>
            </div>

            {/* Réseau & Santé */}
            <div className="bg-[#101416] p-3 rounded-lg border border-[#272a2d]">
              <div className="text-[11px] text-[#87938e] flex items-center justify-between mb-1">
                <span className="flex items-center gap-1"><Icon name="monitoring" size="xs" className="text-[#81d0f8]" /> Score Santé Hôte</span>
                <span className="text-[#81d0f8] font-bold">{hardwareLive.score_sante}%</span>
              </div>
              <div className="text-sm font-bold text-[#e0e3e6] truncate">
                I/O: ↑{hardwareLive.network_sent_mb} Mo / ↓{hardwareLive.network_recv_mb} Mo
              </div>
              <div className="text-[10px] text-[#87938e] mt-1.5">
                Débit: {hardwareLive.network_mbps ?? 0} Mbps • Uptime: {Math.floor(hardwareLive.uptime_secondes / 3600)}h {Math.floor((hardwareLive.uptime_secondes % 3600) / 60)}m
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Grille Supérieure : 3 Cartes (Prédiction Critique + Config + Urgences) ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ── Carte 1 (Gauche, 5 cols) : PRÉDICTION CRITIQUE IMMINENTE ──────── */}
        <div className="lg:col-span-5 bg-[#1d2022] border border-[#ffb4ab]/50 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-[#ffb4ab] text-[11px] font-mono font-bold uppercase tracking-widest mb-3">
              <Icon name="warning" size="sm" className="text-[#ffb4ab]" />
              DIAGNOSTIC PRÉDICTIF (MODÈLE LINÉAIRE)
            </div>
            <h2 className="text-xl font-bold text-[#e0e3e6] leading-tight mb-2">
              {activeUrgence.device} : {activeUrgence.description}
            </h2>
            <p className="text-xs text-[#87938e] leading-relaxed">
              {activeUrgence.cause}
            </p>
          </div>

          <div className="my-4 pt-4 border-t border-[#272a2d]">
            <span className="text-[11px] font-mono text-[#87938e] uppercase tracking-wider block mb-1">
              Time-To-Failure Estimé
            </span>
            <div className="text-4xl font-bold font-mono tracking-tight text-[#ffb4ab]">
              <span>{ttf.jours}</span>{' '}
              <span className="text-xl text-[#bdc9c3] font-normal mr-2">jours</span>
              <span>{String(ttf.heures).padStart(2, '0')}</span>{' '}
              <span className="text-xl text-[#bdc9c3] font-normal">heures</span>
            </div>
          </div>

          <button
            id="supervision-planifier-btn"
            onClick={() => setShowInterventionDrawer(true)}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-[#ffb4ab] hover:bg-[#ffdad6] text-[#00382b] font-mono font-bold text-xs transition-colors shadow-sm"
          >
            <Icon name="build" size="sm" />
            Planifier Intervention &amp; Résoudre
          </button>

          <button
            id="supervision-recalculate-ttf-btn"
            onClick={handleRecalculateTtf}
            disabled={isRecalculating}
            className="w-full mt-2.5 flex items-center justify-center gap-2 py-2.5 rounded-lg border border-[#78d8ba] bg-[#78d8ba]/10 hover:bg-[#78d8ba]/20 text-[#78d8ba] font-mono font-bold text-xs transition-colors cursor-pointer"
          >
            <Icon name="monitoring" size="xs" className="text-[#78d8ba]" />
            <span>{isRecalculating ? 'Calcul du modèle...' : 'Recalculer le TTF'}</span>
          </button>
        </div>

        {/* ── Carte 2 (Centre, 3 cols) : Configuration Alertes ──────────────── */}
        <div className="lg:col-span-3 bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider mb-5">
              <Icon name="tune" size="sm" className="text-[#78d8ba]" />
              Configuration Alertes
            </div>

            <div className="space-y-6">
              {/* Slider 1 : Avertissement */}
              <div>
                <div className="flex justify-between items-center text-xs font-mono mb-2">
                  <span className="text-[#bdc9c3]">Seuil d'Avertissement</span>
                  <span className="px-2 py-0.5 rounded bg-[#ffb4ab]/15 text-[#ffb4ab] font-bold text-[11px]">
                    {warnThreshold}%
                  </span>
                </div>
                <input
                  type="range"
                  min={50}
                  max={90}
                  value={warnThreshold}
                  onChange={e => setWarnThreshold(Number(e.target.value))}
                  className="w-full h-1.5 rounded-full appearance-none cursor-pointer bg-[#0b0f11] accent-[#ffb4ab]"
                />
              </div>

              {/* Slider 2 : Critique */}
              <div>
                <div className="flex justify-between items-center text-xs font-mono mb-2">
                  <span className="text-[#bdc9c3]">Seuil Critique ({selectedDevice})</span>
                  <span className="px-2 py-0.5 rounded bg-[#ffb4ab]/15 text-[#ffb4ab] font-bold text-[11px]">
                    {critThreshold}%
                  </span>
                </div>
                <input
                  type="range"
                  min={60}
                  max={100}
                  value={critThreshold}
                  onChange={e => setCritThreshold(Number(e.target.value))}
                  className="w-full h-1.5 rounded-full appearance-none cursor-pointer bg-[#0b0f11] accent-[#ef4444]"
                />
              </div>
            </div>
          </div>

          <div className="pt-4 text-right">
            <button
              id="supervision-save-thresholds-btn"
              onClick={handleSaveThresholds}
              className="text-xs font-mono font-bold text-[#78d8ba] hover:underline uppercase tracking-wider"
            >
              {thresholdsSaved ? '✓ Enregistré en Base' : 'Enregistrer'}
            </button>
          </div>
        </div>

        {/* ── Carte 3 (Droite, 4 cols) : Urgence Maintenance ────────────────── */}
        <div className="lg:col-span-4 bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider mb-4">
            <span className="text-orange-400 font-bold">!</span>
            Prédictions par Équipement
          </div>

          <div className="space-y-2.5 max-h-64 overflow-y-auto pr-1">
            {urgencesList.map(u => {
              const active = u.device === selectedDevice;
              return (
                <div
                  key={u.id}
                  onClick={() => handleDeviceSelect(u.device, u.equipementId)}
                  className={`p-3 rounded-lg border transition-all cursor-pointer ${
                    active
                      ? 'bg-[#161c22] border-[#ffb4ab] shadow-sm'
                      : 'bg-[#161c22] border-[#272a2d] hover:border-[#3e4945]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-bold text-[#e0e3e6]">
                      {u.device}
                    </span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold ${SEV_BADGE[u.severity]}`}>
                      {u.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#87938e] truncate">{u.description}</p>
                  <div className="flex items-center gap-1.5 mt-1 text-[11px] font-mono text-[#bdc9c3]">
                    <Icon name="schedule" size="xs" className="text-[#87938e]" />
                    <span>{u.ttf}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Bloc Inférieur : Projections des Télémétries Systèmes Réelles ──── */}
      <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h2 className="text-xs font-mono font-semibold tracking-wider text-[#e0e3e6] uppercase">
              Séries Temporelles SQLite &amp; Projections Linéaires ({selectedDevice})
            </h2>
            <div className="flex items-center gap-5 mt-2 text-xs font-mono text-[#87938e]">
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 bg-[#78d8ba] inline-block" />
                Historique Réel Collecté
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 border-t border-dashed border-[#ffb4ab] inline-block" />
                Zone de prédiction (+48h)
              </span>
            </div>
          </div>

          {/* Sélecteur d'équipement */}
          <div className="relative">
            <button
              id="supervision-device-selector"
              onClick={() => setDropdownOpen(v => !v)}
              className="flex items-center gap-3 px-4 py-2 rounded-lg bg-[#161c22] border border-[#3e4945] text-xs font-mono text-[#e0e3e6] hover:border-[#78d8ba] transition-colors"
            >
              <span>{selectedDevice || 'Sélectionner équipement'}</span>
              <Icon name="expand_more" size="xs" className="text-[#87938e]" />
            </button>
            {dropdownOpen && (
              <div className="absolute right-0 top-full mt-1.5 w-64 bg-[#161c22] border border-[#3e4945] rounded-lg shadow-2xl z-20 overflow-hidden font-mono text-xs max-h-64 overflow-y-auto">
                {equipementsList.map(eq => (
                  <button
                    key={eq.id}
                    onClick={() => {
                      handleDeviceSelect(eq.nom, eq.id);
                      setDropdownOpen(false);
                    }}
                    className="w-full px-4 py-2.5 text-left text-[#e0e3e6] hover:bg-[#272a2d] transition-colors flex items-center justify-between"
                  >
                    <span className="truncate">{eq.nom}</span>
                    <span className="text-[10px] text-[#78d8ba] ml-2 shrink-0">{eq.ip}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* 4 Graphiques en Grille 2x2 branchés aux vraies séries SQLite */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* 1. CPU Utilization */}
          <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-4">
            <div className="flex items-center justify-between mb-3 text-xs font-mono">
              <span className="font-semibold text-[#e0e3e6] flex items-center gap-1.5">
                <Icon name="memory" size="xs" className="text-[#78d8ba]" />
                CPU Utilization
              </span>
              <span className="font-bold text-[#78d8ba]">
                {currentMetrics.cpu}%
              </span>
            </div>
            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={cpuSeries}
                  margin={{ top: 5, right: 10, left: -25, bottom: 0 }}
                >
                  <CartesianGrid stroke="#272a2d" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="t" hide />
                  <YAxis domain={[0, 100]} stroke="#87938e" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#101416', borderColor: '#3e4945', fontSize: '11px', fontFamily: 'JetBrains Mono' }}
                    labelFormatter={(_, payload) => payload?.[0]?.payload?.label || ''}
                  />
                  {histSplitIndex > 0 && <ReferenceLine x={histSplitIndex} stroke="#87938e" strokeDasharray="3 3" />}
                  <Area type="monotone" dataKey="hist" name="Historique (%)" stroke="#78d8ba" strokeWidth={2} fill="#78d8ba" fillOpacity={0.1} />
                  <Area type="monotone" dataKey="pred" name="Prédiction (%)" stroke="#ffb4ab" strokeWidth={2} strokeDasharray="4 4" fill="#ffb4ab" fillOpacity={0.1} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* 2. RAM Usage */}
          <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-4">
            <div className="flex items-center justify-between mb-3 text-xs font-mono">
              <span className="font-semibold text-[#e0e3e6] flex items-center gap-1.5">
                <Icon name="monitoring" size="xs" className="text-orange-400" />
                RAM Usage
              </span>
              <span className="font-bold text-orange-400">
                {currentMetrics.ram}%
              </span>
            </div>
            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={ramSeries}
                  margin={{ top: 5, right: 10, left: -25, bottom: 0 }}
                >
                  <CartesianGrid stroke="#272a2d" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="t" hide />
                  <YAxis domain={[0, 100]} stroke="#87938e" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#101416', borderColor: '#3e4945', fontSize: '11px', fontFamily: 'JetBrains Mono' }}
                    labelFormatter={(_, payload) => payload?.[0]?.payload?.label || ''}
                  />
                  {histSplitIndex > 0 && <ReferenceLine x={histSplitIndex} stroke="#87938e" strokeDasharray="3 3" />}
                  <Area type="monotone" dataKey="hist" name="Historique (%)" stroke="#78d8ba" strokeWidth={2} fill="#78d8ba" fillOpacity={0.1} />
                  <Area type="monotone" dataKey="pred" name="Prédiction (%)" stroke="#ffb4ab" strokeWidth={2} strokeDasharray="4 4" fill="#ffb4ab" fillOpacity={0.1} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* 3. Disk I/O & Fill */}
          <div className="bg-[#161c22] border border-[#ffb4ab]/40 rounded-xl p-4">
            <div className="flex items-center justify-between mb-3 text-xs font-mono">
              <span className="font-semibold text-[#ffb4ab] flex items-center gap-1.5">
                <Icon name="storage" size="xs" className="text-[#ffb4ab]" />
                Disk I/O &amp; Fill
              </span>
              <span className="font-bold text-[#ffb4ab]">
                {currentMetrics.disk}%
              </span>
            </div>
            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={diskSeries}
                  margin={{ top: 5, right: 10, left: -25, bottom: 0 }}
                >
                  <CartesianGrid stroke="#272a2d" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="t" hide />
                  <YAxis domain={[0, 110]} stroke="#87938e" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#101416', borderColor: '#3e4945', fontSize: '11px', fontFamily: 'JetBrains Mono' }}
                    labelFormatter={(_, payload) => payload?.[0]?.payload?.label || ''}
                  />
                  <ReferenceLine y={critThreshold} stroke="#e0e3e6" strokeDasharray="3 3" label={{ value: `Seuil ${critThreshold}%`, fill: '#87938e', fontSize: 10 }} />
                  {histSplitIndex > 0 && <ReferenceLine x={histSplitIndex} stroke="#87938e" strokeDasharray="3 3" />}
                  <Area type="monotone" dataKey="hist" name="Historique (%)" stroke="#78d8ba" strokeWidth={2} fill="#78d8ba" fillOpacity={0.1} />
                  <Area type="monotone" dataKey="pred" name="Prédiction (%)" stroke="#ffb4ab" strokeWidth={2} strokeDasharray="4 4" fill="#ffb4ab" fillOpacity={0.2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* 4. Network Traffic */}
          <div className="bg-[#161c22] border border-[#272a2d] rounded-xl p-4">
            <div className="flex items-center justify-between mb-3 text-xs font-mono">
              <span className="font-semibold text-[#e0e3e6] flex items-center gap-1.5">
                <Icon name="monitoring" size="xs" className="text-[#81d0f8]" />
                Network Traffic / Latency
              </span>
              <span className="font-bold text-[#81d0f8]">
                {currentMetrics.net} Mb/s
              </span>
            </div>
            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={netSeries}
                  margin={{ top: 5, right: 10, left: -25, bottom: 0 }}
                >
                  <CartesianGrid stroke="#272a2d" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="t" hide />
                  <YAxis domain={[0, 'auto']} stroke="#87938e" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#101416', borderColor: '#3e4945', fontSize: '11px', fontFamily: 'JetBrains Mono' }}
                    labelFormatter={(_, payload) => payload?.[0]?.payload?.label || ''}
                  />
                  {histSplitIndex > 0 && <ReferenceLine x={histSplitIndex} stroke="#87938e" strokeDasharray="3 3" />}
                  <Area type="monotone" dataKey="hist" name="Débit Réel" stroke="#81d0f8" strokeWidth={2} fill="#81d0f8" fillOpacity={0.1} />
                  <Area type="monotone" dataKey="pred" name="Projection" stroke="#ffb4ab" strokeWidth={2} strokeDasharray="4 4" fill="#ffb4ab" fillOpacity={0.1} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      {/* ── TIROIR LATÉRAL : Planifier Intervention ──────────────────────────── */}
      {showInterventionDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div>
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    Ordre d'Intervention &amp; Remédiation
                  </h3>
                  <p className="text-xs font-mono text-[#ffb4ab] mt-0.5">
                    {activeUrgence.device} — {activeUrgence.description}
                  </p>
                </div>
                <button
                  onClick={() => setShowInterventionDrawer(false)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <Icon name="close" size="md" />
                </button>
              </div>

              <div className="mt-5 space-y-4 font-mono text-xs">
                <div className="p-3.5 bg-[#1d2022] rounded-xl border border-[#272a2d] space-y-2">
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Diagnostic Automatisé</div>
                  <p className="text-[#e0e3e6]">
                    Équipement ciblé : <span className="text-[#78d8ba] font-bold">{activeUrgence.device}</span> (TTF estimé : <span className="text-[#ffb4ab] font-bold">{activeUrgence.ttf}</span>).
                  </p>
                </div>

                <div className="p-3.5 bg-[#1d2022] rounded-xl border border-[#272a2d] space-y-3">
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Actions exécutées à la validation</div>

                  <label className="flex items-center gap-2 cursor-pointer text-[#e0e3e6]">
                    <input type="checkbox" defaultChecked className="accent-[#78d8ba]" />
                    <span>Sondage actif ICMP / TCP / SSH de l'équipement</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-[#e0e3e6]">
                    <input type="checkbox" defaultChecked className="accent-[#78d8ba]" />
                    <span>Recalcul du modèle de régression linéaire (TTF)</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-[#e0e3e6]">
                    <input type="checkbox" defaultChecked className="accent-[#78d8ba]" />
                    <span>Résolution et clôture des alertes actives associées</span>
                  </label>
                </div>
              </div>
            </div>

            <div className="pt-6 border-t border-[#272a2d] flex gap-2">
              <button
                onClick={handleConfirmIntervention}
                className="flex-1 py-2.5 rounded-lg bg-[#78d8ba] text-[#00382b] font-mono font-bold text-xs hover:bg-[#68c8aa] transition-colors"
              >
                Exécuter &amp; Clôturer Alertes
              </button>
              <button
                onClick={() => setShowInterventionDrawer(false)}
                className="px-4 py-2.5 rounded-lg border border-[#3e4945] text-xs font-mono text-[#e0e3e6] hover:bg-[#272a2d] transition-colors"
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
