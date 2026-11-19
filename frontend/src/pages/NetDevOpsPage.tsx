import React, { useState, useEffect, useCallback } from 'react';
import { Icon } from '../components/ui/Icon';
import { netdevopsService } from '../services/api';

/* ── Types ───────────────────────────────────────────────────────────────── */
interface Device {
  id: string;
  name: string;
  type: 'Router' | 'Switch' | 'Firewall';
  ip: string;
  /** null = configuration jamais collectée/auditée : aucune valeur n'est inventée. */
  cisScore: number | null;
  findings: number | null;
  compliant: boolean | null;
}

interface CISFinding {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  currentConfigSnippet: string;
  /** Commandes IOS exactes applicables telles quelles ; vide si la correction exige un paramètre du site. */
  suggestedConfigSnippet: string;
  /** Texte de correction manuelle fourni par la règle CIS. */
  manualRemediation: string;
}

interface Backup {
  id: string;
  index: number;
  date: string;
  hash: string;
}

const errorDetail = (err: any, fallback: string): string => {
  const d = err?.response?.data?.detail;
  return typeof d === 'string' && d ? d : fallback;
};

export const NetDevOpsPage: React.FC = () => {
  const [devicesList, setDevicesList] = useState<Device[]>([]);
  const [devicesLoaded, setDevicesLoaded] = useState(false);
  const [devicesError, setDevicesError] = useState<string | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [findingsList, setFindingsList] = useState<CISFinding[]>([]);
  const [customFinding, setCustomFinding] = useState<CISFinding | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<CISFinding | null>(null);
  const [backupsList, setBackupsList] = useState<Backup[]>([]);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [auditSource, setAuditSource] = useState<string | null>(null);

  const [showApplyDrawer, setShowApplyDrawer] = useState(false);
  const [showRestoreDrawer, setShowRestoreDrawer] = useState(false);
  const [selectedBackup, setSelectedBackup] = useState<Backup | null>(null);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [isApplyingSSH, setIsApplyingSSH] = useState(false);
  const [isAuditing, setIsAuditing] = useState(false);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3500);
  };

  const [findingSearchQuery, setFindingSearchQuery] = useState('');

  /* Script transféré depuis l'Assistant IA : devient une correction personnalisée à relire avant application */
  useEffect(() => {
    const prefillCode = sessionStorage.getItem('netdevops:prefill_code');
    if (prefillCode) {
      sessionStorage.removeItem('netdevops:prefill_code');
      const custom: CISFinding = {
        id: 'custom',
        title: 'Script correctif personnalisé (transféré depuis l\'Assistant)',
        description: 'Commandes proposées par l\'Assistant : à relire avant toute application sur l\'équipement.',
        severity: 'MEDIUM',
        currentConfigSnippet: '',
        suggestedConfigSnippet: prefillCode,
        manualRemediation: '',
      };
      setCustomFinding(custom);
      setSelectedFinding(custom);
      setShowApplyDrawer(true);
      showToast('Script chargé depuis l\'Assistant. Relisez-le avant de l\'appliquer.');
    }
  }, []);

  const allFindings = customFinding ? [customFinding, ...findingsList] : findingsList;
  const filteredFindings = allFindings.filter(f => {
    if (!findingSearchQuery.trim()) return true;
    const q = findingSearchQuery.toLowerCase();
    return f.title.toLowerCase().includes(q) || f.description.toLowerCase().includes(q);
  });

  const loadBackups = useCallback(async (devId: string) => {
    try {
      const backupsRes = await netdevopsService.getBackups(devId);
      setBackupsList(
        (Array.isArray(backupsRes) ? backupsRes : []).map((b: any, idx: number) => ({
          id: `b-${b.index ?? idx}`,
          index: typeof b.index === 'number' ? b.index : idx,
          date: b.ts ? new Date(b.ts).toLocaleString('fr-FR') : `Sauvegarde #${idx + 1}`,
          hash: b.sha256 ?? '',
        })),
      );
    } catch {
      setBackupsList([]);
    }
  }, []);

  /** Lance l'audit réel d'un équipement ; renvoie true si le rapport a pu être produit. */
  const loadDeviceAudit = useCallback(async (devId: string): Promise<boolean> => {
    setAuditError(null);
    try {
      const auditRes = await netdevopsService.runAudit(devId);
      const violations: any[] = Array.isArray(auditRes?.violations) ? auditRes.violations : [];
      const mappedFindings: CISFinding[] = violations.map((v: any, idx: number) => ({
        id: v.id || `f-${idx}`,
        title: v.title || v.id || 'Écart de conformité CIS',
        description: v.description || 'Règle de durcissement CIS Benchmark',
        severity: (v.severity === 'CRITICAL' ? 'CRITICAL' : v.severity === 'HIGH' ? 'HIGH' : 'MEDIUM') as 'CRITICAL' | 'HIGH' | 'MEDIUM',
        currentConfigSnippet: v.snippet || '',
        suggestedConfigSnippet: v.remediation_commands || '',
        manualRemediation: v.remediation || '',
      }));
      setFindingsList(mappedFindings);
      setSelectedFinding(prev => (prev?.id === 'custom' ? prev : mappedFindings[0] ?? null));
      setAuditSource(typeof auditRes?.config_source === 'string' ? auditRes.config_source : null);
      setDevicesList(prev => prev.map(d => d.id === devId ? {
        ...d,
        cisScore: typeof auditRes?.score === 'number' ? Math.round(auditRes.score) : d.cisScore,
        findings: violations.length,
        compliant: violations.length === 0,
      } : d));
      void loadBackups(devId);
      return true;
    } catch (err: any) {
      setFindingsList([]);
      setSelectedFinding(prev => (prev?.id === 'custom' ? prev : null));
      setAuditSource(null);
      setAuditError(errorDetail(err, 'Audit impossible : le serveur n\'a pas pu obtenir la configuration de l\'équipement.'));
      void loadBackups(devId);
      return false;
    }
  }, [loadBackups]);

  useEffect(() => {
    netdevopsService.getDevices().then(devs => {
      const list: any[] = Array.isArray(devs) ? devs : [];
      const mapped: Device[] = list.map((d: any) => ({
        id: d.id,
        name: d.name || d.id,
        type: (d.type === 'switch' ? 'Switch' : d.type === 'router' ? 'Router' : 'Firewall') as 'Router' | 'Switch' | 'Firewall',
        ip: d.ip || '',
        cisScore: typeof d.cis_score === 'number' ? Math.round(d.cis_score) : null,
        findings: typeof d.findings === 'number' ? d.findings : null,
        compliant: typeof d.findings === 'number' ? d.findings === 0 : null,
      }));
      setDevicesList(mapped);
      setDevicesError(null);
      if (mapped.length > 0) {
        setSelectedDevice(mapped[0]);
        void loadDeviceAudit(mapped[0].id);
      }
    }).catch((err: any) => {
      setDevicesError(errorDetail(err, 'Impossible de charger la liste des équipements.'));
    }).finally(() => setDevicesLoaded(true));
  }, [loadDeviceAudit]);

  const handleDeviceChange = (dev: Device) => {
    setSelectedDevice(dev);
    setFindingsList([]);
    setBackupsList([]);
    setAuditSource(null);
    void loadDeviceAudit(dev.id);
  };

  const handleRunAudit = async () => {
    if (!selectedDevice) return;
    setIsAuditing(true);
    showToast(`Audit CIS en cours sur ${selectedDevice.name}...`);
    const ok = await loadDeviceAudit(selectedDevice.id);
    showToast(ok ? `Audit CIS terminé pour ${selectedDevice.name}.` : `Audit CIS impossible pour ${selectedDevice.name}.`);
    setIsAuditing(false);
  };

  const handleApplySSH = async () => {
    if (!selectedDevice || !selectedFinding || !selectedFinding.suggestedConfigSnippet) return;
    setIsApplyingSSH(true);
    try {
      const res = await netdevopsService.remediate(
        selectedDevice.id,
        selectedFinding.suggestedConfigSnippet,
        selectedFinding.id === 'custom' ? undefined : selectedFinding.id,
      );
      await loadDeviceAudit(selectedDevice.id);
      setShowApplyDrawer(false);
      const score = res?.audit?.score;
      showToast(
        typeof score === 'number'
          ? `Correctif appliqué sur ${selectedDevice.name} (SSH). Score CIS relu : ${Math.round(score)} %.`
          : `Correctif appliqué sur ${selectedDevice.name} (SSH).`,
      );
    } catch (err: any) {
      showToast(errorDetail(err, `Le correctif n'a pas pu être appliqué sur ${selectedDevice.name} ; rien n'a été modifié.`));
    } finally {
      setIsApplyingSSH(false);
    }
  };

  const handleRestoreBackup = async () => {
    if (!selectedBackup || !selectedDevice) return;
    try {
      const res = await netdevopsService.restoreBackup(selectedDevice.id, selectedBackup.index);
      await loadDeviceAudit(selectedDevice.id);
      setShowRestoreDrawer(false);
      showToast(res?.note || `Configuration de référence réactivée dans Sentinelle pour ${selectedDevice.name}.`);
    } catch (err: any) {
      setShowRestoreDrawer(false);
      showToast(errorDetail(err, 'Erreur lors de la restauration de la sauvegarde.'));
    }
  };


  return (
    <div className="p-6 lg:p-8 space-y-6 bg-[#101416] min-h-screen text-[#e0e3e6] font-sans">
      {/* ── Toast de feedback ─────────────────────────────────────────────── */}
      {toastMsg && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#1d2022] border border-[#78d8ba] text-[#78d8ba] px-4 py-2.5 rounded-lg shadow-xl font-mono text-xs flex items-center gap-2">
          <Icon name="check_circle" size="sm" className="text-[#78d8ba]" />
          {toastMsg}
        </div>
      )}

      {/* ── En-tête de page (Fidèle à screen.png) ─────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#e0e3e6]">
          NetDevOps Automation
        </h1>
        <p className="text-sm text-[#87938e] mt-0.5">
          Audit de conformité CIS &amp; remédiation SSH
        </p>
      </div>

      {/* ── Layout 2 Colonnes : Équipements (gauche) + Audit/Diff (droite) ─── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ── Colonne Gauche (4 cols / ~320px) : Liste & Sauvegardes ───────── */}
        <div className="lg:col-span-4 space-y-6">
          {/* Bloc 1 : Équipements Réseau */}
          <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider">
                Équipements Réseau
              </h2>
              <span className="text-[11px] font-mono text-[#87938e] px-2 py-0.5 rounded bg-[#161c22] border border-[#272a2d]">
                {devicesList.length} au total
              </span>
            </div>

            <div className="space-y-3">
              {devicesError && (
                <div className="p-3 text-xs text-[#ffb4ab] bg-[#161c22] rounded-lg border border-[#272a2d] font-sans" data-testid="netdevops-devices-error">
                  {devicesError}
                </div>
              )}
              {devicesLoaded && !devicesError && devicesList.length === 0 && (
                <div className="p-4 text-center text-xs text-[#87938e] bg-[#161c22] rounded-lg border border-[#272a2d] font-sans" data-testid="netdevops-no-devices">
                  Aucun équipement dans le parc. Ajoutez-en depuis la page Parc.
                </div>
              )}
              {devicesList.map(d => {
                const isSelected = selectedDevice?.id === d.id;
                return (
                  <div
                    key={d.id}
                    onClick={() => handleDeviceChange(d)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
                      isSelected
                        ? 'bg-[#15231f] border-[#78d8ba] shadow-sm'
                        : 'bg-[#161c22] border-[#272a2d] hover:border-[#3e4945]'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-[#1d2022] text-[#78d8ba]">
                        {d.type === 'Switch' ? (
                          <Icon name="layers" size="sm" className="text-[#78d8ba]" />
                        ) : d.type === 'Router' ? (
                          <Icon name="router" size="sm" className="text-orange-400" />
                        ) : (
                          <Icon name="security" size="sm" className="text-[#78d8ba]" />
                        )}
                      </div>
                      <div>
                        <div className={`text-xs font-mono font-bold ${isSelected ? 'text-[#78d8ba]' : 'text-[#e0e3e6]'}`}>
                          {d.name}
                        </div>
                        <div className="flex items-center gap-1.5 mt-1 text-[11px] font-mono">
                          <span
                            className="w-2 h-2 rounded-full inline-block"
                            style={{ backgroundColor: d.compliant === null ? '#87938e' : d.compliant ? '#78d8ba' : '#ffb4ab' }}
                          />
                          <span className="text-[#87938e]">
                            {d.compliant === null ? 'Non audité' : d.compliant ? 'Conforme' : `${d.findings} écart(s)`}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Badge Score CIS */}
                    <div
                      className={`px-3 py-1.5 rounded-lg border text-center font-mono ${
                        d.cisScore === null
                          ? 'border-[#3e4945] bg-[#161c22] text-[#87938e]'
                          : d.cisScore >= 90
                          ? 'border-[#78d8ba]/40 bg-[#78d8ba]/10 text-[#78d8ba]'
                          : d.cisScore >= 75
                          ? 'border-orange-500/40 bg-orange-500/10 text-orange-400'
                          : 'border-[#ffb4ab]/40 bg-[#ffb4ab]/10 text-[#ffb4ab]'
                      }`}
                    >
                      <div className="text-sm font-bold leading-none">{d.cisScore === null ? 'N/A' : `${d.cisScore}%`}</div>
                      <div className="text-[9px] uppercase tracking-wider mt-0.5 opacity-80">CIS SCORE</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Bloc 2 : Historique de sauvegarde */}
          <div className="bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-5">
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider mb-4">
              <Icon name="schedule" size="sm" className="text-[#78d8ba]" />
              Historique de sauvegarde
            </div>

            <div className="space-y-3 font-mono text-xs">
              {backupsList.length === 0 && (
                <div className="p-3 text-center text-[11px] text-[#87938e] font-sans" data-testid="netdevops-no-backups">
                  Aucune sauvegarde pour cet équipement.
                </div>
              )}
              {backupsList.map(b => (
                <div
                  key={b.id}
                  className="p-3 bg-[#161c22] border border-[#272a2d] rounded-lg flex items-center justify-between"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-[#78d8ba]" />
                      <span className="font-semibold text-[#e0e3e6]">{b.date}</span>
                    </div>
                    <div className="text-[11px] text-[#87938e] mt-1 pl-4">
                      SHA-256 : {b.hash ? `${b.hash.slice(0, 12)}…` : 'indisponible'}
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setSelectedBackup(b);
                      setShowRestoreDrawer(true);
                    }}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#1d2022] border border-[#3e4945] hover:border-[#78d8ba] text-[#78d8ba] text-xs transition-colors"
                  >
                    <Icon name="restore" size="xs" />
                    Restaurer
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Colonne Droite (8 cols) : Détail de l'audit & Diff IA ─────────── */}
        <div className="lg:col-span-8 bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-6 flex flex-col justify-between">
          {!selectedDevice ? (
            <div className="text-sm text-[#87938e] text-center py-16" data-testid="netdevops-no-selection">
              Sélectionnez un équipement pour lancer ou consulter son audit CIS.
            </div>
          ) : (
          <>
          <div>
            {/* En-tête du détail */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between pb-5 border-b border-[#272a2d] gap-3">
              <div>
                <div className="flex items-center gap-2 text-lg font-bold font-mono">
                  <span className="text-[#78d8ba]">{selectedDevice.name}</span>
                  <span className="text-[#3e4945]">|</span>
                  <span className="text-[#e0e3e6]">Détail de l'audit</span>
                </div>
                <div className="text-xs font-mono text-[#87938e] mt-1">
                  CIS Cisco IOS 15 Benchmark v4.0.0{auditSource ? ` — configuration : ${auditSource}` : ''}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  id="netdevops-run-audit-btn"
                  onClick={handleRunAudit}
                  disabled={isAuditing}
                  className="px-3 py-1.5 rounded-lg border border-[#78d8ba] text-[#78d8ba] hover:bg-[#78d8ba]/10 text-xs font-mono font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Icon name="refresh" size="xs" className={isAuditing ? 'animate-spin' : ''} />
                  <span>{isAuditing ? 'Audit en cours...' : 'Lancer Audit CIS'}</span>
                </button>

                {selectedDevice.compliant === null && findingsList.length === 0 ? (
                  <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-[#161c22] border border-[#3e4945] text-xs font-mono font-bold text-[#87938e]">
                    Non audité
                  </div>
                ) : selectedDevice.compliant ? (
                  <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-[#78d8ba]/15 border border-[#78d8ba]/40 text-xs font-mono font-bold text-[#78d8ba]">
                    <Icon name="check_circle" size="sm" />
                    Conforme
                  </div>
                ) : (
                  <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-[#ffb4ab]/15 border border-[#ffb4ab]/40 text-xs font-mono font-bold text-[#ffb4ab]">
                    <Icon name="warning" size="sm" />
                    {findingsList.length} écart(s)
                  </div>
                )}
              </div>
            </div>

            {/* Zone centrale : Findings CIS à gauche + Diff IA à droite */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mt-5">
              {/* Findings CIS avec Recherche Rapide (5 cols) */}
              <div className="lg:col-span-5 space-y-3 font-mono">
                {/* Barre de recherche instantanée */}
                <div className="relative mb-2">
                  <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#87938e] pointer-events-none">
                    <Icon name="search" size="xs" />
                  </span>
                  <input
                    type="text"
                    value={findingSearchQuery}
                    onChange={e => setFindingSearchQuery(e.target.value)}
                    placeholder="Filtrer les anomalies CIS (ex: password, ssh, vty)..."
                    className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#101416] border border-[#272a2d] text-xs text-[#e0e3e6] placeholder-[#87938e] focus:outline-none focus:border-[#78d8ba] transition-colors"
                  />
                </div>

                {/* Liste filtrée des anomalies */}
                {auditError ? (
                  <div className="p-4 text-xs text-[#ffb4ab] font-sans bg-[#161c22] rounded-lg border border-[#272a2d]" data-testid="netdevops-audit-error">
                    {auditError}
                  </div>
                ) : filteredFindings.length === 0 ? (
                  <div className="p-6 text-center text-xs text-[#87938e] font-sans bg-[#161c22] rounded-lg border border-[#272a2d]">
                    {allFindings.length === 0 ? 'Aucun écart CIS relevé sur la dernière configuration.' : 'Aucune anomalie ne correspond à votre filtre.'}
                  </div>
                ) : (
                  filteredFindings.map(f => {
                    const isSel = selectedFinding?.id === f.id;
                    return (
                      <div
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`p-3.5 rounded-lg border transition-all cursor-pointer ${
                          isSel
                            ? 'bg-[#161c22] border-l-4 border-l-[#ffb4ab] border-y-[#272a2d] border-r-[#272a2d] shadow-sm'
                            : 'bg-[#161c22] border border-[#272a2d] hover:border-[#3e4945]'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <div className="text-xs font-bold text-[#e0e3e6]">
                            {f.title}
                          </div>
                          <span className="text-[10px] text-[#ffb4ab] bg-[#ffb4ab]/10 px-1.5 py-0.5 rounded border border-[#ffb4ab]/20 font-bold">
                            CIS
                          </span>
                        </div>
                        <div className="text-[11px] text-[#87938e] leading-relaxed">
                          {f.description}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>

              {/* Suggestions d'automatisation IA & Diff côte à côte (7 cols) */}
              <div className="lg:col-span-7 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider mb-3">
                    <Icon name="memory" size="sm" className="text-[#78d8ba]" />
                    Correction proposée
                  </div>

                  {/* Tableau Comparatif Diff Cisco IOS */}
                  <div className="grid grid-cols-2 rounded-xl border border-[#272a2d] bg-[#12161a] overflow-hidden font-mono text-[11px]">
                    {/* Colonne Gauche : Current Config */}
                    <div className="border-r border-[#272a2d] p-3 flex flex-col">
                      <div className="text-[10px] text-[#87938e] uppercase font-bold pb-2 border-b border-[#272a2d] mb-2">
                        Extrait de la configuration
                      </div>
                      <pre className="text-[#e0e3e6] overflow-x-auto leading-relaxed opacity-80 whitespace-pre font-mono">
                        {selectedFinding?.currentConfigSnippet || '(aucun extrait : directive absente ou non applicable)'}
                      </pre>
                    </div>

                    {/* Colonne Droite : AI Suggested Correction */}
                    <div className="p-3 bg-[#15231f]/40 flex flex-col">
                      <div className="text-[10px] text-[#78d8ba] uppercase font-bold pb-2 border-b border-[#272a2d] mb-2">
                        Commandes à appliquer
                      </div>
                      <pre className="text-[#78d8ba] overflow-x-auto leading-relaxed whitespace-pre font-mono font-semibold">
                        {selectedFinding?.suggestedConfigSnippet || '(aucune commande automatique : correction manuelle)'}
                      </pre>
                      {selectedFinding && !selectedFinding.suggestedConfigSnippet && selectedFinding.manualRemediation && (
                        <p className="mt-3 text-[11px] text-[#bdc9c3] font-sans leading-relaxed" data-testid="netdevops-manual-remediation">
                          Correction manuelle : {selectedFinding.manualRemediation}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Boutons d'action en bas à droite (Fidèles à screen.png) */}
          <div className="pt-6 border-t border-[#272a2d] flex items-center justify-end gap-3 mt-6">
            <button
              id="netdevops-approve-btn"
              onClick={() => setShowApplyDrawer(true)}
              disabled={!selectedFinding || !selectedFinding.suggestedConfigSnippet}
              title={selectedFinding && !selectedFinding.suggestedConfigSnippet ? 'Cette règle exige une correction manuelle' : undefined}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#78d8ba] hover:bg-[#68c8aa] text-[#00382b] font-mono font-bold text-xs transition-colors shadow-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Icon name="check_circle" size="sm" />
              Appliquer
            </button>
          </div>
          </>
          )}
        </div>
      </div>

      {/* ── Tiroir : déploiement SSH ── */}
      {showApplyDrawer && selectedDevice && selectedFinding && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-lg bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div className="flex items-center gap-2">
                  <Icon name="terminal" size="md" className="text-[#78d8ba]" />
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    Déploiement SSH (Cisco IOS)
                  </h3>
                </div>
                <button
                  onClick={() => setShowApplyDrawer(false)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <Icon name="close" size="md" />
                </button>
              </div>

              <div className="mt-5 space-y-4 font-mono text-xs">
                <div className="p-3.5 bg-[#1d2022] rounded-xl border border-[#272a2d] space-y-2">
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Cible SSH</div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Équipement :</span>
                    <span className="text-[#78d8ba] font-bold">{selectedDevice.name}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Adresse IP :</span>
                    <span className="text-[#e0e3e6] font-bold">{selectedDevice.ip}:22</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Pilote d'automatisation :</span>
                    <span className="text-[#bdc9c3]">SSH interactif (Paramiko)</span>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-[10px] text-[#87938e] uppercase font-bold">Commandes à injecter</div>
                  <pre className="p-3 bg-[#0b0f11] border border-[#272a2d] rounded-lg text-[#78d8ba] text-[11px] leading-relaxed overflow-x-auto whitespace-pre">
{`configure terminal
${selectedFinding.suggestedConfigSnippet}
end
write memory`}
                  </pre>
                  <button
                    id="netdevops-copy-cli-btn"
                    onClick={() => {
                      navigator.clipboard.writeText(`configure terminal\n${selectedFinding.suggestedConfigSnippet}\nend\nwrite memory`);
                      showToast('Commandes copiées dans le presse-papiers.');
                    }}
                    className="w-full py-2 rounded-lg border border-[#3e4945] hover:border-[#78d8ba] text-xs font-mono text-[#dfe4e0] hover:text-[#78d8ba] flex items-center justify-center gap-1.5 transition-colors cursor-pointer mt-2"
                  >
                    <Icon name="content_copy" size="xs" />
                    <span>Copier les commandes CLI</span>
                  </button>
                </div>

                <div className="p-3 bg-[#1d2022] rounded-lg border border-[#272a2d] text-[#bdc9c3] text-[11px]">
                  Les commandes sont envoyées par SSH, puis la configuration en place est relue et sauvegardée (SHA-256). Si la connexion ou une commande échoue, rien n'est enregistré.
                </div>
              </div>
            </div>

            <div className="pt-6 border-t border-[#272a2d] flex gap-2">
              <button
                onClick={handleApplySSH}
                disabled={isApplyingSSH}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg bg-[#78d8ba] text-[#00382b] font-mono font-bold text-xs hover:bg-[#68c8aa] transition-colors disabled:opacity-50"
              >
                {isApplyingSSH ? (
                  <>Exécution SSH en cours...</>
                ) : (
                  <>
                    <Icon name="check_circle" size="sm" />
                    Exécuter sur l'équipement
                  </>
                )}
              </button>
              <button
                onClick={() => setShowApplyDrawer(false)}
                className="px-4 py-2.5 rounded-lg border border-[#3e4945] text-xs font-mono text-[#e0e3e6] hover:bg-[#272a2d] transition-colors"
              >
                Annuler
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── TIROIR LATÉRAL GESTION DE FENÊTRES V1 : Restauration de Sauvegarde ── */}
      {showRestoreDrawer && selectedBackup && selectedDevice && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div className="flex items-center gap-2">
                  <Icon name="restore" size="md" className="text-orange-400" />
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    Restaurer une sauvegarde
                  </h3>
                </div>
                <button
                  onClick={() => setShowRestoreDrawer(false)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <Icon name="close" size="md" />
                </button>
              </div>

              <div className="mt-5 space-y-4 font-mono text-xs">
                <p className="text-xs text-[#bdc9c3]">
                  Vous êtes sur le point de restaurer la configuration de <span className="text-[#78d8ba] font-bold">{selectedDevice.name}</span> à partir de l'instantané du <span className="text-[#e0e3e6] font-bold">{selectedBackup.date}</span>. La configuration est réactivée comme référence dans Sentinelle ; elle n'est pas poussée automatiquement sur l'équipement.
                </p>

                <div className="p-3 bg-[#1d2022] rounded-lg border border-[#272a2d] space-y-2">
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">SHA-256 :</span>
                    <span className="text-[#78d8ba] break-all">{selectedBackup.hash || 'indisponible'}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-6 border-t border-[#272a2d] flex gap-2">
              <button
                onClick={handleRestoreBackup}
                className="flex-1 py-2.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-mono font-bold text-xs transition-colors"
              >
                Confirmer la restauration
              </button>
              <button
                onClick={() => setShowRestoreDrawer(false)}
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
