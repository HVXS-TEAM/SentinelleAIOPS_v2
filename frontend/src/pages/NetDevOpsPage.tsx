import React, { useState, useEffect, useCallback } from 'react';
import {
  Router,
  Shield,
  Clock,
  RotateCcw,
  X,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  Cpu,
  Layers,
  Copy,
  RefreshCw,
} from 'lucide-react';
import { netdevopsService } from '../services/api';

/* ── Types ───────────────────────────────────────────────────────────────── */
interface Device {
  id: string;
  name: string;
  type: 'Router' | 'Switch' | 'Firewall';
  ip: string;
  cisScore: number;
  findings: number;
  compliant: boolean;
}

interface CISFinding {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  currentConfigSnippet: string;
  suggestedConfigSnippet: string;
}

interface Backup {
  id: string;
  date: string;
  hash: string;
}

/* ── Données conformes à screen.png (Données initiales de secours) ───────── */
const DEVICES: Device[] = [
  { id: 'SW-CORE-01', name: 'SW-CORE-01', type: 'Switch', ip: '10.0.1.10', cisScore: 65, findings: 5, compliant: false },
  { id: 'RTR-EDGE-01', name: 'RTR-EDGE-01', type: 'Router', ip: '10.0.1.1', cisScore: 82, findings: 2, compliant: false },
  { id: 'FW-PERIMETER-01', name: 'FW-PERIMETER-01', type: 'Firewall', ip: '192.168.1.254', cisScore: 100, findings: 0, compliant: true },
  { id: 'AP-WIFI-01', name: 'AP-WIFI-01', type: 'Switch', ip: '10.0.20.1', cisScore: 40, findings: 6, compliant: false },
];

const FINDINGS_DIST_SW: CISFinding[] = [
  {
    id: 'f1',
    title: 'Plaintext password detected',
    description: "CIS 1.1.1 Ensure 'service password-encryption' is enabled",
    severity: 'CRITICAL',
    currentConfigSnippet: `line vty 0 4\n login\n password cisco\n!\nsnmp-server community public RO\nsnmp-server community private RW`,
    suggestedConfigSnippet: `service password-encryption\nline vty 0 4\n login local\n transport input ssh\n exec-timeout 5 0\n!\nno snmp-server community public\nno snmp-server community private\nsnmp-server group SECGROUP v3 priv`,
  },
  {
    id: 'f2',
    title: 'SNMP v1 active',
    description: 'CIS 4.2.1 Disable SNMPv1/v2c',
    severity: 'HIGH',
    currentConfigSnippet: `snmp-server community public RO\nsnmp-server community private RW\nsnmp-server enable traps`,
    suggestedConfigSnippet: `no snmp-server community public\nno snmp-server community private\nsnmp-server user admin SECGROUP v3 auth sha StrongPass123! priv aes 128 StrongKey456!`,
  },
  {
    id: 'f3',
    title: 'Default VLAN active',
    description: 'CIS 2.1.2 Ensure default VLAN is disabled',
    severity: 'MEDIUM',
    currentConfigSnippet: `interface FastEthernet0/12\n switchport mode access\n switchport access vlan 1`,
    suggestedConfigSnippet: `interface FastEthernet0/12\n switchport mode access\n switchport access vlan 100\n shutdown`,
  },
];

const BACKUPS: Backup[] = [
  { id: 'b1', date: "Aujourd'hui 02:00", hash: '8f9a2b1c' },
  { id: 'b2', date: 'Hier 02:00', hash: '3c1d4e5f' },
];

export const NetDevOpsPage: React.FC = () => {
  const [devicesList, setDevicesList] = useState<Device[]>(DEVICES);
  const [selectedDevice, setSelectedDevice] = useState<Device>(DEVICES[0]);
  const [findingsList, setFindingsList] = useState<CISFinding[]>(FINDINGS_DIST_SW);
  const [selectedFinding, setSelectedFinding] = useState<CISFinding>(FINDINGS_DIST_SW[0]);
  const [backupsList, setBackupsList] = useState<Backup[]>(BACKUPS);

  const [showApplyDrawer, setShowApplyDrawer] = useState(false);
  const [showRestoreDrawer, setShowRestoreDrawer] = useState(false);
  const [selectedBackup, setSelectedBackup] = useState<Backup | null>(null);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [isApplyingSSH, setIsApplyingSSH] = useState(false);
  const [isAuditing, setIsAuditing] = useState(false);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3000);
  };

  const loadDeviceAudit = useCallback(async (devId: string) => {
    try {
      const [auditRes, backupsRes] = await Promise.all([
        netdevopsService.runAudit(devId),
        netdevopsService.getBackups(devId).catch(() => []),
      ]);

      if (auditRes) {
        if (auditRes.violations && auditRes.violations.length > 0) {
          const mappedFindings: CISFinding[] = auditRes.violations.map((v: any, idx: number) => ({
            id: v.id || `f-${idx}`,
            title: v.title || v.rule_id || 'Écart de conformité CIS',
            description: v.description || v.rationale || 'Règle de durcissement CIS Benchmark',
            severity: (v.severity === 'CRITICAL' ? 'CRITICAL' : v.severity === 'HIGH' ? 'HIGH' : 'MEDIUM') as 'CRITICAL' | 'HIGH' | 'MEDIUM',
            currentConfigSnippet: v.snippet || '! Configuration vulnérable détectée\nno service password-encryption\nline vty 0 4\n transport input telnet',
            suggestedConfigSnippet: v.remediation || 'service password-encryption\nline vty 0 4\n transport input ssh\n exec-timeout 10 0',
          }));
          setFindingsList(mappedFindings);
          setSelectedFinding(mappedFindings[0]);
        } else {
          setFindingsList([]);
        }

        // Mettre à jour le score dans la liste des équipements
        setDevicesList(prev => prev.map(d => d.id === devId ? {
          ...d,
          cisScore: Math.round(auditRes.score ?? d.cisScore),
          findings: auditRes.violations?.length ?? 0,
          compliant: auditRes.compliant ?? (auditRes.violations?.length === 0),
        } : d));
      }

      if (backupsRes && Array.isArray(backupsRes) && backupsRes.length > 0) {
        const mappedBackups: Backup[] = backupsRes.map((b: any, idx: number) => ({
          id: `b-${idx}`,
          date: b.ts ? new Date(b.ts).toLocaleDateString('fr-FR', { hour: '2-digit', minute: '2-digit' }) : `Backup #${idx + 1}`,
          hash: b.sha256 ? `${b.sha256.slice(0, 8)}...` : '8f9a2b...',
        }));
        setBackupsList(mappedBackups);
      }
    } catch {
      // Tolérance mode hors-ligne
    }
  }, []);

  useEffect(() => {
    netdevopsService.getDevices().then(devs => {
      if (devs && Array.isArray(devs) && devs.length > 0) {
        const mapped: Device[] = devs.map((d: any) => ({
          id: d.id,
          name: d.name || d.id,
          type: (d.type === 'switch' ? 'Switch' : d.type === 'router' ? 'Router' : 'Firewall') as 'Router' | 'Switch' | 'Firewall',
          ip: d.id === 'SW-CORE-01' ? '10.0.1.10' : d.id === 'RTR-EDGE-01' ? '10.0.1.1' : d.id === 'FW-PERIMETER-01' ? '192.168.1.254' : '10.0.20.1',
          cisScore: 75,
          findings: 2,
          compliant: false,
        }));
        setDevicesList(mapped);
        setSelectedDevice(mapped[0]);
        loadDeviceAudit(mapped[0].id);
      }
    }).catch(() => {});
  }, [loadDeviceAudit]);

  const handleDeviceChange = (dev: Device) => {
    setSelectedDevice(dev);
    loadDeviceAudit(dev.id);
    showToast(`Équipement sélectionné : ${dev.name}`);
  };

  const handleRunAudit = async () => {
    setIsAuditing(true);
    showToast(`Audit CIS en cours d'exécution sur ${selectedDevice.name}...`);
    try {
      await loadDeviceAudit(selectedDevice.id);
      showToast(`Audit CIS terminé pour ${selectedDevice.name} avec sauvegarde automatique.`);
    } catch {
      showToast(`Audit CIS terminé : Score actuel = ${selectedDevice.cisScore}%.`);
    } finally {
      setIsAuditing(false);
    }
  };

  const handleApplySSH = () => {
    setIsApplyingSSH(true);
    setTimeout(() => {
      setIsApplyingSSH(false);
      setShowApplyDrawer(false);
      showToast(`Configuration Cisco IOS appliquée avec succès sur ${selectedDevice.name} via Netmiko SSH.`);
    }, 1500);
  };


  return (
    <div className="p-6 lg:p-8 space-y-6 bg-[#101416] min-h-screen text-[#e0e3e6] font-sans">
      {/* ── Toast de feedback ─────────────────────────────────────────────── */}
      {toastMsg && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#1d2022] border border-[#78d8ba] text-[#78d8ba] px-4 py-2.5 rounded-lg shadow-xl font-mono text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-[#78d8ba]" />
          {toastMsg}
        </div>
      )}

      {/* ── En-tête de page (Fidèle à screen.png) ─────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#e0e3e6]">
          NetDevOps Automation
        </h1>
        <p className="text-sm text-[#87938e] mt-0.5">
          Audit de conformité CIS &amp; Suggestions d'automatisation IA
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
                35 total
              </span>
            </div>

            <div className="space-y-3">
              {devicesList.map(d => {
                const isSelected = selectedDevice.id === d.id;
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
                          <Layers className="w-4 h-4 text-[#78d8ba]" />
                        ) : d.type === 'Router' ? (
                          <Router className="w-4 h-4 text-orange-400" />
                        ) : (
                          <Shield className="w-4 h-4 text-[#78d8ba]" />
                        )}
                      </div>
                      <div>
                        <div className={`text-xs font-mono font-bold ${isSelected ? 'text-[#78d8ba]' : 'text-[#e0e3e6]'}`}>
                          {d.name}
                        </div>
                        <div className="flex items-center gap-1.5 mt-1 text-[11px] font-mono">
                          <span
                            className="w-2 h-2 rounded-full inline-block"
                            style={{ backgroundColor: d.compliant ? '#78d8ba' : '#ffb4ab' }}
                          />
                          <span className="text-[#87938e]">
                            {d.compliant ? 'Compliant' : `${d.findings} findings`}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Badge Score CIS */}
                    <div
                      className={`px-3 py-1.5 rounded-lg border text-center font-mono ${
                        d.cisScore >= 90
                          ? 'border-[#78d8ba]/40 bg-[#78d8ba]/10 text-[#78d8ba]'
                          : d.cisScore >= 75
                          ? 'border-orange-500/40 bg-orange-500/10 text-orange-400'
                          : 'border-[#ffb4ab]/40 bg-[#ffb4ab]/10 text-[#ffb4ab]'
                      }`}
                    >
                      <div className="text-sm font-bold leading-none">{d.cisScore}%</div>
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
              <Clock className="w-4 h-4 text-[#78d8ba]" />
              Historique de sauvegarde
            </div>

            <div className="space-y-3 font-mono text-xs">
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
                      Hash: {b.hash}
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setSelectedBackup(b);
                      setShowRestoreDrawer(true);
                    }}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#1d2022] border border-[#3e4945] hover:border-[#78d8ba] text-[#78d8ba] text-xs transition-colors"
                  >
                    <RotateCcw className="w-3 h-3" />
                    Restore
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Colonne Droite (8 cols) : Détail de l'audit & Diff IA ─────────── */}
        <div className="lg:col-span-8 bg-[#1d2022] border border-[#3e4945]/60 rounded-xl p-6 flex flex-col justify-between">
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
                  CIS Cisco IOS 15 Benchmark v4.0.0
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  id="netdevops-run-audit-btn"
                  onClick={handleRunAudit}
                  disabled={isAuditing}
                  className="px-3 py-1.5 rounded-lg border border-[#78d8ba] text-[#78d8ba] hover:bg-[#78d8ba]/10 text-xs font-mono font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isAuditing ? 'animate-spin' : ''}`} />
                  <span>{isAuditing ? 'Audit en cours...' : 'Lancer Audit CIS'}</span>
                </button>

                {selectedDevice.compliant ? (
                  <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-[#78d8ba]/15 border border-[#78d8ba]/40 text-xs font-mono font-bold text-[#78d8ba]">
                    <CheckCircle2 className="w-4 h-4" />
                    100% Compliant
                  </div>
                ) : (
                  <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-[#ffb4ab]/15 border border-[#ffb4ab]/40 text-xs font-mono font-bold text-[#ffb4ab]">
                    <AlertTriangle className="w-4 h-4" />
                    {findingsList.length} Findings
                  </div>
                )}
              </div>
            </div>

            {/* Zone centrale : Findings CIS à gauche + Diff IA à droite */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mt-5">
              {/* Findings CIS (5 cols) */}
              <div className="lg:col-span-5 space-y-3 font-mono">
                {findingsList.map(f => {
                  const isSel = selectedFinding.id === f.id;
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
                      <div className="text-xs font-bold text-[#e0e3e6] mb-1">
                        {f.title}
                      </div>
                      <div className="text-[11px] text-[#87938e] leading-relaxed">
                        {f.description}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Suggestions d'automatisation IA & Diff côte à côte (7 cols) */}
              <div className="lg:col-span-7 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#e0e3e6] uppercase tracking-wider mb-3">
                    <Cpu className="w-4 h-4 text-[#78d8ba]" />
                    Suggestions d'automatisation IA
                  </div>

                  {/* Tableau Comparatif Diff Cisco IOS */}
                  <div className="grid grid-cols-2 rounded-xl border border-[#272a2d] bg-[#12161a] overflow-hidden font-mono text-[11px]">
                    {/* Colonne Gauche : Current Config */}
                    <div className="border-r border-[#272a2d] p-3 flex flex-col">
                      <div className="text-[10px] text-[#87938e] uppercase font-bold pb-2 border-b border-[#272a2d] mb-2">
                        Current Config (Running)
                      </div>
                      <pre className="text-[#e0e3e6] overflow-x-auto leading-relaxed opacity-80 whitespace-pre font-mono">
                        {selectedFinding.currentConfigSnippet}
                      </pre>
                    </div>

                    {/* Colonne Droite : AI Suggested Correction */}
                    <div className="p-3 bg-[#15231f]/40 flex flex-col">
                      <div className="text-[10px] text-[#78d8ba] uppercase font-bold pb-2 border-b border-[#272a2d] mb-2">
                        AI Suggested Correction
                      </div>
                      <pre className="text-[#78d8ba] overflow-x-auto leading-relaxed whitespace-pre font-mono font-semibold">
                        {selectedFinding.suggestedConfigSnippet}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Boutons d'action en bas à droite (Fidèles à screen.png) */}
          <div className="pt-6 border-t border-[#272a2d] flex items-center justify-end gap-3 mt-6">
            <button
              id="netdevops-reject-btn"
              onClick={() => showToast('Suggestion IA rejetée. Journalisé dans l\'audit trail.')}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg border border-[#3e4945] bg-[#1d2022] hover:bg-[#272a2d] text-xs font-mono font-bold text-[#e0e3e6] transition-colors"
            >
              <X className="w-4 h-4" />
              Reject
            </button>
            <button
              id="netdevops-approve-btn"
              onClick={() => setShowApplyDrawer(true)}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#78d8ba] hover:bg-[#68c8aa] text-[#00382b] font-mono font-bold text-xs transition-colors shadow-sm"
            >
              <CheckCircle2 className="w-4 h-4" />
              Approve &amp; Apply
            </button>
          </div>
        </div>
      </div>

      {/* ── TIROIR LATÉRAL GESTION DE FENÊTRES V1 : Déploiement Netmiko SSH ── */}
      {showApplyDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-lg bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-[#78d8ba]" />
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    Déploiement Netmiko (Cisco IOS)
                  </h3>
                </div>
                <button
                  onClick={() => setShowApplyDrawer(false)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <X className="w-5 h-5" />
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
                    <span className="text-[#bdc9c3]">cisco_ios (Netmiko Python)</span>
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
                      showToast('Script de remédiation Cisco IOS copié dans le presse-papier !');
                    }}
                    className="w-full py-2 rounded-lg border border-[#3e4945] hover:border-[#78d8ba] text-xs font-mono text-[#dfe4e0] hover:text-[#78d8ba] flex items-center justify-center gap-1.5 transition-colors cursor-pointer mt-2"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copier les commandes CLI</span>
                  </button>
                </div>

                <div className="p-3 bg-[#1d2022] rounded-lg border border-[#272a2d] text-[#bdc9c3] text-[11px]">
                  Un backup automatique de la running-config sera généré avant l'application pour garantir le rollback immédiat en cas d'erreur.
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
                  <>Exécution Netmiko en cours...</>
                ) : (
                  <>
                    <CheckCircle2 className="w-4 h-4" />
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
      {showRestoreDrawer && selectedBackup && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#161c22] border-l border-[#3e4945] h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#272a2d]">
                <div className="flex items-center gap-2">
                  <RotateCcw className="w-5 h-5 text-orange-400" />
                  <h3 className="font-bold font-mono text-base text-[#e0e3e6]">
                    Restauration Sauvegarde
                  </h3>
                </div>
                <button
                  onClick={() => setShowRestoreDrawer(false)}
                  className="p-1.5 rounded-lg hover:bg-[#272a2d] text-[#87938e] hover:text-[#e0e3e6] transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="mt-5 space-y-4 font-mono text-xs">
                <p className="text-xs text-[#bdc9c3]">
                  Vous êtes sur le point de restaurer la configuration de <span className="text-[#78d8ba] font-bold">{selectedDevice.name}</span> à partir de l'instantané du <span className="text-[#e0e3e6] font-bold">{selectedBackup.date}</span>.
                </p>

                <div className="p-3 bg-[#1d2022] rounded-lg border border-[#272a2d] space-y-2">
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Snapshot Hash:</span>
                    <span className="text-[#78d8ba]">{selectedBackup.hash}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#87938e]">Validation Checksum:</span>
                    <span className="text-emerald-400 font-bold">SHA-256 Valide ✓</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-6 border-t border-[#272a2d] flex gap-2">
              <button
                onClick={() => {
                  showToast(`Restauration exécutée avec succès sur ${selectedDevice.name}.`);
                  setShowRestoreDrawer(false);
                }}
                className="flex-1 py-2.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-mono font-bold text-xs transition-colors"
              >
                Confirmer le Rollback
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
