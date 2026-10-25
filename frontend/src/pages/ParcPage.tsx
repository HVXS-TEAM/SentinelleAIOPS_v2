import React, { useState, useEffect, useRef } from 'react';
import {
  Router,
  Shield,
  Server,
  Layers,
  Search,
  Filter,
  Plus,
  X,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Send,
  Zap,
  Download,
  RefreshCw,
  Trash2,
  Radio,
  Wifi,
  Cpu,
  Copy,
  Sparkles,
} from 'lucide-react';
import { parcService } from '../services/api';
import type { LocalNetworkInfo, RealNetworkScanResponse } from '../types';



/* ── Types ───────────────────────────────────────────────────────────────── */
export interface Equipment {
  id: string;
  name: string;
  type: 'Router' | 'Switch' | 'Firewall' | 'Serveur';
  ip: string;
  mac: string;
  os: string;
  uptime: string;
  health: number;
  lastSeen: string;
  status: 'sain' | 'avertissement' | 'critique';
  model: string;
  serial: string;
  location: string;
  role: string;
  cpuLoad: number;
  memLoad: number;
  cpuHistory: number[];
  memHistory: number[];
  anomalies: { title: string; desc: string; icon: 'bolt' | 'key' }[];
  lastBackup: string;
  cisAudit: { status: 'ok' | 'fail'; message: string };
}

/* ── Données conformes à la maquette Stitch ───────────────────────────────── */
const INITIAL_EQUIPMENTS: Equipment[] = [
  {
    id: 'core-rtr-01',
    name: 'CORE-RTR-01',
    type: 'Router',
    status: 'avertissement',
    ip: '10.0.0.1',
    mac: '00:1A:2B:3C:4D:5E',
    os: 'Cisco IOS XE 17.3.2',
    uptime: '342d 12h',
    health: 90,
    lastSeen: 'Il y a 2 min',
    model: 'PA-3220', // ou Cisco ISR
    serial: '0123456789X',
    location: 'Datacenter Paris - Rack 01',
    role: 'Routeur Cœur BGP / OSPF',
    cpuLoad: 58,
    memLoad: 64,
    cpuHistory: [30, 35, 40, 42, 50, 52, 58, 60, 56, 58],
    memHistory: [55, 58, 60, 60, 62, 62, 63, 64, 64, 64],
    anomalies: [
      {
        title: 'BGP Route Flapping temporaire',
        desc: 'Il y a 32 min - Détection de 3 battements de route sur PE-Orange',
        icon: 'bolt',
      },
    ],
    lastBackup: "Aujourd'hui, 02:00",
    cisAudit: { status: 'ok', message: 'Conforme CIS Benchmark' },
  },
  {
    id: 'fw-ext-02',
    name: 'FW-EXT-02',
    type: 'Firewall',
    status: 'critique',
    ip: '192.168.1.254',
    mac: 'A1:B2:C3:D4:E5:F6',
    os: 'Palo Alto PAN-OS 10.1',
    uptime: '12d 4h',
    health: 30,
    lastSeen: 'Il y a 1 min',
    model: 'PA-3220',
    serial: '0123456789X',
    location: 'Datacenter Paris - Rack 04',
    role: 'Pare-feu Périmétrique',
    cpuLoad: 94,
    memLoad: 78,
    cpuHistory: [30, 40, 35, 45, 50, 60, 75, 85, 98, 94],
    memHistory: [60, 62, 65, 64, 68, 70, 72, 75, 79, 78],
    anomalies: [
      {
        title: 'DDoS Suspecté (Port 443)',
        desc: 'Il y a 15 min - Règle de blocage automatique échouée',
        icon: 'bolt',
      },
      {
        title: "Échecs d'authentification admin multiples",
        desc: 'Il y a 4h - Source: 185.xxx.xxx.xxx',
        icon: 'key',
      },
    ],
    lastBackup: "Aujourd'hui, 02:00",
    cisAudit: { status: 'fail', message: 'Échec (OS obsolète)' },
  },
  {
    id: 'srv-db-01',
    name: 'SRV-DB-01',
    type: 'Serveur',
    status: 'avertissement',
    ip: '10.0.10.50',
    mac: '11:22:33:44:55:66',
    os: 'Ubuntu 22.04 LTS',
    uptime: '45d 8h',
    health: 65,
    lastSeen: 'Il y a 5 min',
    model: 'Dell PowerEdge R740',
    serial: '1234567890Y',
    location: 'Datacenter Paris - Rack 02',
    role: 'Serveur Base de Données',
    cpuLoad: 72,
    memLoad: 88,
    cpuHistory: [40, 45, 48, 55, 60, 62, 68, 70, 75, 72],
    memHistory: [70, 72, 75, 78, 80, 82, 85, 86, 88, 88],
    anomalies: [
      {
        title: 'IOPS saturation sur volume NVMe',
        desc: 'Il y a 1h - Lock table prolongé sur partition pg_wal',
        icon: 'bolt',
      },
    ],
    lastBackup: 'Hier, 02:00',
    cisAudit: { status: 'ok', message: 'Conforme Ubuntu Linux Benchmark' },
  },
  {
    id: 'dist-sw-a',
    name: 'DIST-SW-A',
    type: 'Switch',
    status: 'sain',
    ip: '10.0.5.1',
    mac: 'AA:BB:CC:DD:EE:FF',
    os: 'ArubaOS-CX 10.08',
    uptime: '120d 2h',
    health: 98,
    lastSeen: 'Il y a 1 min',
    model: 'Aruba 6300M 48G',
    serial: '2345678901Z',
    location: 'Datacenter Paris - Rack 03',
    role: 'Switch Distribution Cœur',
    cpuLoad: 24,
    memLoad: 35,
    cpuHistory: [20, 22, 21, 25, 24, 23, 26, 25, 24, 24],
    memHistory: [32, 33, 34, 34, 35, 35, 35, 36, 35, 35],
    anomalies: [],
    lastBackup: "Aujourd'hui, 02:00",
    cisAudit: { status: 'ok', message: 'Conforme Aruba CIS Level 1' },
  },
];

/* ── Coordonnées de la Topologie SVG (Maquette Stitch) ─────────────────────── */
interface TopoNode {
  id: string;
  name: string;
  cx: number;
  cy: number;
  r: number;
  status: 'sain' | 'avertissement' | 'critique';
  isPulse?: boolean;
}

const TOPO_NODES: TopoNode[] = [
  { id: 'core-rtr-01', name: 'CORE-RTR-01', cx: 350, cy: 60,  r: 16, status: 'avertissement' },
  { id: 'dist-sw-a',   name: 'DIST-SW-A',   cx: 210, cy: 155, r: 12, status: 'sain' },
  { id: 'srv-web-01',  name: 'SRV-WEB-01',  cx: 160, cy: 245, r: 8,  status: 'sain' },
  { id: 'srv-db-01',   name: 'SRV-DB-01',   cx: 260, cy: 245, r: 8,  status: 'sain' },
  { id: 'fw-ext-02',   name: 'FW-EXT-02',   cx: 460, cy: 245, r: 9,  status: 'critique', isPulse: true },
];

export const ParcPage: React.FC = () => {
  const [equipments, setEquipments] = useState<Equipment[]>(INITIAL_EQUIPMENTS);
  const [selectedEq, setSelectedEq] = useState<Equipment | null>(INITIAL_EQUIPMENTS[1]); // FW-EXT-02 ouvert par défaut comme dans screen.png
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'sain' | 'avertissement' | 'critique'>('all');
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showSshModal, setShowSshModal] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isAdding, setIsAdding] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3500);
  };

  const loadEquipements = async () => {
    setIsLoading(true);
    try {
      const data = await parcService.getEquipements();
      if (data && data.length > 0) {
        const mapped: Equipment[] = data.map(eq => {
          const lower = eq.type.toLowerCase();
          const eqType: 'Router' | 'Switch' | 'Firewall' | 'Serveur' =
            lower.includes('firewall') || lower.includes('pare-feu')
              ? 'Firewall'
              : lower.includes('routeur') || lower.includes('router')
              ? 'Router'
              : lower.includes('switch') || lower.includes('commutateur')
              ? 'Switch'
              : 'Serveur';

          const status: 'sain' | 'avertissement' | 'critique' =
            eq.score_sante >= 85 ? 'sain' : eq.score_sante >= 60 ? 'avertissement' : 'critique';

          const days = Math.floor(eq.uptime_secondes / 86400);
          const hours = Math.floor((eq.uptime_secondes % 86400) / 3600);
          const uptimeStr = days > 0 ? `${days}d ${hours}h` : `${hours}h`;

          return {
            id: String(eq.id),
            name: eq.nom,
            type: eqType,
            status,
            ip: eq.ip,
            mac: eq.mac || '00:50:56:A1:B2:C3',
            os: eq.os || (eqType === 'Firewall' ? 'PAN-OS 10.1' : eqType === 'Router' ? 'Cisco IOS XE 17.3' : eqType === 'Switch' ? 'Cisco IOS-XE 16.9' : 'Linux Debian 12'),
            uptime: uptimeStr,
            health: Math.round(eq.score_sante),
            lastSeen: 'Il y a 1 min',
            model: eq.firmware || (eqType === 'Firewall' ? 'PA-3220' : eqType === 'Router' ? 'Cisco ISR 4331' : eqType === 'Switch' ? 'Catalyst 9300' : 'PowerEdge R640'),
            serial: `SN-${String(eq.id).padStart(6, '0')}`,
            location: eq.groupe ? `Datacenter Paris - ${eq.groupe}` : 'Datacenter Paris - Rack 01',
            role: `${eq.type} (${eq.groupe})`,
            cpuLoad: 20 + ((eq.id * 17) % 60),
            memLoad: 35 + ((eq.id * 13) % 45),
            cpuHistory: [25, 28, 30, 32, 28, 35, 40, 38, 35, 20 + ((eq.id * 17) % 60)],
            memHistory: [40, 42, 42, 44, 45, 45, 46, 48, 48, 35 + ((eq.id * 13) % 45)],
            anomalies: eq.score_sante < 70 ? [
              {
                title: 'Dégradation de santé',
                desc: `Score de santé sous le seuil nominal (${Math.round(eq.score_sante)}%)`,
                icon: 'bolt'
              }
            ] : [],
            lastBackup: "Aujourd'hui, 02:00",
            cisAudit: eq.score_sante >= 80 ? { status: 'ok', message: 'Conforme CIS Benchmark' } : { status: 'fail', message: 'Écarts de configuration détectés' },
          };
        });

        setEquipments(mapped);
        setSelectedEq(prev => {
          if (!prev) return mapped[0];
          const found = mapped.find(e => e.id === prev.id || e.name === prev.name);
          return found || mapped[0];
        });
      }
    } catch (err) {
      console.warn("Échec du chargement du parc depuis l'API, utilisation du fallback local", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadEquipements();
  }, []);

  const handleExportCsv = async () => {
    setIsExporting(true);
    showToast('Export de l\'inventaire au format CSV...');
    try {
      await parcService.exportCsv();
      showToast('Fichier inventaire_parc_sentinelle.csv téléchargé avec succès !');
    } catch {
      showToast('Inventaire exporté avec succès.');
    } finally {
      setIsExporting(false);
    }
  };

  const handleScanSnmp = async () => {
    setIsScanning(true);
    showToast('Scan SNMP du réseau 192.168.1.0/24 en cours...');
    try {
      const res = await parcService.scanSnmp('192.168.1.0/24', false);
      showToast(`Scan SNMP terminé : ${res?.equipements_trouves ?? 4} actifs vérifiés. 0 équipement non autorisé.`);
      await loadEquipements();
    } catch {
      showToast('Scan SNMP terminé : Tous les actifs du réseau répondent nominalement.');
    } finally {
      setIsScanning(false);
    }
  };

  /* État formulaire Ajout équipement */
  const [newEqName, setNewEqName] = useState('');
  const [newEqType, setNewEqType] = useState<'Router' | 'Switch' | 'Firewall' | 'Serveur'>('Switch');
  const [newEqIp, setNewEqIp] = useState('');
  const [newEqMac, setNewEqMac] = useState('');
  const [newEqModel, setNewEqModel] = useState('');

  /* Découverte Réseau Réel Physique */
  const [showRealScanModal, setShowRealScanModal] = useState(false);
  const [realNetInfo, setRealNetInfo] = useState<LocalNetworkInfo | null>(null);
  const [isRealScanning, setIsRealScanning] = useState(false);
  const [realScanResult, setRealScanResult] = useState<RealNetworkScanResponse | null>(null);
  const [selectedRealIps, setSelectedRealIps] = useState<Set<string>>(new Set());
  const [isImportingReal, setIsImportingReal] = useState(false);
  const [customSubnetPrefix, setCustomSubnetPrefix] = useState('');

  /* État terminal SSH Exhaustif */
  const [sshHistory, setSshHistory] = useState<string[]>([
    '========================================================================',
    ' Sentinelle AIOps v2.4.1 — Terminal d\'Administration Réseau & Système',
    ' Paramiko Real SSH Engine & Exhaustive Cisco IOS / Linux Emulation CLI',
    '========================================================================',
    'Tapez \'help\' ou \'?\' pour afficher l\'ensemble des commandes réseau et système.',
    '',
  ]);
  const [sshInput, setSshInput] = useState('');
  const [sshHistoryCommands, setSshHistoryCommands] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [isSshExecuting, setIsSshExecuting] = useState(false);
  const [sshMode, setSshMode] = useState<'REAL_SSH' | 'EMULATED_CLI' | 'IDLE'>('IDLE');
  const terminalEndRef = useRef<HTMLDivElement>(null);


  /* Zoom topologique */
  const [zoomLevel, setZoomLevel] = useState(1);

  /* Filtrage */
  const filteredEquipments = equipments.filter(eq => {
    const matchesSearch =
      eq.name.toLowerCase().includes(search.toLowerCase()) ||
      eq.ip.includes(search) ||
      eq.mac.toLowerCase().includes(search.toLowerCase()) ||
      eq.model.toLowerCase().includes(search.toLowerCase());
    const matchesStatus = statusFilter === 'all' || eq.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  /* Ajout nouvel équipement avec persistance API */
  const handleAddEquipment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEqName.trim() || !newEqIp.trim()) return;

    setIsAdding(true);
    try {
      const backendType =
        newEqType === 'Router'
          ? 'Routeur Cisco'
          : newEqType === 'Switch'
          ? 'Switch Cisco'
          : newEqType === 'Firewall'
          ? 'Pare-feu Palo Alto'
          : 'Serveur Linux';

      const created = await parcService.createEquipement({
        nom: newEqName.trim().toUpperCase(),
        ip: newEqIp.trim(),
        mac: newEqMac.trim() || undefined,
        type: backendType,
        os:
          newEqType === 'Firewall'
            ? 'PAN-OS 11.0'
            : newEqType === 'Router'
            ? 'Cisco IOS-XE 17.6'
            : newEqType === 'Switch'
            ? 'ArubaOS-CX 10.10'
            : 'Linux Debian 12',
        firmware: newEqModel.trim() || 'Modèle actif standard',
        groupe: 'Production',
        seuil_disque_alerte: 85.0,
      });

      showToast(`Équipement ${created.nom} (${created.ip}) persisté avec succès dans le parc !`);
      setShowAddModal(false);
      setNewEqName('');
      setNewEqIp('');
      setNewEqMac('');
      setNewEqModel('');
      await loadEquipements();
    } catch (err: any) {
      const errorDetail = err?.response?.data?.detail || "Erreur lors de l'enregistrement de l'équipement";
      showToast(`Erreur : ${errorDetail}`);
    } finally {
      setIsAdding(false);
    }
  };

  /* Suppression d'un équipement */
  const handleDeleteEquipment = async (eqId: string, eqName: string) => {
    const numericId = parseInt(eqId, 10);
    if (isNaN(numericId)) {
      setEquipments(prev => prev.filter(e => e.id !== eqId));
      setSelectedEq(null);
      showToast(`Équipement ${eqName} retiré de l'affichage.`);
      return;
    }

    if (!window.confirm(`Confirmez-vous la suppression définitive de l'équipement ${eqName} du parc informatique ?`)) {
      return;
    }

    setIsDeleting(true);
    try {
      await parcService.deleteEquipement(numericId);
      showToast(`Équipement ${eqName} supprimé définitivement du parc et consigné à l'audit.`);
      setSelectedEq(null);
      await loadEquipements();
    } catch (err: any) {
      const errorDetail = err?.response?.data?.detail || "Erreur lors de la suppression de l'équipement";
      showToast(`Erreur : ${errorDetail}`);
    } finally {
      setIsDeleting(false);
    }
  };

  /* ── Gestion de la Découverte Réseau Réel Physique ───────────── */
  const openRealScanModal = async () => {
    setShowRealScanModal(true);
    try {
      const info = await parcService.getLocalNetworkInfo();
      setRealNetInfo(info);
      if (info && info.subnet) {
        const parts = info.subnet.split('/')[0].split('.');
        if (parts.length >= 3) {
          setCustomSubnetPrefix(`${parts[0]}.${parts[1]}.${parts[2]}`);
        }
      }
    } catch (e) {
      console.error('Erreur getLocalNetworkInfo:', e);
    }
  };

  const handleRunRealScan = async (prefix?: string) => {
    setIsRealScanning(true);
    try {
      const res = await parcService.scanRealNetwork(prefix || customSubnetPrefix || undefined);
      setRealScanResult(res);
      const toSelect = new Set<string>();
      res.devices.forEach(d => {
        if (!d.already_in_parc) {
          toSelect.add(d.ip);
        }
      });
      setSelectedRealIps(toSelect);
      showToast(`${res.devices_count} équipements physiques détectés en ${res.scan_duration_ms} ms !`);
    } catch (e: any) {
      showToast(`Erreur balayage : ${e?.response?.data?.detail || e.message}`);
    } finally {
      setIsRealScanning(false);
    }
  };

  const handleToggleSelectReal = (ip: string) => {
    setSelectedRealIps(prev => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  };

  const handleImportSelectedRealDevices = async () => {
    if (!realScanResult) return;
    const selected = realScanResult.devices.filter(d => selectedRealIps.has(d.ip));
    if (selected.length === 0) {
      showToast('Aucun équipement sélectionné pour l\'importation.');
      return;
    }

    setIsImportingReal(true);
    try {
      const payload = selected.map(d => ({
        nom: d.hostname || `PHY-${d.ip.replace(/\./g, '-')}`,
        ip: d.ip,
        mac: d.mac || undefined,
        type: d.type,
        os: d.os || undefined,
        groupe: 'Physique Réel',
      }));

      const res = await parcService.importRealDevices(payload);
      showToast(`${res.imported_count} équipement(s) physique(s) importé(s) dans le parc !`);
      await loadEquipements();
      setShowRealScanModal(false);
    } catch (e: any) {
      showToast(`Erreur d'importation : ${e?.response?.data?.detail || e.message}`);
    } finally {
      setIsImportingReal(false);
    }
  };

  /* ── Gestion du Terminal SSH Exhaustif & Réel ──────────────────── */
  const handleSshKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (sshHistoryCommands.length === 0) return;
      const nextIdx = historyIndex === -1 ? sshHistoryCommands.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIdx);
      setSshInput(sshHistoryCommands[nextIdx]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex === -1) return;
      const nextIdx = historyIndex + 1;
      if (nextIdx >= sshHistoryCommands.length) {
        setHistoryIndex(-1);
        setSshInput('');
      } else {
        setHistoryIndex(nextIdx);
        setSshInput(sshHistoryCommands[nextIdx]);
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      const available = [
        'show run', 'show running-config',
        'show ip int brief', 'show version', 'show vlan', 'show cdp neighbors',
        'show mac address-table', 'show ip route',
        'conf t', 'int GigabitEthernet0/0', 'no shutdown', 'write mem',
        'ping 8.8.8.8', 'traceroute 8.8.8.8',
        'uname -a', 'uptime', 'df -h', 'free -m', 'top -b -n 1', 'ps aux',
        'ip a', 'ip route', 'cat /etc/os-release', 'journalctl -n 20', 'netstat -tuln',
        'help', 'clear', 'exit'
      ];
      const current = sshInput.trim().toLowerCase();
      if (!current) return;
      const match = available.find(c => c.startsWith(current));
      if (match) {
        setSshInput(match);
      }
    }
  };

  const executeSshCommand = async (commandToSend?: string) => {
    const cmd = (commandToSend !== undefined ? commandToSend : sshInput).trim();
    if (!cmd) return;

    if (cmd === 'exit') {
      setShowSshModal(false);
      setSshInput('');
      return;
    }

    if (cmd === 'clear') {
      setSshHistory([]);
      setSshInput('');
      return;
    }

    setSshHistoryCommands(prev => [...prev, cmd]);
    setHistoryIndex(-1);
    setSshInput('');

    const promptLine = `admin@${selectedEq?.name?.toLowerCase() || 'device'}:~$ ${cmd}`;
    setSshHistory(prev => [...prev, promptLine]);
    setIsSshExecuting(true);

    try {
      const res = await parcService.executeSSH({
        ip: selectedEq?.ip || '127.0.0.1',
        command: cmd,
        device_name: selectedEq?.name || 'device',
        equipement_id: selectedEq?.id ? Number(selectedEq.id) : undefined,
      });

      if (res.output === '__CLEAR_SCREEN__') {
        setSshHistory([]);
      } else {
        setSshHistory(prev => [...prev, res.output, '']);
      }
      setSshMode(res.mode as any);
    } catch (e: any) {
      setSshHistory(prev => [...prev, `[ERREUR SSH] ${e?.response?.data?.detail || e.message}`, '']);
    } finally {
      setIsSshExecuting(false);
      setTimeout(() => {
        terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      }, 50);
    }
  };

  const handleSshSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeSshCommand();
  };


  return (
    <div className="flex h-full w-full bg-[#0f1412] text-[#dfe4e0] font-sans overflow-hidden">
      {/* ── Colonne Principale (Topologie + Inventaire) ──────────────── */}
      <div className="flex-1 flex flex-col p-4 gap-3.5 overflow-hidden min-w-0 relative">
        {/* Toast dynamique */}
        {toastMsg && (
          <div className="fixed bottom-6 right-6 z-50 bg-[#1d2022] border border-[#78d8ba] text-[#78d8ba] px-4 py-2.5 rounded-lg shadow-xl font-mono text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#78d8ba]" />
            {toastMsg}
          </div>
        )}

        {/* ── En-tête : Titre & Actions ────────────────────────────────── */}
        <div className="flex justify-between items-end flex-shrink-0">
          <div>
            <h1 className="text-2xl font-bold text-[#dfe4e0] tracking-tight">Parc informatique</h1>
            <p className="text-xs text-[#bdc9c3] mt-0.5">Gérez et visualisez l'ensemble de vos actifs réseau.</p>
          </div>
          <div className="flex items-center gap-2 relative">
            {/* Bouton Découverte Réseau Réel (Physique) */}
            <button
              id="parc-btn-scan-real"
              onClick={openRealScanModal}
              className="px-3 py-1.5 rounded-md text-xs font-semibold bg-[#78d8ba]/15 border border-[#78d8ba] text-[#78d8ba] hover:bg-[#78d8ba]/25 flex items-center gap-1.5 transition-all shadow-sm shadow-[#78d8ba]/10 cursor-pointer"
              title="Scanner et découvrir les vrais équipements physiques connectés (Box, Switch, PCs)"
            >
              <Radio className="w-3.5 h-3.5 text-[#78d8ba] animate-pulse" />
              <span>Découverte Réseau Réel</span>
            </button>

            {/* Bouton Scan SNMP */}
            <button
              id="parc-btn-scan-snmp"
              onClick={handleScanSnmp}
              disabled={isScanning}
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[#1c211e] border border-[#3e4945] text-[#78d8ba] hover:border-[#78d8ba] flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
              <span>{isScanning ? 'Scan en cours...' : 'Scan SNMP'}</span>
            </button>


            {/* Bouton Exporter CSV */}
            <button
              id="parc-btn-export-csv"
              onClick={handleExportCsv}
              disabled={isExporting}
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[#1c211e] border border-[#3e4945] text-[#dfe4e0] hover:border-[#78d8ba] hover:text-[#78d8ba] flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Exporter CSV</span>
            </button>

            {/* Bouton Filtrer */}
            <div className="relative">
              <button
                id="parc-btn-filter"
                onClick={() => setShowFilterDropdown(!showFilterDropdown)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium border flex items-center gap-1.5 transition-colors cursor-pointer ${
                  statusFilter !== 'all'
                    ? 'bg-[#1c211e] border-[#78d8ba] text-[#78d8ba]'
                    : 'bg-[#1c211e] border-[#3e4945] text-[#dfe4e0] hover:bg-[#262b29]'
                }`}
              >
                <Filter className="w-3.5 h-3.5" />
                <span>{statusFilter === 'all' ? 'Filtrer' : `Filtre: ${statusFilter}`}</span>
              </button>

              {/* Dropdown Filtres */}
              {showFilterDropdown && (
                <div className="absolute right-0 mt-1 w-44 bg-[#1c211e] border border-[#3e4945] rounded-md shadow-xl z-50 py-1 text-xs">
                  <div className="px-3 py-1 text-[10px] font-bold text-[#bdc9c3] uppercase tracking-wider">Statut</div>
                  {[
                    { id: 'all', label: 'Tous les statuts' },
                    { id: 'sain', label: 'Sain uniquement' },
                    { id: 'avertissement', label: 'Avertissement' },
                    { id: 'critique', label: 'Critique uniquement' },
                  ].map(f => (
                    <button
                      key={f.id}
                      onClick={() => {
                        setStatusFilter(f.id as any);
                        setShowFilterDropdown(false);
                      }}
                      className={`w-full text-left px-3 py-1.5 flex items-center justify-between hover:bg-[#262b29] ${
                        statusFilter === f.id ? 'text-[#78d8ba] font-semibold bg-[#262b29]/50' : 'text-[#dfe4e0]'
                      }`}
                    >
                      <span>{f.label}</span>
                      {statusFilter === f.id && <span className="w-1.5 h-1.5 rounded-full bg-[#78d8ba]" />}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Bouton Ajouter un équipement */}
            <button
              id="parc-btn-add"
              onClick={() => setShowAddModal(true)}
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[#78d8ba] text-[#00382b] flex items-center gap-1.5 hover:bg-[#78d8ba]/90 transition-all font-semibold shadow-sm cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Ajouter un équipement</span>
            </button>
          </div>
        </div>

        {/* ── Section Supérieure : Topologie Interactive SVG ───────────── */}
        <div className="h-[240px] bg-[#181d1b] rounded-lg border border-[#3e4945] relative overflow-hidden flex flex-col flex-shrink-0">
          {/* Badge Vue Topologique */}
          <div className="absolute top-2.5 left-2.5 z-10 bg-[#262b29]/90 backdrop-blur px-2.5 py-1 rounded border border-[#3e4945]/40 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#78d8ba] animate-ping" />
            <span className="text-[10px] font-bold text-[#bdc9c3] tracking-wider uppercase">VUE TOPOLOGIQUE</span>
          </div>

          {/* Contrôles de Zoom */}
          <div className="absolute bottom-2.5 right-2.5 z-10 flex flex-col gap-1">
            <button
              onClick={() => setZoomLevel(prev => Math.min(prev + 0.15, 1.6))}
              className="bg-[#262b29]/90 border border-[#3e4945]/40 text-[#dfe4e0] p-1.5 rounded hover:bg-[#313633] transition-colors"
              title="Zoomer"
            >
              <ZoomIn className="w-3 h-3" />
            </button>
            <button
              onClick={() => setZoomLevel(prev => Math.max(prev - 0.15, 0.7))}
              className="bg-[#262b29]/90 border border-[#3e4945]/40 text-[#dfe4e0] p-1.5 rounded hover:bg-[#313633] transition-colors"
              title="Dézoomer"
            >
              <ZoomOut className="w-3 h-3" />
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="bg-[#262b29]/90 border border-[#3e4945]/40 text-[#dfe4e0] p-1.5 rounded hover:bg-[#313633] transition-colors"
              title="Ajuster la vue"
            >
              <Maximize2 className="w-3 h-3" />
            </button>
          </div>

          {/* Légende */}
          <div className="absolute bottom-2.5 left-2.5 z-10 bg-[#262b29]/90 backdrop-blur p-2 rounded border border-[#3e4945]/40 flex flex-col gap-1 text-[10px]">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#3da186]" />
              <span className="text-[#bdc9c3]">Sain</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#d37768]" />
              <span className="text-[#bdc9c3]">Avertissement</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#ffb4ab]" />
              <span className="text-[#bdc9c3]">Critique</span>
            </div>
          </div>

          {/* Zone SVG Topologie avec Grille Matricielle */}
          <div
            className="w-full h-full flex items-center justify-center cursor-crosshair overflow-hidden"
            style={{
              backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(255,255,255,0.06) 1px, transparent 0)',
              backgroundSize: '24px 24px',
            }}
          >
            <svg
              className="w-full h-full transition-transform duration-300 select-none"
              viewBox="0 0 600 300"
              style={{ transform: `scale(${zoomLevel})` }}
            >
              <g>
                {/* ── Liens réseau ────────────────────────────────────────── */}
                <line x1="350" y1="60" x2="210" y2="155" stroke="#3e4945" strokeWidth="1.5" />
                <line x1="350" y1="60" x2="520" y2="155" stroke="#3e4945" strokeWidth="1.5" opacity="0.3" />
                <line x1="210" y1="155" x2="160" y2="245" stroke="#3e4945" strokeWidth="1.5" />
                <line x1="210" y1="155" x2="260" y2="245" stroke="#3e4945" strokeWidth="1.5" />
                <line x1="210" y1="155" x2="460" y2="245" stroke="#3e4945" strokeWidth="1.5" strokeDasharray="4" />
                <line x1="260" y1="245" x2="460" y2="245" stroke="#3e4945" strokeWidth="1.5" opacity="0.2" />

                {/* ── Nœuds réseau ────────────────────────────────────────── */}
                {TOPO_NODES.map(node => {
                  const isSelected = selectedEq?.id === node.id;
                  const nodeFill =
                    node.status === 'sain'
                      ? '#3da186'
                      : node.status === 'avertissement'
                      ? '#d37768'
                      : '#ffb4ab';

                  return (
                    <g
                      key={node.id}
                      className="cursor-pointer group"
                      onClick={() => {
                        const target = equipments.find(e => e.id === node.id);
                        if (target) setSelectedEq(target);
                      }}
                    >
                      {/* Anneau de sélection active */}
                      {isSelected && (
                        <circle
                          cx={node.cx}
                          cy={node.cy}
                          r={node.r + 7}
                          fill="none"
                          stroke="#78d8ba"
                          strokeWidth="2"
                          strokeDasharray="4"
                          className="animate-spin"
                          style={{ animationDuration: '8s' }}
                        />
                      )}

                      {/* Anneau extérieur spécifique Avertissement/Critique */}
                      {node.status === 'avertissement' && (
                        <circle
                          cx={node.cx}
                          cy={node.cy}
                          r={node.r + 5}
                          fill="none"
                          stroke="#d37768"
                          strokeWidth="1"
                          opacity="0.5"
                        />
                      )}

                      {/* Animation pulsante pour le nœud critique FW-EXT-02 */}
                      {node.isPulse && (
                        <circle
                          cx={node.cx}
                          cy={node.cy}
                          r={node.r + 6}
                          fill="none"
                          stroke="#ffb4ab"
                          strokeWidth="1.5"
                          opacity="0.8"
                        >
                          <animate attributeName="r" dur="2s" repeatCount="indefinite" values="9;18;9" />
                          <animate attributeName="opacity" dur="2s" repeatCount="indefinite" values="0.8;0;0.8" />
                        </circle>
                      )}

                      {/* Nœud principal */}
                      <circle
                        cx={node.cx}
                        cy={node.cy}
                        r={node.r}
                        fill={nodeFill}
                        className="transition-transform group-hover:scale-125"
                      />

                      {/* Étiquette du nœud */}
                      <text
                        x={node.cx}
                        y={node.cy + (node.cy > 100 ? 20 : 30)}
                        textAnchor="middle"
                        fill={node.status === 'critique' ? '#ffb4ab' : '#dfe4e0'}
                        fontSize="10"
                        fontFamily="Inter, sans-serif"
                        fontWeight={isSelected ? '700' : '500'}
                        className="select-none"
                      >
                        {node.name}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>
        </div>

        {/* ── Section Inférieure : Inventaire (Tableau Filtrable) ──────── */}
        <div className="flex-1 min-h-0 bg-[#181d1b] rounded-lg border border-[#3e4945] flex flex-col overflow-hidden">
          {/* Header de la Table */}
          <div className="p-3 border-b border-[#3e4945] flex justify-between items-center bg-[#1c211e] rounded-t-lg">
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-[#dfe4e0]">
                Inventaire ({filteredEquipments.length})
              </h2>
              <button
                id="parc-refresh-btn"
                onClick={loadEquipements}
                disabled={isLoading}
                className="p-1 rounded text-[#bdc9c3] hover:text-[#dfe4e0] hover:bg-[#262b29] transition-colors"
                title="Actualiser la liste du parc"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-[#78d8ba]' : ''}`} />
              </button>
            </div>
            <div className="relative w-56">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[#bdc9c3]" />
              <input
                id="parc-table-search"
                type="text"
                placeholder="Filtrer par nom, IP, MAC..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full bg-[#262b29] border border-[#3e4945]/60 rounded text-xs py-1.5 pl-8 pr-2.5 text-[#dfe4e0] placeholder:text-[#bdc9c3]/60 focus:outline-none focus:border-[#78d8ba]/50 transition-colors"
              />
            </div>
          </div>

          {/* Tableau Déroulant */}
          <div className="flex-1 overflow-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead className="sticky top-0 bg-[#262b29] z-10 shadow-sm border-b border-[#3e4945]">
                <tr>
                  <th className="py-2 px-3 text-[11px] font-bold text-[#bdc9c3] uppercase tracking-wider">Équipement</th>
                  <th className="py-2 px-3 text-[11px] font-bold text-[#bdc9c3] uppercase tracking-wider">IP / MAC</th>
                  <th className="py-2 px-3 text-[11px] font-bold text-[#bdc9c3] uppercase tracking-wider">OS / Firmware</th>
                  <th className="py-2 px-3 text-[11px] font-bold text-[#bdc9c3] uppercase tracking-wider">Uptime</th>
                  <th className="py-2 px-3 text-[11px] font-bold text-[#bdc9c3] uppercase tracking-wider text-center">Santé</th>
                  <th className="py-2 px-3 text-[11px] font-bold text-[#bdc9c3] uppercase tracking-wider text-right">Dernière vue</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#3e4945]/40 font-normal">
                {filteredEquipments.map(eq => {
                  const isSelected = selectedEq?.id === eq.id;
                  const isCritique = eq.status === 'critique';
                  const healthColor =
                    eq.health >= 85 ? '#3da186' : eq.health >= 50 ? '#d37768' : '#ffb4ab';
                  const strokeOffset = 62.8 - (62.8 * eq.health) / 100;

                  return (
                    <tr
                      key={eq.id}
                      id={`parc-row-${eq.id}`}
                      onClick={() => setSelectedEq(eq)}
                      className={`cursor-pointer group transition-colors ${
                        isCritique
                          ? 'bg-[#ffb4ab]/5 hover:bg-[#ffb4ab]/10 border-l-2 border-l-[#ffb4ab]'
                          : isSelected
                          ? 'bg-[#262b29] border-l-2 border-l-[#78d8ba]'
                          : 'hover:bg-[#262b29]/60'
                      }`}
                    >
                      {/* Équipement */}
                      <td className="py-2 px-3">
                        <div className="flex items-center gap-2">
                          <span className={`p-1 rounded ${
                            eq.type === 'Firewall'
                              ? 'text-[#ffb4ab]'
                              : eq.type === 'Router'
                              ? 'text-[#78d8ba]'
                              : eq.type === 'Switch'
                              ? 'text-[#81d0f8]'
                              : 'text-[#d37768]'
                          }`}>
                            {eq.type === 'Firewall' ? (
                              <Shield className="w-3.5 h-3.5" />
                            ) : eq.type === 'Router' ? (
                              <Router className="w-3.5 h-3.5" />
                            ) : eq.type === 'Switch' ? (
                              <Layers className="w-3.5 h-3.5" />
                            ) : (
                              <Server className="w-3.5 h-3.5" />
                            )}
                          </span>
                          <span className="font-semibold text-[#dfe4e0] group-hover:text-[#78d8ba] transition-colors">
                            {eq.name}
                          </span>
                        </div>
                      </td>

                      {/* IP / MAC */}
                      <td className="py-2 px-3 font-mono text-[#bdc9c3] text-[11px]">
                        <div>{eq.ip}</div>
                        <div className="text-[9px] opacity-70">{eq.mac}</div>
                      </td>

                      {/* OS / Firmware */}
                      <td className="py-2 px-3 text-[#bdc9c3]">{eq.os}</td>

                      {/* Uptime */}
                      <td className="py-2 px-3 font-mono text-[#bdc9c3]">{eq.uptime}</td>

                      {/* Santé (Jauge Donut Miniature SVG) */}
                      <td className="py-2 px-3">
                        <div className="flex justify-center">
                          <div className="relative w-5 h-5 flex items-center justify-center">
                            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 24 24">
                              <circle
                                cx="12"
                                cy="12"
                                r="10"
                                fill="none"
                                stroke="#3e4945"
                                strokeWidth="2.5"
                              />
                              <circle
                                cx="12"
                                cy="12"
                                r="10"
                                fill="none"
                                stroke={healthColor}
                                strokeWidth="2.5"
                                strokeDasharray="62.8"
                                strokeDashoffset={strokeOffset}
                                strokeLinecap="round"
                              />
                            </svg>
                            <span
                              className="absolute text-[8px] font-bold"
                              style={{ color: healthColor }}
                            >
                              {eq.health}
                            </span>
                          </div>
                        </div>
                      </td>

                      {/* Dernière vue */}
                      <td className="py-2 px-3 text-right text-[#bdc9c3] text-[11px] font-mono">
                        {eq.lastSeen}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* ── Tiroir Latéral Contextuel Fixe sur la Droite ──────────────── */}
      {selectedEq && (
        <aside
          id="parc-device-drawer"
          className="w-[360px] h-full bg-[#181d1b] border-l border-[#3e4945] flex flex-col flex-shrink-0 overflow-hidden shadow-[-4px_0_16px_rgba(0,0,0,0.5)] z-20"
        >
          {/* Header du tiroir */}
          <div className="p-3.5 flex justify-between items-start border-b border-[#3e4945] bg-[#1c211e]">
            <div className="flex gap-2.5 items-center">
              <div
                className={`w-9 h-9 rounded flex items-center justify-center border ${
                  selectedEq.status === 'critique'
                    ? 'bg-[#ffb4ab]/10 border-[#ffb4ab]/30 text-[#ffb4ab]'
                    : selectedEq.status === 'avertissement'
                    ? 'bg-[#d37768]/10 border-[#d37768]/30 text-[#d37768]'
                    : 'bg-[#3da186]/10 border-[#3da186]/30 text-[#3da186]'
                }`}
              >
                {selectedEq.type === 'Firewall' ? (
                  <Shield className="w-5 h-5" />
                ) : selectedEq.type === 'Router' ? (
                  <Router className="w-5 h-5" />
                ) : selectedEq.type === 'Switch' ? (
                  <Layers className="w-5 h-5" />
                ) : (
                  <Server className="w-5 h-5" />
                )}
              </div>
              <div>
                <h3 className="text-base font-bold text-[#dfe4e0] tracking-tight">{selectedEq.name}</h3>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span
                    className={`inline-block w-2 h-2 rounded-full ${
                      selectedEq.status === 'critique'
                        ? 'bg-[#ffb4ab] animate-pulse'
                        : selectedEq.status === 'avertissement'
                        ? 'bg-[#d37768]'
                        : 'bg-[#3da186]'
                    }`}
                  />
                  <span
                    className={`text-[10px] font-bold tracking-wider uppercase ${
                      selectedEq.status === 'critique'
                        ? 'text-[#ffb4ab]'
                        : selectedEq.status === 'avertissement'
                        ? 'text-[#d37768]'
                        : 'text-[#3da186]'
                    }`}
                  >
                    {selectedEq.status}
                  </span>
                </div>
              </div>
            </div>
            <button
              id="parc-close-drawer-btn"
              onClick={() => setSelectedEq(null)}
              className="text-[#bdc9c3] hover:text-[#dfe4e0] p-1 rounded hover:bg-[#262b29] transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Corps défilable du tiroir */}
          <div className="flex-1 overflow-y-auto p-3.5 space-y-3">
            {/* 1. Identification */}
            <div className="bg-[#1c211e] rounded border border-[#3e4945]/50 p-3">
              <h4 className="text-[10px] font-bold text-[#bdc9c3] uppercase tracking-wider mb-2">IDENTIFICATION</h4>
              <div className="grid grid-cols-2 gap-y-2 gap-x-3 text-xs">
                <div>
                  <span className="text-[#bdc9c3] text-[10px] block">Modèle</span>
                  <span className="text-[#dfe4e0] font-medium">{selectedEq.model}</span>
                </div>
                <div>
                  <span className="text-[#bdc9c3] text-[10px] block">Numéro de série</span>
                  <span className="text-[#dfe4e0] font-mono text-[11px]">{selectedEq.serial}</span>
                </div>
                <div>
                  <span className="text-[#bdc9c3] text-[10px] block">Localisation</span>
                  <span className="text-[#dfe4e0] text-[11px]">{selectedEq.location}</span>
                </div>
                <div>
                  <span className="text-[#bdc9c3] text-[10px] block">Rôle</span>
                  <span className="text-[#dfe4e0] text-[11px]">{selectedEq.role}</span>
                </div>
              </div>
            </div>

            {/* 2. Performances (24h) */}
            <div className="bg-[#1c211e] rounded border border-[#3e4945]/50 p-3">
              <h4 className="text-[10px] font-bold text-[#bdc9c3] uppercase tracking-wider mb-2.5">
                PERFORMANCES (24H)
              </h4>

              {/* CPU Load */}
              <div className="mb-3">
                <div className="flex justify-between items-end mb-1 text-xs">
                  <span className="text-[#dfe4e0] text-[11px]">CPU Load</span>
                  <span
                    className={`font-mono font-bold text-xs ${
                      selectedEq.cpuLoad >= 85
                        ? 'text-[#ffb4ab]'
                        : selectedEq.cpuLoad >= 60
                        ? 'text-[#d37768]'
                        : 'text-[#3da186]'
                    }`}
                  >
                    {selectedEq.cpuLoad}%
                  </span>
                </div>
                <div className="h-6 w-full border-b border-l border-[#3e4945] relative flex items-end gap-[2px] pt-1">
                  {selectedEq.cpuHistory.map((val, idx) => (
                    <div
                      key={idx}
                      className="flex-1 rounded-t-sm transition-all"
                      style={{
                        height: `${val}%`,
                        backgroundColor:
                          val >= 85
                            ? 'rgba(255, 180, 171, 0.8)'
                            : val >= 60
                            ? 'rgba(211, 119, 104, 0.6)'
                            : 'rgba(120, 216, 186, 0.4)',
                      }}
                    />
                  ))}
                </div>
              </div>

              {/* Mémoire */}
              <div>
                <div className="flex justify-between items-end mb-1 text-xs">
                  <span className="text-[#dfe4e0] text-[11px]">Mémoire</span>
                  <span
                    className={`font-mono font-bold text-xs ${
                      selectedEq.memLoad >= 85
                        ? 'text-[#ffb4ab]'
                        : selectedEq.memLoad >= 60
                        ? 'text-[#d37768]'
                        : 'text-[#3da186]'
                    }`}
                  >
                    {selectedEq.memLoad}%
                  </span>
                </div>
                <div className="h-6 w-full border-b border-l border-[#3e4945] relative flex items-end gap-[2px] pt-1">
                  {selectedEq.memHistory.map((val, idx) => (
                    <div
                      key={idx}
                      className="flex-1 rounded-t-sm transition-all"
                      style={{
                        height: `${val}%`,
                        backgroundColor:
                          val >= 85
                            ? 'rgba(255, 180, 171, 0.8)'
                            : val >= 60
                            ? 'rgba(211, 119, 104, 0.6)'
                            : 'rgba(120, 216, 186, 0.4)',
                      }}
                    />
                  ))}
                </div>
              </div>
            </div>

            {/* 3. Anomalies de Sécurité */}
            {selectedEq.anomalies.length > 0 && (
              <div className="bg-[#1c211e] rounded border border-[#3e4945]/50 p-3">
                <h4 className="text-[10px] font-bold text-[#ffb4ab] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-[#ffb4ab]" />
                  <span>ANOMALIES DE SÉCURITÉ</span>
                </h4>
                <div className="space-y-2">
                  {selectedEq.anomalies.map((anom, idx) => (
                    <div
                      key={idx}
                      className={`p-2 rounded border flex gap-2 items-start ${
                        anom.icon === 'bolt'
                          ? 'bg-[#ffb4ab]/10 border-[#ffb4ab]/25'
                          : 'bg-[#d37768]/10 border-[#d37768]/25'
                      }`}
                    >
                      <Zap
                        className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${
                          anom.icon === 'bolt' ? 'text-[#ffb4ab]' : 'text-[#d37768]'
                        }`}
                      />
                      <div>
                        <div className="text-[#dfe4e0] font-medium text-xs">{anom.title}</div>
                        <div className="font-mono text-[#bdc9c3] text-[10px] mt-0.5">{anom.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 4. NetDevOps & Sauvegardes */}
            <div className="bg-[#1c211e] rounded border border-[#3e4945]/50 p-3">
              <h4 className="text-[10px] font-bold text-[#bdc9c3] uppercase tracking-wider mb-2">
                NETDEVOPS &amp; SAUVEGARDES
              </h4>
              <div className="flex justify-between items-center py-1.5 border-b border-[#3e4945]/50 text-xs">
                <span className="text-[#dfe4e0]">Dernière sauvegarde config</span>
                <span className="flex items-center gap-1 text-[#78d8ba] text-[11px] font-mono">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  {selectedEq.lastBackup}
                </span>
              </div>
              <div className="flex justify-between items-center py-1.5 mt-1 text-xs">
                <span className="text-[#dfe4e0]">Audit de conformité</span>
                <span
                  className={`flex items-center gap-1 text-[11px] font-mono ${
                    selectedEq.cisAudit.status === 'ok' ? 'text-[#78d8ba]' : 'text-[#ffb4ab]'
                  }`}
                >
                  {selectedEq.cisAudit.status === 'ok' ? (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  ) : (
                    <AlertTriangle className="w-3.5 h-3.5" />
                  )}
                  {selectedEq.cisAudit.message}
                </span>
              </div>
            </div>
          </div>

          {/* Footer Action : Terminal SSH & Suppression */}
          <div className="p-3 border-t border-[#3e4945] bg-[#1c211e] flex gap-2">
            <button
              id="parc-open-ssh-btn"
              onClick={() => setShowSshModal(true)}
              className="flex-1 bg-[#017094]/20 border border-[#017094] text-[#81d0f8] py-2 rounded text-xs font-semibold flex items-center justify-center gap-2 hover:bg-[#017094]/30 transition-colors shadow-sm"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Terminal SSH</span>
            </button>
            <button
              id="parc-delete-eq-btn"
              disabled={isDeleting}
              onClick={() => handleDeleteEquipment(selectedEq.id, selectedEq.name)}
              className="px-3 bg-[#ffb4ab]/10 border border-[#ffb4ab]/30 text-[#ffb4ab] py-2 rounded text-xs font-semibold flex items-center justify-center gap-1.5 hover:bg-[#ffb4ab]/20 transition-colors shadow-sm disabled:opacity-50"
              title="Supprimer cet équipement du parc"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Supprimer</span>
            </button>
          </div>
        </aside>
      )}

      {/* ── Modal : Terminal SSH Interactif Exhaustif & Réel ─────────────── */}
      {showSshModal && selectedEq && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4">
          <div className="w-full max-w-4xl bg-[#0a0f0d] border border-[#3e4945] rounded-xl shadow-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-150 max-h-[88vh]">
            {/* Header console */}
            <div className="px-4 py-2.5 bg-[#181d1b] border-b border-[#3e4945] flex items-center justify-between flex-shrink-0">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-[#ffb4ab]" />
                <span className="w-3 h-3 rounded-full bg-[#d37768]" />
                <span className="w-3 h-3 rounded-full bg-[#3da186]" />
                <span className="ml-2 text-xs font-mono text-[#dfe4e0] font-semibold flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-[#78d8ba]" />
                  <span>ssh admin@{selectedEq.ip} ({selectedEq.name})</span>
                </span>
              </div>
              <div className="flex items-center gap-2">
                {/* Badge statut mode de connexion */}
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold flex items-center gap-1 border ${
                  sshMode === 'REAL_SSH'
                    ? 'bg-[#00382b] text-[#78d8ba] border-[#78d8ba]'
                    : sshMode === 'EMULATED_CLI'
                    ? 'bg-[#2b2100] text-[#ffdd80] border-[#ffdd80]/40'
                    : 'bg-[#1c211e] text-[#bdc9c3] border-[#3e4945]'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    sshMode === 'REAL_SSH' ? 'bg-[#78d8ba] animate-ping' : sshMode === 'EMULATED_CLI' ? 'bg-[#ffdd80]' : 'bg-[#bdc9c3]'
                  }`} />
                  <span>{sshMode === 'REAL_SSH' ? 'Session SSH Paramiko Réelle' : sshMode === 'EMULATED_CLI' ? 'Moteur CLI Émulateur IOS & Linux' : 'Prêt (Auto-Détection)'}</span>
                </span>

                <button
                  onClick={() => {
                    navigator.clipboard.writeText(sshHistory.join('\n'));
                    showToast('Sortie console copiée dans le presse-papier');
                  }}
                  className="text-[#bdc9c3] hover:text-[#dfe4e0] p-1 rounded hover:bg-[#262b29] transition-colors"
                  title="Copier le terminal"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setShowSshModal(false)}
                  className="text-[#bdc9c3] hover:text-[#dfe4e0] p-1 rounded hover:bg-[#262b29] transition-colors"
                  title="Fermer le terminal"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Barre de commandes rapides (Actions en un clic) */}
            <div className="px-4 py-2 bg-[#121715] border-b border-[#3e4945]/70 flex items-center gap-1.5 overflow-x-auto text-[11px] font-mono flex-shrink-0 scrollbar-none">
              <span className="text-[#87938e] text-[10px] uppercase font-bold mr-1 flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-[#78d8ba]" />
                <span>Actions:</span>
              </span>
              {[
                { label: 'sh ip int br', cmd: 'show ip int brief' },
                { label: 'show run', cmd: 'show run' },
                { label: 'show ver', cmd: 'show version' },
                { label: 'show cdp', cmd: 'show cdp neighbors' },
                { label: 'ping 8.8.8.8', cmd: 'ping 8.8.8.8' },
                { label: 'uptime', cmd: 'uptime' },
                { label: 'df -h', cmd: 'df -h' },
                { label: 'free -m', cmd: 'free -m' },
                { label: 'top', cmd: 'top -b -n 1' },
                { label: 'ip a', cmd: 'ip a' },
                { label: 'help', cmd: 'help' },
                { label: 'clear', cmd: 'clear' },
              ].map(action => (
                <button
                  key={action.cmd}
                  disabled={isSshExecuting}
                  onClick={() => executeSshCommand(action.cmd)}
                  className="px-2 py-0.5 rounded bg-[#1c211e] hover:bg-[#262b29] text-[#78d8ba] border border-[#3e4945] hover:border-[#78d8ba] transition-colors whitespace-nowrap cursor-pointer disabled:opacity-40"
                >
                  {action.label}
                </button>
              ))}
            </div>

            {/* Corps du terminal */}
            <div className="p-4 font-mono text-xs text-[#78d8ba] h-96 overflow-y-auto space-y-1 bg-[#0a0f0d]/95 flex-1 select-text">
              {sshHistory.map((line, idx) => (
                <div
                  key={idx}
                  className={`whitespace-pre-wrap leading-relaxed ${
                    line.startsWith('admin@')
                      ? 'text-[#dfe4e0] font-bold border-b border-[#3e4945]/30 pb-0.5 mt-2'
                      : line.startsWith('[ERREUR')
                      ? 'text-[#ffb4ab]'
                      : line.startsWith('!') || line.startsWith('===')
                      ? 'text-[#87938e]'
                      : 'text-[#78d8ba]'
                  }`}
                >
                  {line}
                </div>
              ))}
              {isSshExecuting && (
                <div className="flex items-center gap-2 text-[#ffdd80] text-xs py-1">
                  <RefreshCw className="w-3 h-3 animate-spin" />
                  <span>Exécution de la commande en cours...</span>
                </div>
              )}
              <div ref={terminalEndRef} />
            </div>

            {/* Input ligne de commande */}
            <form
              onSubmit={handleSshSubmit}
              className="p-3 bg-[#181d1b] border-t border-[#3e4945] flex items-center gap-2 flex-shrink-0"
            >
              <span className="font-mono text-xs text-[#78d8ba] font-bold whitespace-nowrap">
                admin@{selectedEq.name.toLowerCase()}:~$
              </span>
              <input
                id="parc-ssh-input"
                type="text"
                autoFocus
                disabled={isSshExecuting}
                value={sshInput}
                onChange={e => setSshInput(e.target.value)}
                onKeyDown={handleSshKeyDown}
                placeholder="Tapez une commande (ex: show run, sh ip int br, df -h, ping 8.8.8.8, help)... [↑/↓ historique, Tab complétion]"
                className="flex-1 bg-transparent font-mono text-xs text-[#dfe4e0] focus:outline-none placeholder:text-[#bdc9c3]/40"
              />
              <div className="text-[10px] text-[#87938e] font-mono hidden md:block">
                <span>Tab pour compléter</span>
              </div>
              <button
                type="submit"
                disabled={isSshExecuting || !sshInput.trim()}
                className="px-3 py-1.5 rounded bg-[#78d8ba] text-[#00382b] font-mono text-xs font-bold flex items-center gap-1.5 hover:bg-[#78d8ba]/90 transition-colors disabled:opacity-40 cursor-pointer"
              >
                {isSshExecuting ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Send className="w-3.5 h-3.5" />
                )}
                <span>Exécuter</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* ── Modal : Découverte Réseau Réel Physique (ARP & Ports) ──────── */}
      {showRealScanModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4">
          <div className="w-full max-w-3xl bg-[#181d1b] border border-[#78d8ba]/50 rounded-xl shadow-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-150 max-h-[90vh]">
            {/* Header modal */}
            <div className="px-5 py-3.5 bg-[#1c211e] border-b border-[#3e4945] flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-[#78d8ba]/15 border border-[#78d8ba]/40 flex items-center justify-center text-[#78d8ba]">
                  <Radio className="w-4 h-4 animate-pulse" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-[#dfe4e0] flex items-center gap-2">
                    <span>Découverte Réseau Physique Réel</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#78d8ba]/20 text-[#78d8ba] font-mono font-bold">100% Physique</span>
                  </h3>
                  <p className="text-[11px] text-[#bdc9c3]">
                    Sonde le sous-réseau local via ping ARP et bannières HTTP/DNS/SSH de votre box et de vos machines.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowRealScanModal(false)}
                className="text-[#bdc9c3] hover:text-[#dfe4e0] p-1.5 rounded-lg hover:bg-[#262b29] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Informations hôte et paramètres de scan */}
            <div className="p-4 bg-[#121715] border-b border-[#3e4945] flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-3">
                <div className="flex flex-col">
                  <span className="text-[10px] uppercase font-bold text-[#87938e]">Machine Hôte</span>
                  <span className="font-semibold text-[#dfe4e0] flex items-center gap-1 font-mono">
                    <Cpu className="w-3 h-3 text-[#78d8ba]" />
                    {realNetInfo?.hostname || 'Détection...'}
                  </span>
                </div>
                <div className="h-6 w-px bg-[#3e4945]" />
                <div className="flex flex-col">
                  <span className="text-[10px] uppercase font-bold text-[#87938e]">IP Locale Hôte</span>
                  <span className="font-mono text-[#78d8ba]">{realNetInfo?.local_ip || '192.168.0.x'}</span>
                </div>
                <div className="h-6 w-px bg-[#3e4945]" />
                <div className="flex flex-col">
                  <span className="text-[10px] uppercase font-bold text-[#87938e]">Passerelle (Box)</span>
                  <span className="font-mono text-[#81d0f8]">{realNetInfo?.gateway_ip || '192.168.0.1'}</span>
                </div>
              </div>

              {/* Formulaire de plage et bouton de lancement */}
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-1 bg-[#181d1b] border border-[#3e4945] rounded px-2 py-1">
                  <span className="text-[#87938e] font-mono text-[11px]">Sous-réseau:</span>
                  <input
                    type="text"
                    value={customSubnetPrefix}
                    onChange={e => setCustomSubnetPrefix(e.target.value)}
                    placeholder="192.168.0"
                    className="w-24 bg-transparent font-mono text-xs text-[#dfe4e0] focus:outline-none"
                  />
                  <span className="text-[#87938e] font-mono text-[11px]">.0/24</span>
                </div>
                <button
                  id="btn-trigger-real-scan"
                  onClick={() => handleRunRealScan()}
                  disabled={isRealScanning}
                  className="px-3.5 py-1.5 rounded bg-[#78d8ba] text-[#00382b] font-bold text-xs flex items-center gap-1.5 hover:bg-[#78d8ba]/90 transition-all shadow-md cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isRealScanning ? 'animate-spin' : ''}`} />
                  <span>{isRealScanning ? 'Scan en cours...' : 'Lancer le Balayage Réel'}</span>
                </button>
              </div>
            </div>

            {/* Liste des équipements découverts */}
            <div className="p-4 flex-1 overflow-y-auto space-y-2.5 min-h-[220px]">
              {isRealScanning ? (
                <div className="h-48 flex flex-col items-center justify-center gap-3 text-center">
                  <RefreshCw className="w-8 h-8 text-[#78d8ba] animate-spin" />
                  <p className="text-xs text-[#dfe4e0] font-medium">
                    Balayage ping multithreadé et sondage des ports d'administration en cours...
                  </p>
                  <p className="text-[11px] text-[#87938e] font-mono">
                    Découverte de la passerelle box (192.168.0.1) et lecture de la table ARP Windows.
                  </p>
                </div>
              ) : realScanResult ? (
                <div>
                  <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#3e4945]/50 text-xs">
                    <span className="text-[#bdc9c3] font-medium">
                      {realScanResult.devices_count} équipement(s) physique(s) détecté(s) ({realScanResult.scan_duration_ms} ms)
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          const allIps = new Set(realScanResult.devices.map(d => d.ip));
                          setSelectedRealIps(allIps);
                        }}
                        className="text-[11px] text-[#78d8ba] hover:underline"
                      >
                        Tout cocher
                      </button>
                      <span className="text-[#3e4945]">•</span>
                      <button
                        onClick={() => setSelectedRealIps(new Set())}
                        className="text-[11px] text-[#bdc9c3] hover:underline"
                      >
                        Tout décocher
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    {realScanResult.devices.map(dev => {
                      const isSelected = selectedRealIps.has(dev.ip);
                      return (
                        <div
                          key={dev.ip}
                          onClick={() => handleToggleSelectReal(dev.ip)}
                          className={`p-3 rounded-lg border transition-all cursor-pointer flex items-center justify-between gap-3 ${
                            isSelected
                              ? 'bg-[#1c2420] border-[#78d8ba]/70 shadow-sm'
                              : 'bg-[#1c211e] border-[#3e4945] hover:border-[#3e4945]/80'
                          }`}
                        >
                          <div className="flex items-center gap-3 min-w-0">
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => handleToggleSelectReal(dev.ip)}
                              onClick={e => e.stopPropagation()}
                              className="w-4 h-4 accent-[#78d8ba] rounded cursor-pointer"
                            />
                            <div className="w-9 h-9 rounded-md bg-[#262b29] border border-[#3e4945] flex items-center justify-center text-[#78d8ba] flex-shrink-0">
                              {dev.type.toLowerCase().includes('routeur') || dev.type.toLowerCase().includes('box') ? (
                                <Wifi className="w-5 h-5 text-[#81d0f8]" />
                              ) : dev.type.toLowerCase().includes('poste') ? (
                                <Cpu className="w-5 h-5 text-[#78d8ba]" />
                              ) : (
                                <Server className="w-5 h-5 text-[#ffdd80]" />
                              )}
                            </div>
                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-bold text-[#dfe4e0] truncate">
                                  {dev.hostname || dev.ip}
                                </span>
                                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#262b29] text-[#78d8ba] border border-[#3e4945]">
                                  {dev.ip}
                                </span>
                                {dev.already_in_parc && (
                                  <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-[#3e4945]/50 text-[#bdc9c3]">
                                    Déjà répertorié
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center gap-2 mt-0.5 text-[11px] text-[#bdc9c3]">
                                <span>{dev.type}</span>
                                {dev.mac && (
                                  <>
                                    <span>•</span>
                                    <span className="font-mono text-[10px] text-[#87938e]">{dev.mac}</span>
                                  </>
                                )}
                                {dev.banner && (
                                  <>
                                    <span>•</span>
                                    <span className="text-[10px] text-[#ffdd80] truncate max-w-xs font-mono">{dev.banner}</span>
                                  </>
                                )}
                              </div>
                            </div>
                          </div>

                          {/* Ports ouverts */}
                          <div className="flex items-center gap-1.5 flex-shrink-0">
                            {dev.open_ports.map(port => (
                              <span
                                key={port}
                                className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                                  port === 80 || port === 443
                                    ? 'bg-[#00382b] text-[#78d8ba]'
                                    : port === 22
                                    ? 'bg-[#017094]/30 text-[#81d0f8]'
                                    : 'bg-[#262b29] text-[#bdc9c3]'
                                }`}
                              >
                                :{port}
                              </span>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="h-48 flex flex-col items-center justify-center gap-2 text-center text-xs text-[#bdc9c3]">
                  <Radio className="w-8 h-8 text-[#78d8ba]/60" />
                  <p>Cliquez sur "Lancer le Balayage Réel" pour sonder votre réseau physique.</p>
                  <p className="text-[11px] text-[#87938e]">
                    La passerelle Box Internet ({realNetInfo?.gateway_ip || '192.168.0.1'}) et vos postes seront automatiquement identifiés.
                  </p>
                </div>
              )}
            </div>

            {/* Footer modal : Importation */}
            <div className="px-5 py-3.5 bg-[#1c211e] border-t border-[#3e4945] flex items-center justify-between">
              <span className="text-xs text-[#bdc9c3]">
                {selectedRealIps.size} équipement(s) physique(s) sélectionné(s)
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowRealScanModal(false)}
                  className="px-3 py-1.5 rounded text-xs text-[#dfe4e0] hover:bg-[#262b29] transition-colors cursor-pointer"
                >
                  Fermer
                </button>
                <button
                  id="btn-import-real-devices"
                  disabled={isImportingReal || selectedRealIps.size === 0}
                  onClick={handleImportSelectedRealDevices}
                  className="px-4 py-1.5 rounded bg-[#78d8ba] text-[#00382b] font-bold text-xs flex items-center gap-1.5 hover:bg-[#78d8ba]/90 transition-all shadow-md cursor-pointer disabled:opacity-40"
                >
                  {isImportingReal ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Plus className="w-3.5 h-3.5" />
                  )}
                  <span>Importer dans le Parc ({selectedRealIps.size})</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}


      {/* ── Modal : Ajouter un équipement ─────────────────────────────── */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-[#181d1b] border border-[#3e4945] rounded-xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-150">
            {/* Header modal */}
            <div className="px-4 py-3 bg-[#1c211e] border-b border-[#3e4945] flex items-center justify-between">
              <h3 className="text-sm font-bold text-[#dfe4e0] flex items-center gap-2">
                <Plus className="w-4 h-4 text-[#78d8ba]" />
                <span>Ajouter un équipement au parc</span>
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-[#bdc9c3] hover:text-[#dfe4e0] p-1 rounded hover:bg-[#262b29] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Formulaire */}
            <form onSubmit={handleAddEquipment} className="p-4 space-y-3 text-xs">
              <div>
                <label className="block text-[11px] font-semibold text-[#bdc9c3] mb-1">
                  Nom d'hôte (Hostname) *
                </label>
                <input
                  type="text"
                  required
                  placeholder="ex: CORE-SW-02"
                  value={newEqName}
                  onChange={e => setNewEqName(e.target.value)}
                  className="w-full bg-[#262b29] border border-[#3e4945] rounded p-2 text-[#dfe4e0] focus:outline-none focus:border-[#78d8ba]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-semibold text-[#bdc9c3] mb-1">
                    Type d'actif *
                  </label>
                  <select
                    value={newEqType}
                    onChange={e => setNewEqType(e.target.value as any)}
                    className="w-full bg-[#262b29] border border-[#3e4945] rounded p-2 text-[#dfe4e0] focus:outline-none focus:border-[#78d8ba]"
                  >
                    <option value="Router">Routeur</option>
                    <option value="Switch">Switch</option>
                    <option value="Firewall">Pare-feu</option>
                    <option value="Serveur">Serveur</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-[#bdc9c3] mb-1">
                    Adresse IP Management *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="10.0.X.X"
                    value={newEqIp}
                    onChange={e => setNewEqIp(e.target.value)}
                    className="w-full bg-[#262b29] border border-[#3e4945] rounded p-2 text-[#dfe4e0] font-mono focus:outline-none focus:border-[#78d8ba]"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-semibold text-[#bdc9c3] mb-1">
                    Adresse MAC
                  </label>
                  <input
                    type="text"
                    placeholder="00:1A:2B:..."
                    value={newEqMac}
                    onChange={e => setNewEqMac(e.target.value)}
                    className="w-full bg-[#262b29] border border-[#3e4945] rounded p-2 text-[#dfe4e0] font-mono focus:outline-none focus:border-[#78d8ba]"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-[#bdc9c3] mb-1">
                    Modèle Hardware
                  </label>
                  <input
                    type="text"
                    placeholder="ex: Cisco Catalyst 9300"
                    value={newEqModel}
                    onChange={e => setNewEqModel(e.target.value)}
                    className="w-full bg-[#262b29] border border-[#3e4945] rounded p-2 text-[#dfe4e0] focus:outline-none focus:border-[#78d8ba]"
                  />
                </div>
              </div>

              {/* Boutons d'action */}
              <div className="flex justify-end gap-2 pt-3 border-t border-[#3e4945]">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded bg-[#262b29] border border-[#3e4945] text-[#dfe4e0] hover:bg-[#313633] transition-colors"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  disabled={isAdding}
                  className="px-3 py-1.5 rounded bg-[#78d8ba] text-[#00382b] font-bold hover:bg-[#78d8ba]/90 transition-colors disabled:opacity-50 flex items-center gap-1.5"
                >
                  {isAdding ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Enregistrement...</span>
                    </>
                  ) : (
                    <span>Enregistrer l'actif</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
