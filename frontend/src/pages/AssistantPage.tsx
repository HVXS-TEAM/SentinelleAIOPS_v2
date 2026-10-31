import React, { useState, useRef, useEffect } from 'react';
import { Icon } from '../components/ui/Icon';
import { assistantService } from '../services/api';
import { type AuthenticatedUser } from './LoginPage';

/* ── Types ───────────────────────────────────────────────────────────────── */
export interface AssistantPageProps {
  currentUser?: AuthenticatedUser | null;
  onNavigateTab?: (tab: string) => void;
}

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string | React.ReactNode;
  timestamp: string;
  sources?: string[];
  suggestedFollowups?: string[];
  mode?: string;
}

/* ── 4 Cartes d'Accueil Style ChatGPT / Gemini ──────────────────────────── */
const WELCOME_SUGGESTIONS = [
  {
    id: 'cisco-audit',
    iconName: 'verified_user',
    title: 'Audit durcissement Cisco IOS',
    description: 'Détecter les mots de passe clairs, inspecter les VTY et appliquer les règles CIS.',
    prompt: 'line vty 0 4 password cisco',
    color: '#78d8ba',
  },
  {
    id: 'ttf-saturation',
    iconName: 'monitoring',
    title: 'Saturation disque prédictive (TTF)',
    description: 'Identifier les serveurs critiques risquant une saturation d’ici la fin de semaine.',
    prompt: 'Quels serveurs risquent une saturation disque cette semaine ?',
    color: '#ffb4ab',
  },
  {
    id: 'security-anomaly',
    iconName: 'warning',
    title: 'Anomalies & Force-Brute',
    description: 'Corréler les logs récents avec l’algorithme Isolation Forest et anonymisation RGPD.',
    prompt: 'Y a-t-il eu des attaques par force brute ou des déviations récentes ?',
    color: '#81d0f8',
  },
  {
    id: 'pra-continuity',
    iconName: 'database',
    title: 'Continuité d’activité & Sauvegardes PRA',
    description: 'Vérifier l’intégrité SHA-256 et la validité du plan de reprise d’activité.',
    prompt: 'Quel est le statut du PRA et de l’intégrité des sauvegardes ?',
    color: '#e0c068',
  },
];

/* ── Suggestions rapides (chips de référence) ────────────────────────────── */
const QUICK_PROMPTS = [
  { id: 'qp1', label: 'Analyser le trafic réseau', iconName: 'monitoring' },
  { id: 'qp2', label: 'Vérifier la conformité', iconName: 'verified_user' },
  { id: 'qp3', label: 'Résumé des alertes critiques', iconName: 'description' },
];

/* ── Table de démo de la maquette de référence ───────────────────────────── */
const DEMO_PREDICTIVE_SERVERS = [
  {
    name: 'APP-SRV-01',
    isCritical: true,
    date: 'Jeu. 14 Nov, 02:00',
    usage: '88.4%',
  },
  {
    name: 'DB-CLUSTER-M1',
    isCritical: false,
    date: 'Ven. 15 Nov, 18:30',
    usage: '86.1%',
  },
  {
    name: 'STO-NODE-04',
    isCritical: false,
    date: 'Sam. 16 Nov, 09:15',
    usage: '85.0%',
  },
];

export const AssistantPage: React.FC<AssistantPageProps> = ({ currentUser, onNavigateTab }) => {
  /* La discussion démarre vide pour un accueil élégant et personnalisé à la ChatGPT / Gemini */
  const [messages, setMessages] = useState<Message[]>([]);

  /* Récupération et calcul du prénom de l'utilisateur actif */
  const user = currentUser || (() => {
    try {
      const stored = localStorage.getItem('sentinelle_auth_user');
      return stored ? (JSON.parse(stored) as AuthenticatedUser) : null;
    } catch {
      return null;
    }
  })();

  const getDisplayName = (): string => {
    if (!user) return 'Jamel';
    const fullName = user.nom_complet || user.identifiant;
    if (fullName.includes('Jamel') || fullName.includes('Edwin')) return 'Jamel';
    if (fullName.toLowerCase().includes('admin') || user.identifiant === 'admin') return 'Jamel';
    if (fullName.includes('Sarah')) return 'Sarah';
    if (fullName.includes('David')) return 'David';
    if (fullName.includes('Ellen')) return 'Ellen';
    return fullName.split(' ')[0] || 'Jamel';
  };

  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [showCleanupModal, setShowCleanupModal] = useState(false);
  const [cleanupStep, setCleanupStep] = useState<'idle' | 'running' | 'done'>('idle');
  const [cleanupLogs, setCleanupLogs] = useState<string[]>([]);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const chatBottomRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCodeId(id);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  /* Importation et lecture de logs ou fichiers de configuration */
  const handleFileAttach = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const content = reader.result as string;
      const snippet = content.slice(0, 400);
      setInput(
        `[Fichier importé : ${file.name} (${(file.size / 1024).toFixed(1)} Ko)]\n\`\`\`cisco\n${snippet}${
          content.length > 400 ? '\n...' : ''
        }\n\`\`\`\nAnalyse la santé opérationnelle et la conformité de ce fichier.`
      );
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  /* Réinitialisation de la conversation vers l'écran d'accueil */
  const handleClearChat = () => {
    setMessages([]);
  };

  /* Lancement de l'action de nettoyage de logs (Remédiation AIOps v1) */
  const handleStartCleanup = () => {
    setShowCleanupModal(true);
    setCleanupStep('running');
    setCleanupLogs([
      'Connexion SSH agentifiée vers APP-SRV-01 (10.0.10.20)...',
      'Vérification des points de montage : /var/log saturé à 88.4% (58.2 Go).',
      'Arrêt temporaire du flux de rotation de logs.',
      'Compression et archivage des logs archivés > 14 jours...',
      'Purge sécurisée des fichiers temporaires /tmp/app_cache_*...',
      'Nettoyage des conteneurs orphelins et caches Docker dind...',
      'Recalcul du stockage : Espace libéré = 18.4 Go (Nouveau taux : 58.1%).',
      'Validation de santé : Système stable et nominal ✓',
    ]);

    setTimeout(() => {
      setCleanupStep('done');
    }, 2200);
  };

  /* Génération de réponse contextuelle via API et RAG */
  const handleSendPrompt = async (textToSend?: string) => {
    const query = (textToSend || input).trim();
    if (!query || isTyping) return;

    const userMessage: Message = {
      id: `u-${Date.now()}`,
      role: 'user',
      content: query,
      timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsTyping(true);

    try {
      const apiRes = await assistantService.sendMessage(query);
      const answerText = apiRes?.response || apiRes?.reponse;
      if (answerText) {
        const aiResponse: Message = {
          id: `a-${Date.now()}`,
          role: 'assistant',
          content: answerText,
          timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
          sources: apiRes.sources || ['Base de données Sentinelle'],
          suggestedFollowups: apiRes.suggested_followups || [],
          mode: apiRes.mode || 'rag_local',
        };
        setMessages(prev => [...prev, aiResponse]);
        setIsTyping(false);
        return;
      }
    } catch {
      // Repli fluide vers le mode heuristique local
    }

    setTimeout(() => {
      let aiContent: string;
      let sources = ['RAG Local Sentinelle'];
      let followups = ['Quels sont les équipements en alerte ?', 'Quel est le score CIS des équipements ?'];
      const q = query.toLowerCase();

      if (q.includes('saturation') || q.includes('disque') || q.includes('ttf') || q.includes('serveur')) {
        sources = ['Supervision Prédictive TTF', 'Collecteur SNMP', 'sentinelle.db'];
        followups = ['Proposer un nettoyage automatique des logs', 'Comment sont calculées les prédictions TTF ?'];
        const aiResponse: Message = {
          id: `a-${Date.now()}`,
          role: 'assistant',
          content: null, // Déclenche le tableau des serveurs avec bouton Proposer nettoyage
          timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
          sources,
          suggestedFollowups: followups,
          mode: 'rag_local',
        };
        setMessages(prev => [...prev, aiResponse]);
        setIsTyping(false);
        return;
      } else if (q.includes('trafic') || q.includes('réseau') || q.includes('qos')) {
        sources = ['Supervision Télémétrie', 'NetFlow / sFlow'];
        followups = ['Voir les alertes associées au pic de trafic', 'Limiter la bande passante sur CORE-RTR-01'];
        aiContent = 
`### Analyse du Trafic Réseau & Liens Inter-Datacenter

L'inspection en temps réel du trafic NetFlow / sFlow montre un pic anormal sur le lien d'interconnexion :
- [CRITIQUE] **CORE-RTR-01 → DIST-SW-A** : **2.4 Gbps** (Capacité nominale : 2.5 Gbps, saturation à 96%).
- [MAJEUR] **Flux prédominant** : \`TCP/443\` (Synchronisation continue des bases de données inter-DC).
- [CONFORME] **Recommandation QoS** : Activation immédiate d'une limitation de bande passante par classe de service.`;
      } else if (q.includes('conformité') || q.includes('cis') || q.includes('benchmark')) {
        sources = ['NetDevOps CIS Benchmark', 'Cisco IOS 15'];
        followups = ['Comment corriger les failles de DIST-SW-A ?', 'Sauvegarder les configurations actives'];
        aiContent = 
`### Audit de Conformité CIS Benchmark Cisco IOS

Résultat synthétique du dernier audit de durcissement sur vos commutateurs et routeurs :
- [CONFORME] **FW-EXT-02** (Firewall) : **100% de conformité** (0 violation).
- [ATTENTION] **CORE-RTR-01** (Routeur Core) : **82% de conformité** (2 violations mineures).
- [NON-CONFORME] **DIST-SW-A** (Switch Distribution) : **65% de conformité** (5 violations critiques).

**[ALERTE - AUDIT CIS] Vulnérabilités majeures détectées sur DIST-SW-A :**
- [CRITIQUE - CIS 1.1.1] Ligne VTY avec mot de passe en clair (\`cisco\`).
- [CRITIQUE - CIS 1.2.2] Protocole Telnet actif sans SSH imposé (\`transport input all\`).`;
      } else {
        sources = ['Gestion de Parc', 'Supervision TTF', 'Sécurité'];
        aiContent = 
`### Synthèse Globale Sentinelle AIOps

Analyse contextuelle de votre infrastructure :
- **Équipements supervisés** : 3 nœuds actifs, 1 nécessitant une attention urgente (DIST-SW-A).
- **Prédictions TTF** : 3 serveurs surveillés avec risque de saturation disque d'ici fin de semaine.
- **Cybersécurité** : Modèle Isolation Forest actif avec masquage RGPD conforme CNIL.`;
      }

      const aiResponse: Message = {
        id: `a-${Date.now()}`,
        role: 'assistant',
        content: aiContent,
        timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
        sources,
        suggestedFollowups: followups,
        mode: 'rag_local',
      };

      setMessages(prev => [...prev, aiResponse]);
      setIsTyping(false);
    }, 600);
  };

  /* Filtrage strict : conversion des émojis en tags cliniques normalisés et purge Unicode */
  const sanitizeClinicalText = (raw: string): string => {
    const replacements: Array<[string, string]> = [
      ['🔴', '[CRITIQUE] '],
      ['🚨', '[CRITIQUE] '],
      ['🟠', '[MAJEUR] '],
      ['🟡', '[MINEUR] '],
      ['⚠️', '[ALERTE] '],
      ['⚠', '[ALERTE] '],
      ['🟢', '[CONFORME] '],
      ['✅', '[CONFORME] '],
      ['🔒', '[AUDIT CIS] '],
      ['🛡️', ''],
      ['🛡', ''],
      ['🔍', ''],
      ['📊', ''],
      ['⏳', ''],
      ['📋', ''],
      ['🌐', ''],
    ];
    let cleaned = raw;
    for (const [emoji, tag] of replacements) {
      cleaned = cleaned.split(emoji).join(tag);
    }
    return cleaned
      .replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{2300}-\u{23FF}\u{FE0F}]/gu, '')
      .replace(/(\[(?:CRITIQUE|MAJEUR|MINEUR|CONFORME|ALERTE|AUDIT CIS)\])\s+\1/g, '$1')
      .replace(/[ \t]{2,}/g, ' ');
  };

  /* Rendu formaté d'un message textuel (Markdown, Code blocks, Badges) */
  const renderTextChunk = (text: string, key: string) => {
    const cleanText = sanitizeClinicalText(text);
    const lines = cleanText.split('\n');
    return (
      <div key={key} className="space-y-1.5 leading-relaxed text-sm text-[#dfe4e0]">
        {lines.map((line, idx) => {
          if (!line.trim()) return <div key={idx} className="h-1" />;
          if (line.startsWith('### ')) {
            return (
              <h4 key={idx} className="text-sm font-bold text-[#78d8ba] font-mono flex items-center gap-1.5 pt-1 pb-0.5 border-b border-[#3e4945]/40">
                <Icon name="auto_awesome" size="xs" className="text-[#78d8ba]" />
                <span>{line.replace('### ', '').trim()}</span>
              </h4>
            );
          }
          const formatted = line
            .replace(/\*\*(.*?)\*\*/g, '<strong class="text-[#e0e3e6] font-semibold">$1</strong>')
            .replace(/`([^`]+)`/g, '<code class="px-1.5 py-0.5 rounded bg-[#0b0f11] text-[#78d8ba] font-mono text-xs border border-[#3e4945]/60">$1</code>');
          return (
            <p
              key={idx}
              className="text-[13.5px] text-[#dfe4e0] leading-relaxed"
              dangerouslySetInnerHTML={{ __html: formatted }}
            />
          );
        })}
      </div>
    );
  };

  // ── Colorateur syntaxique Cisco IOS & Shell ──────────────────────────────
  const highlightCiscoLine = (line: string): React.ReactNode => {
    const trimmed = line.trim();
    if (trimmed.startsWith('!')) {
      return <span className="text-[#87938e] italic">{line}</span>;
    }

    const ciscoKeywords = [
      'configure terminal', 'conf t', 'end', 'exit', 'write memory', 'wr mem', 'write',
      'service password-encryption', 'no service password-encryption',
      'transport input ssh', 'transport input telnet', 'login local',
      'logging synchronous', 'exec-timeout', 'enable secret', 'enable password',
      'username', 'ip ssh version', 'crypto key generate rsa', 'line vty', 'line con',
      'interface', 'ip address', 'no shutdown', 'shutdown'
    ];

    const tokens = line.split(/(\s+)/);
    return (
      <span>
        {tokens.map((token, idx) => {
          const lower = token.toLowerCase();
          if (ciscoKeywords.includes(lower) || ['line', 'interface', 'vlan', 'ip', 'no', 'service', 'transport'].includes(lower)) {
            return <span key={idx} className="text-[#81d0f8] font-semibold">{token}</span>;
          }
          if (['ssh', 'secret', 'sha256', 'type 9', 'type 8', 'type 5', 'quarantine'].includes(lower)) {
            return <span key={idx} className="text-[#78d8ba] font-bold">{token}</span>;
          }
          if (['telnet', 'cisco', 'v1', 'v2c', 'password'].includes(lower)) {
            return <span key={idx} className="text-[#ffb4ab] font-bold">{token}</span>;
          }
          if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/.test(token)) {
            return <span key={idx} className="text-[#a7c8ff] underline decoration-dotted">{token}</span>;
          }
          return <span key={idx} className="text-[#dfe4e0]">{token}</span>;
        })}
      </span>
    );
  };

  // ── Rendu structuré des blocs CLI avec Action NetDevOps ──────────────────
  const renderAssistantMessage = (content: string | React.ReactNode, msgId: string) => {
    if (typeof content !== 'string') return content;

    const codeBlockRegex = /```([a-z0-9_-]*)\n([\s\S]*?)```/gi;
    const parts: React.ReactNode[] = [];
    let lastIndex = 0;
    let match: RegExpExecArray | null;
    let blockIdx = 0;

    while ((match = codeBlockRegex.exec(content)) !== null) {
      if (match.index > lastIndex) {
        parts.push(renderTextChunk(content.substring(lastIndex, match.index), `${msgId}-t-${lastIndex}`));
      }
      const lang = match[1] || 'Cisco IOS';
      const code = match[2].trim();
      const codeId = `${msgId}-code-${blockIdx++}`;
      const lines = code.split('\n');

      parts.push(
        <div key={codeId} className="my-3 rounded-lg overflow-hidden border border-[#3e4945] bg-[#070a0b] font-mono text-xs shadow-lg">
          {/* En-tête du terminal */}
          <div className="px-3 py-1.5 bg-[#14181a] border-b border-[#3e4945]/60 flex items-center justify-between text-[11px] text-[#bdc9c3]">
            <div className="flex items-center gap-2 text-[#78d8ba]">
              <Icon name="terminal" size="xs" />
              <span className="uppercase font-bold tracking-wider">{lang}</span>
              <span className="text-[10px] text-[#87938e]">• {lines.length} lignes</span>
            </div>

            <div className="flex items-center gap-2">
              {/* Bouton Copier */}
              <button
                onClick={() => copyToClipboard(code, codeId)}
                className="flex items-center gap-1 text-[#bdc9c3] hover:text-[#78d8ba] px-2 py-0.5 rounded hover:bg-white/5 transition-colors cursor-pointer"
                title="Copier les commandes dans le presse-papiers"
              >
                {copiedCodeId === codeId ? (
                  <>
                    <Icon name="check" size="xs" className="text-[#78d8ba]" />
                    <span className="text-[10px] text-[#78d8ba] font-bold">Copié !</span>
                  </>
                ) : (
                  <>
                    <Icon name="content_copy" size="xs" />
                    <span className="text-[10px]">Copier</span>
                  </>
                )}
              </button>

              {/* Bouton Passerelle Déployer vers NetDevOps */}
              <button
                onClick={() => {
                  sessionStorage.setItem('netdevops:prefill_code', code);
                  if (onNavigateTab) {
                    onNavigateTab('netdevops');
                  }
                }}
                className="flex items-center gap-1 bg-[#78d8ba] hover:bg-[#68c8aa] text-[#00382b] font-bold px-2.5 py-0.5 rounded text-[10px] transition-colors cursor-pointer shadow-sm active:scale-95"
                title="Transférer directement ce script vers le module NetDevOps"
              >
                <Icon name="rocket_launch" size="xs" />
                <span>Déployer via NetDevOps</span>
              </button>
            </div>
          </div>

          {/* Corps avec numérotation et coloration */}
          <div className="p-3 overflow-x-auto leading-relaxed max-h-[340px] select-text">
            <table className="w-full border-collapse">
              <tbody>
                {lines.map((l, lIdx) => (
                  <tr key={lIdx} className="hover:bg-white/[0.02]">
                    <td className="w-7 pr-3 text-right text-[#87938e]/40 select-none text-[11px] align-top">
                      {lIdx + 1}
                    </td>
                    <td className="whitespace-pre pl-1 text-[12px]">
                      {highlightCiscoLine(l)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      );
      lastIndex = match.index + match[0].length;
    }

    if (lastIndex < content.length) {
      parts.push(renderTextChunk(content.substring(lastIndex), `${msgId}-tail`));
    }

    return <div className="space-y-2">{parts}</div>;
  };

  return (
    <div className="flex flex-col h-full w-full bg-[#101416] text-[#dfe4e0] font-sans relative overflow-hidden assistant-page-root">
      {/* ── Bannière Supérieure : Statut Moteur IA ───────────────────── */}
      <div className="bg-[#14181a] border-b border-[#272a2d] px-6 py-2.5 flex items-center justify-between text-xs font-mono shrink-0 assistant-top-banner">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#78d8ba] animate-pulse" />
          <span className="font-bold text-[#e0e3e6] assistant-banner-title">Sentinelle Neural Core v2.4</span>
          <span className="text-[#87938e]">|</span>
          <span className="text-[#78d8ba] bg-[#78d8ba]/10 border border-[#78d8ba]/30 px-2 py-0.5 rounded text-[10px]">
            Mode RAG Hybride Actif
          </span>
        </div>
        <div className="hidden sm:flex items-center gap-3 text-[11px] text-[#87938e]">
          <span className="flex items-center gap-1">
            <Icon name="check_circle" size="xs" className="text-[#78d8ba]" />
            Isolation Forest Synchro
          </span>
          <span>•</span>
          <span className="flex items-center gap-1">
            <Icon name="verified_user" size="xs" className="text-[#81d0f8]" />
            Anonymisation IP RGPD
          </span>
        </div>
      </div>

      {/* ── Zone de défilement des messages (Max-W-4XL Centré) ────────── */}
      <div className="flex-1 min-h-0 overflow-y-auto px-4 md:px-8 py-4 scroll-smooth assistant-chat-scroll flex flex-col">
        {messages.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-center px-4 max-w-3xl mx-auto w-full animate-in fade-in zoom-in-95 duration-300">
            {/* Symbole Officiel du Bouclier Sentinelle avec Halo Lumineux */}
            <div className="relative mb-3 group">
              <div className="w-14 h-14 rounded-2xl bg-[#0b0f11] border border-[#78d8ba]/50 flex items-center justify-center shadow-[0_0_25px_rgba(120,216,186,0.35)] p-2 transition-transform duration-300 group-hover:scale-105 assistant-hero-avatar">
                <img
                  src="/sentinelle_symbol.png"
                  alt="Symbole Sentinelle"
                  className="w-full h-full object-contain filter drop-shadow-[0_0_8px_rgba(120,216,186,0.6)]"
                />
              </div>
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#78d8ba] opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-[#78d8ba]" />
              </span>
            </div>

            {/* Formule de politesse & Salutation chaleureuse au prénom */}
            <h1 className="text-xl sm:text-2xl font-extrabold text-[#e0e3e6] mb-1 tracking-tight assistant-hero-title">
              Bonjour <span className="text-[#78d8ba]">{getDisplayName()}</span>, que voulez-vous faire aujourd'hui ?
            </h1>
            <p className="text-xs sm:text-sm text-[#87938e] max-w-xl mx-auto mb-4 leading-relaxed assistant-hero-subtitle">
              Je suis tout à vous pour superviser l'infrastructure, auditer les configurations Cisco ou corréler les alertes de sécurité en temps réel. Par quoi commençons-nous ?
            </p>

            {/* 4 Cartes d'action rapide modernes (Style ChatGPT / Gemini) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 w-full text-left">
              {WELCOME_SUGGESTIONS.map((card) => {
                return (
                  <button
                    key={card.id}
                    onClick={() => handleSendPrompt(card.prompt)}
                    className="p-3 rounded-xl bg-[#161c20] hover:bg-[#1e252a] border border-[#272a2d] hover:border-[#78d8ba]/50 transition-all duration-200 group flex flex-col justify-between shadow-sm cursor-pointer assistant-hero-card"
                  >
                    <div className="flex items-center justify-between mb-1 w-full">
                      <div
                        className="w-6 h-6 rounded-md flex items-center justify-center border"
                        style={{
                          backgroundColor: `${card.color}15`,
                          borderColor: `${card.color}40`,
                          color: card.color,
                        }}
                      >
                        <Icon name={card.iconName} size="xs" />
                      </div>
                      <Icon name="arrow_forward" size="xs" className="text-[#87938e] group-hover:text-[#78d8ba] group-hover:translate-x-0.5 transition-all" />
                    </div>
                    <div>
                      <h3 className="text-xs font-bold text-[#e0e3e6] group-hover:text-[#78d8ba] transition-colors mb-0.5 assistant-card-title">
                        {card.title}
                      </h3>
                      <p className="text-[11px] text-[#87938e] leading-snug assistant-card-desc">
                        {card.description}
                      </p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="w-full max-w-4xl mx-auto flex flex-col gap-6">
            {/* Messages de la conversation */}
            {messages.map(msg => {
            if (msg.role === 'user') {
              return (
                <div key={msg.id} className="flex gap-4 self-end max-w-[85%]">
                  <div className="bg-[#272a2d] border border-[#3e4945]/40 rounded-2xl rounded-tr-sm px-5 py-3.5 shadow-sm backdrop-blur-md assistant-user-bubble">
                    <p className="text-[14.5px] text-[#dfe4e0] leading-relaxed assistant-bubble-text whitespace-pre-wrap">
                      {msg.content as string}
                    </p>
                  </div>
                </div>
              );
            }

            /* Réponse IA */
            return (
              <div key={msg.id} className="flex gap-4 self-start max-w-[92%] w-full">
                {/* Symbole Bouclier Sentinelle */}
                <div className="w-10 h-10 rounded-lg bg-[#0b0f11] flex items-center justify-center border border-[#78d8ba]/40 shrink-0 mt-1 shadow-[0_0_12px_rgba(120,216,186,0.2)] p-1.5 assistant-bot-avatar">
                  <img
                    src="/sentinelle_symbol.png"
                    alt="Sentinelle AIOps"
                    className="w-full h-full object-contain filter drop-shadow-[0_0_4px_rgba(120,216,186,0.5)]"
                  />
                </div>

                <div className="flex-1 space-y-3">
                  <div className="bg-[#1d2022] border border-[#3e4945]/40 rounded-2xl rounded-tl-sm px-6 py-5 shadow-sm assistant-ai-bubble">
                    {msg.content ? (
                      renderAssistantMessage(msg.content, msg.id)
                    ) : (
                      /* Tableau prédictif identique à screen.png */
                      <>
                        <p className="text-[15px] text-[#dfe4e0] mb-4 leading-relaxed">
                          D'après l'analyse prédictive des tendances de consommation, 3 serveurs présentent un risque élevé de saturation disque ( &gt;90%) d'ici la fin de la semaine :
                        </p>

                        <div className="bg-[#181d1b] border border-[#3e4945]/40 rounded-lg overflow-hidden mt-4">
                          {/* Header du tableau */}
                          <div className="grid grid-cols-12 gap-2 bg-[#1c211e] px-4 py-2.5 border-b border-[#3e4945]/30">
                            <div className="col-span-5 text-[11px] font-bold text-[#bdc9c3] uppercase tracking-wider">
                              SERVEUR
                            </div>
                            <div className="col-span-4 text-[11px] font-bold text-[#bdc9c3] uppercase tracking-wider">
                              DATE PRÉVUE
                            </div>
                            <div className="col-span-3 text-[11px] font-bold text-[#bdc9c3] uppercase tracking-wider text-right">
                              USAGE ACTUEL
                            </div>
                          </div>

                          {/* Lignes du tableau */}
                          <div className="divide-y divide-[#3e4945]/20 font-mono text-xs">
                            {DEMO_PREDICTIVE_SERVERS.map(srv => (
                              <div
                                key={srv.name}
                                className={`grid grid-cols-12 gap-2 px-4 py-3 items-center hover:bg-[#262b29]/50 transition-colors ${
                                  srv.isCritical ? 'bg-[#ffb4ab]/5' : ''
                                }`}
                              >
                                <div
                                  className={`col-span-5 font-semibold flex items-center gap-2 ${
                                    srv.isCritical ? 'text-[#ffb4ab]' : 'text-[#78d8ba]'
                                  }`}
                                >
                                  {srv.isCritical ? (
                                    <Icon name="warning" size="sm" className="text-[#ffb4ab] animate-pulse" />
                                  ) : (
                                    <Icon name="dns" size="sm" className="text-[#78d8ba]" />
                                  )}
                                  <span>{srv.name}</span>
                                </div>
                                <div className="col-span-4 text-[#dfe4e0] font-sans">
                                  {srv.date}
                                </div>
                                <div
                                  className={`col-span-3 font-bold text-right ${
                                    srv.isCritical ? 'text-[#ffb4ab]' : 'text-[#78d8ba]'
                                  }`}
                                >
                                  {srv.usage}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Bouton d'action sous la réponse */}
                        <div className="mt-4 flex gap-3">
                          <button
                            id="assistant-propose-cleanup-btn"
                            onClick={handleStartCleanup}
                            className="bg-[#1F8A70]/15 border border-[#1F8A70]/40 text-[#78d8ba] hover:bg-[#1F8A70]/30 text-xs px-4 py-2 rounded uppercase tracking-wider transition-all flex items-center gap-2 font-bold shadow-sm cursor-pointer"
                          >
                            <Icon name="build" size="xs" />
                            <span>Proposer nettoyage</span>
                          </button>
                        </div>
                      </>
                    )}

                    {/* Sources RAG citées */}
                    {msg.sources && msg.sources.length > 0 && (
                      <div className="mt-4 pt-3 border-t border-[#3e4945]/40 flex flex-wrap items-center gap-2 text-[10px] font-mono">
                        <span className="text-[#87938e] flex items-center gap-1">
                          <Icon name="database" size="xs" className="text-[#78d8ba]" />
                          Sources RAG :
                        </span>
                        {msg.sources.map((s, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 rounded bg-[#12161a] border border-[#3e4945]/60 text-[#78d8ba] assistant-source-badge"
                          >
                            {s}
                          </span>
                        ))}
                        <span className="ml-auto px-2 py-0.5 rounded bg-[#78d8ba]/10 text-[#78d8ba] border border-[#78d8ba]/30 font-bold uppercase tracking-wider assistant-mode-pill">
                          {msg.mode === 'ollama' ? '● Ollama LLM' : '● RAG Local Souverain'}
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Suggestions de rebond (Questions de suivi interactives) */}
                  {msg.suggestedFollowups && msg.suggestedFollowups.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pl-2">
                      <span className="text-[11px] text-[#87938e] flex items-center gap-1 font-mono">
                        <Icon name="auto_awesome" size="xs" className="text-[#78d8ba]" />
                        Approfondir :
                      </span>
                      {msg.suggestedFollowups.map((f, idx) => (
                        <button
                          key={idx}
                          onClick={() => handleSendPrompt(f)}
                          className="text-[11px] text-[#dfe4e0] hover:text-[#78d8ba] bg-[#181d1b] hover:bg-[#262b29] border border-[#3e4945]/60 hover:border-[#78d8ba]/40 px-2.5 py-1 rounded-full transition-colors flex items-center gap-1 cursor-pointer font-sans shadow-sm assistant-followup-chip"
                        >
                          <span>{f}</span>
                          <Icon name="arrow_forward" size={10} className="text-[#78d8ba]" />
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {/* Indicateur de saisie / réflexion en cours */}
          {isTyping && (
            <div className="flex gap-4 self-start max-w-[90%] w-full">
              <div className="w-10 h-10 rounded-lg bg-[#1d2022] flex items-center justify-center border border-[#78d8ba]/30 shrink-0 mt-1">
                <Icon name="smart_toy" size="md" className="text-[#78d8ba] animate-bounce" />
              </div>
              <div className="bg-[#1d2022] border border-[#3e4945]/40 rounded-2xl rounded-tl-sm px-6 py-4 shadow-sm flex items-center gap-2.5">
                <Icon name="progress_activity" size="sm" className="text-[#78d8ba] animate-spin" />
                <span className="text-xs text-[#bdc9c3] font-mono">
                  Sentinelle IA consulte les métriques Prometheus et les logs prédictifs...
                </span>
              </div>
            </div>
          )}

            <div ref={chatBottomRef} />
          </div>
        )}
      </div>

      {/* ── Zone de Saisie Inférieure (Fixe en bas avec blur) ──────────── */}
      <div className="bg-[#101416]/90 backdrop-blur-xl border-t border-[#3e4945]/30 p-4 shrink-0 w-full relative z-10 assistant-bottom-bar">
        <div className="max-w-4xl mx-auto flex flex-col gap-2.5">
          {/* Suggestion Chips & Nouvelle discussion (affichés en cours de discussion) */}
          {messages.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 mb-0.5">
              {QUICK_PROMPTS.map(chip => {
                return (
                  <button
                    key={chip.id}
                    id={`assistant-chip-${chip.id}`}
                    onClick={() => handleSendPrompt(chip.label)}
                    className="bg-[#1d2022] border border-[#3e4945]/50 hover:border-[#78d8ba] hover:text-[#78d8ba] text-[#bdc9c3] text-[13px] px-4 py-1.5 rounded-full transition-all flex items-center gap-2 shadow-sm cursor-pointer assistant-chip"
                  >
                    <Icon name={chip.iconName} size="xs" className="text-[#78d8ba]" />
                    <span>{chip.label}</span>
                  </button>
                );
              })}

              <button
                id="assistant-btn-clear"
                onClick={handleClearChat}
                className="bg-[#1d2022] border border-[#3e4945]/50 hover:border-[#ffb4ab]/60 hover:text-[#ffb4ab] text-[#bdc9c3] text-xs px-3 py-1.5 rounded-full transition-all flex items-center gap-1.5 shadow-sm cursor-pointer ml-auto"
                title="Réinitialiser l'écran d'accueil"
              >
                <Icon name="delete" size="xs" />
                <span>Nouvelle discussion</span>
              </button>
            </div>
          )}

          {/* Input Box */}
          <div className="relative bg-[#181d1b] border border-[#3e4945]/60 rounded-xl focus-within:border-[#78d8ba] focus-within:shadow-[0_0_12px_rgba(120,216,186,0.15)] transition-all flex flex-col assistant-input-box">
            <textarea
              id="assistant-textarea-input"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSendPrompt();
                }
              }}
              placeholder="Demander à Sentinelle IA..."
              rows={1}
              style={{ minHeight: '56px' }}
              className="bg-transparent border-none focus:outline-none text-[15px] text-[#dfe4e0] p-3.5 pb-10 w-full placeholder-[#bdc9c3]/50 resize-none assistant-textarea"
            />

            {/* Badge LECTURE SEULE */}
            <div className="absolute bottom-2.5 left-3.5 flex items-center gap-2">
              <div className="bg-[#272a2d] border border-[#3e4945]/50 px-2 py-0.5 rounded text-[#bdc9c3] text-[10px] font-mono uppercase tracking-wider flex items-center gap-1.5 assistant-readonly-badge">
                <Icon name="visibility" size="xs" className="text-[#78d8ba]" />
                <span>Lecture seule</span>
              </div>
            </div>

            {/* Boutons d'action : Pièce jointe & Envoyer */}
            <div className="absolute bottom-2 right-2 flex items-center gap-1.5">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileAttach}
                accept=".txt,.log,.conf,.cfg,.json,.yaml,.yml,.csv"
                className="hidden"
                id="assistant-file-input"
              />
              <button
                id="assistant-btn-attach"
                type="button"
                onClick={() => fileInputRef.current?.click()}
                title="Joindre un fichier de configuration ou journal (.cfg, .log, .json, .yaml)"
                className="w-9 h-9 rounded-lg text-[#bdc9c3] hover:text-[#dfe4e0] hover:bg-[#272a2d] transition-colors flex items-center justify-center cursor-pointer"
              >
                <Icon name="attach_file" size="sm" />
              </button>
              <button
                id="assistant-btn-send"
                onClick={() => handleSendPrompt()}
                disabled={!input.trim() || isTyping}
                className={`w-9 h-9 rounded-lg transition-all flex items-center justify-center shadow-md ${
                  input.trim() && !isTyping
                    ? 'bg-[#1F8A70] hover:bg-[#156e58] text-white cursor-pointer'
                    : 'bg-[#272a2d] text-[#bdc9c3]/40 cursor-not-allowed'
                }`}
              >
                <Icon name="send" size="sm" />
              </button>
            </div>
          </div>

          {/* Mention légale en pied de page */}
          <div className="text-center text-[11px] text-[#bdc9c3]/60 font-mono mt-0.5">
            L'IA peut faire des erreurs. Vérifiez les informations critiques dans les dashboards principaux.
          </div>
        </div>
      </div>

      {/* ── Modal : Automatisation de Nettoyage de Disque (v1) ─────────── */}
      {showCleanupModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-[#181d1b] border border-[#3e4945] rounded-xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-150 flex flex-col">
            {/* Header modal */}
            <div className="px-4 py-3 bg-[#1c211e] border-b border-[#3e4945] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-[#78d8ba]/10 border border-[#78d8ba]/30 flex items-center justify-center text-[#78d8ba]">
                  <Icon name="delete" size="sm" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-[#dfe4e0]">
                    Planification Nettoyage Disque AIOps
                  </h3>
                  <p className="text-[10px] text-[#bdc9c3] font-mono">
                    Cible : APP-SRV-01 (10.0.10.20)
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowCleanupModal(false)}
                className="text-[#bdc9c3] hover:text-[#dfe4e0] p-1 rounded hover:bg-[#262b29] transition-colors"
              >
                <Icon name="close" size="sm" />
              </button>
            </div>

            {/* Corps du modal */}
            <div className="p-4 space-y-3">
              <div className="bg-[#0a0f0d] border border-[#3e4945]/60 rounded-lg p-3 font-mono text-xs text-[#78d8ba] h-48 overflow-y-auto space-y-1">
                {cleanupLogs.map((line, idx) => (
                  <div key={idx} className="leading-relaxed">
                    <span className="text-[#bdc9c3]/50">[{idx + 1}]</span> {line}
                  </div>
                ))}
              </div>

              {cleanupStep === 'done' && (
                <div className="p-3 bg-[#3da186]/10 border border-[#3da186]/30 rounded-lg flex items-center gap-2 text-xs text-[#78d8ba]">
                  <Icon name="check_circle" size="sm" className="shrink-0" />
                  <span>
                    Remédiation terminée avec succès : 18.4 Go récupérés. Le serveur est désormais à 58.1% d'usage.
                  </span>
                </div>
              )}
            </div>

            {/* Footer modal */}
            <div className="px-4 py-3 bg-[#1c211e] border-t border-[#3e4945] flex justify-end gap-2">
              <button
                onClick={() => setShowCleanupModal(false)}
                className="px-4 py-1.5 rounded bg-[#262b29] border border-[#3e4945] text-xs text-[#dfe4e0] hover:bg-[#313633] transition-colors font-medium"
              >
                {cleanupStep === 'done' ? 'Fermer' : 'Annuler'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
