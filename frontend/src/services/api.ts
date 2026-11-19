import axios from 'axios';
import type { AuthResponse, RegisterData, Equipement, MetricSeries, Prediction, Alerte, LocalNetworkInfo, RealNetworkScanResponse, HardwareLiveStats, MfaSetupResponse, SetupStatus, SetupData, ForgotPasswordResponse, ResetCodeResponse } from '../types';

const API_BASE_URL =
  import.meta.env.VITE_API_URL ||
  (typeof window !== 'undefined' && window.location.port === '5173'
    ? 'http://localhost:8000/api/v1'
    : '/api/v1');

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const SESSION_KEYS = {
  token: 'sentinelle_token',
  user: 'sentinelle_user',
  authUser: 'sentinelle_auth_user',
} as const;

export const SESSION_EXPIRED_EVENT = 'sentinelle:session-expired';

const CLE_THEME = 'sentinelle_theme_preference';

/** Efface toutes les données propres au compte précédent (jeton, profil, préférences d'interface,
 *  brouillons). Seule la préférence de thème, liée au poste, est conservée. */
export const clearPersonalData = (): void => {
  try {
    Object.values(SESSION_KEYS).forEach(key => localStorage.removeItem(key));
    for (const store of [localStorage, sessionStorage]) {
      Object.keys(store)
        .filter(k => (k.startsWith('sentinelle_') && k !== CLE_THEME) || k.startsWith('netdevops:'))
        .forEach(k => store.removeItem(k));
    }
  } catch {
    /* stockage indisponible : rien à effacer */
  }
};

export const clearSession = (): void => clearPersonalData();

/** Ouvre une session : les données du compte précédent sont effacées avant d'enregistrer le nouveau jeton. */
const startSession = (data: AuthResponse): void => {
  if (!data.access_token) return;
  clearPersonalData();
  localStorage.setItem(SESSION_KEYS.token, data.access_token);
  localStorage.setItem(SESSION_KEYS.user, JSON.stringify(data));
};

// Injection automatique du jeton JWT dans les requêtes sortantes
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem(SESSION_KEYS.token);
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Un JWT absent, expiré ou falsifié termine la session : l'UI ne doit jamais
// s'afficher « connectée » sans jeton valide (sinon les pages tombent en 401).
apiClient.interceptors.response.use(
  response => response,
  (error: unknown) => {
    const status = axios.isAxiosError(error) ? error.response?.status : undefined;
    const url = axios.isAxiosError(error) ? error.config?.url ?? '' : '';
    if (status === 401 && !url.includes('/auth/login')) {
      clearSession();
      window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT));
    }
    return Promise.reject(error);
  },
);

// Services d'authentification
export const authService = {
  login: async (identifiant: string, mot_de_passe: string, code_mfa?: string): Promise<AuthResponse> => {
    const response = await apiClient.post<AuthResponse>('/auth/login', {
      identifiant,
      mot_de_passe,
      ...(code_mfa ? { code_mfa } : {}),
    });
    startSession(response.data);
    return response.data;
  },
  register: async (data: RegisterData): Promise<AuthResponse> => {
    const response = await apiClient.post<AuthResponse>('/auth/register', data);
    startSession(response.data);
    return response.data;
  },
  getSetupStatus: async (): Promise<SetupStatus> => {
    const response = await apiClient.get<SetupStatus>('/auth/setup-status');
    return response.data;
  },
  setup: async (data: SetupData): Promise<AuthResponse> => {
    const response = await apiClient.post<AuthResponse>('/auth/setup', data);
    startSession(response.data);
    return response.data;
  },
  forgotPassword: async (identifiant: string): Promise<ForgotPasswordResponse> => {
    const response = await apiClient.post<ForgotPasswordResponse>('/auth/forgot-password', { identifiant });
    return response.data;
  },
  resetPassword: async (identifiant: string, code: string, nouveau_mot_de_passe: string): Promise<{ reset: boolean }> => {
    const response = await apiClient.post('/auth/reset-password', { identifiant, code, nouveau_mot_de_passe });
    return response.data;
  },
  changePassword: async (mot_de_passe_actuel: string, nouveau_mot_de_passe: string): Promise<{ changed: boolean }> => {
    const response = await apiClient.post('/auth/change-password', { mot_de_passe_actuel, nouveau_mot_de_passe });
    return response.data;
  },
  logout: async () => {
    try {
      await apiClient.post('/auth/logout');
    } finally {
      clearSession();
    }
  },
  validateSession: async (): Promise<boolean> => {
    if (!localStorage.getItem(SESSION_KEYS.token)) return false;
    try {
      await apiClient.get('/auth/me');
      return true;
    } catch (err: unknown) {
      console.warn('Session invalide ou expirée', err);
      return false;
    }
  },
  getCurrentUser: () => {
    const raw = localStorage.getItem(SESSION_KEYS.user);
    return raw ? JSON.parse(raw) : null;
  },
};

// Services de supervision prédictive et cycle de vie des alertes
export const supervisionService = {
  getMetrics: async (equipementId: number, typeMetrique = 'disk_percent', limit = 48): Promise<MetricSeries> => {
    const response = await apiClient.get<MetricSeries>(`/supervision/metrics/${equipementId}`, {
      params: { type_metrique: typeMetrique, limit },
    });
    return response.data;
  },
  getPredictions: async (): Promise<Prediction[]> => {
    const response = await apiClient.get<Prediction[]>('/supervision/predictions');
    return response.data;
  },
  recalculateTTF: async (equipementId: number, metrique = 'disk_percent'): Promise<Prediction> => {
    const response = await apiClient.post<Prediction>(`/supervision/recalculate/${equipementId}`, null, {
      params: { metrique },
    });
    return response.data;
  },
  updateThreshold: async (equipementId: number, seuil: number) => {
    const response = await apiClient.put(`/supervision/threshold/${equipementId}`, {
      seuil_disque_alerte: seuil,
    });
    return response.data;
  },
  getHardwareLive: async (): Promise<HardwareLiveStats> => {
    const response = await apiClient.get<HardwareLiveStats>('/supervision/hardware/live');
    return response.data;
  },
  getAlerts: async (statut?: string, limit = 100): Promise<Alerte[]> => {
    const response = await apiClient.get<Alerte[]>('/supervision/alerts', {
      params: { ...(statut ? { statut } : {}), limit },
    });
    return response.data;
  },
  acknowledgeAlert: async (alerteId: number): Promise<Alerte> => {
    const response = await apiClient.put<Alerte>(`/supervision/alerts/${alerteId}/acknowledge`);
    return response.data;
  },
  resolveAlert: async (alerteId: number): Promise<Alerte> => {
    const response = await apiClient.put<Alerte>(`/supervision/alerts/${alerteId}/resolve`);
    return response.data;
  },
  probeAll: async (): Promise<{ total: number; online: number; offline: number }> => {
    const response = await apiClient.post('/supervision/probe-all');
    return response.data;
  },
};

// Services de gestion de parc et inventaire
export const parcService = {
  getEquipements: async (groupe?: string): Promise<Equipement[]> => {
    const response = await apiClient.get<Equipement[]>('/parc/equipements', {
      params: groupe && groupe !== 'Tous' ? { groupe } : {},
    });
    return response.data;
  },
  getEquipementDetail: async (equipementId: number): Promise<Equipement> => {
    const response = await apiClient.get<Equipement>(`/parc/equipements/${equipementId}`);
    return response.data;
  },
  updateEquipement: async (
    equipementId: number,
    data: {
      nom?: string;
      ip?: string;
      mac?: string;
      type?: string;
      os?: string;
      firmware?: string;
      groupe?: string;
      seuil_disque_alerte?: number;
      mot_de_passe_secret?: string;
    },
  ): Promise<Equipement> => {
    const response = await apiClient.put<Equipement>(`/parc/equipements/${equipementId}`, data);
    return response.data;
  },
  probeEquipement: async (equipementId: number): Promise<Equipement> => {
    const response = await apiClient.post<Equipement>(`/parc/equipements/${equipementId}/probe`);
    return response.data;
  },
  scanSnmp: async (plageIp: string) => {
    const response = await apiClient.post('/parc/scan-snmp', {
      plage_ip: plageIp,
    });
    return response.data;
  },
  getLocalNetworkInfo: async (): Promise<LocalNetworkInfo> => {
    const response = await apiClient.get<LocalNetworkInfo>('/parc/local-network-info');
    return response.data;
  },
  scanRealNetwork: async (ipPrefix?: string): Promise<RealNetworkScanResponse> => {
    const response = await apiClient.post<RealNetworkScanResponse>('/parc/scan-real', null, {
      params: ipPrefix ? { ip_prefix: ipPrefix } : {},
    });
    return response.data;
  },
  importRealDevices: async (devices: {
    nom: string;
    ip: string;
    mac?: string;
    type: string;
    os?: string;
    groupe?: string;
  }[]) => {
    const response = await apiClient.post('/parc/import-real-devices', { devices });
    return response.data;
  },
  recalculateScores: async () => {
    const response = await apiClient.post('/parc/recalculate-scores');
    return response.data;
  },
  executeSSH: async (params: {
    ip: string;
    command: string;
    equipement_id?: number;
    port?: number;
    username?: string;
    password?: string;
    device_name?: string;
  }): Promise<{
    output: string;
    exit_code: number;
    mode: string;
    device: string;
    horodatage: string;
  }> => {
    const response = await apiClient.post('/parc/ssh/execute', params);
    return response.data;
  },
  exportCsv: async () => {
    const response = await apiClient.get('/parc/export-csv', { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'inventaire_parc_sentinelle.csv');
    document.body.appendChild(link);
    link.click();
    link.remove();
  },
  createEquipement: async (data: {
    nom: string;
    ip: string;
    mac?: string;
    type: string;
    os?: string;
    firmware?: string;
    groupe?: string;
    seuil_disque_alerte?: number;
    mot_de_passe_secret?: string;
  }): Promise<Equipement> => {
    const response = await apiClient.post<Equipement>('/parc/equipements', data);
    return response.data;
  },
  deleteEquipement: async (equipementId: number): Promise<{ message: string }> => {
    const response = await apiClient.delete<{ message: string }>(`/parc/equipements/${equipementId}`);
    return response.data;
  },
};

// Services de cybersécurité et détection d'anomalies
export const securiteService = {
  getEvents: async (anomaliesOnly = true) => {
    const response = await apiClient.get('/securite/events', {
      params: { anomalies_only: anomaliesOnly, limit: 50 },
    });
    return response.data;
  },
  getStats: async () => {
    const response = await apiClient.get('/securite/stats');
    return response.data;
  },
  scanRealSecurity: async () => {
    const response = await apiClient.post('/securite/scan-real');
    return response.data;
  },
  blockIp: async (ip: string, incidentId?: number, motif = 'Blocage manuel opérateur SOC') => {
    const response = await apiClient.post('/securite/block-ip', {
      source_ip: ip,
      incident_id: incidentId,
      motif,
    });
    return response.data;
  },
  isolateDevice: async (equipementId: number, deviceName: string, motif = 'Isolement préventif suite à anomalie critique') => {
    const response = await apiClient.post('/securite/isolate-device', {
      equipement_id: equipementId,
      device_name: deviceName,
      motif,
    });
    return response.data;
  },
};

// Services NetDevOps – Audit CIS, Backup, Diff, Remédiation & Restauration
export const netdevopsService = {
  getDevices: async () => {
    const response = await apiClient.get('/netdevops/devices');
    return response.data;
  },
  runAudit: async (deviceId: string) => {
    const response = await apiClient.post(`/netdevops/audit/${deviceId}`);
    return response.data;
  },
  getBackups: async (deviceId: string) => {
    const response = await apiClient.get(`/netdevops/backups/${deviceId}`);
    return response.data;
  },
  getDiff: async (deviceId: string, indexA = 1, indexB = 0) => {
    const response = await apiClient.get(`/netdevops/diff/${deviceId}`, {
      params: { index_a: indexA, index_b: indexB },
    });
    return response.data;
  },
  remediate: async (deviceId: string, remediationSnippet: string, ruleId?: string) => {
    const response = await apiClient.post(`/netdevops/remediate/${deviceId}`, {
      remediation_snippet: remediationSnippet,
      rule_id: ruleId,
    });
    return response.data;
  },
  restoreBackup: async (deviceId: string, backupIndex = 0) => {
    const response = await apiClient.post(`/netdevops/restore/${deviceId}`, {
      backup_index: backupIndex,
    });
    return response.data;
  },
};

// Services Dashboard Global AIOps
export const dashboardService = {
  getSummary: async () => {
    const response = await apiClient.get('/dashboard/summary');
    return response.data;
  },
  refreshSummary: async () => {
    const response = await apiClient.post('/dashboard/refresh');
    return response.data;
  },
};

// Services Assistant IA Conversationnel (RAG local & Ollama)
export const assistantService = {
  sendMessage: async (message: string) => {
    const response = await apiClient.post('/assistant/chat', { message });
    return response.data;
  },
  getSuggestedPrompts: async (): Promise<string[]> => {
    const response = await apiClient.get('/assistant/suggested-prompts');
    return response.data;
  },
};

// Services Administration, RBAC & Continuité d'Activité (PRA)
// Gestion du second facteur (TOTP) de l'utilisateur connecté
export const MFA_REQUIRED_DETAIL = 'MFA_REQUIRED';

export const isMfaRequiredError = (err: unknown): boolean =>
  axios.isAxiosError(err) &&
  err.response?.status === 401 &&
  err.response?.data?.detail === MFA_REQUIRED_DETAIL;

export const mfaService = {
  setup: async (): Promise<MfaSetupResponse> => {
    const response = await apiClient.post<MfaSetupResponse>('/auth/mfa/setup');
    return response.data;
  },
  enable: async (code: string): Promise<{ mfa_active: boolean; recovery_codes: string[] }> => {
    const response = await apiClient.post('/auth/mfa/enable', { code });
    return response.data;
  },
  disable: async (mot_de_passe: string, code: string): Promise<{ mfa_active: boolean }> => {
    const response = await apiClient.post('/auth/mfa/disable', { mot_de_passe, code });
    return response.data;
  },
  me: async (): Promise<{ email: string; mfa_active: boolean }> => {
    const response = await apiClient.get('/auth/me');
    return response.data;
  },
};

// Services d'administration (comptes, audit, PRA, notifications)
export const adminService = {
  getUsers: async () => {
    const response = await apiClient.get('/admin/users');
    return response.data;
  },
  createUser: async (userData: {
    identifiant: string;
    email: string;
    nom_complet: string;
    mot_de_passe: string;
    role: string;
  }) => {
    const response = await apiClient.post('/admin/users', userData);
    return response.data;
  },
  updateUserRole: async (userId: number, role: 'Administrateur' | 'Technicien' | 'Visiteur') => {
    const response = await apiClient.put(`/admin/users/${userId}/role`, { role });
    return response.data;
  },
  resetUserPassword: async (userId: number, nouveau_mot_de_passe: string) => {
    const response = await apiClient.post(`/admin/users/${userId}/password`, { nouveau_mot_de_passe });
    return response.data;
  },
  generateResetCode: async (userId: number): Promise<ResetCodeResponse> => {
    const response = await apiClient.post<ResetCodeResponse>(`/admin/users/${userId}/reset-code`);
    return response.data;
  },
  resetUserMfa: async (userId: number) => {
    const response = await apiClient.post(`/admin/users/${userId}/mfa/reset`);
    return response.data;
  },
  toggleUserStatus: async (userId: number) => {
    const response = await apiClient.put(`/admin/users/${userId}/status`);
    return response.data;
  },
  getAuditLogs: async (limit = 100, action?: string, search?: string) => {
    const response = await apiClient.get('/admin/audit-logs', {
      params: { limit, action, search },
    });
    return response.data;
  },
  triggerPraBackup: async () => {
    const response = await apiClient.post('/admin/pra/backup');
    return response.data;
  },
  listPraBackups: async () => {
    const response = await apiClient.get('/admin/pra/backups');
    return response.data;
  },
  verifyBackup: async (filename: string) => {
    const response = await apiClient.post(`/admin/pra/verify/${filename}`);
    return response.data;
  },
  restorePraBackup: async (filename: string) => {
    const response = await apiClient.post(`/admin/pra/restore/${filename}`);
    return response.data;
  },
  getPraMetrics: async () => {
    const response = await apiClient.get('/admin/pra/metrics');
    return response.data;
  },
  downloadAuditReportPdf: async (title = "Rapport d'Audit Global et Résilience", scope = "Infrastructure Globale") => {
    const response = await apiClient.get('/admin/reports/generate-pdf', {
      params: { title, scope },
      responseType: 'blob',
    });
    const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
    const link = document.createElement('a');
    link.href = url;
    const safeTitle = title.toLowerCase().replace(/[^a-z0-9]/g, '_');
    link.setAttribute('download', `sentinelle_audit_${safeTitle}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },
  getNotificationConfig: async () => {
    const response = await apiClient.get('/admin/notifications/config');
    return response.data;
  },
  saveNotificationConfig: async (payload: {
    telegram_enabled: boolean;
    telegram_token: string;
    telegram_chat_id: string;
    discord_enabled: boolean;
    discord_webhook: string;
    email_enabled: boolean;
    smtp_server: string;
    smtp_port: number;
    email_recipient: string;
    email_use_tls?: boolean;
  }) => {
    const response = await apiClient.put('/admin/notifications/config', payload);
    return response.data;
  },
  testNotificationChannel: async (payload: {
    channel: 'telegram' | 'discord' | 'email';
    message?: string;
    telegram_config?: { bot_token: string; chat_id: string };
    discord_config?: { webhook_url: string };
    email_config?: { smtp_server: string; smtp_port: number; recipient: string; use_tls?: boolean };
  }): Promise<{ success: boolean; channel: string; message: string; details?: string }> => {
    const response = await apiClient.post('/admin/notifications/test', payload);
    return response.data;
  },
  dispatchNotificationAlert: async (payload: {
    channels: Array<'telegram' | 'discord' | 'email'>;
    titre: string;
    message: string;
    severite?: 'INFO' | 'WARNING' | 'CRITICAL';
    telegram_config?: { bot_token: string; chat_id: string };
    discord_config?: { webhook_url: string };
    email_config?: { smtp_server: string; smtp_port: number; recipient: string };
  }) => {
    const response = await apiClient.post('/admin/notifications/dispatch', payload);
    return response.data;
  },
};
