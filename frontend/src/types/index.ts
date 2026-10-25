/**
 * Définitions TypeScript globales pour Sentinelle AIOps.
 */

export interface User {
  id: number;
  identifiant: string;
  email: string;
  nom_complet: string;
  role: 'Administrateur' | 'Technicien' | 'Visiteur';
  mfa_active: boolean;
  est_actif: boolean;
  date_creation: string;
  derniere_connexion?: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  role: string;
  nom_complet: string;
  identifiant: string;
  email?: string;
  message?: string;
}

export interface RegisterData {
  identifiant: string;
  email: string;
  nom_complet: string;
  mot_de_passe: string;
  role: string;
}

export interface Equipement {
  id: number;
  nom: string;
  ip: string;
  mac?: string;
  type: string;
  os?: string;
  firmware?: string;
  uptime_secondes: number;
  score_sante: number;
  statut_collecte: 'OK' | 'Erreur' | 'Injoignable';
  derniere_collecte: string;
  groupe: string;
  seuil_disque_alerte: number;
}

export interface MetricPoint {
  id: number;
  equipement_id: number;
  type_metrique: string;
  valeur: number;
  horodatage: string;
}

export interface MetricSeries {
  equipement_id: number;
  equipement_nom: string;
  type_metrique: string;
  points: MetricPoint[];
}

export interface Prediction {
  id: number;
  equipement_id: number;
  equipement_nom?: string;
  metrique: string;
  valeur_actuelle: number;
  pente_horaire: number;
  r2_score: number;
  mape_erreur?: number;
  indice_confiance: 'Haute' | 'Moyenne' | 'Faible';
  ttf_estime_heures?: number;
  date_saturation_estimee?: string;
  date_calcul: string;
}

export interface Alerte {
  id: number;
  equipement_id?: number;
  module_origine: 'Supervision' | 'Sécurité' | 'NetDevOps' | 'Parc';
  severite: 'INFO' | 'WARNING' | 'CRITICAL';
  titre: string;
  message: string;
  statut: 'Active' | 'Acquittée' | 'Résolue';
  correlation_id?: string;
  date_creation: string;
}

export interface HardwareLiveStats {
  equipement_id: number;
  hostname: string;
  ip: string;
  os: string;
  firmware: string;
  cpu_percent: number;
  cpu_count: number;
  ram_percent: number;
  ram_total_gb: number;
  ram_used_gb: number;
  disk_percent: number;
  disk_total_gb: number;
  disk_used_gb: number;
  disk_mount: string;
  network_sent_mb: number;
  network_recv_mb: number;
  uptime_secondes: number;
  score_sante: number;
  horodatage: string;
}

export interface LocalNetworkInfo {
  local_ip: string;
  subnet: string;
  hostname: string;
  gateway_ip?: string;
  interface_name?: string;
}

export interface DiscoveredDevice {
  ip: string;
  mac?: string;
  hostname?: string;
  type: string;
  os?: string;
  open_ports: number[];
  banner?: string;
  already_in_parc: boolean;
}

export interface RealNetworkScanResponse {
  subnet: string;
  local_host: LocalNetworkInfo;
  devices_count: number;
  devices: DiscoveredDevice[];
  scan_duration_ms: number;
}


