# 🛡️ Sentinelle AIOps v2 — Bilan des Travaux (Passage en 100 % Réel) & Guide de Mise à Jour du `.exe`

> **Objectif accompli** : Transformer **Sentinelle AIOps v2** d'un prototype orienté démonstration vers un **outil de supervision Windows, de cybersécurité et d'automatisation NetDevOps 100 % fonctionnel en conditions réelles**, tout en conservant strictement la stack et les dépendances existantes.

---

## 1. Synthèse des Travaux Réalisés par Module

### 1.1. Collecte Matérielle & Ordonnanceur Temps Réel (`APScheduler` + `psutil` + `Paramiko`)
* **Fichiers modifiés / créés** :
  * [`backend/app/modules/supervision/hardware_collector.py`](backend/app/modules/supervision/hardware_collector.py)
  * [`backend/app/core/scheduler.py`](backend/app/core/scheduler.py) *(Nouveau)*
  * [`backend/app/main.py`](backend/app/main.py)
* **Évolutions réalisées** :
  1. **Détection réseau physique réelle** : La machine hôte remonte désormais sa **vraie adresse IP locale** et sa **vraie adresse MAC matérielle** (via `psutil.net_if_addrs()`), et non plus `127.0.0.1` / `00:00:00:00:00:00`.
  2. **Débit réseau en temps réel (`network_mbps`)** : Calcul du débit I/O instantané réel en Mbps via différentiel des compteurs `psutil.net_io_counters()` et persistance dans la table SQLite `metriques`.
  3. **Prédictions TTF multi-ressources** : Calcul automatique de la régression linéaire et du *Time-To-Failure* (TTF) sur les 3 métriques critiques : **Disque (`disk_percent`)**, **RAM (`ram_percent`)** et **CPU (`cpu_percent`)**.
  4. **Ordonnanceur autonome en tâche de fond (`APScheduler`)** :
     * **Toutes les 45 s** : Collecte automatique des métriques matérielles de la machine hôte.
     * **Toutes les 180 s** : Sondage actif (Ping ICMP silencieux `CREATE_NO_WINDOW`, ports TCP, SSH `Paramiko`, recalcul des scores de santé) de tous les équipements du parc.
     * **Toutes les 12 h** : Purge automatique des métriques de plus de 30 jours pour maîtriser l'empreinte disque de `sentinelle.db`.

---

### 1.2. Dashboard Exécutif & Topologie Dynamique
* **Fichiers modifiés** :
  * [`backend/app/modules/dashboard/service.py`](backend/app/modules/dashboard/service.py)
  * [`backend/app/api/v1/endpoints/dashboard.py`](backend/app/api/v1/endpoints/dashboard.py)
  * [`frontend/src/pages/DashboardPage.tsx`](frontend/src/pages/DashboardPage.tsx)
* **Évolutions réalisées** :
  1. **Suppression des courbes statiques codées en dur** : Le graphique principal et les mini-sparklines affichent désormais la **vraie série temporelle issue de SQLite (`telemetry_series`)** prolongée par **4 points de projection linéaire future (+15 min à +60 min)**.
  2. **Carte Topologique Dynamique** : La topologie du Dashboard se construit dynamiquement à partir des **équipements réellement présents dans votre inventaire** (votre PC hôte, votre passerelle/box, vos serveurs et switchs détectés), avec leur statut, score de santé et IP réels.
  3. **Bouton « Actualiser & Sonder » (`POST /api/v1/dashboard/refresh`)** : Force une collecte matérielle + réseau immédiate et met à jour tous les KPI.

---

### 1.3. Supervision Prédictive & Cycle de Vie Complet des Alertes
* **Fichiers modifiés** :
  * [`backend/app/schemas/supervision.py`](backend/app/schemas/supervision.py)
  * [`backend/app/modules/supervision/service.py`](backend/app/modules/supervision/service.py)
  * [`backend/app/api/v1/endpoints/supervision.py`](backend/app/api/v1/endpoints/supervision.py)
  * [`frontend/src/pages/SupervisionPage.tsx`](frontend/src/pages/SupervisionPage.tsx)
* **Évolutions réalisées** :
  1. **Gestion complète des alertes** : Ajout d'un panneau interactif permettant de filtrer les alertes (`Actives`, `Acquittées`, `Résolues`, `Toutes`), d'**Acquitter** (`PUT /api/v1/supervision/alerts/{id}/acknowledge`) et de **Résoudre** (`PUT /api/v1/supervision/alerts/{id}/resolve`) chaque incident.
  2. **Auto-Recovery** : Lorsqu'un équipement précédemment injoignable répond à nouveau au sondage, son alerte *« Échec de collecte »* passe automatiquement au statut `Résolue` et son score de santé remonte.
  3. **Courbes temps réel par équipement** : Les graphiques CPU, RAM, Disque et Réseau (Mbps) chargent directement l'historique SQLite de l'équipement sélectionné.

---

### 1.4. Parc & Inventaire : Télémétrie Réelle, Sonde Unitaire & Terminal Système Réel
* **Fichiers modifiés** :
  * [`backend/app/schemas/parc.py`](backend/app/schemas/parc.py)
  * [`backend/app/modules/parc/service.py`](backend/app/modules/parc/service.py)
  * [`backend/app/modules/parc/ssh_service.py`](backend/app/modules/parc/ssh_service.py)
  * [`backend/app/api/v1/endpoints/parc.py`](backend/app/api/v1/endpoints/parc.py)
  * [`frontend/src/pages/ParcPage.tsx`](frontend/src/pages/ParcPage.tsx)
* **Évolutions réalisées** :
  1. **Suppression des valeurs fictives dans les cartes et le tiroir d'inspection** : Chaque équipement est enrichi côté backend avec ses vraies métriques SQLite (`cpu_percent`, `ram_percent`, `disk_percent`, `network_mbps`), ses courbes historiques (`cpu_history`, `ram_history`), son statut CIS réel (`cis_status`, `cis_message`) et l'horodatage de sa dernière sauvegarde.
  2. **Sondage actif à la demande (`POST /api/v1/parc/equipements/{id}/probe`)** : Mesure la latence RTT réelle en millisecondes, détecte les ports TCP ouverts, interroge en SSH (`Paramiko`) si configuré et met à jour l'état de santé en direct.
  3. **Édition d'équipement & Chiffrement SSH Fernet (`PUT /api/v1/parc/equipements/{id}`)** : Permet d'enregistrer et chiffrer en AES-128 (Fernet) les identifiants SSH (`utilisateur:mot_de_passe`) directement depuis l'interface.
  4. **Terminal Interactif Réel** :
     * Sur la machine hôte et le LAN : exécute réellement `ping`, `arp -a`, `ipconfig /all`, `nslookup`, `tracert`, `netstat`, `df -h`, `free -m`, `ps aux`, `uptime`, `whoami` sans ouvrir aucune fenêtre `cmd.exe`.
     * Sur un serveur ou switch avec port 22 ouvert : ouvre une vraie session SSH `Paramiko`.

---

### 1.5. Cybersécurité Active : Scan Windows EventLog / Sockets & Pare-feu Windows Réel
* **Fichiers modifiés** :
  * [`backend/app/schemas/securite.py`](backend/app/schemas/securite.py)
  * [`backend/app/modules/securite/service.py`](backend/app/modules/securite/service.py)
  * [`backend/app/api/v1/endpoints/securite.py`](backend/app/api/v1/endpoints/securite.py)
  * [`frontend/src/pages/SecuritePage.tsx`](frontend/src/pages/SecuritePage.tsx)
* **Évolutions réalisées** :
  1. **Scan de sécurité réel de l'hôte (`POST /api/v1/securite/scan-real`)** : Inspecte les sockets réseau actifs (`psutil.net_connections`) ainsi que le journal d'événements **Windows Security (`EventID 4625 / 4624` via `wevtutil`)** ou `/var/log/auth.log`, puis soumet les observations au moteur **Isolation Forest**.
  2. **Blocage réel d'adresse IP dans le Pare-feu Windows (`POST /api/v1/securite/block-ip`)** : Crée une règle entrante de blocage dans **Windows Defender Firewall** (`netsh advfirewall firewall add rule name="Sentinelle_AIOps_Block_<IP>" dir=in action=block remoteip=<IP>`), résout l'alerte associée et journalise l'action dans l'audit.
  3. **Isolement d'équipement (`POST /api/v1/securite/isolate-device`)** : Place l'équipement compromis en quarantaine réseau et consigne l'événement.

---

### 1.6. NetDevOps : Remédiation CIS en 1 Clic & Restauration SHA-256
* **Fichiers modifiés** :
  * [`backend/app/modules/netdevops/service.py`](backend/app/modules/netdevops/service.py)
  * [`backend/app/api/v1/endpoints/netdevops.py`](backend/app/api/v1/endpoints/netdevops.py)
  * [`frontend/src/pages/NetDevOpsPage.tsx`](frontend/src/pages/NetDevOpsPage.tsx)
* **Évolutions réalisées** :
  1. **Synchronisation SQLite complète** : Les audits CIS mettent à jour la table `audits_reseau` et les sauvegardes alimentent la table `sauvegardes_config` (ce qui impacte directement le score de santé composite du parc).
  2. **Remédiation CIS réelle (`POST /api/v1/netdevops/remediate/{device_id}`)** : Les boutons **« Appliquer ce correctif »** et **« Tout Corriger (CIS) »** appliquent réellement les directives de durcissement sur la configuration de l'équipement (et en SSH via `Paramiko` si joignable), créent un snapshot signé **SHA-256**, recalculent le score CIS (jusqu'à 100 %) et affichent le **Diff unifié**.
  3. **Restauration de sauvegarde (`POST /api/v1/netdevops/restore/{device_id}`)** : Permet de restaurer en 1 clic n'importe quelle version antérieure depuis l'historique des sauvegardes.

---

### 1.7. Administration, Restauration PRA à Chaud & Mode « 100 % Réseau Physique »
* **Fichiers modifiés** :
  * [`backend/app/schemas/admin.py`](backend/app/schemas/admin.py)
  * [`backend/app/modules/admin/service.py`](backend/app/modules/admin/service.py)
  * [`backend/app/api/v1/endpoints/admin.py`](backend/app/api/v1/endpoints/admin.py)
  * [`frontend/src/pages/AdminPage.tsx`](frontend/src/pages/AdminPage.tsx)
* **Évolutions réalisées** :
  1. **Restauration PRA SQLite à chaud (`POST /api/v1/admin/pra/restore/{filename}`)** : Vérifie l'intégrité **SHA-256** de l'archive sélectionnée, crée un snapshot de sécurité pré-restauration, puis restaure à chaud la base `sentinelle.db` via l'API transactionnelle `sqlite3.backup()`.
  2. **Persistance chiffrée des notifications (`GET/PUT /api/v1/admin/notifications/config`)** : Les tokens Telegram, Webhooks Discord et paramètres SMTP sont sauvegardés et chiffrés côté serveur (et non plus perdus à la fermeture).
  3. **Bascule en « Mode 100 % Réseau Physique » (`POST /api/v1/admin/environment/real-only`)** : Purge en 1 clic les équipements fictifs du laboratoire initial pour ne conserver que votre PC hôte et les équipements réellement découverts sur votre réseau local (LAN).

---

## 2. Étapes de Mise à Jour de l'Exécutable Windows (`.exe`)

L'exécutable autonome **`Sentinelle-AIOps.exe`** embarque directement le dossier `frontend/dist` (l'interface React compilée) ainsi que tout le backend Python FastAPI et le lanceur graphique PyQt6.

Voici la procédure exacte à exécuter sous **Windows (PowerShell)** à la racine du projet :

### Étape 1 — Compiler la nouvelle interface Frontend (`frontend/dist`)
Ouvrez un terminal **PowerShell** à la racine du projet (`Sentinelle AIOPS -  v2`) et exécutez :

```powershell
cd frontend
npm run build
cd ..
```
> **Vérification** : Cette commande exécute `tsc -b && vite build` et met à jour le dossier `frontend\dist` avec toutes les nouvelles fonctionnalités React.

---

### Étape 2 — Fermer toute instance en cours de Sentinelle AIOps
Avant de régénérer le `.exe`, assurez-vous qu'aucune instance de `Sentinelle-AIOps.exe` n'est ouverte (y compris dans la zone de notification *System Tray* près de l'horloge Windows), sinon Windows verrouillera le fichier `dist\Sentinelle-AIOps.exe`.

En cas de doute, vous pouvez exécuter dans PowerShell :
```powershell
Stop-Process -Name "Sentinelle-AIOps" -Force -ErrorAction SilentlyContinue
```

---

### Étape 3 — Recompiler l'exécutable autonome (`dist\Sentinelle-AIOps.exe`) avec PyInstaller
Activez l'environnement virtuel Python du projet puis lancez `PyInstaller` avec le fichier [`sentinelle.spec`](sentinelle.spec) (qui inclut déjà `apscheduler`, `paramiko`, `psutil`, `PyQt6`, `uvicorn`, `fastapi` et `frontend/dist`) :

```powershell
.\.venv\Scripts\Activate.ps1
pyinstaller --clean --noconfirm sentinelle.spec
```

Une fois la compilation terminée (environ 45 à 90 secondes), votre nouvel exécutable autonome est prêt à l'emplacement :
```text
dist\Sentinelle-AIOps.exe
```

---

### Étape 4 — (Optionnel) Régénérer l'installateur Windows (`dist\Sentinelle-AIOps-Setup.exe`)
Si vous utilisez **NSIS (Nullsoft Scriptable Install System)** pour produire l'installateur complet configuré dans [`installer.nsi`](installer.nsi) :

```powershell
makensis installer.nsi
```
Cela mettra à jour l'installateur :
```text
dist\Sentinelle-AIOps-Setup.exe
```

---

## 3. Scénario de Démonstration Temps Réel (Soutenance / Présentation)

Pour démontrer que l'application fonctionne à **100 % en réel** lors de votre présentation :

1. **Supervision Matérielle & Réseau Réelle** :
   * Dans **Parc & Inventaire**, cliquez sur **« Mode 100 % Réseau Physique (Purger Démo) »** (ou depuis **Administration & PRA**) ou lancez le **Scanner Réseau Local** : l'application découvre votre passerelle/box et les machines de votre réseau avec leurs vraies adresses IP/MAC et leur latence en millisecondes.
   * Ouvrez le **Terminal SSH / Système** sur votre machine hôte et tapez `ipconfig /all`, `netstat`, `df -h` ou `ping 8.8.8.8` : la vraie sortie système s'affiche instantanément sans aucune fenêtre `cmd.exe`.
2. **Gestion Réelle du Cycle de Vie des Alertes** :
   * Dans **Supervision & TTF**, cliquez sur **« Collecter Mon PC »**, puis dans la table **Gestion des Alertes**, cliquez sur **« Acquitter »** puis **« Résoudre »** : l'état change en base SQLite et le score de santé global remonte en direct.
3. **Cybersécurité & Pare-feu Windows Réel** :
   * Dans **Cybersécurité (IA)**, cliquez sur **« Scanner Sécurité Hôte (Réel) »** pour analyser vos connexions actives et journaux Windows.
   * Dans le tiroir d'inspection d'une menace, cliquez sur **« Bloquer l'IP (Pare-feu) »** : la règle de blocage est injectée dans le Pare-feu Windows Defender (`netsh advfirewall`).
4. **NetDevOps : Durcissement CIS & Rollback SHA-256** :
   * Dans **NetDevOps (CIS)**, sélectionnez un équipement ayant des non-conformités et cliquez sur **« Tout Corriger (CIS) »** : le score CIS passe à **100 %**, une sauvegarde SHA-256 est créée et le **Diff unifié** affiche les lignes ajoutées/supprimées. Cliquez ensuite sur **« Restaurer »** dans l'historique pour prouver le retour arrière instantané.
5. **Continuité d'Activité (PRA)** :
   * Dans **Administration & PRA**, créez une sauvegarde à chaud, vérifiez son empreinte **SHA-256**, puis cliquez sur **« Restaurer »** pour démontrer la restauration transactionnelle SQLite sans coupure de service.

