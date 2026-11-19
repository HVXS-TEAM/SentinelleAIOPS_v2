# Sentinelle AIOps v2 — Dossier technique

Ce document décrit ce que le code fait réellement. Chaque affirmation renvoie à un module du dépôt ; ce qui n'est pas implémenté est signalé comme tel dans la section « Limites connues ».

## 1. Vue d'ensemble

Sentinelle est une application de supervision et de sécurité pour un parc informatique :

- un **backend FastAPI** (`backend/app`) qui collecte, analyse et expose une API REST sous `/api/v1` ;
- une **base SQLite** gérée par SQLAlchemy 2 (`backend/app/db`), créée vide au premier lancement ;
- une **interface React 19 / TypeScript** (`frontend/src`) qui n'affiche que des données renvoyées par le serveur ;
- un **lanceur de bureau PyQt6** (`launcher.py`) qui démarre le serveur sans fenêtre console.

Aucune donnée n'est préremplie : ni compte, ni équipement, ni événement. Tout ce qui apparaît à l'écran provient de l'hôte local, d'équipements ajoutés ou découverts, ou de journaux réellement lus.

## 2. Sources de données

| Source | Module | Ce qui est lu |
| :--- | :--- | :--- |
| Hôte local | `supervision/hardware_collector.py` | CPU, RAM, disque, débit réseau (psutil) |
| Équipements du parc | `supervision`, `parc` | ping, ports TCP, SSH (Paramiko), SNMP selon le secret enregistré |
| Journaux de l'hôte | `securite/collectors.py` | `auth.log`, `secure`, journald (Linux) ; `wevtutil` événements 4625/4624 (Windows) |
| Syslog réseau | `securite/syslog_receiver.py` | datagrammes UDP, uniquement depuis des IP d'équipements du parc |
| Réseau local | `parc` | découverte ARP / ICMP / TCP |

Format du secret d'un équipement : `utilisateur:motdepasse` désigne un accès SSH ; une chaîne sans `:` est une communauté SNMP. Les secrets sont chiffrés en base avec Fernet et jamais renvoyés par l'API.

Le récepteur syslog est désactivé par défaut (`SYSLOG_ENABLED=false`, port `5514`). Une source qui ne répond pas ou qui n'est pas lisible est signalée dans la réponse avec son statut ; elle n'est jamais remplacée par des valeurs inventées.

## 3. Ordonnanceur

`core/scheduler.py` (APScheduler) lance en tâche de fond :

- la collecte des métriques de l'hôte (toutes les 45 s) ;
- le sondage des équipements et le recalcul des scores de santé (toutes les 180 s) ;
- l'analyse des journaux de sécurité (`SECURITY_SCAN_INTERVAL_MINUTES`, 5 minutes par défaut) ;
- la purge des métriques de plus de 30 jours.

## 4. Score de santé d'un équipement

Calculé par `ParcService.calculate_health_score` à partir de quatre composantes pondérées :

| Composante | Poids |
| :--- | :---: |
| Disponibilité | 35 % |
| Ressources (pénalité au-delà de 75 % d'utilisation) | 25 % |
| Alertes actives (CRITICAL −25, WARNING −10) | 25 % |
| Conformité CIS | 15 % |

Un équipement jamais audité CIS n'obtient pas de score de conformité : l'interface affiche « Jamais auditée ».

## 5. Prédiction de saturation (TTF)

`SupervisionService.calculate_ttf` ajuste une droite par `numpy.polyfit` sur les 48 dernières mesures de la ressource.

- La pente horaire doit dépasser 0,001 point par heure, sinon aucune échéance n'est annoncée.
- Le seuil est celui de l'équipement pour le disque (`seuil_disque_alerte`, sinon `DEFAULT_CRITICAL_DISK_THRESHOLD`) et 90 % pour les autres métriques.
- Le R² et le MAPE (sur le dernier quart de l'échantillon) sont renvoyés avec la prédiction, ainsi qu'un niveau de confiance qui dépend du nombre de points et du R².
- L'échéance est bornée à 10 ans pour rester représentable.

C'est une extrapolation linéaire : elle ne prévoit pas les ruptures de tendance.

## 6. Détection de sécurité

Les événements d'authentification sont parsés (sshd, Cisco `%SEC_LOGIN`, Windows 4625/4624), dédupliqués par empreinte SHA-256 et stockés dans `journal_authentifications`.

Deux niveaux de détection :

1. **Règles statiques, toujours actives** : force brute (au moins 5 échecs, dont 80 % ou plus des tentatives d'une IP sur la fenêtre) et password spraying (au moins 3 comptes distincts et 3 échecs).
2. **Isolation Forest** (scikit-learn, 200 arbres, `random_state=42`) entraînée sur l'historique réel agrégé par IP et par fenêtre, uniquement quand `SECURITY_MIN_BASELINE_SAMPLES` (30 par défaut) échantillons existent.

Le modèle réellement utilisé est indiqué dans `/securite/stats` (`regles_statiques` ou `isolation_forest+regles_statiques`), avec le nombre d'échantillons disponibles et requis. Les alertes sont dédupliquées.

Réponses aux incidents :

- **Blocage d'IP** : tente `netsh advfirewall` (Windows) ou `iptables` (Linux). Si la commande n'est pas appliquée (droits insuffisants, outil absent), l'API répond `409` et l'incident n'est pas marqué bloqué. Une IP invalide ou anonymisée est refusée (`422`).
- **Isolement d'équipement** : l'équipement est marqué `QUARANTINE_MARKED` ; aucune action réseau n'est exécutée (`network_action_performed: false`).

Anonymisation : l'adresse affichée dans les rapports masque le dernier octet IPv4 (`198.51.100.***`). Ce n'est pas un hachage ; l'adresse complète reste en base pour permettre le blocage.

## 7. Audit CIS et NetDevOps

Les règles sont décrites dans `backend/config/cis_rules.yaml`. Un audit lit la configuration réelle de l'équipement par SSH, évalue chaque règle et renvoie les écarts, avec les commandes de correction (`remediation_commands`) fournies par la règle.

- Une règle sans commande de correction ne peut pas être appliquée automatiquement ; le bouton d'application est désactivé.
- Chaque modification passe par une sauvegarde horodatée avec empreinte SHA-256, ce qui permet la restauration.
- L'application des correctifs exige le rôle Technicien ou Administrateur.

## 8. Sécurité applicative

- **Authentification** : JWT HS256 (`ACCESS_TOKEN_EXPIRE_MINUTES`, 8 h par défaut), mots de passe en bcrypt (12 caractères minimum, lettres et chiffres), TOTP optionnel par compte (secret chiffré Fernet, anti-rejeu, 8 codes de secours).
- **Verrouillage** : 15 minutes après 5 échecs consécutifs, tracé dans `journal_audit`.
- **Rôles** : Administrateur, Technicien, Visiteur. Toute l'API, hors `/api/v1/auth/*` et `/api/v1/health`, exige un jeton valide ; les droits par action figurent dans le README.
- **Clés** : `SECRET_KEY` et `FERNET_KEY` sont générées au premier démarrage ou lues dans `backend/.env` ; l'application refuse une clé connue, trop courte ou invalide.
- **SSH** : la clé d'hôte est épinglée à la première connexion (`ssh_known_hosts`) ; une clé différente est refusée. `SSH_STRICT_HOST_KEYS=true` refuse aussi les hôtes inconnus.
- **Création de compte** : depuis la machine qui héberge Sentinelle (adresse de bouclage, sans en-tête `X-Forwarded-For`, `Forwarded` ni `X-Real-IP`), le profil est choisi par le demandeur ; c'est le modèle de confiance « qui dispose de l'application est de confiance » (`LOCAL_ACCOUNT_CREATION=false` pour le retirer). Depuis le réseau, l'inscription est fermée par défaut (`ALLOW_SELF_REGISTRATION=false`) et ne crée que des Visiteur. Sur une base vide, `POST /auth/setup` crée le premier compte avec le profil choisi.
- **Mot de passe oublié** : jeton à usage unique (table `jetons_reinitialisation`, empreinte SHA-256 seule), 30 minutes, 5 essais maximum, un nouveau jeton invalide le précédent. Livré par e-mail si `SMTP_HOST` et `SMTP_FROM` sont définis, sinon par un code généré par un administrateur. La réponse de `/auth/forgot-password` est identique que le compte existe ou non.
- **Erreurs** : aucune exception n'est avalée sans trace ; une erreur imprévue renvoie un `500` générique avec un `request_id` à retrouver dans `logs/sentinelle.log`.

## 9. Sauvegarde et restauration

`scripts/backup_restore_db.py` et le module d'administration créent des sauvegardes à chaud de la base SQLite, avec empreinte SHA-256 vérifiée avant toute restauration.

## 10. Vérification

- `python -m pytest backend/tests` : suite backend, exécutée dans un dossier temporaire (`SENTINELLE_DATA_DIR`).
- `npm run test` dans `frontend` : tests Vitest, dont `no-invented-data.test.ts` qui interdit le retour de données ou de modes de démonstration dans les sources.
- `.github/workflows/ci.yml` : rejoue le tout sous Linux et Windows, avec vérification des types, lint et build.
- `python scripts/verifier_terrain.py` et `Documentation/VALIDATION_TERRAIN.md` : validation de bout en bout sur un vrai réseau.

## 11. Limites connues

- Le TTF est linéaire ; il ne détecte ni saisonnalité ni rupture.
- L'Isolation Forest n'est active qu'après constitution d'une base d'historique suffisante ; avant cela seules les règles statiques détectent.
- Le syslog est reçu en UDP clair, sans authentification de l'émetteur autre que son adresse IP.
- L'isolement d'équipement est un marquage logique, pas une coupure réseau.
- Le blocage d'IP agit sur le pare-feu de la machine qui héberge Sentinelle, avec les droits du processus.
- La mesure réelle de la qualité de détection dépend de votre réseau ; aucun taux de précision n'est annoncé.
