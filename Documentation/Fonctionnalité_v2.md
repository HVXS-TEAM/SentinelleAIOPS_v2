# Fonctionnalités v2 — Plateforme AIOps Sentinelle

Plan de réalisation module par module : durée estimée, fonctions à garder, à ajouter ou à peaufiner, et ce qui est reporté. Durée totale : environ 2 à 3 mois (7 blocs de 1 à 2 semaines). Si le temps est limité à un mois, couper les blocs 6 (partie reporting) et 7.

## Ordre de réalisation

1. Socle (API, base de données, authentification)
2. Supervision
3. Gestion de parc
4. Sécurité
5. NetDevOps
6. Dashboard et reporting
7. Assistant IA (optionnel, à faire en dernier)

L'interface React se construit au fil de l'eau : une page par module terminé, plutôt qu'à la fin.

---

## 1. Socle (1 à 2 semaines)

**À garder**
- FastAPI, modèles SQLAlchemy
- Connexion JWT
- Rôles Administrateur / Technicien / Visiteur
- Journal d'audit

**À ajouter ou peaufiner**
- Migrations avec Alembic
- Chiffrement des identifiants SSH/SNMP stockés (Fernet)
- Limitation des tentatives de connexion
- Endpoint `/health` et logs applicatifs propres
- Secrets dans un fichier `.env` (jamais dans Git), validation des entrées avec Pydantic, CORS limité au frontend, dépendances figées
- Script de sauvegarde et de restauration de la base, avec un test de restauration réel (PRA simplifié)
- Jeu de données de démonstration
- Tests pytest sur l'authentification
- Docker / docker-compose

**À reporter à la fin**
- MFA TOTP
- Refresh tokens

---

## 2. Supervision (1 à 2 semaines)

**À garder**
- Collecte SNMP / SSH
- Série temporelle par métrique et par équipement
- Régression linéaire pour le Time-To-Failure (TTF)
- Alerte préventive

**À ajouter ou peaufiner**
- Script de simulation de remplissage de disque, pour valider la prédiction
- Calcul de l'erreur de prédiction (par exemple MAPE)
- Comparaison régression linéaire / lissage de Holt
- Indicateur de confiance quand il y a peu de points
- Gestion des données manquantes
- Gestion des pannes de collecte (timeouts, équipement injoignable, réponses SNMP invalides) avec un statut « dernière collecte réussie » par équipement
- Seuils configurables par équipement

**À reporter**
- Bande passante
- Modèles polynomiaux

---

## 3. Gestion de parc (1 semaine)

**À garder**
- Découverte SNMP
- Fiche équipement
- Score de santé

**À ajouter ou peaufiner**
- Formule de score simple et documentée, avec poids configurables
- Alerte si un équipement disparaît après N cycles sans réponse
- Alerte si un équipement inconnu apparaît sur le réseau (intérêt sécurité)
- Import / export CSV
- Groupes ou étiquettes

---

## 4. Sécurité (1 à 2 semaines)

**À garder**
- Parsing de auth.log (et Syslog)
- Indicateurs par fenêtre glissante
- Isolation Forest
- Alertes classées par sévérité

**À ajouter ou peaufiner**
- Détection simple par seuil comme point de comparaison (baseline), pour prouver l'apport du modèle
- Indicateurs : échecs par minute, nombre d'IP distinctes, ratio échecs/succès, utilisateurs inexistants, heures atypiques
- Jeu de test étiqueté (attaque simulée avec hydra + trafic normal) et matrice de confusion
- Explication de chaque alerte (quel indicateur l'a déclenchée)
- Regroupement des alertes en doublon
- Corrélation d'alertes : relier une alerte de sécurité et une alerte de supervision sur le même équipement dans un laps de temps court (par exemple échecs SSH en rafale puis CPU qui monte)
- Anonymisation partielle des IP et purge automatique (RGPD)

**À reporter**
- Traitement en temps réel (le traitement par lot suffit)

---

## 5. NetDevOps (2 semaines)

**À garder**
- Extraction de configuration avec Netmiko
- Sauvegarde de configuration
- Rapport d'audit
- Validation humaine avant toute correction

**À changer**
- Détection par un fichier de règles YAML (10 à 15 règles CIS pour Cisco IOS : mots de passe non chiffrés, SNMP v1/v2, Telnet, bannière absente, SSHv2, etc.)
- Le LLM local (Ollama) sert uniquement à expliquer le constat et proposer la commande de correction

**À ajouter ou peaufiner**
- Comparaison (diff) entre deux sauvegardes
- Score de conformité par équipement
- Restauration d'une sauvegarde

**À reporter**
- Application automatique des correctifs (générer un script que l'administrateur copie lui-même)
- Nornir

---

## 6. Dashboard et reporting (1 à 2 semaines)

**À garder**
- Vue d'ensemble (état du parc, alertes, TTF, conformité)
- Fiche équipement
- Liste des alertes

**À ajouter ou peaufiner**
- Filtres et acquittement des alertes
- Page des tâches planifiées : dernière exécution, résultat et prochaine échéance de chaque tâche APScheduler
- Page de paramètres : seuils d'alerte, canal de notification, durée de conservation (plutôt que des valeurs en dur dans le code)
- Rapport PDF d'audit
- Une seule notification au départ (e-mail ou Telegram)

**À reporter**
- Notification Discord
- Rapports planifiés

---

## 7. Assistant IA (1 semaine, optionnel)

**À garder**
- Lecture seule stricte

**À faire**
- 5 à 8 fonctions prédéfinies, sans SQL libre : état d'un équipement, alertes critiques, équipements avec un TTF bas, dernier audit
- Jeu de 10 questions de test

---

## En continu

- Tests unitaires et d'intégration
- Dépôt Git propre, commits réguliers
- Notes de ce qui est appris dans chaque module, pour la soutenance
- Script de démonstration : un scénario scripté qui lance l'attaque simulée, remplit un disque et ajoute un équipement, pour une soutenance reproductible
- Tableau de traçabilité exigences ↔ tests : critère d'acceptation, test qui le vérifie, résultat
- README d'installation (clone, `.env`, lancement) et journal de bord avec captures d'écran à chaque module, pour le mémoire

## Priorités parmi les ajouts

À faire en premier, car peu coûteux et très rentables à la soutenance : gestion des pannes de collecte, sauvegarde/restauration de la base, scénario de démonstration scripté, tableau de traçabilité exigences ↔ tests.
