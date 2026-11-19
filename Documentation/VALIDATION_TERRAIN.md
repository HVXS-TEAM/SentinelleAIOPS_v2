# Validation sur un réseau réel

Ce guide fait passer Sentinelle d'« installé » à « vérifié face à de vrais équipements ». Il vaut pour un
laboratoire GNS3 (routeurs/commutateurs Cisco IOSv/IOSvL2), des serveurs Linux et un poste Windows.
Chaque étape donne la manipulation, le résultat attendu et, en cas d'écart, la cause probable.
Aucune donnée n'est simulée : un équipement éteint, un journal illisible ou une clé SSH changée apparaissent
comme des échecs, et c'est le comportement voulu.

## 0. Prérequis
- Sentinelle démarré (`README.md` §10) et compte administrateur créé à la première ouverture.
- Le serveur Sentinelle doit **joindre** les équipements en IP (ICMP, TCP 22, UDP 161) : en GNS3, relier le
  nuage « Cloud » (ou une interface TAP/VMware) au même réseau que l'hôte.
- Tester d'abord à la main depuis la machine qui héberge Sentinelle : `ping <ip>` puis `ssh <utilisateur>@<ip>`.

## 1. Équipement Cisco IOS (IOSv, IOSvL2, matériel)
Configuration minimale à saisir sur l'équipement (adapter noms, adresses et secrets) :

```
hostname SW-CORE-01
ip domain-name lab.local
crypto key generate rsa modulus 2048
ip ssh version 2
username sentinelle privilege 15 secret <mot-de-passe-long>
enable secret <autre-mot-de-passe>
line vty 0 4
 login local
 transport input ssh
 exec-timeout 10 0
snmp-server community <chaine-snmp> RO
service timestamps log datetime msec
logging host <ip-du-serveur-sentinelle> transport udp port 5514
logging trap informational
login on-failure log
login on-success log
```

Dans Sentinelle (page **Parc → Ajouter**) : nom identique au `hostname`, IP, type, OS. Le champ secret
accepte **soit** `utilisateur:mot-de-passe` (accès SSH, utilisé pour l'audit CIS, la configuration et le terminal),
**soit** une chaîne SNMP seule (télémétrie SNMP v2c). Les deux ne tiennent pas dans un même champ : pour un
équipement à superviser en SNMP *et* à auditer en SSH, la sonde SNMP essaie la communauté `public` si le secret
est de la forme `utilisateur:mot-de-passe`.

Résultats attendus :
| Action | Résultat attendu |
| :--- | :--- |
| Parc → sonder l'équipement | Joignable, latence mesurée, ports 22 (et 161) ouverts |
| NetDevOps → Audit | Score CIS calculé, « configuration : live » (relue en SSH) |
| Corriger une règle sans paramètre (ex. `CIS-1.6` : `no ip http server`) | Commandes envoyées par SSH, `write memory`, score relu plus haut |
| Règle avec paramètre (ex. `CIS-1.2`) | Correction manuelle affichée, bouton d'application désactivé |
| Équipement éteint puis audit | Dernière sauvegarde réelle utilisée (« sauvegarde <date> ») ou erreur 409 si aucune |
| Changer la clé SSH de l'équipement (`crypto key zeroize rsa` puis régénérer) | Connexion **refusée** (clé épinglée) ; levée par un administrateur via `/api/v1/admin/ssh/known-hosts` |

## 2. Serveur Linux
1. Installer `openssh-server`, créer un compte de service, l'ajouter dans Parc avec `utilisateur:mot-de-passe`.
2. Sonde attendue : CPU/RAM/disque réels collectés en SSH ; terminal : la sortie est celle de la machine.
3. **Détection d'intrusion** : si Sentinelle tourne sur ce serveur, vérifier la lecture du journal :
   `sudo tail -n 3 /var/log/auth.log` (ou `/var/log/secure`, ou `journalctl _COMM=sshd -n 3`). Le compte qui lance
   Sentinelle doit pouvoir lire ce fichier (groupe `adm` sous Debian/Ubuntu).
4. Depuis **une autre machine**, provoquer six échecs réels : `for i in 1 2 3 4 5 6; do ssh faux@<ip-serveur>; done`
   (saisir un mauvais mot de passe). Puis, dans Sentinelle, **Sécurité → scan** : une anomalie `brute_force` apparaît,
   avec l'IP de la machine émettrice (dernier octet masqué).
5. Blocage : le bouton « Bloquer l'IP » crée une règle `iptables`. Sans droits root, l'API répond 409 avec le motif ;
   lancer Sentinelle avec les droits nécessaires (ou accorder `CAP_NET_ADMIN`) pour que la règle soit réellement posée.

## 3. Poste ou serveur Windows
1. Lancer Sentinelle **en administrateur** : la lecture du journal Security (événements 4625/4624) l'exige.
   Sinon le scan répond « droits administrateur requis » et n'invente rien.
2. Provoquer de vrais échecs depuis une autre machine du réseau : `net use \\<ip-windows>\IPC$ /user:faux mauvais` (×6).
3. Sécurité → scan : anomalie `brute_force` avec l'IP source lue dans l'événement 4625.
4. Blocage : règle `netsh advfirewall` « Sentinelle_Block_<ip> » visible dans le pare-feu Windows.

## 4. Journaux des équipements réseau (syslog)
1. Démarrer Sentinelle avec `SYSLOG_ENABLED=true` (port UDP 5514 par défaut ; ouvrir ce port dans le pare-feu de l'hôte).
2. Depuis un poste du réseau, saisir six mots de passe faux en SSH vers l'IOSv.
3. Sécurité → panneau « Sources & moteur » : la source `syslog` compte les événements, le compteur « reçus » augmente.
4. Les datagrammes d'une IP absente du parc sont **ignorés** (compteur « ignorés ») : si rien n'est enregistré,
   vérifier que l'IP source des journaux est bien celle de la fiche équipement (utiliser `logging source-interface`).

## 5. Vérification automatique
```
python scripts/verifier_terrain.py --url http://127.0.0.1:8000 --user admin
```
(mot de passe dans la variable `SENTINELLE_PASSWORD` ou saisi de façon masquée ; `--mfa <code>` si le MFA est actif ;
`--json` pour une sortie exploitable.) L'outil enchaîne : santé, connexion, **une sonde par équipement**, audit CIS de
chaque équipement réseau, lecture des journaux de l'hôte, état du récepteur syslog, découverte du sous-réseau.
Code de sortie : `0` aucun échec, `1` au moins un échec, `2` serveur injoignable ou connexion refusée.

Un « ÉCHEC » est une information fiable, pas un défaut de l'outil. Causes fréquentes :
| Message | Cause probable |
| :--- | :--- |
| `injoignable (ICMP/TCP sans réponse)` | routage GNS3 absent, équipement éteint, pare-feu de l'hôte |
| `Configuration indisponible …` | SSH impossible **et** aucune sauvegarde : renseigner `utilisateur:mot-de-passe`, vérifier `transport input ssh` |
| `Clé d'hôte SSH rejetée` | clé changée depuis le premier contact : vérifier puis oublier l'empreinte (administration) |
| `illisible : Permission denied` (journal) | compte sans droit de lecture (groupe `adm`) ou Sentinelle non lancé en administrateur (Windows) |
| `Aucune règle de pare-feu n'a été créée` | droits root / administrateur manquants pour `iptables` / `netsh` |

## 6. Limites connues (à connaître avant de s'y fier)
- La remédiation CIS n'est appliquée que par une **vraie** session SSH réussie ; sinon rien n'est enregistré.
- « Restaurer » une sauvegarde réactive la configuration de référence dans Sentinelle ; elle n'est **pas** poussée sur l'équipement.
- Le bouton de quarantaine **marque** l'équipement dans Sentinelle ; l'isolement réseau (VLAN, ACL, port) reste manuel.
- L'Isolation Forest ne s'active qu'après `SECURITY_MIN_BASELINE_SAMPLES` observations réelles ; avant, seules les règles statiques détectent.
- Les journaux Linux/Windows lus sont ceux de la machine qui héberge Sentinelle ; pour les autres serveurs, utiliser leur syslog vers Sentinelle.
