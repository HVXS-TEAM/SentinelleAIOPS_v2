"""Vérification de bout en bout d'une installation Sentinelle face au VRAI réseau.

Interroge l'API d'un serveur en marche et rend un verdict par contrôle (OK / ÉCHEC / INFO) :
santé, connexion, sondes de chaque équipement du parc, audit CIS (configuration lue en SSH ou
dernière sauvegarde), journaux d'authentification de l'hôte, récepteur syslog, découverte du
sous-réseau. Rien n'est simulé : un équipement éteint ou un journal illisible ressort en ÉCHEC.

Usage :
    python scripts/verifier_terrain.py --url http://127.0.0.1:8000 --user admin
    (mot de passe : variable SENTINELLE_PASSWORD, sinon saisie masquée ; --mfa pour le code TOTP)
Code de sortie : 0 si aucun ÉCHEC, 1 sinon, 2 si le serveur est injoignable ou la connexion refusée.
Seule la bibliothèque standard est utilisée.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

OK, ECHEC, INFO = "OK", "ÉCHEC", "INFO"

# (méthode, chemin, corps JSON | None, jeton | None) -> (code HTTP, JSON | None)
Requeteur = Callable[[str, str, Optional[Dict[str, Any]], Optional[str]], Tuple[int, Any]]


@dataclass
class Controle:
    nom: str
    statut: str
    detail: str


class ServeurInjoignable(Exception):
    pass


def requeteur_http(base_url: str, delai: float = 60.0) -> Requeteur:
    def appel(methode, chemin, corps, jeton):
        donnees = json.dumps(corps).encode() if corps is not None else None
        req = urllib.request.Request(base_url.rstrip("/") + chemin, data=donnees, method=methode)
        req.add_header("Content-Type", "application/json")
        if jeton:
            req.add_header("Authorization", f"Bearer {jeton}")
        try:
            with urllib.request.urlopen(req, timeout=delai) as r:
                return r.status, json.loads(r.read().decode() or "null")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode() or "null")
            except ValueError:
                return exc.code, None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ServeurInjoignable(str(exc)) from exc
    return appel


def _detail(corps: Any, defaut: str) -> str:
    if isinstance(corps, dict) and isinstance(corps.get("detail"), str):
        return corps["detail"]
    return defaut


def verifier(req: Requeteur, user: str, mdp: str, mfa: Optional[str] = None) -> Tuple[List[Controle], bool]:
    """Exécute tous les contrôles. Renvoie (résultats, connexion_établie)."""
    res: List[Controle] = []
    ajout = lambda n, s, d: res.append(Controle(n, s, d))  # noqa: E731

    code, c = req("GET", "/api/v1/health", None, None)
    if code != 200 or not isinstance(c, dict) or c.get("status") != "healthy":
        ajout("Santé du serveur", ECHEC, f"HTTP {code} : {c}")
        return res, False
    ajout("Santé du serveur", OK, "base de données accessible")

    corps = {"identifiant": user, "mot_de_passe": mdp}
    if mfa:
        corps["code_mfa"] = mfa
    code, c = req("POST", "/api/v1/auth/login", corps, None)
    if code != 200 or not isinstance(c, dict) or "access_token" not in c:
        ajout("Connexion", ECHEC, _detail(c, f"HTTP {code}"))
        return res, False
    jeton = c["access_token"]
    ajout("Connexion", OK, f"{c.get('identifiant')} ({c.get('role')})")

    # Parc : une sonde réelle par équipement
    code, parc = req("GET", "/api/v1/parc/equipements", None, jeton)
    if code != 200 or not isinstance(parc, list):
        ajout("Inventaire du parc", ECHEC, _detail(parc, f"HTTP {code}"))
        parc = []
    elif not parc:
        ajout("Inventaire du parc", INFO, "aucun équipement : ajoutez-en ou lancez une découverte")
    else:
        ajout("Inventaire du parc", OK, f"{len(parc)} équipement(s)")
    for eq in parc:
        code, c = req("POST", f"/api/v1/parc/equipements/{eq['id']}/probe", None, jeton)
        nom = f"Sonde {eq.get('nom')} ({eq.get('ip')})"
        if code != 200 or not isinstance(c, dict):
            ajout(nom, ECHEC, _detail(c, f"HTTP {code}"))
            continue
        p = c.get("probe", {})
        if p.get("reachable"):
            lat = p.get("latency_ms")
            ports = ",".join(str(x) for x in p.get("open_ports") or []) or "aucun"
            ajout(nom, OK, f"joignable, latence {lat} ms, ports ouverts : {ports}, mode {p.get('mode')}")
        else:
            ajout(nom, ECHEC, "injoignable (ICMP/TCP sans réponse)")

    # NetDevOps : audit CIS de chaque équipement réseau
    code, devs = req("GET", "/api/v1/netdevops/devices", None, jeton)
    for d in (devs if code == 200 and isinstance(devs, list) else []):
        nom = f"Audit CIS {d.get('name')}"
        code, c = req("POST", f"/api/v1/netdevops/audit/{d['id']}", None, jeton)
        if code == 200 and isinstance(c, dict):
            ajout(nom, OK, f"score {c.get('score')} %, {len(c.get('violations', []))} écart(s), configuration : {c.get('config_source')}")
        else:
            ajout(nom, ECHEC, _detail(c, f"HTTP {code}"))

    # Sécurité : journaux de l'hôte + syslog
    code, c = req("POST", "/api/v1/securite/scan-real", None, jeton)
    if code != 200 or not isinstance(c, dict):
        ajout("Journaux d'authentification de l'hôte", ECHEC, _detail(c, f"HTTP {code}"))
    else:
        for s in c.get("sources", []):
            ajout(f"Source {s.get('source')}", OK if s.get("lisible") else ECHEC,
                  f"{s.get('evenements_lus', 0)} événement(s) lus" if s.get("lisible") else s.get("detail", ""))
        ajout("Analyse de sécurité", OK if not c.get("aucune_source_lisible") else ECHEC,
              f"{c.get('evenements_analyses', 0)} événement(s) analysé(s), {c.get('anomalies_detectees', 0)} anomalie(s), modèle {c.get('modele')}")
    code, c = req("GET", "/api/v1/securite/stats", None, jeton)
    if code == 200 and isinstance(c, dict):
        if c.get("syslog_actif"):
            ajout("Récepteur syslog", OK, f"{c.get('syslog_datagrammes_recus', 0)} datagramme(s) reçu(s), {c.get('syslog_ignores_source_inconnue', 0)} ignoré(s) (source hors parc)")
        else:
            ajout("Récepteur syslog", INFO, "désactivé (SYSLOG_ENABLED=true pour recevoir les journaux des équipements)")
        ajout("Historique d'apprentissage", INFO, f"{c.get('echantillons_baseline', 0)} / {c.get('echantillons_requis', 0)} observations")

    # Découverte du sous-réseau réel
    code, c = req("GET", "/api/v1/parc/local-network-info", None, jeton)
    if code == 200 and isinstance(c, dict) and c.get("subnet"):
        code, s = req("POST", "/api/v1/parc/scan-snmp", {"plage_ip": c["subnet"]}, jeton)
        if code == 200 and isinstance(s, dict):
            actifs, inconnus = len(s.get("equipements_actifs", [])), s.get("nouveaux_detectes", 0)
            ajout(f"Découverte de {c['subnet']}", OK if inconnus == 0 else INFO,
                  f"{actifs} hôte(s) actif(s), {inconnus} absent(s) du parc")
        else:
            ajout(f"Découverte de {c['subnet']}", ECHEC, _detail(s, f"HTTP {code}"))
    else:
        ajout("Découverte du sous-réseau", ECHEC, "sous-réseau local indéterminé")
    return res, True


def afficher(res: List[Controle]) -> None:
    largeur = max((len(r.nom) for r in res), default=10)
    for r in res:
        print(f"[{r.statut:<5}] {r.nom:<{largeur}}  {r.detail}")
    echecs = sum(1 for r in res if r.statut == ECHEC)
    print(f"\n{len(res)} contrôle(s) : {sum(1 for r in res if r.statut == OK)} OK, {echecs} ÉCHEC, "
          f"{sum(1 for r in res if r.statut == INFO)} INFO")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Vérifie Sentinelle face au réseau réel.")
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--user", required=True)
    ap.add_argument("--mfa", default=None, help="code TOTP si le MFA est activé")
    ap.add_argument("--json", action="store_true", help="sortie JSON")
    a = ap.parse_args(argv)
    mdp = os.environ.get("SENTINELLE_PASSWORD") or getpass.getpass("Mot de passe : ")
    try:
        res, connecte = verifier(requeteur_http(a.url), a.user, mdp, a.mfa)
    except ServeurInjoignable as exc:
        print(f"Serveur injoignable ({a.url}) : {exc}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps([r.__dict__ for r in res], ensure_ascii=False, indent=2))
    else:
        afficher(res)
    if not connecte:
        return 2
    return 1 if any(r.statut == ECHEC for r in res) else 0


if __name__ == "__main__":
    sys.exit(main())
