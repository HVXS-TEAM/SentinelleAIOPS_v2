"""Détection de sécurité sur journaux réels : analyseurs, journal, règles, Isolation Forest, syslog, pare-feu."""
import socket
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.db.models import (
    Alerte, Equipement, EvenementSecurite, JournalAuthentification,
)
from backend.app.db.session import SessionLocal
from backend.app.main import app
from backend.app.modules.securite import collectors
from backend.app.modules.securite.service import SecurityService
from backend.app.modules.securite.syslog_receiver import SyslogReceiver

client = TestClient(app)
IP_EMETTRICE = "127.0.0.2"


def _headers(identifiant="admin", mdp="AdminPassword2026!"):
    r = client.post("/api/v1/auth/login", json={"identifiant": identifiant, "mot_de_passe": mdp})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def db():
    session = SessionLocal()
    for modele in (JournalAuthentification, EvenementSecurite):
        session.query(modele).delete()
    session.query(Alerte).filter(Alerte.module_origine == "Sécurité").delete()
    session.commit()
    yield session
    for modele in (JournalAuthentification, EvenementSecurite):
        session.query(modele).delete()
    session.query(Alerte).filter(Alerte.module_origine == "Sécurité").delete()
    session.commit()
    session.close()


def _maintenant():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _echecs(ip, n, debut=None, users=("root",), origine="linux_authlog"):
    debut = debut or _maintenant() - timedelta(minutes=5)
    return [{"horodatage": debut + timedelta(seconds=i), "ip": ip, "user": users[i % len(users)],
             "succes": False, "invalide": False, "origine": origine} for i in range(n)]


# ── Analyseurs ───────────────────────────────────────────────────────────────

def test_analyseur_sshd_cisco_et_horodatage_iso():
    f = collectors.parse_auth_line("2026-11-18T07:59:01+01:00 h sshd[1]: Failed password for invalid user bob from 203.0.113.5 port 22 ssh2")
    assert (f["ip"], f["user"], f["succes"], f["invalide"]) == ("203.0.113.5", "bob", False, True)
    assert f["horodatage"] == datetime(2026, 11, 18, 6, 59, 1)  # converti en UTC
    c = collectors.parse_auth_line("*Nov 18 07:59:01.123: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 10.1.1.5] [localport: 22] [Reason: Login Authentication Failed]")
    assert (c["ip"], c["user"], c["succes"]) == ("10.1.1.5", "admin", False)
    ok = collectors.parse_auth_line("Nov 18 07:59:01 h sshd[1]: Accepted publickey for deploy from 10.0.0.2 port 22 ssh2")
    assert ok["succes"] is True
    assert collectors.parse_auth_line("Failed password for x from pas-une-ip port 22 ssh2") is None
    assert collectors.parse_auth_line("CRON[1]: pam_unix(cron:session): session opened") is None


def test_analyseur_windows_4625_4624():
    modele = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{eid}</EventID><TimeCreated SystemTime="2026-11-18T06:59:01.1234567Z"/></System><EventData><Data Name="TargetUserName">bob</Data><Data Name="IpAddress">{ip}</Data><Data Name="LogonType">{lt}</Data><Data Name="SubStatus">0xc0000064</Data></EventData></Event>'
    xml = (modele.format(eid=4625, ip="203.0.113.9", lt=3)
           + modele.format(eid=4624, ip="10.0.0.7", lt=3)
           + modele.format(eid=4624, ip="10.0.0.8", lt=5)      # ouverture de service : ignorée
           + modele.format(eid=4625, ip="-", lt=2))            # source locale : ignorée
    evs = collectors.parse_windows_events_xml(xml)
    assert [(e["ip"], e["succes"]) for e in evs] == [("203.0.113.9", False), ("10.0.0.7", True)]
    assert evs[0]["invalide"] is True and evs[0]["origine"] == "windows_eventlog"
    assert collectors.parse_windows_events_xml("pas du xml") == []


# ── Journal, règles et alertes ───────────────────────────────────────────────

def test_ingestion_sans_doublon(db):
    evs = _echecs("203.0.113.10", 4)
    assert SecurityService.ingest_events(db, evs) == 4
    assert SecurityService.ingest_events(db, evs) == 0  # relecture du même journal
    assert db.query(JournalAuthentification).count() == 4


def test_force_brute_detectee_alerte_unique_et_ip_saine_ignoree(db):
    SecurityService.ingest_events(db, _echecs("203.0.113.20", 8))
    SecurityService.ingest_events(db, [{"horodatage": _maintenant() - timedelta(minutes=2), "ip": "10.0.0.5",
                                        "user": "alice", "succes": True, "invalide": False, "origine": "linux_authlog"}])
    r1 = SecurityService.analyze_window(db)
    assert r1["modele"] == "regles_statiques" and r1["echantillons_baseline"] == 0
    assert r1["anomalies_detectees"] == 1 and r1["anomalies"][0]["type"] == "brute_force"
    assert r1["evenements_analyses"] == 9
    SecurityService.analyze_window(db)  # relance : pas de doublon
    assert db.query(EvenementSecurite).count() == 1
    assert db.query(Alerte).filter(Alerte.module_origine == "Sécurité", Alerte.statut == "Active").count() == 1
    ev = db.query(EvenementSecurite).one()
    assert ev.source_ip == "203.0.113.20" and ev.score_anomalie == 0.0 and ev.is_anomaly


def test_password_spraying_et_severite_critique(db):
    SecurityService.ingest_events(db, _echecs("203.0.113.21", 4, users=("a", "b", "c", "d")))
    r = SecurityService.analyze_window(db)
    assert r["anomalies"][0]["type"] == "brute_force" or r["anomalies"][0]["type"] == "password_spraying"
    assert r["anomalies"][0]["severite"] == "CRITICAL"


def test_isolation_forest_entraine_sur_historique_reel(db):
    hier = _maintenant() - timedelta(hours=30)
    historique = []
    for h in range(40):  # trafic réaliste : 1 à 4 connexions par IP, un échec de temps en temps
        n = 1 + h % 4
        for k in range(n):
            historique.append({"horodatage": hier + timedelta(hours=h % 20, minutes=h, seconds=k * 20), "ip": f"10.0.{h}.1",
                               "user": "u", "succes": not (k == 0 and h % 5 == 0), "invalide": False,
                               "origine": "linux_authlog"})
    SecurityService.ingest_events(db, historique)
    SecurityService.ingest_events(db, _echecs("203.0.113.30", 4))  # sous le seuil de la règle (5)
    r = SecurityService.analyze_window(db)
    assert r["modele"] == "isolation_forest+regles_statiques"
    assert r["echantillons_baseline"] >= 30
    assert r["anomalies_detectees"] == 1
    a = r["anomalies"][0]
    assert a["detecte_par_isolation_forest"] is True and a["detecte_par_regle"] is False
    assert a["score_ia"] != 0.0


def test_scan_sans_source_lisible_n_invente_rien(db, monkeypatch):
    statut = [{"source": "/var/log/auth.log", "lisible": False, "detail": "illisible : Permission denied", "evenements_lus": 0}]
    monkeypatch.setattr(collectors, "collecter_hote", lambda: ([], statut))
    r = SecurityService.run_real_security_scan(db)
    assert r["aucune_source_lisible"] is True and r["nouveaux_evenements"] == 0
    assert r["anomalies_detectees"] == 0 and r["evenements_analyses"] == 0
    assert db.query(JournalAuthentification).count() == 0 and db.query(EvenementSecurite).count() == 0


def test_scan_ingere_les_evenements_de_l_hote(db, monkeypatch):
    statut = [{"source": "journald", "lisible": True, "detail": "lu", "evenements_lus": 6}]
    evs = _echecs("203.0.113.40", 6)  # relecture du même journal : mêmes horodatages
    monkeypatch.setattr(collectors, "collecter_hote", lambda: (evs, statut))
    r = SecurityService.run_real_security_scan(db)
    assert r["nouveaux_evenements"] == 6 and r["anomalies_detectees"] == 1
    assert SecurityService.run_real_security_scan(db)["nouveaux_evenements"] == 0


# ── Syslog (UDP réel sur la boucle locale) ───────────────────────────────────

def test_recepteur_syslog_ne_retient_que_les_equipements_du_parc(db):
    ligne = b"<188>Nov 18 07:59:01 SW1: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 203.0.113.60] [localport: 22]"
    rec = SyslogReceiver("127.0.0.1", 0)
    rec.start()
    try:
        def envoyer():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((IP_EMETTRICE, 0))  # adresse source dédiée, distincte de celle de l'hôte de test
            s.sendto(ligne, ("127.0.0.1", rec.port))
            s.close()
        envoyer()  # cette adresse n'est pas dans le parc : ignoré
        t = time.time()
        while rec.recus < 1 and time.time() - t < 3:
            time.sleep(0.05)
        assert rec.ignores_source_inconnue == 1 and rec.enregistres == 0

        eq = Equipement(nom="SW-SYSLOG-TEST", ip=IP_EMETTRICE, type="Switch", os="IOS",
                        identifiants_chiffres="x", statut_collecte="OK", score_sante=100.0)
        db.add(eq); db.commit()
        try:
            envoyer()
            t = time.time()
            while rec.enregistres < 1 and time.time() - t < 3:
                time.sleep(0.05)
            assert rec.enregistres == 1
            ligne_bd = db.query(JournalAuthentification).one()
            assert ligne_bd.source_ip == "203.0.113.60" and ligne_bd.origine == "syslog"
            assert ligne_bd.equipement_id == eq.id and ligne_bd.succes is False
        finally:
            db.query(JournalAuthentification).delete()
            db.delete(eq); db.commit()
    finally:
        rec.stop()


# ── Pare-feu et isolement honnêtes ───────────────────────────────────────────

def test_blocage_refuse_quand_aucune_regle_n_est_creee(db, monkeypatch):
    SecurityService.ingest_events(db, _echecs("203.0.113.70", 6))
    SecurityService.analyze_window(db)
    monkeypatch.setattr(SecurityService, "_apply_firewall_block",
                        staticmethod(lambda ip, rule: (False, "IPTABLES", "droits administrateur requis")))
    r = client.post("/api/v1/securite/block-ip", json={"source_ip": "203.0.113.70"}, headers=_headers())
    assert r.status_code == 409 and "Aucune règle" in r.json()["detail"]
    assert "[BLOQUÉ]" not in (db.query(EvenementSecurite).one().explication or "")
    assert db.query(Alerte).filter(Alerte.statut == "Active", Alerte.module_origine == "Sécurité").count() == 1


def test_blocage_applique_marque_l_incident_et_resout_l_alerte(db, monkeypatch):
    SecurityService.ingest_events(db, _echecs("203.0.113.71", 6))
    SecurityService.analyze_window(db)
    monkeypatch.setattr(SecurityService, "_apply_firewall_block",
                        staticmethod(lambda ip, rule: (True, "IPTABLES", "Règle créée.")))
    r = client.post("/api/v1/securite/block-ip", json={"source_ip": "203.0.113.71"}, headers=_headers())
    assert r.status_code == 200 and r.json()["status"] == "BLOCKED"
    db.expire_all()
    assert "[BLOQUÉ]" in db.query(EvenementSecurite).one().explication
    assert db.query(Alerte).filter(Alerte.statut == "Active", Alerte.module_origine == "Sécurité").count() == 0
    assert client.get("/api/v1/securite/stats", headers=_headers()).json()["ips_bloquees"] == 1


def test_blocage_refuse_une_ip_anonymisee():
    r = client.post("/api/v1/securite/block-ip", json={"source_ip": "203.0.113.***"}, headers=_headers())
    assert r.status_code == 422


def test_blocage_reserve_aux_roles_autorises():
    r = client.post("/api/v1/securite/block-ip", json={"source_ip": "203.0.113.5"},
                    headers=_headers("visiteur", "VisiteurPassword2026!"))
    assert r.status_code == 403


def test_aucune_ligne_de_log_fabriquee_dans_le_code():
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "app" / "modules" / "securite"
    for f in src.glob("*.py"):
        texte = f.read_text(encoding="utf-8")
        for motif in ("netscan", "host_session", "Account=winuser", "contamination=0.25"):
            assert motif not in texte, f"{f.name} contient {motif!r}"


def test_syslog_desactive_par_defaut():
    from backend.app.core.config import settings
    assert settings.SYSLOG_ENABLED is False
