"""
Module NetDevOps – Audit CIS Benchmark, Backup & Diff de configs Cisco IOS.

Responsabilités :
  - Charger les règles CIS depuis cis_rules.yaml
  - Auditer une config Cisco simulée et produire un score de conformité
  - Sauvegarder les configs horodatées en JSON
  - Générer un diff humain entre deux sauvegardes
  - Appeler l'API Ollama locale pour des recommandations LLM
"""

from __future__ import annotations

import difflib
import json
import os
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

from backend.app.core.config import DATA_DIR, CIS_RULES_PATH, CONFIG_BACKUP_DIR

# ── Chemins ──────────────────────────────────────────────────────────────────

_BASE_DIR = DATA_DIR
_CIS_RULES_PATH = CIS_RULES_PATH
_BACKUP_DIR = CONFIG_BACKUP_DIR
_BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# ── Configs Cisco IOS simulées ────────────────────────────────────────────────

_SIMULATED_CONFIGS: dict[str, str] = {
    "SW-CORE-01": textwrap.dedent("""\
        version 15.2
        hostname SW-CORE-01
        service password-encryption
        enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
        !
        ip ssh version 2
        ip http secure-server
        !
        ntp server 192.168.1.1
        service timestamps log datetime msec localtime show-timezone
        logging host 192.168.1.254
        logging trap informational
        !
        banner motd ^C Authorized access only. ^C
        !
        line vty 0 4
         exec-timeout 10 0
         transport input ssh
         login local
        !
        no ip source-route
        no ip http server
        !
        snmp-server community SNMP-BTS01 ro
        !
        interface GigabitEthernet0/1
         no cdp enable
         ip access-group ACL-WAN in
        !
        ip access-group ACL-WAN in
        end
    """),

    "RTR-EDGE-01": textwrap.dedent("""\
        version 15.4
        hostname RTR-EDGE-01
        enable password cisco123
        !
        line vty 0 4
         transport input telnet
        !
        ip http server
        snmp-server community public ro
        snmp-server community private rw
        !
        interface GigabitEthernet0/0
         cdp enable
        !
        end
    """),

    "FW-PERIMETER-01": textwrap.dedent("""\
        version 9.8
        hostname FW-PERIMETER-01
        service password-encryption
        enable secret 8 $8$dsJues.4IuoFpk$pWPsOO4UaV8WRO
        !
        ip ssh version 2
        no ip http server
        !
        ntp server 10.0.0.1
        ntp authenticate
        service timestamps log datetime
        logging host 10.0.0.254
        logging trap informational
        !
        banner motd ^C Restricted – BTS SIO Lab ^C
        !
        line vty 0 4
         exec-timeout 10 0
         transport input ssh
         login local
        !
        no ip source-route
        no cdp enable
        ip access-group ACL-PERIMETER in
        end
    """),

    "AP-WIFI-01": textwrap.dedent("""\
        version 12.4
        hostname AP-WIFI-01
        !
        line vty 0 4
         transport input telnet
        !
        ip http server
        snmp-server community public ro
        !
        end
    """),
}

# ── Chargement des règles CIS ─────────────────────────────────────────────────


def _load_cis_rules() -> list[dict[str, Any]]:
    """Charge et retourne les règles depuis le fichier YAML."""
    with _CIS_RULES_PATH.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])


# ── Moteur d'audit ────────────────────────────────────────────────────────────

_SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}


def _audit_config(device_id: str, config: str) -> dict[str, Any]:
    """
    Applique les règles CIS sur une config et retourne un rapport structuré.

    Score = (points obtenus / points possibles) × 100
    """
    rules = _load_cis_rules()
    violations: list[dict[str, Any]] = []
    compliant: list[dict[str, Any]] = []

    total_weight = sum(_SEVERITY_WEIGHT.get(r.get("severity", "LOW"), 1) for r in rules)
    earned_weight = 0

    for rule in rules:
        rule_id = rule["id"]
        severity = rule.get("severity", "LOW")
        weight = _SEVERITY_WEIGHT.get(severity, 1)
        passed = True
        fail_reason = ""

        # Vérification du pattern attendu
        if "pattern" in rule:
            if not re.search(rule["pattern"], config, re.IGNORECASE):
                passed = False
                fail_reason = f"Pattern attendu introuvable : '{rule['pattern']}'"

        # Vérification du pattern interdit
        if "regex_forbidden" in rule and re.search(rule["regex_forbidden"], config, re.IGNORECASE):
            passed = False
            fail_reason = (
                fail_reason + " | " if fail_reason else ""
            ) + f"Pattern interdit détecté : '{rule['regex_forbidden']}'"

        if passed:
            earned_weight += weight
            compliant.append({"id": rule_id, "title": rule["title"], "severity": severity})
        else:
            violations.append(
                {
                    "id": rule_id,
                    "title": rule["title"],
                    "severity": severity,
                    "cis_ref": rule.get("cis_ref", ""),
                    "description": rule.get("description", "").strip(),
                    "fail_reason": fail_reason,
                    "remediation": rule.get("remediation", ""),
                }
            )

    score = round((earned_weight / total_weight) * 100, 1) if total_weight else 0

    return {
        "device_id": device_id,
        "audit_ts": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "total_rules": len(rules),
        "passed_rules": len(compliant),
        "failed_rules": len(violations),
        "violations": sorted(violations, key=lambda v: _SEVERITY_WEIGHT.get(v["severity"], 0), reverse=True),
        "compliant": compliant,
    }


# ── Sauvegarde & Diff ─────────────────────────────────────────────────────────


def _backup_path(device_id: str) -> Path:
    return _BACKUP_DIR / f"{device_id}.json"


def _save_backup(device_id: str, config: str) -> dict[str, Any]:
    """Ajoute une sauvegarde horodatée de la config dans le fichier JSON du device."""
    path = _backup_path(device_id)
    history: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "config": config,
    }
    history.insert(0, entry)
    # Conservation des 10 dernières sauvegardes
    history = history[:10]
    path.write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"device_id": device_id, "saved_at": entry["ts"], "total_backups": len(history)}


def _get_backups(device_id: str) -> list[dict[str, Any]]:
    path = _backup_path(device_id)
    if not path.exists():
        return []
    history = json.loads(path.read_text(encoding="utf-8"))
    # On ne retourne pas la config complète dans la liste
    return [{"ts": e["ts"], "index": i} for i, e in enumerate(history)]


def _diff_configs(device_id: str, index_a: int = 1, index_b: int = 0) -> dict[str, Any]:
    """Retourne un diff unifié entre deux sauvegardes (index_a=ancienne, index_b=récente)."""
    path = _backup_path(device_id)
    if not path.exists():
        return {"error": "Aucune sauvegarde disponible."}

    history = json.loads(path.read_text(encoding="utf-8"))
    if len(history) <= max(index_a, index_b):
        return {"error": "Index de sauvegarde invalide."}

    config_a = history[index_a]["config"].splitlines(keepends=True)
    config_b = history[index_b]["config"].splitlines(keepends=True)

    diff_lines = list(
        difflib.unified_diff(
            config_a,
            config_b,
            fromfile=f"{device_id} [{history[index_a]['ts']}]",
            tofile=f"{device_id} [{history[index_b]['ts']}]",
        )
    )

    return {
        "device_id": device_id,
        "from_ts": history[index_a]["ts"],
        "to_ts": history[index_b]["ts"],
        "diff": "".join(diff_lines),
        "changed_lines": sum(1 for l in diff_lines if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))),
    }


# ── Intégration Ollama LLM ────────────────────────────────────────────────────

_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")


_UNICODE_EMOJI_RE = re.compile(
    r"[\U0001F300-\U0001FAFF\u2600-\u27BF\u2300-\u23FF\uFE0F]"
)


async def _get_llm_recommendations(violations: list[dict[str, Any]], device_id: str) -> str:
    """
    Appelle Ollama localement pour générer des recommandations en langage naturel.
    Retourne un texte de fallback si Ollama n'est pas disponible.
    """
    if not violations:
        return "[CONFORME] Aucune violation détectée. La configuration est conforme au CIS Benchmark."

    violations_text = "\n".join(
        f"- [{v['severity']}] {v['id']} – {v['title']}: {v['remediation']}"
        for v in violations[:8]  # Limite pour ne pas saturer le prompt
    )

    prompt = (
        f"Tu es un expert réseau et sécurité. "
        f"L'équipement '{device_id}' présente les non-conformités CIS suivantes :\n\n"
        f"{violations_text}\n\n"
        f"Rédige un rapport de recommandations concis (max 200 mots) en français, "
        f"priorisé par criticité. Commence par les risques CRITICAL, puis HIGH, puis MEDIUM. "
        f"N'utilise aucun émoji ; utilise uniquement les tags [CRITIQUE], [MAJEUR], [MINEUR], [CONFORME]."
    )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{_OLLAMA_URL}/api/generate",
                json={"model": _OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            response.raise_for_status()
            raw_text = response.json().get("response", "").strip()
            return _UNICODE_EMOJI_RE.sub("", raw_text).strip()
    except Exception:
        # Fallback : recommandations synthétiques générées localement
        return _generate_local_recommendations(violations, device_id)


def _generate_local_recommendations(violations: list[dict[str, Any]], device_id: str) -> str:
    """Génère des recommandations locales si Ollama n'est pas disponible."""
    critical = [v for v in violations if v["severity"] == "CRITICAL"]
    high = [v for v in violations if v["severity"] == "HIGH"]
    medium = [v for v in violations if v["severity"] == "MEDIUM"]

    lines = [f"[AUDIT CIS] **Rapport de conformité CIS – {device_id}**\n"]

    if critical:
        lines.append("### [CRITIQUE] Actions critiques immédiates")
        for v in critical:
            lines.append(f"- **{v['id']}** : {v['remediation']}")

    if high:
        lines.append("\n### [MAJEUR] Corrections haute priorité")
        for v in high:
            lines.append(f"- **{v['id']}** : {v['remediation']}")

    if medium:
        lines.append("\n### [MINEUR] Améliorations recommandées")
        for v in medium:
            lines.append(f"- **{v['id']}** : {v['remediation']}")

    return "\n".join(lines)


# ── API publique du service ───────────────────────────────────────────────────


def get_available_devices() -> list[dict[str, str]]:
    """Retourne la liste des équipements disponibles pour l'audit."""
    return [
        {"id": "SW-CORE-01", "name": "Switch Core", "type": "switch", "os": "IOS 15.2"},
        {"id": "RTR-EDGE-01", "name": "Routeur Edge", "type": "router", "os": "IOS 15.4"},
        {"id": "FW-PERIMETER-01", "name": "Pare-feu Périmètre", "type": "firewall", "os": "ASA 9.8"},
        {"id": "AP-WIFI-01", "name": "Point d'Accès WiFi", "type": "access_point", "os": "IOS 12.4"},
    ]


async def run_audit(device_id: str) -> dict[str, Any]:
    """
    Lance un audit CIS complet sur un équipement.
    Sauvegarde automatiquement la config auditée et génère les recommandations LLM.
    """
    config = _SIMULATED_CONFIGS.get(device_id)
    if config is None:
        raise ValueError(f"Équipement inconnu : {device_id}")

    # Audit CIS
    report = _audit_config(device_id, config)

    # Sauvegarde automatique de la config auditée
    _save_backup(device_id, config)

    # Recommandations LLM (Ollama ou fallback local)
    report["llm_recommendations"] = await _get_llm_recommendations(report["violations"], device_id)

    return report


def get_device_backups(device_id: str) -> list[dict[str, Any]]:
    """Retourne l'historique des sauvegardes d'un équipement."""
    if device_id not in _SIMULATED_CONFIGS:
        raise ValueError(f"Équipement inconnu : {device_id}")
    return _get_backups(device_id)


def get_config_diff(device_id: str, index_a: int = 1, index_b: int = 0) -> dict[str, Any]:
    """Retourne le diff entre deux sauvegardes d'un équipement."""
    if device_id not in _SIMULATED_CONFIGS:
        raise ValueError(f"Équipement inconnu : {device_id}")
    return _diff_configs(device_id, index_a, index_b)
