"""Tests unitaires et d'intégration du module Assistant IA Conversationnel (RAG local & Ollama)."""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.modules.assistant.service import AssistantService

client = TestClient(app)


def test_suggested_prompts_list():
    """Vérifie la présence et la pertinence des questions suggérées prédéfinies."""
    prompts = AssistantService.get_suggested_prompts()
    assert len(prompts) >= 4
    for p in prompts:
        assert isinstance(p, str)
        assert len(p) > 10


def test_build_system_context():
    """Vérifie l'extraction du contexte opérationnel multi-tables depuis SQLite."""
    db = SessionLocal()
    try:
        context = AssistantService._build_system_context(db)
        assert "CONTEXTE INFRASTRUCTURE SENTINELLE AIOPS" in context
        assert "Équipements" in context
        assert "Prédictions Time-To-Failure" in context
        assert "Alertes Actives" in context
    finally:
        db.close()


def test_semantic_intents_local_fallback():
    """Vérifie le routage sémantique et la précision des réponses en mode RAG local."""
    db = SessionLocal()
    try:
        # 1. Question Santé du parc
        res_sante = AssistantService._local_fallback_answer("Quels sont les équipements en état critique ou dégradé ?", db)
        assert "État de santé" in res_sante["response"]
        assert "Gestion de Parc" in res_sante["sources"]
        assert len(res_sante["suggested_followups"]) > 0

        # 2. Question Prédictions TTF
        res_ttf = AssistantService._local_fallback_answer("Y a-t-il des saturations de disque prévues dans les prochains jours ?", db)
        assert "Analyse Prédictive" in res_ttf["response"]
        assert "Supervision Prédictive" in res_ttf["sources"]

        # 3. Question Sécurité
        res_sec = AssistantService._local_fallback_answer("Quelles sont les attaques par force brute ou anomalies récentes ?", db)
        assert "Cybersécurité" in res_sec["response"]
        assert "Cybersécurité AIOps" in res_sec["sources"]

        # 4. Question CIS Benchmark
        res_cis = AssistantService._local_fallback_answer("Quel équipement Cisco a le pire score de conformité CIS ?", db)
        assert "CIS Benchmark" in res_cis["response"]
        assert "NetDevOps CIS" in res_cis["sources"]

        # 5. Question Générale
        res_gen = AssistantService._local_fallback_answer("Bonjour, fais-moi un résumé du réseau.", db)
        assert "Synthèse Globale" in res_gen["response"]
    finally:
        db.close()


@pytest.mark.asyncio
async def test_assistant_chat_async():
    """Vérifie l'appel au service asynchrone AssistantService.chat."""
    db = SessionLocal()
    try:
        res = await AssistantService.chat("Quelles sont les pannes imminentes ?", db)
        assert "response" in res
        assert "sources" in res
        assert "suggested_followups" in res
        assert res["mode"] in ["ollama", "rag_local"]
    finally:
        db.close()


def test_api_assistant_endpoints():
    """Vérifie les points de terminaison REST de l'API Assistant IA."""
    # 1. Questions suggérées
    resp_prompts = client.get("/api/v1/assistant/suggested-prompts")
    assert resp_prompts.status_code == 200
    prompts = resp_prompts.json()
    assert len(prompts) >= 4

    # 2. Chat POST
    payload = {"message": "Donne-moi une synthèse globale du parc"}
    resp_chat = client.post("/api/v1/assistant/chat", json=payload)
    assert resp_chat.status_code == 200
    data = resp_chat.json()
    assert "response" in data
    assert len(data["response"]) > 0
    assert "sources" in data
    assert "suggested_followups" in data
    assert "mode" in data


def test_config_snippet_and_file_analysis():
    """Vérifie l'analyse experte d'un fichier de configuration Cisco importé."""
    db = SessionLocal()
    try:
        sample_cfg = "[Fichier importé : switch-core.cfg]\nline vty 0 4\n login\n password cisco\n!"
        res = AssistantService._local_fallback_answer(sample_cfg, db)
        assert "Diagnostic Expert de Configuration" in res["response"]
        assert "Parseur Sémantique NetDevOps" in res["sources"]
        assert "configure terminal" in res["response"]
        assert len(res["suggested_followups"]) > 0
    finally:
        db.close()


def test_pra_and_continuity_intent():
    """Vérifie le routage sémantique sur les sauvegardes et le PRA."""
    db = SessionLocal()
    try:
        res = AssistantService._local_fallback_answer("Comment fonctionne la sauvegarde et le PRA ?", db)
        assert "Plan de Continuité" in res["response"]
        assert "Administration PRA" in res["sources"]
    finally:
        db.close()

