"""Tests unitaires et d'intégration du système de notifications multi-canal."""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.modules.admin.notifications import NotificationService
from backend.app.schemas.admin import (
    TelegramChannelConfig,
    DiscordChannelConfig,
    EmailChannelConfig,
    NotificationTestResponse,
)

client = TestClient(app)


def get_auth_token(identifiant: str = "admin", mot_de_passe: str = "AdminPassword2026!") -> str:
    resp = client.post("/api/v1/auth/login", json={"identifiant": identifiant, "mot_de_passe": mot_de_passe})
    return resp.json()["access_token"]


def test_discord_webhook_invalid_url():
    """Vérifie le rejet d'une URL de webhook non sécurisée ou malformée."""
    cfg = DiscordChannelConfig(webhook_url="ftp://invalid-url.com")
    res = NotificationService.test_discord(cfg)
    assert res.success is False
    assert "doit commencer par http" in res.message


def test_discord_webhook_mocked_success():
    """Vérifie le succès d'un webhook Discord lorsqu'une réponse HTTP 204 est reçue."""
    cfg = DiscordChannelConfig(webhook_url="https://discord.com/api/webhooks/12345/abcdef")
    with patch("backend.app.modules.admin.notifications.httpx.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_instance.post.return_value = mock_resp
        mock_client_cls.return_value.__enter__.return_value = mock_instance

        res = NotificationService.test_discord(cfg, "Alerte test unitaire")
        assert res.success is True
        assert "avec succès" in res.message
        assert res.channel == "discord"


def test_telegram_bot_mocked_success():
    """Vérifie l'émission vers Telegram Bot API lors d'une réponse HTTP 200."""
    cfg = TelegramChannelConfig(bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11", chat_id="@sentinelle_test")
    with patch("backend.app.modules.admin.notifications.httpx.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_instance.post.return_value = mock_resp
        mock_client_cls.return_value.__enter__.return_value = mock_instance

        res = NotificationService.test_telegram(cfg, "Alerte test Telegram")
        assert res.success is True
        assert "@sentinelle_test" in res.message


def test_email_smtp_connection_handling():
    """Vérifie le traitement robuste d'un serveur SMTP hors ligne."""
    cfg = EmailChannelConfig(
        smtp_server="127.0.0.1",
        smtp_port=25255,  # Port fermé
        recipient="admin@sentinelle.local",
        use_tls=False,
    )
    res = NotificationService.test_email(cfg, "Test SMTP")
    assert res.success is False
    assert "Échec de connexion" in res.message


def test_api_notification_test_endpoint():
    """Vérifie l'endpoint REST POST /api/v1/admin/notifications/test."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    with patch.object(
        NotificationService,
        "test_discord",
        return_value=NotificationTestResponse(
            success=True,
            channel="discord",
            message="✓ Notification de test transmise avec succès au Webhook Discord.",
            details="Code réponse HTTP: 204",
        ),
    ):
        resp = client.post(
            "/api/v1/admin/notifications/test",
            headers=headers,
            json={
                "channel": "discord",
                "message": "Test via endpoint API",
                "discord_config": {
                    "webhook_url": "https://discord.com/api/webhooks/test/123"
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["channel"] == "discord"


def test_api_notification_dispatch_endpoint():
    """Vérifie la diffusion multi-canaux et l'enregistrement dans le journal d'audit."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    with patch.object(
        NotificationService,
        "test_discord",
        return_value=NotificationTestResponse(
            success=True,
            channel="discord",
            message="Succès Discord",
        ),
    ), patch.object(
        NotificationService,
        "test_telegram",
        return_value=NotificationTestResponse(
            success=True,
            channel="telegram",
            message="Succès Telegram",
        ),
    ):
        payload = {
            "channels": ["discord", "telegram"],
            "titre": "Surcharge CPU Imminente",
            "message": "SW-CORE-01 dépasse 92% de charge",
            "severite": "CRITICAL",
            "discord_config": {
                "webhook_url": "https://discord.com/api/webhooks/test/456"
            },
            "telegram_config": {
                "bot_token": "token_test_123",
                "chat_id": "@sentinelle_alertes"
            },
        }
        resp = client.post(
            "/api/v1/admin/notifications/dispatch",
            headers=headers,
            json=payload,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_envoyes"] == 2
        assert data["echecs"] == 0
        assert len(data["rapports"]) == 2
