"""
Module de gestion et d'expédition des alertes multi-canaux (Telegram, Discord, SMTP).

Gère la validation, le test interactif et le dispatch d'incidents critiques
vers les canaux d'exploitation configurés.
"""

from __future__ import annotations

import smtplib
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from typing import Any
import httpx
from sqlalchemy.orm import Session

from backend.app.schemas.admin import (
    TelegramChannelConfig,
    DiscordChannelConfig,
    EmailChannelConfig,
    NotificationTestRequest,
    NotificationTestResponse,
    NotificationDispatchRequest,
    NotificationDispatchResponse,
)
from backend.app.core.audit import log_audit_action
from backend.app.db.models import User


class NotificationService:
    @staticmethod
    def test_discord(
        config: DiscordChannelConfig,
        custom_message: str | None = None,
    ) -> NotificationTestResponse:
        """Transmet une alerte formatée vers un webhook Discord entrant."""
        if not config.webhook_url.startswith(("http://", "https://")):
            return NotificationTestResponse(
                success=False,
                channel="discord",
                message="L'URL du Webhook Discord doit commencer par http:// ou https://",
                details="Format d'URL invalide",
            )

        now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")
        desc = custom_message or "Notification de test émise depuis la console d'administration Sentinelle AIOps."

        payload = {
            "username": "Sentinelle AIOps — Supervision",
            "embeds": [
                {
                    "title": "🛡️ [ALERTE TEST] Sentinelle AIOps",
                    "description": desc,
                    "color": 0x0D9488,  # Couleur Sentinelle Teal
                    "fields": [
                        {"name": "Plateforme", "value": "Sentinelle AIOps v2.4.1", "inline": True},
                        {"name": "Sévérité", "value": "INFO / TEST", "inline": True},
                        {"name": "Horodatage", "value": now_str, "inline": False},
                    ],
                    "footer": {"text": "Système de Continuité & AIOps • BTS SIO SISR"},
                }
            ],
        }

        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(config.webhook_url, json=payload)
                if 200 <= resp.status_code < 300:
                    return NotificationTestResponse(
                        success=True,
                        channel="discord",
                        message="✓ Notification de test transmise avec succès au Webhook Discord.",
                        details=f"Code réponse HTTP: {resp.status_code}",
                    )
                return NotificationTestResponse(
                    success=False,
                    channel="discord",
                    message=f"Le Webhook Discord a retourné une erreur HTTP {resp.status_code}.",
                    details=resp.text[:200],
                )
        except (httpx.ConnectError, httpx.TimeoutException, socket.error) as exc:
            return NotificationTestResponse(
                success=False,
                channel="discord",
                message="Impossible de joindre le serveur Discord (hôte injoignable ou délai dépassé).",
                details=str(exc),
            )
        except Exception as exc:
            return NotificationTestResponse(
                success=False,
                channel="discord",
                message=f"Erreur inattendue lors de l'envoi Discord : {exc}",
                details=str(exc),
            )

    @staticmethod
    def test_telegram(
        config: TelegramChannelConfig,
        custom_message: str | None = None,
    ) -> NotificationTestResponse:
        """Transmet une alerte textuelle via la Bot API Telegram."""
        if not config.bot_token or not config.chat_id:
            return NotificationTestResponse(
                success=False,
                channel="telegram",
                message="Le token du bot et le Chat ID sont obligatoires.",
                details="Configuration incomplète",
            )

        now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")
        msg = (
            f"🛡️ *[ALERTE TEST] Sentinelle AIOps*\n"
            f"────────────────────────\n"
            f"{custom_message or 'Notification de test émise depuis la console d administration.'}\n\n"
            f"• *Plateforme :* Sentinelle AIOps v2.4.1\n"
            f"• *Horodatage :* `{now_str}`\n"
            f"• *Statut :* Actif ✓"
        )

        api_url = f"https://api.telegram.org/bot{config.bot_token}/sendMessage"
        payload = {
            "chat_id": config.chat_id,
            "text": msg,
            "parse_mode": "Markdown",
        }

        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(api_url, json=payload)
                if resp.status_code == 200:
                    return NotificationTestResponse(
                        success=True,
                        channel="telegram",
                        message=f"✓ Alerte de test délivrée avec succès sur le canal Telegram ({config.chat_id}).",
                        details="Message ACK Telegram reçu",
                    )
                elif resp.status_code == 401:
                    return NotificationTestResponse(
                        success=False,
                        channel="telegram",
                        message="Token de bot Telegram invalide ou révoqué (HTTP 401).",
                        details=resp.text[:200],
                    )
                elif resp.status_code == 400:
                    return NotificationTestResponse(
                        success=False,
                        channel="telegram",
                        message=f"Chat ID '{config.chat_id}' introuvable ou droits de diffusion insuffisants (HTTP 400).",
                        details=resp.text[:200],
                    )
                return NotificationTestResponse(
                    success=False,
                    channel="telegram",
                    message=f"Telegram API a retourné un code d'erreur HTTP {resp.status_code}.",
                    details=resp.text[:200],
                )
        except (httpx.ConnectError, httpx.TimeoutException, socket.error) as exc:
            return NotificationTestResponse(
                success=False,
                channel="telegram",
                message="Impossible de contacter l'API Telegram (réseau déconnecté ou pare-feu bloquant).",
                details=str(exc),
            )
        except Exception as exc:
            return NotificationTestResponse(
                success=False,
                channel="telegram",
                message=f"Erreur inattendue Telegram : {exc}",
                details=str(exc),
            )

    @staticmethod
    def test_email(
        config: EmailChannelConfig,
        custom_message: str | None = None,
    ) -> NotificationTestResponse:
        """Émet un email d'alerte MIME structuré vers le serveur SMTP configuré."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "[Sentinelle AIOps] Alerte Test de Supervision"
        msg["From"] = "sentinelle-noreply@sentinelle.local"
        msg["To"] = config.recipient

        now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")
        body_text = (
            f"Sentinelle AIOps - Alerte de Test\n"
            f"Date: {now_str}\n"
            f"Destinataire: {config.recipient}\n\n"
            f"{custom_message or 'Test de communication du canal de messagerie SMTP.'}\n"
        )
        body_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f8fafc; padding: 20px;">
          <div style="max-width: 550px; background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px;">
            <h3 style="color: #0d9488; margin-top: 0;">🛡️ Sentinelle AIOps — Alerte de Test</h3>
            <p style="color: #334155;">{custom_message or "Notification de test émise depuis la console d'administration."}</p>
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 15px 0;" />
            <p style="font-size: 11px; color: #64748b;">
              <b>Serveur SMTP :</b> {config.smtp_server}:{config.smtp_port}<br/>
              <b>Horodatage :</b> {now_str}<br/>
              <b>Environnement :</b> BTS SIO SISR
            </p>
          </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        try:
            with smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=5) as server:
                if config.use_tls:
                    server.starttls()
                server.send_message(msg)
                return NotificationTestResponse(
                    success=True,
                    channel="email",
                    message=f"✓ Email de test expédié avec succès à {config.recipient} via {config.smtp_server}:{config.smtp_port}.",
                    details="SMTP 250 OK",
                )
        except (smtplib.SMTPConnectError, socket.error, ConnectionRefusedError) as exc:
            return NotificationTestResponse(
                success=False,
                channel="email",
                message=f"Échec de connexion au serveur SMTP {config.smtp_server}:{config.smtp_port} (serveur injoignable).",
                details=str(exc),
            )
        except smtplib.SMTPException as exc:
            return NotificationTestResponse(
                success=False,
                channel="email",
                message=f"Erreur protocolaire SMTP : {exc}",
                details=str(exc),
            )
        except Exception as exc:
            return NotificationTestResponse(
                success=False,
                channel="email",
                message=f"Erreur d'envoi d'email : {exc}",
                details=str(exc),
            )

    @classmethod
    def dispatch_alert(
        cls,
        req: NotificationDispatchRequest,
        db: Session,
        current_user: User | None = None,
    ) -> NotificationDispatchResponse:
        """Diffuse une alerte sur tous les canaux sélectionnés et consigne l'action à l'audit."""
        results: list[NotificationTestResponse] = []
        full_msg = f"[{req.severite}] {req.titre} — {req.message}"

        for ch in req.channels:
            if ch == "discord" and req.discord_config:
                results.append(cls.test_discord(req.discord_config, custom_message=full_msg))
            elif ch == "telegram" and req.telegram_config:
                results.append(cls.test_telegram(req.telegram_config, custom_message=full_msg))
            elif ch == "email" and req.email_config:
                results.append(cls.test_email(req.email_config, custom_message=full_msg))

        echecs = sum(1 for r in results if not r.success)
        total = len(results)

        # Journal d'audit inaltérable
        log_audit_action(
            db=db,
            action="NOTIFICATION_DISPATCH",
            cible=f"{', '.join(req.channels)} ({req.severite})",
            user=current_user,
            details=f"Alerte '{req.titre}' : {total - echecs}/{total} canaux délivrés avec succès",
        )

        return NotificationDispatchResponse(
            total_envoyes=total,
            echecs=echecs,
            rapports=results,
        )
