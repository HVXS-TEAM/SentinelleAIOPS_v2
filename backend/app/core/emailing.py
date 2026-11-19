"""Envoi d'e-mails par SMTP (facultatif). Sans configuration, rien n'est envoyé ni simulé."""
import logging
import smtplib
import ssl
from email.message import EmailMessage

from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class EmailError(Exception):
    """L'e-mail n'a pas pu être remis au serveur SMTP."""


def smtp_configure() -> bool:
    return bool(settings.SMTP_HOST and settings.SMTP_FROM)


def envoyer(destinataire: str, sujet: str, corps: str) -> None:
    """Envoie un e-mail texte. Lève EmailError en cas d'échec (le mot de passe SMTP n'est jamais journalisé)."""
    if not smtp_configure():
        raise EmailError("SMTP non configuré.")
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = destinataire
    msg["Subject"] = sujet
    msg.set_content(corps)
    try:
        if settings.SMTP_PORT == 465:
            serveur = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15,
                                       context=ssl.create_default_context())
        else:
            serveur = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)
        with serveur:
            if settings.SMTP_PORT != 465 and settings.SMTP_STARTTLS:
                serveur.starttls(context=ssl.create_default_context())
            if settings.SMTP_USER:
                serveur.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            serveur.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        logger.warning("Envoi d'e-mail impossible via %s:%s : %s", settings.SMTP_HOST, settings.SMTP_PORT, type(exc).__name__)
        raise EmailError(str(type(exc).__name__)) from exc
