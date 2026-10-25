"""Modèles de données SQLAlchemy 2.0 pour Sentinelle AIOps.

Couvre l'ensemble des 9 tables requises par le cahier des charges et la v2 :
- utilisateurs (RBAC, auth, verrouillage)
- equipements (parc, inventaire, santé)
- metriques (séries temporelles)
- predictions (Time-To-Failure, MAPE, régression)
- evenements_securite (Isolation Forest, logs, RGPD)
- audits_reseau (CIS Benchmark, remédiations)
- sauvegardes_config (running-config, SHA-256)
- alertes (notifications, corrélation)
- journal_audit (traçabilité inaltérable)
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    ForeignKey, Text, Index
)
from sqlalchemy.orm import relationship
from backend.app.db.session import Base


def utc_now() -> datetime:
    """Horodatage courant en UTC."""
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "utilisateurs"

    id = Column(Integer, primary_key=True, index=True)
    identifiant = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    nom_complet = Column(String(100), nullable=False)
    hash_mot_de_passe = Column(String(255), nullable=False)
    role = Column(String(20), default="Technicien", nullable=False)  # Administrateur, Technicien, Visiteur
    mfa_active = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(64), nullable=True)
    est_actif = Column(Boolean, default=True, nullable=False)
    date_creation = Column(DateTime, default=utc_now, nullable=False)
    derniere_connexion = Column(DateTime, nullable=True)
    tentatives_echouees = Column(Integer, default=0, nullable=False)
    bloque_jusqu_a = Column(DateTime, nullable=True)

    # Relations
    actions_audit = relationship("JournalAudit", back_populates="utilisateur")


class Equipement(Base):
    __tablename__ = "equipements"

    id = Column(Integer, primary_key=True, index=True)
    nom = Column(String(100), unique=True, index=True, nullable=False)
    ip = Column(String(45), unique=True, index=True, nullable=False)
    mac = Column(String(20), nullable=True)
    type = Column(String(50), nullable=False)  # Switch Cisco, Routeur Cisco, Serveur Linux, Serveur Windows
    os = Column(String(100), nullable=True)
    firmware = Column(String(50), nullable=True)
    uptime_secondes = Column(Integer, default=0, nullable=False)
    score_sante = Column(Float, default=100.0, nullable=False)  # 0 à 100
    statut_collecte = Column(String(20), default="OK", nullable=False)  # OK, Erreur, Injoignable
    date_decouverte = Column(DateTime, default=utc_now, nullable=False)
    derniere_collecte = Column(DateTime, default=utc_now, nullable=False)
    identifiants_chiffres = Column(Text, nullable=True)  # Fernet AES
    groupe = Column(String(50), default="Production", nullable=False)
    seuil_disque_alerte = Column(Float, default=85.0, nullable=False)

    # Relations
    metriques = relationship("Metrique", back_populates="equipement", cascade="all, delete-orphan")
    predictions = relationship("Prediction", back_populates="equipement", cascade="all, delete-orphan")
    audits = relationship("AuditReseau", back_populates="equipement", cascade="all, delete-orphan")
    sauvegardes = relationship("SauvegardeConfig", back_populates="equipement", cascade="all, delete-orphan")
    alertes = relationship("Alerte", back_populates="equipement")


class Metrique(Base):
    __tablename__ = "metriques"

    id = Column(Integer, primary_key=True, index=True)
    equipement_id = Column(Integer, ForeignKey("equipements.id", ondelete="CASCADE"), nullable=False, index=True)
    type_metrique = Column(String(50), nullable=False, index=True)  # cpu_percent, ram_percent, disk_percent, network_mbps
    valeur = Column(Float, nullable=False)
    horodatage = Column(DateTime, default=utc_now, nullable=False, index=True)

    equipement = relationship("Equipement", back_populates="metriques")

    __table_args__ = (
        Index("idx_metrique_equip_type_time", "equipement_id", "type_metrique", "horodatage"),
    )


class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, index=True)
    equipement_id = Column(Integer, ForeignKey("equipements.id", ondelete="CASCADE"), nullable=False, index=True)
    metrique = Column(String(50), default="disk_percent", nullable=False)
    valeur_actuelle = Column(Float, nullable=False)
    pente_horaire = Column(Float, nullable=False)  # Variation estimée en % par heure
    r2_score = Column(Float, nullable=False)  # Coefficient de détermination
    mape_erreur = Column(Float, nullable=True)  # Mean Absolute Percentage Error
    indice_confiance = Column(String(20), default="Moyenne", nullable=False)  # Haute, Moyenne, Faible
    ttf_estime_heures = Column(Float, nullable=True)  # Heures jusqu'au seuil critique
    date_saturation_estimee = Column(DateTime, nullable=True)
    date_calcul = Column(DateTime, default=utc_now, nullable=False)

    equipement = relationship("Equipement", back_populates="predictions")


class EvenementSecurite(Base):
    __tablename__ = "evenements_securite"

    id = Column(Integer, primary_key=True, index=True)
    equipement_id = Column(Integer, ForeignKey("equipements.id", ondelete="SET NULL"), nullable=True)
    source_ip = Column(String(45), index=True, nullable=False)
    source_ip_anonymisee = Column(String(45), nullable=False)  # RGPD : ex. 198.51.***.***
    utilisateur_cible = Column(String(50), nullable=True)
    type_evenement = Column(String(50), nullable=False)  # brute_force_ssh, scan_ports, escalade_privilege
    score_anomalie = Column(Float, nullable=False)  # Sortie Isolation Forest
    severite = Column(String(20), default="WARNING", nullable=False)  # INFO, WARNING, CRITICAL
    is_anomaly = Column(Boolean, default=True, nullable=False)
    explication = Column(Text, nullable=True)  # Indicateur déclencheur
    tentatives_minute = Column(Integer, default=1, nullable=False)
    horodatage = Column(DateTime, default=utc_now, nullable=False, index=True)


class AuditReseau(Base):
    __tablename__ = "audits_reseau"

    id = Column(Integer, primary_key=True, index=True)
    equipement_id = Column(Integer, ForeignKey("equipements.id", ondelete="CASCADE"), nullable=False, index=True)
    regle_cis = Column(String(50), nullable=False)  # ex. CIS-Cisco-2.1
    titre_regle = Column(String(150), nullable=False)
    constat = Column(Text, nullable=False)
    criticite = Column(String(20), default="Moyenne", nullable=False)  # Faible, Moyenne, Élevée, Critique
    correctif_propose = Column(Text, nullable=False)  # Commandes Cisco IOS
    statut = Column(String(20), default="Non-conforme", nullable=False)  # Conforme, Non-conforme, Corrigé
    explication_llm = Column(Text, nullable=True)
    date_audit = Column(DateTime, default=utc_now, nullable=False)

    equipement = relationship("Equipement", back_populates="audits")


class SauvegardeConfig(Base):
    __tablename__ = "sauvegardes_config"

    id = Column(Integer, primary_key=True, index=True)
    equipement_id = Column(Integer, ForeignKey("equipements.id", ondelete="CASCADE"), nullable=False, index=True)
    contenu = Column(Text, nullable=False)  # Configuration running-config
    hash_integrite = Column(String(64), nullable=False)  # SHA-256
    commentaire = Column(String(200), nullable=True)
    date_sauvegarde = Column(DateTime, default=utc_now, nullable=False)

    equipement = relationship("Equipement", back_populates="sauvegardes")


class Alerte(Base):
    __tablename__ = "alertes"

    id = Column(Integer, primary_key=True, index=True)
    equipement_id = Column(Integer, ForeignKey("equipements.id", ondelete="SET NULL"), nullable=True, index=True)
    module_origine = Column(String(30), nullable=False)  # Supervision, Sécurité, NetDevOps, Parc
    severite = Column(String(20), default="WARNING", nullable=False)  # INFO, WARNING, CRITICAL
    titre = Column(String(150), nullable=False)
    message = Column(Text, nullable=False)
    statut = Column(String(20), default="Active", nullable=False)  # Active, Acquittée, Résolue
    correlation_id = Column(String(50), nullable=True, index=True)  # Lien multi-modules
    date_creation = Column(DateTime, default=utc_now, nullable=False, index=True)
    date_acquittement = Column(DateTime, nullable=True)
    acquittee_par = Column(String(50), nullable=True)

    equipement = relationship("Equipement", back_populates="alertes")


class JournalAudit(Base):
    __tablename__ = "journal_audit"

    id = Column(Integer, primary_key=True, index=True)
    utilisateur_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="SET NULL"), nullable=True)
    nom_utilisateur = Column(String(50), nullable=False, default="Système")
    action = Column(String(50), nullable=False)  # LOGIN_SUCCESS, CONFIG_APPLY, THRESHOLD_CHANGE...
    cible = Column(String(100), nullable=False)  # Equipement, module ou ressource ciblée
    details = Column(Text, nullable=True)
    adresse_ip = Column(String(45), nullable=True)
    horodatage = Column(DateTime, default=utc_now, nullable=False, index=True)

    utilisateur = relationship("User", back_populates="actions_audit")
