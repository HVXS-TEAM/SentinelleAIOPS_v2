"""Initialisation de la base de données et chargement du jeu de démonstration (Seed BTS)."""
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
import hashlib
from backend.app.db.session import engine, SessionLocal, Base
from backend.app.db.models import (
    User, Equipement, Metrique, Prediction,
    EvenementSecurite, AuditReseau, SauvegardeConfig, Alerte, JournalAudit
)
from backend.app.core.security import get_password_hash, encrypt_secret


def init_db(db: Session) -> None:
    """Crée les tables et injecte les données réalistes du laboratoire BTS."""
    Base.metadata.create_all(bind=engine)

    # 1. Comptes utilisateurs de test
    if not db.query(User).filter(User.identifiant == "admin").first():
        users = [
            User(
                identifiant="admin",
                email="admin@sentinelle.local",
                nom_complet="Administrateur Sécurité & Réseau",
                hash_mot_de_passe=get_password_hash("AdminPassword2026!"),
                role="Administrateur",
                mfa_active=False,
                est_actif=True,
            ),
            User(
                identifiant="tech",
                email="technicien@sentinelle.local",
                nom_complet="Technicien Support N2",
                hash_mot_de_passe=get_password_hash("TechPassword2026!"),
                role="Technicien",
                mfa_active=False,
                est_actif=True,
            ),
            User(
                identifiant="visiteur",
                email="visiteur@sentinelle.local",
                nom_complet="Auditeur Externe / Jury",
                hash_mot_de_passe=get_password_hash("VisiteurPassword2026!"),
                role="Visiteur",
                mfa_active=False,
                est_actif=True,
            ),
        ]
        db.add_all(users)
        db.commit()

    # 2. Équipements du parc du lab BTS
    if db.query(Equipement).count() == 0:
        now = datetime.now(timezone.utc)
        equipements = [
            Equipement(
                nom="SW-CORE-01",
                ip="192.168.1.1",
                mac="00:1A:2B:3C:4D:01",
                type="Switch Cisco",
                os="Cisco IOS-XE",
                firmware="16.9.4",
                uptime_secondes=1584000,
                score_sante=98.5,
                statut_collecte="OK",
                date_decouverte=now - timedelta(days=30),
                derniere_collecte=now,
                identifiants_chiffres=encrypt_secret("cisco:cisco123"),
                groupe="Cœur de réseau",
            ),
            Equipement(
                nom="RTR-EDGE-01",
                ip="192.168.1.254",
                mac="00:1A:2B:3C:4D:02",
                type="Routeur Cisco",
                os="Cisco IOS-XE",
                firmware="17.3.2",
                uptime_secondes=3456000,
                score_sante=95.0,
                statut_collecte="OK",
                date_decouverte=now - timedelta(days=45),
                derniere_collecte=now,
                identifiants_chiffres=encrypt_secret("cisco:cisco123"),
                groupe="Frontière & WAN",
            ),
            Equipement(
                nom="SRV-APP-01",
                ip="192.168.1.10",
                mac="00:50:56:A1:B2:10",
                type="Serveur Linux",
                os="Debian GNU/Linux 12 (Bookworm)",
                firmware="Kernel 6.1.0-18-amd64",
                uptime_secondes=864000,
                score_sante=78.0,  # Score légèrement dégradé pour illustrer la supervision
                statut_collecte="OK",
                date_decouverte=now - timedelta(days=20),
                derniere_collecte=now,
                identifiants_chiffres=encrypt_secret("debian:labo2026!"),
                groupe="Applications",
                seuil_disque_alerte=85.0,
            ),
            Equipement(
                nom="SRV-DB-01",
                ip="192.168.1.20",
                mac="00:50:56:A1:B2:20",
                type="Serveur Linux",
                os="Ubuntu 22.04 LTS (Jammy)",
                firmware="Kernel 5.15.0-94-generic",
                uptime_secondes=2592000,
                score_sante=99.0,
                statut_collecte="OK",
                date_decouverte=now - timedelta(days=25),
                derniere_collecte=now,
                identifiants_chiffres=encrypt_secret("postgres:dbsecret2026"),
                groupe="Base de données",
            ),
        ]
        db.add_all(equipements)
        db.commit()

        # Re-récupérer avec ID
        sw_core = db.query(Equipement).filter_by(nom="SW-CORE-01").first()
        srv_app = db.query(Equipement).filter_by(nom="SRV-APP-01").first()

        # 3. Métriques historiques (24 dernières heures pour SRV-APP-01 et SW-CORE-01)
        metrics_to_add = []
        for i in range(24, 0, -1):
            time_point = now - timedelta(hours=i)
            # Remplissage disque montant progressivement sur SRV-APP-01 (65% à 84%)
            disk_val = 65.0 + (24 - i) * 0.8
            metrics_to_add.append(Metrique(equipement_id=srv_app.id, type_metrique="disk_percent", valeur=disk_val, horodatage=time_point))
            metrics_to_add.append(Metrique(equipement_id=srv_app.id, type_metrique="cpu_percent", valeur=28.0 + (i % 7) * 2.5, horodatage=time_point))
            metrics_to_add.append(Metrique(equipement_id=srv_app.id, type_metrique="ram_percent", valeur=52.0 + (i % 5) * 1.8, horodatage=time_point))
            
            # Switch Core stable
            metrics_to_add.append(Metrique(equipement_id=sw_core.id, type_metrique="cpu_percent", valeur=14.0 + (i % 4) * 1.2, horodatage=time_point))
            metrics_to_add.append(Metrique(equipement_id=sw_core.id, type_metrique="ram_percent", valeur=38.0, horodatage=time_point))

        db.add_all(metrics_to_add)

        # 4. Prédiction TTF initiale sur SRV-APP-01
        prediction_app = Prediction(
            equipement_id=srv_app.id,
            metrique="disk_percent",
            valeur_actuelle=84.2,
            pente_horaire=0.8,
            r2_score=0.985,
            mape_erreur=1.2,
            indice_confiance="Haute",
            ttf_estime_heures=19.75,  # (100 - 84.2) / 0.8 = ~19.75h
            date_saturation_estimee=now + timedelta(hours=19.75),
            date_calcul=now,
        )
        db.add(prediction_app)

        # 5. Alertes initiales
        alertes = [
            Alerte(
                equipement_id=srv_app.id,
                module_origine="Supervision",
                severite="WARNING",
                titre="Prédiction saturation disque (/var)",
                message="SRV-APP-01 : Le taux d'occupation disque atteindra 90% dans moins de 8 heures (TTF estimé: 19.75h).",
                statut="Active",
                date_creation=now - timedelta(hours=2),
            ),
            Alerte(
                equipement_id=sw_core.id,
                module_origine="NetDevOps",
                severite="INFO",
                titre="Audit CIS : Mot de passe d'administration non chiffré",
                message="SW-CORE-01 : La directive 'service password-encryption' est absente de la configuration active.",
                statut="Active",
                date_creation=now - timedelta(hours=5),
            ),
        ]
        db.add_all(alertes)

        # 6. Audit CIS initial sur SW-CORE-01
        audits_cis = [
            AuditReseau(
                equipement_id=sw_core.id,
                regle_cis="CIS-Cisco-1.1",
                titre_regle="Chiffrement des mots de passe réversibles",
                constat="La commande globale 'service password-encryption' n'est pas activée sur l'équipement.",
                criticite="Élevée",
                correctif_propose="configure terminal\nservice password-encryption\nend\nwrite memory",
                statut="Non-conforme",
                explication_llm="L'absence de ce service permet à un opérateur observant la configuration de lire certains mots de passe en clair ou faiblement protégés.",
                date_audit=now - timedelta(hours=5),
            ),
            AuditReseau(
                equipement_id=sw_core.id,
                regle_cis="CIS-Cisco-2.1",
                titre_regle="Désactivation du protocole Telnet (accès VTY)",
                constat="Les lignes vty 0 4 acceptent le transport entrant Telnet non sécurisé.",
                criticite="Critique",
                correctif_propose="configure terminal\nline vty 0 4\ntransport input ssh\nend\nwrite memory",
                statut="Non-conforme",
                explication_llm="Telnet transmet les identifiants et les commandes d'administration en texte clair sur le réseau local.",
                date_audit=now - timedelta(hours=5),
            ),
        ]
        db.add_all(audits_cis)

        # 7. Sauvegarde running-config initiale
        sample_cisco_config = """!
version 16.9
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname SW-CORE-01
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXReNm/
!
username admin privilege 15 password 0 cisco123
!
interface GigabitEthernet0/1
 description Interconnexion RTR-EDGE-01
 switchport mode trunk
!
line vty 0 4
 transport input all
 login local
!
end
"""
        sha = hashlib.sha256(sample_cisco_config.encode()).hexdigest()
        sauvegarde = SauvegardeConfig(
            equipement_id=sw_core.id,
            contenu=sample_cisco_config,
            hash_integrite=sha,
            commentaire="Sauvegarde nominale initiale - Lab BTS",
            date_sauvegarde=now - timedelta(days=1),
        )
        db.add(sauvegarde)

        # 8. Journal d'audit d'initialisation
        admin_user = db.query(User).filter_by(identifiant="admin").first()
        log_entry = JournalAudit(
            utilisateur_id=admin_user.id if admin_user else None,
            nom_utilisateur="admin",
            action="SYSTEM_INIT",
            cible="Base de données Sentinelle AIOps",
            details="Initialisation complète du schéma et injection du jeu d'essai du laboratoire BTS.",
            adresse_ip="127.0.0.1",
            horodatage=now,
        )
        db.add(log_entry)
        db.commit()


if __name__ == "__main__":
    db = SessionLocal()
    try:
        init_db(db)
        print("Base de données Sentinelle AIOps initialisée et pré-remplie avec succès !")
    finally:
        db.close()
