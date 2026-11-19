"""Endpoints d'authentification, contrôle des accès et journalisation."""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import User
from backend.app.schemas.auth import (
    Token, LoginRequest, UserOut, RegisterRequest, MfaCodeRequest, MfaDisableRequest,
    SetupRequest, ChangePasswordRequest, ForgotPasswordRequest, ResetPasswordWithCodeRequest,
)
from backend.app.core import emailing, mfa, reinitialisation
from backend.app.core.config import settings
from backend.app.core.security import verify_password, create_access_token, get_password_hash
from backend.app.core.audit import log_audit_action
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentification & RBAC"])

MFA_REQUIRED_DETAIL = "MFA_REQUIRED"
MIN_PASSWORD_LENGTH = 12
ROLES_VALIDES = ("Administrateur", "Technicien", "Visiteur")
_BOUCLAGE = {"127.0.0.1", "::1", "localhost"}


def requete_locale(request: Request) -> bool:
    """Vrai si la requête vient de la machine qui héberge Sentinelle (bouclage, sans en-tête de proxy).

    Modèle de confiance : qui dispose de l'application installée sur le poste est de confiance et
    peut créer un compte en choisissant son profil. Désactivable (LOCAL_ACCOUNT_CREATION=false).
    """
    if not settings.LOCAL_ACCOUNT_CREATION:
        return False
    if any(request.headers.get(h) for h in ("x-forwarded-for", "forwarded", "x-real-ip")):
        return False
    return (request.client.host if request.client else "") in _BOUCLAGE


def check_password_policy(password: str) -> None:
    """Politique de mot de passe : 12 caractères minimum, avec lettres et chiffres."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Le mot de passe doit comporter au moins {MIN_PASSWORD_LENGTH} caractères.",
        )
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir des lettres et des chiffres.",
        )


@router.get("/setup-status", summary="État de la première configuration (public)")
def setup_status(request: Request, db: Session = Depends(get_db)):
    """Indique si aucun compte n'existe encore (poste neuf : choix du profil puis création du premier compte)
    et quelles options de création de compte et de récupération de mot de passe sont offertes."""
    local = requete_locale(request)
    return {
        "needs_setup": db.query(User).count() == 0,
        "allow_registration": bool(settings.ALLOW_SELF_REGISTRATION),
        "local_creation": local,
        "roles_disponibles": list(ROLES_VALIDES) if local else ["Visiteur"],
        "smtp_configure": emailing.smtp_configure(),
    }


@router.post("/setup", summary="Crée le premier administrateur (uniquement si aucun compte n'existe)")
def initial_setup(req: SetupRequest, request: Request, db: Session = Depends(get_db)):
    """Première mise en service : crée l'unique compte Administrateur initial. Refusé (409) dès
    qu'un compte existe, quel que soit l'appelant."""
    if db.query(User).count() > 0:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="La configuration initiale est déjà effectuée.")
    identifiant = req.identifiant.strip()
    email = req.email.strip().lower()
    if len(identifiant) < 3:
        raise HTTPException(status_code=400, detail="L'identifiant doit comporter au moins 3 caractères.")
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Adresse email invalide.")
    if req.role not in ROLES_VALIDES:
        raise HTTPException(status_code=400, detail="Profil inconnu : Administrateur, Technicien ou Visiteur.")
    check_password_policy(req.mot_de_passe)
    user = User(
        identifiant=identifiant,
        email=email,
        nom_complet=req.nom_complet.strip() or identifiant,
        hash_mot_de_passe=get_password_hash(req.mot_de_passe),
        role=req.role,
        est_actif=True,
        mfa_active=False,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="La configuration initiale est déjà effectuée.")
    db.refresh(user)
    log_audit_action(
        db=db,
        action="INITIAL_SETUP",
        cible=f"Compte: {user.identifiant}",
        user=user,
        details=f"Création du premier compte (profil {user.role})",
        ip_address=request.client.host if request.client else "127.0.0.1",
    )
    token = create_access_token(subject=user.identifiant, role=user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role,
        "nom_complet": user.nom_complet,
        "identifiant": user.identifiant,
    }


@router.post("/change-password", summary="Change son propre mot de passe")
def change_password(
    req: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(req.mot_de_passe_actuel, current_user.hash_mot_de_passe):
        raise HTTPException(status_code=401, detail="Mot de passe actuel incorrect")
    check_password_policy(req.nouveau_mot_de_passe)
    if req.nouveau_mot_de_passe == req.mot_de_passe_actuel:
        raise HTTPException(status_code=400, detail="Le nouveau mot de passe doit différer de l'actuel.")
    current_user.hash_mot_de_passe = get_password_hash(req.nouveau_mot_de_passe)
    db.commit()
    log_audit_action(
        db=db,
        action="PASSWORD_CHANGED",
        cible=f"Compte: {current_user.identifiant}",
        user=current_user,
        details="Mot de passe modifié par l'utilisateur",
        ip_address=request.client.host if request.client else "127.0.0.1",
    )
    return {"changed": True}


def _count_failed_attempt(db: Session, user: User, now: datetime, client_ip: str) -> None:
    """Incrémente le compteur d'échecs ; au 5e échec consécutif, verrouille le compte 15 min (403)."""
    user.tentatives_echouees = (user.tentatives_echouees or 0) + 1
    if user.tentatives_echouees >= 5:
        user.bloque_jusqu_a = now + timedelta(minutes=15)
        db.commit()
        log_audit_action(
            db=db,
            action="ACCOUNT_LOCKED",
            cible=f"Compte: {user.identifiant}",
            details="Compte verrouillé temporairement pour 15 minutes suite à 5 tentatives consécutives infructueuses",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte temporairement verrouillé pour 15 minutes suite à 5 tentatives infructueuses consécutives.",
        )
    db.commit()


@router.post("/login", response_model=Token, summary="Connexion utilisateur (JSON)")
def login_json(
    request_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Authentifie un utilisateur avec politique anti-bruteforce (verrouillage 15min après 5 échecs)."""
    user = db.query(User).filter(User.identifiant == request_data.identifiant).first()
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = datetime.now(timezone.utc)

    # 1. Vérification si le compte est actuellement verrouillé
    if user and user.bloque_jusqu_a:
        lock_until = user.bloque_jusqu_a
        if lock_until.tzinfo is None:
            lock_until = lock_until.replace(tzinfo=timezone.utc)

        if lock_until > now:
            remaining_sec = int((lock_until - now).total_seconds())
            remaining_min = max(1, (remaining_sec + 59) // 60)
            log_audit_action(
                db=db,
                action="LOGIN_BLOCKED",
                cible=f"Compte: {user.identifiant}",
                details=f"Tentative de connexion sur un compte temporairement verrouillé (reste {remaining_min} min)",
                ip_address=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Compte temporairement verrouillé suite à 5 tentatives infructueuses consécutives. Réessayez dans {remaining_min} minute(s).",
            )
        else:
            # Expiration du verrouillage : réinitialisation automatique
            user.bloque_jusqu_a = None
            user.tentatives_echouees = 0
            db.commit()

    # 2. Vérification des identifiants
    if not user or not verify_password(request_data.mot_de_passe, user.hash_mot_de_passe):
        if user:
            _count_failed_attempt(db, user, now, client_ip)

        # Enregistrement tentative échouée dans journal d'audit
        attempt_str = f" (échec {user.tentatives_echouees}/5)" if user else ""
        log_audit_action(
            db=db,
            action="LOGIN_FAILURE",
            cible=f"Compte: {request_data.identifiant}",
            details=f"Tentative de connexion avec mot de passe incorrect{attempt_str}",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiant ou mot de passe incorrect",
        )

    # 3. Vérification si le compte a été désactivé par l'administrateur
    if not user.est_actif:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ce compte utilisateur est désactivé",
        )

    # 3 bis. Second facteur (TOTP ou code de secours) si le compte l'a activé
    if user.mfa_active:
        if not request_data.code_mfa:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=MFA_REQUIRED_DETAIL,
                headers={"X-MFA-Required": "true"},
            )
        if not mfa.verify_second_factor(user, request_data.code_mfa):
            db.rollback()
            log_audit_action(
                db=db,
                action="MFA_FAILURE",
                cible=f"Compte: {user.identifiant}",
                details="Code du second facteur invalide",
                ip_address=client_ip,
            )
            _count_failed_attempt(db, user, now, client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Code MFA invalide",
            )

    # 4. Succès de l'authentification : réinitialisation des compteurs et traçabilité
    user.tentatives_echouees = 0
    user.bloque_jusqu_a = None
    user.derniere_connexion = now
    db.commit()

    log_audit_action(
        db=db,
        action="LOGIN_SUCCESS",
        cible=f"Compte: {user.identifiant} ({user.role})",
        user=user,
        details="Connexion JWT établie avec succès",
        ip_address=client_ip,
    )

    token = create_access_token(subject=user.identifiant, role=user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role,
        "nom_complet": user.nom_complet,
        "identifiant": user.identifiant,
    }


@router.post("/login-form", response_model=Token, summary="Connexion OpenAPI (Swagger UI)")
def login_form(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Permet l'authentification interactive directement depuis l'interface Swagger /docs."""
    req = LoginRequest(
        identifiant=form_data.username,
        mot_de_passe=form_data.password,
        code_mfa=form_data.client_secret or None,  # Swagger : code MFA saisi dans « client_secret »
    )
    return login_json(request_data=req, request=request, db=db)


@router.get("/me", response_model=UserOut, summary="Profil de l'utilisateur connecté")
def read_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    """Retourne les informations du compte actuellement authentifié."""
    return current_user


@router.post("/logout", summary="Déconnexion de session")
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Journalise la déconnexion de l'utilisateur."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    log_audit_action(
        db=db,
        action="LOGOUT",
        cible=f"Compte: {current_user.identifiant}",
        user=current_user,
        details="Session terminée par l'utilisateur",
        ip_address=client_ip,
    )
    return {"message": "Déconnexion enregistrée avec succès"}


@router.post("/register", summary="Inscription et création de compte utilisateur")
def register_user(
    req: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Crée un compte utilisateur réel.
    - Depuis la machine qui héberge Sentinelle (requete_locale) : le profil demandé est appliqué
      (Administrateur, Technicien ou Visiteur), même si l'inscription publique est fermée.
    - Depuis le réseau : le rôle demandé est ignoré, le compte est "Visiteur" (lecture seule), et
      l'inscription doit être ouverte (ALLOW_SELF_REGISTRATION).
    Hachage bcrypt, traçabilité dans le journal d'audit, émission d'un jeton JWT.
    """
    local = requete_locale(request)
    if not local and not settings.ALLOW_SELF_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="L'inscription publique est désactivée. Contactez un administrateur.",
        )
    if local and req.role not in ROLES_VALIDES:
        raise HTTPException(status_code=400, detail="Profil inconnu : Administrateur, Technicien ou Visiteur.")

    identifiant = req.identifiant.strip()
    email = req.email.strip().lower()
    nom_complet = req.nom_complet.strip()

    if len(identifiant) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="L'identifiant doit comporter au moins 3 caractères.",
        )
    check_password_policy(req.mot_de_passe)

    # Vérification d'unicité identifiant et email
    existing_user = (
        db.query(User)
        .filter((User.identifiant == identifiant) | (User.email == email))
        .first()
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Un compte avec cet identifiant ou cette adresse email existe déjà.",
        )

    # Profil RBAC : choisi uniquement depuis le poste local, sinon Visiteur (anti-élévation de privilèges)
    role = req.role if local else "Visiteur"

    new_user = User(
        identifiant=identifiant,
        email=email,
        nom_complet=nom_complet or identifiant,
        hash_mot_de_passe=get_password_hash(req.mot_de_passe),
        role=role,
        est_actif=True,
        mfa_active=False,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    client_ip = request.client.host if request.client else "127.0.0.1"
    log_audit_action(
        db=db,
        action="USER_REGISTERED",
        cible=f"Compte: {new_user.identifiant} ({new_user.role})",
        user=new_user,
        details=f"Création de compte réussie avec le profil {new_user.role}",
        ip_address=client_ip,
    )

    token = create_access_token(subject=new_user.identifiant, role=new_user.role)
    return {
        "message": "Compte créé avec succès",
        "access_token": token,
        "token_type": "bearer",
        "role": new_user.role,
        "nom_complet": new_user.nom_complet,
        "identifiant": new_user.identifiant,
        "email": new_user.email,
    }



# ── Second facteur TOTP : enrôlement et désactivation par l'utilisateur ─────

@router.post("/mfa/setup", summary="Démarre l'enrôlement MFA (secret TOTP + URI otpauth)")
def mfa_setup(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Génère un secret TOTP à scanner dans une application d'authentification. Le MFA n'est actif
    qu'après confirmation par /auth/mfa/enable. Le secret n'est affiché que dans cette réponse."""
    if current_user.mfa_active:
        raise HTTPException(status_code=400, detail="Le MFA est déjà activé. Désactivez-le avant de le reconfigurer.")
    enrollment = mfa.start_enrollment(current_user)
    db.commit()
    return enrollment


@router.post("/mfa/enable", summary="Confirme l'enrôlement avec un premier code et active le MFA")
def mfa_enable(
    req: MfaCodeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retourne les codes de secours (affichés une seule fois, à conserver hors ligne)."""
    if current_user.mfa_active:
        raise HTTPException(status_code=400, detail="Le MFA est déjà activé.")
    try:
        codes = mfa.activate(current_user, req.code)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    db.commit()
    log_audit_action(
        db=db,
        action="MFA_ENABLED",
        cible=f"Compte: {current_user.identifiant}",
        user=current_user,
        details="Second facteur TOTP activé",
        ip_address=request.client.host if request.client else "127.0.0.1",
    )
    return {"mfa_active": True, "recovery_codes": codes}


@router.post("/mfa/disable", summary="Désactive son propre MFA (mot de passe + code requis)")
def mfa_disable(
    req: MfaDisableRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not current_user.mfa_active:
        raise HTTPException(status_code=400, detail="Le MFA n'est pas activé.")
    if not verify_password(req.mot_de_passe, current_user.hash_mot_de_passe):
        raise HTTPException(status_code=401, detail="Mot de passe incorrect")
    if not mfa.verify_second_factor(current_user, req.code):
        db.rollback()
        raise HTTPException(status_code=401, detail="Code MFA invalide")
    mfa.deactivate(current_user)
    db.commit()
    log_audit_action(
        db=db,
        action="MFA_DISABLED",
        cible=f"Compte: {current_user.identifiant}",
        user=current_user,
        details="Second facteur TOTP désactivé par l'utilisateur",
        ip_address=client_ip,
    )
    return {"mfa_active": False}


_REPONSE_OUBLI_EMAIL = {
    "mode": "email",
    "message": "Si ce compte existe, un e-mail contenant un lien de réinitialisation vient d'être envoyé.",
}
_REPONSE_OUBLI_ADMIN = {
    "mode": "admin_code",
    "message": "L'envoi d'e-mails n'est pas configuré sur ce serveur. Demandez un code de réinitialisation à votre administrateur.",
}


@router.post("/forgot-password", summary="Demande de réinitialisation de mot de passe (publique)")
def forgot_password(req: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Avec SMTP configuré : envoie un lien à usage unique. Sinon : indique de demander un code à
    l'administrateur. La réponse ne révèle jamais si le compte existe."""
    if not emailing.smtp_configure():
        return _REPONSE_OUBLI_ADMIN
    cle = req.identifiant.strip()
    user = db.query(User).filter((User.identifiant == cle) | (User.email == cle.lower())).first()
    if user and user.est_actif and not reinitialisation.demande_recente(db, user):
        jeton = reinitialisation.creer_jeton(db, user, "email")
        lien = f"{settings.PUBLIC_URL.rstrip('/')}/?reset={jeton}&u={user.identifiant}"
        try:
            emailing.envoyer(
                user.email,
                "Sentinelle AIOps — réinitialisation de votre mot de passe",
                f"Bonjour {user.nom_complet},\n\nPour choisir un nouveau mot de passe, ouvrez ce lien "
                f"(valable {settings.RESET_TOKEN_MINUTES} minutes, usage unique) :\n{lien}\n\n"
                "Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.",
            )
        except emailing.EmailError:
            pass  # déjà journalisé ; la réponse reste identique pour ne pas révéler l'existence du compte
        log_audit_action(db=db, action="PASSWORD_RESET_REQUESTED", cible=f"Compte: {user.identifiant}", user=user,
                         details="Lien de réinitialisation demandé par e-mail",
                         ip_address=request.client.host if request.client else "127.0.0.1")
    return _REPONSE_OUBLI_EMAIL


@router.post("/reset-password", summary="Choisit un nouveau mot de passe avec un lien ou un code à usage unique")
def reset_password(req: ResetPasswordWithCodeRequest, request: Request, db: Session = Depends(get_db)):
    erreur = HTTPException(status_code=400, detail="Code invalide ou expiré.")
    user = db.query(User).filter(User.identifiant == req.identifiant.strip()).first()
    if user is None or not user.est_actif:
        raise erreur
    check_password_policy(req.nouveau_mot_de_passe)
    if not reinitialisation.consommer(db, user, req.code):
        raise erreur
    user.hash_mot_de_passe = get_password_hash(req.nouveau_mot_de_passe)
    user.tentatives_echouees = 0
    user.bloque_jusqu_a = None
    db.commit()
    log_audit_action(db=db, action="PASSWORD_RESET", cible=f"Compte: {user.identifiant}", user=user,
                     details="Mot de passe réinitialisé avec un jeton à usage unique",
                     ip_address=request.client.host if request.client else "127.0.0.1")
    return {"reset": True}

