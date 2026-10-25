"""Endpoints d'authentification, contrôle des accès et journalisation."""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import User
from backend.app.schemas.auth import Token, LoginRequest, UserOut, RegisterRequest
from backend.app.core.security import verify_password, create_access_token, get_password_hash
from backend.app.core.audit import log_audit_action
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentification & RBAC"])


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
            else:
                db.commit()

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
    req = LoginRequest(identifiant=form_data.username, mot_de_passe=form_data.password)
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
    Crée un compte utilisateur réel avec le profil choisi (Administrateur, Technicien, Visiteur).
    Hachage bcrypt sécurisé, traçabilité dans le journal d'audit et émission d'un token JWT.
    """
    identifiant = req.identifiant.strip()
    email = req.email.strip().lower()
    nom_complet = req.nom_complet.strip()

    if len(identifiant) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="L'identifiant doit comporter au moins 3 caractères.",
        )
    if len(req.mot_de_passe) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit comporter au moins 6 caractères.",
        )

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

    # Contrôle du profil RBAC
    allowed_roles = ["Administrateur", "Technicien", "Visiteur"]
    role = req.role if req.role in allowed_roles else "Technicien"

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
