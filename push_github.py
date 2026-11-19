"""
Script de commit et push via dulwich (implémentation Python pure de git).
Utilisé car le binaire git n'est pas accessible dans cet environnement.
Auteur : Antigravity
"""

import os
import sys
from dulwich.repo import Repo
from dulwich import porcelain

# --- Configuration ---
REPO_PATH = os.path.dirname(os.path.abspath(__file__))
REMOTE_URL = "https://github.com/HVXS-TEAM/SentinelleAIOPS_v2.git"
BRANCH = b"refs/heads/main"
COMMIT_MESSAGE = (
    "feat: étapes 10, 11A, 11B — documentation propre, comptes modernes, "
    "mot de passe oublié, code admin, isolation de session"
)
AUTHOR = b"Edwin Jamel Kouokam <hvxsteam@gmail.com>"


def main() -> None:
    """Point d'entrée principal : stage, commit, push."""
    print(f"[1/4] Ouverture du dépôt : {REPO_PATH}")
    repo = Repo(REPO_PATH)

    # --- Lecture du statut ---
    status = porcelain.status(repo)

    # Collecte de tous les fichiers à stager
    fichiers_a_ajouter = []
    fichiers_a_supprimer = []

    # Fichiers modifiés non stagés (modify / delete dans unstaged)
    for chemin in status.unstaged:
        chemin_abs = os.path.join(REPO_PATH, chemin.decode("utf-8").replace("\\", os.sep))
        if os.path.exists(chemin_abs):
            fichiers_a_ajouter.append(chemin.decode("utf-8").replace("\\", "/"))
        else:
            # Fichier supprimé du disque → à enlever de l'index
            fichiers_a_supprimer.append(chemin.decode("utf-8").replace("\\", "/"))

    # Fichiers non suivis (nouveaux)
    for chemin in status.untracked:
        chemin_abs = os.path.join(REPO_PATH, chemin.decode("utf-8").replace("\\", os.sep))
        if os.path.exists(chemin_abs) and not chemin.startswith(b".venv"):
            fichiers_a_ajouter.append(chemin.decode("utf-8").replace("\\", "/"))

    # Fichiers staged delete (supprimés et déjà détectés par dulwich)
    for chemin in status.staged.get("delete", []):
        fichiers_a_supprimer.append(chemin.decode("utf-8").replace("\\", "/"))

    print(f"[2/4] Fichiers à ajouter : {len(fichiers_a_ajouter)}")
    for f in fichiers_a_ajouter:
        print(f"  + {f}")
    print(f"      Fichiers à supprimer : {len(fichiers_a_supprimer)}")
    for f in fichiers_a_supprimer:
        print(f"  - {f}")

    if not fichiers_a_ajouter and not fichiers_a_supprimer:
        print("[!] Rien à committer (working tree clean).")
        sys.exit(0)

    # --- Stage ---
    print("[3/4] Stage des modifications...")
    if fichiers_a_ajouter:
        porcelain.add(repo, paths=fichiers_a_ajouter)
    if fichiers_a_supprimer:
        # Suppression un par un pour ignorer les fichiers déjà absents de l'index
        for chemin_sup in fichiers_a_supprimer:
            try:
                porcelain.rm(repo, paths=[chemin_sup])
            except Exception as e_rm:
                print(f"  [IGNORÉ rm] {chemin_sup} : {e_rm}")

    # --- Commit ---
    print(f"[4/4] Commit : {COMMIT_MESSAGE[:60]}...")
    sha = porcelain.commit(
        repo,
        message=COMMIT_MESSAGE.encode("utf-8"),
        author=AUTHOR,
        committer=AUTHOR,
    )
    print(f"      SHA : {sha.decode() if isinstance(sha, bytes) else sha}")

    # --- Push ---
    print(f"[5/5] Push vers {REMOTE_URL} ...")
    # Récupération des credentials GitHub (token ou user/pass)
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    gh_user = os.environ.get("GITHUB_USER", "")
    gh_pass = os.environ.get("GITHUB_PASS", "")

    if gh_token:
        # Authentification par token PAT (recommandé)
        from dulwich.client import HttpGitClient
        remote_url_auth = REMOTE_URL.replace(
            "https://", f"https://{gh_token}@"
        )
    else:
        remote_url_auth = REMOTE_URL

    try:
        porcelain.push(
            repo,
            remote_location=remote_url_auth,
            refspecs=f"refs/heads/main:refs/heads/main",
            username=gh_user if gh_user else None,
            password=gh_pass if gh_pass else None,
        )
        print("✅ Push réussi !")
    except Exception as exc:
        print(f"❌ Erreur lors du push : {exc}")
        print()
        print("→ Si l'authentification échoue, définissez GITHUB_TOKEN=<votre_token_PAT>")
        print("  et relancez ce script.")
        sys.exit(1)


if __name__ == "__main__":
    main()
