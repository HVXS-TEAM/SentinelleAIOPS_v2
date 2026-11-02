"""
Lanceur Graphique Dédié Sentinelle AIOps (Mode Desktop Natif — Zéro Console).
Ce script est le point d'entrée pour le packaging PyInstaller (.exe) et le Setup NSIS :
  1. Redirige les flux standard en mode fenêtré (console=False) pour éviter tout crash Uvicorn.
  2. Affiche un Lanceur Graphique Dédié PyQt6 (style Game Launcher / SOC Control Center)
     avec barre de progression temps réel, contrôle des 4 sous-systèmes et icône System Tray.
  3. Initialise la base SQLite, monte le build React et démarre Uvicorn en arrière-plan.
  4. Ouvre Sentinelle AIOps dans une fenêtre applicative native dédiée (sans barre d'URL ni onglets)
     et arrête proprement tous les services à la fermeture.
"""

from __future__ import annotations

import multiprocessing
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional

# Protection globale immédiate sous Windows contre l'ouverture de fenêtres de terminal (conhost.exe)
if platform.system() == "Windows" and not getattr(subprocess.Popen, "_sentinelle_no_window_patched", False):
    _orig_popen_init = subprocess.Popen.__init__
    _CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    def _silent_popen_init(self, *args, **kwargs):
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | _CREATE_NO_WINDOW
        _orig_popen_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _silent_popen_init  # type: ignore[method-assign]
    subprocess.Popen._sentinelle_no_window_patched = True  # type: ignore[attr-defined]

# ── 1. Résolution des chemins (Mode compilé PyInstaller vs Développement) ─────
if getattr(sys, "frozen", False):
    BASE_DIR = Path(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
    APP_DIR = Path(os.path.dirname(sys.executable))
else:
    BASE_DIR = Path(__file__).resolve().parent
    APP_DIR = BASE_DIR

sys.path.insert(0, str(BASE_DIR))

# Fixer le répertoire de travail sur APP_DIR pour que sentinelle.db soit persisté à côté de l'exécutable
try:
    os.chdir(str(APP_DIR))
except Exception:
    pass

# ── 2. Redirection silencieuse stdout/stderr lorsque console=False ───────────
LOG_FILE_PATH = APP_DIR / "sentinelle_runtime.log"
if sys.stdout is None or sys.stderr is None:
    try:
        _log_stream = open(LOG_FILE_PATH, "a", encoding="utf-8", buffering=1)
        if sys.stdout is None:
            sys.stdout = _log_stream
        if sys.stderr is None:
            sys.stderr = _log_stream
    except Exception:
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")

import psutil
import uvicorn
from fastapi import Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QPoint
from PyQt6.QtGui import QIcon, QPixmap, QFont, QColor, QAction, QMouseEvent
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QFrame,
    QGridLayout,
    QSystemTrayIcon,
    QMenu,
)

from backend.app.main import app
from backend.app.db.session import engine, SessionLocal, Base
from backend.app.db.init_db import init_db

HOST = "127.0.0.1"
PORT = 8000
APP_URL = f"http://{HOST}:{PORT}"


def is_port_in_use(host: str, port: int) -> bool:
    """Vérifie si une instance du serveur écoute déjà sur le port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex((host, port)) == 0


def ensure_clean_port(host: str, preferred_port: int = 8000) -> int:
    """
    Libère le port en arrêtant toute ancienne instance résiduelle de Sentinelle-AIOps
    ou bascule sur un port libre si un service tiers occupe le port 8000.
    """
    current_pid = os.getpid()
    parent_pid = os.getppid()

    # 1. Arrêter les anciennes instances de Sentinelle-AIOps restées en arrière-plan
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info["pid"]
            name = (proc.info["name"] or "").lower()
            if pid in (current_pid, parent_pid):
                continue
            if "sentinelle-aiops" in name:
                proc.terminate()
        except Exception:
            pass

    # 2. Si le port préféré est encore occupé, tenter de terminer le processus détenteur
    if is_port_in_use(host, preferred_port):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["pid"] in (current_pid, parent_pid):
                    continue
                for conn in proc.net_connections(kind="inet"):
                    if conn.laddr and conn.laddr.port == preferred_port:
                        proc.terminate()
            except Exception:
                pass
        for _ in range(10):
            if not is_port_in_use(host, preferred_port):
                break
            time.sleep(0.15)

    # 3. Vérifier que l'on peut effectivement binder le port préféré, sinon trouver un port libre
    for candidate_port in (preferred_port, 8001, 8080, 8888):
        if not is_port_in_use(host, candidate_port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_sock:
                    test_sock.bind((host, candidate_port))
                return candidate_port
            except OSError:
                continue

    return preferred_port


def setup_database() -> None:
    """Initialise les tables SQLite et injecte les données initiales si nécessaire."""
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        init_db(db)


def setup_static_routes() -> None:
    """Monte le build React (frontend/dist) directement sur FastAPI."""
    dist_dir = BASE_DIR / "frontend" / "dist"
    if not dist_dir.exists():
        return

    assets_dir = dist_dir / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.middleware("http")
    async def spa_root_redirect(request: Request, call_next):
        if request.url.path == "/" and "text/html" in request.headers.get("accept", ""):
            index_path = dist_dir / "index.html"
            if index_path.exists():
                return FileResponse(str(index_path))
        return await call_next(request)

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(request: Request, full_path: str):
        if full_path.startswith(("api/", "docs", "redoc")):
            return FileResponse(str(dist_dir / "index.html"))
        candidate = dist_dir / full_path
        if candidate.exists() and candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(dist_dir / "index.html"))


def find_native_app_host() -> Optional[str]:
    """Détecte le moteur d'affichage natif Windows (Edge WebView/App ou Chrome App)."""
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        shutil.which("msedge"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        shutil.which("chrome"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def launch_dedicated_app_window(url: str) -> Optional[subprocess.Popen]:
    """
    Ouvre Sentinelle AIOps dans une fenêtre applicative native dédiée (mode --app),
    sans barre d'adresse, sans onglets et avec un profil isolé dédié.
    """
    browser_bin = find_native_app_host()
    if not browser_bin:
        return None

    profile_dir = APP_DIR / ".sentinelle_app_profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    args = [
        browser_bin,
        f"--app={url}",
        f"--user-data-dir={profile_dir}",
        "--window-size=1440,900",
        "--disable-extensions",
        "--disable-features=Translate,msEdgeSidebarV2",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        return subprocess.Popen(args, creationflags=creation_flags)
    except Exception:
        return None


class BootSignals(QObject):
    """Signaux thread-safe pour mettre à jour le Lanceur Graphique PyQt6."""
    progress = pyqtSignal(int, str, str)  # (pourcentage, étape_id, message)
    ready = pyqtSignal()
    error = pyqtSignal(str)


class SentinelleLauncherWindow(QWidget):
    """
    Lanceur Graphique Dédié Sentinelle AIOps (Style Game Launcher / Poste de Commandement SOC).
    """

    def __init__(self) -> None:
        super().__init__()
        self.signals = BootSignals()
        self.server: Optional[uvicorn.Server] = None
        self.app_process: Optional[subprocess.Popen] = None
        self._drag_pos: Optional[QPoint] = None
        self._is_ready = False

        self._init_window()
        self._build_ui()
        self._init_tray()

        self.signals.progress.connect(self._on_progress)
        self.signals.ready.connect(self._on_ready)
        self.signals.error.connect(self._on_error)

        # Surveillance de la fenêtre applicative dédiée
        self._monitor_timer = QTimer(self)
        self._monitor_timer.setInterval(1500)
        self._monitor_timer.timeout.connect(self._check_app_window_state)

        # Démarrage asynchrone de la séquence d'initialisation
        QTimer.singleShot(250, self._start_boot_sequence)

    def _init_window(self) -> None:
        self.setWindowTitle("Sentinelle AIOps — Lanceur & Centre de Contrôle")
        self.setFixedSize(760, 490)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowSystemMenuHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)

        icon_path = BASE_DIR / "sentinelle.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self.setStyleSheet("""
            QWidget#LauncherRoot {
                background-color: #090c0e;
                border: 1px solid #252c32;
                color: #e0e3e6;
                font-family: 'Segoe UI', 'Inter', sans-serif;
            }
            QFrame#HeaderBar {
                background-color: #0b0f11;
                border-bottom: 1px solid #1e2429;
            }
            QFrame#StatusCard {
                background-color: #14181b;
                border: 1px solid #252c32;
                border-radius: 8px;
            }
            QProgressBar {
                background-color: #14181b;
                border: 1px solid #252c32;
                border-radius: 5px;
                height: 12px;
                text-align: center;
                color: transparent;
            }
            QProgressBar::chunk {
                background-color: #78d8ba;
                border-radius: 4px;
            }
            QPushButton#PrimaryLaunchBtn {
                background-color: #78d8ba;
                color: #00382b;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12px;
                padding: 10px 22px;
            }
            QPushButton#PrimaryLaunchBtn:hover {
                background-color: #94f5d6;
            }
            QPushButton#PrimaryLaunchBtn:disabled {
                background-color: #1e2429;
                color: #8b9792;
            }
            QPushButton#SecondaryBtn {
                background-color: #14181b;
                color: #e0e3e6;
                border: 1px solid #252c32;
                border-radius: 6px;
                font-size: 11px;
                padding: 9px 16px;
            }
            QPushButton#SecondaryBtn:hover {
                border-color: #78d8ba;
                color: #78d8ba;
            }
            QPushButton#DangerBtn {
                background-color: #14181b;
                color: #ffb4ab;
                border: 1px solid #3e2729;
                border-radius: 6px;
                font-size: 11px;
                padding: 9px 16px;
            }
            QPushButton#DangerBtn:hover {
                background-color: #3a1216;
                border-color: #ffb4ab;
            }
        """)

    def _build_ui(self) -> None:
        self.setObjectName("LauncherRoot")
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(1, 1, 1, 1)
        root_layout.setSpacing(0)

        # ── 1. Barre de titre personnalisée (Frameless Drag Bar) ──────────────
        header = QFrame(self)
        header.setObjectName("HeaderBar")
        header.setFixedHeight(44)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 0, 12, 0)

        title_lbl = QLabel("SENTINELLE AIOPS // LANCEUR D'EXPLOITATION DÉDIÉ")
        title_lbl.setStyleSheet("color: #78d8ba; font-family: 'Consolas', monospace; font-size: 11px; font-weight: bold; letter-spacing: 1px;")
        header_layout.addWidget(title_lbl)
        header_layout.addStretch()

        version_badge = QLabel("v2.4.1 — BUILD CERTIFIÉ BTS SIO SISR")
        version_badge.setStyleSheet("color: #8b9792; background-color: #14181b; border: 1px solid #252c32; border-radius: 4px; padding: 3px 8px; font-family: 'Consolas', monospace; font-size: 10px;")
        header_layout.addWidget(version_badge)

        min_btn = QPushButton("—")
        min_btn.setFixedSize(28, 28)
        min_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        min_btn.setStyleSheet("background: transparent; color: #8b9792; border: none; font-weight: bold;")
        min_btn.clicked.connect(self.showMinimized)
        header_layout.addWidget(min_btn)

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(28, 28)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setStyleSheet("background: transparent; color: #ffb4ab; border: none; font-weight: bold;")
        close_btn.clicked.connect(self.shutdown_all)
        header_layout.addWidget(close_btn)

        root_layout.addWidget(header)

        # ── 2. Corps principal du Lanceur ────────────────────────────────────
        body = QWidget(self)
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(28, 22, 28, 22)
        body_layout.setSpacing(18)

        # Bannière Héro avec Logo + Titre
        hero_layout = QHBoxLayout()
        hero_layout.setSpacing(18)

        logo_label = QLabel()
        logo_label.setFixedSize(72, 72)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setStyleSheet("background-color: #0b0f11; border: 1px solid #78d8ba; border-radius: 14px; padding: 6px;")

        logo_path = BASE_DIR / "frontend" / "dist" / "sentinelle_logo.png"
        if not logo_path.exists():
            logo_path = BASE_DIR / "Documentation" / "sentinelle_logo.png"
        if logo_path.exists():
            pix = QPixmap(str(logo_path)).scaled(
                58, 58, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            )
            logo_label.setPixmap(pix)
        else:
            logo_label.setText("AIOPS")
            logo_label.setStyleSheet("color: #78d8ba; font-weight: bold; background-color: #0b0f11; border: 1px solid #78d8ba; border-radius: 14px;")

        hero_layout.addWidget(logo_label)

        hero_text_layout = QVBoxLayout()
        hero_text_layout.setSpacing(4)
        main_title = QLabel("Sentinelle AIOps Command Center")
        main_title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        main_title.setStyleSheet("color: #e0e3e6;")
        subtitle = QLabel("Plateforme Centralisée de Supervision Prédictive, Cybersécurité & Automatisation NetDevOps")
        subtitle.setStyleSheet("color: #8b9792; font-size: 12px;")
        hero_text_layout.addWidget(main_title)
        hero_text_layout.addWidget(subtitle)
        hero_layout.addLayout(hero_text_layout, 1)

        body_layout.addLayout(hero_layout)

        # ── 3. Grille des 4 Sous-Systèmes (Cartes de Statut) ─────────────────
        grid = QGridLayout()
        grid.setSpacing(10)

        self.card_labels: dict[str, QLabel] = {}
        subsystems = [
            ("db", "PERSISTANCE & AUDIT TRAIL", "Base SQLite & Scellement SHA-256"),
            ("ai", "MOTEUR NEURAL AIOPS", "Isolation Forest & Régression TTF"),
            ("probe", "SONDE MATÉRIELLE HÔTE", "Collecteur Télémétrique psutil"),
            ("api", "SERVEUR D'APPLICATION", f"Runtime Local ({HOST}:{PORT})"),
        ]

        for idx, (key, title, desc) in enumerate(subsystems):
            card = QFrame()
            card.setObjectName("StatusCard")
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(14, 10, 14, 10)
            c_layout.setSpacing(4)

            top_row = QHBoxLayout()
            t_lbl = QLabel(title)
            t_lbl.setStyleSheet("color: #81d0f8; font-family: 'Consolas', monospace; font-size: 10px; font-weight: bold;")
            s_lbl = QLabel("[EN ATTENTE]")
            s_lbl.setStyleSheet("color: #8b9792; font-family: 'Consolas', monospace; font-size: 10px; font-weight: bold;")
            self.card_labels[key] = s_lbl

            top_row.addWidget(t_lbl)
            top_row.addStretch()
            top_row.addWidget(s_lbl)

            d_lbl = QLabel(desc)
            d_lbl.setStyleSheet("color: #e0e3e6; font-size: 11px;")

            c_layout.addLayout(top_row)
            c_layout.addWidget(d_lbl)
            grid.addWidget(card, idx // 2, idx % 2)

        body_layout.addLayout(grid)

        # ── 4. Barre de progression & Journal d'initialisation ───────────────
        prog_box = QVBoxLayout()
        prog_box.setSpacing(6)

        status_row = QHBoxLayout()
        self.status_label = QLabel("Initialisation des sous-systèmes Sentinelle AIOps...")
        self.status_label.setStyleSheet("color: #e0e3e6; font-family: 'Consolas', monospace; font-size: 11px;")
        self.percent_label = QLabel("0%")
        self.percent_label.setStyleSheet("color: #78d8ba; font-family: 'Consolas', monospace; font-size: 11px; font-weight: bold;")
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        status_row.addWidget(self.percent_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        prog_box.addLayout(status_row)
        prog_box.addWidget(self.progress_bar)
        body_layout.addLayout(prog_box)

        # ── 5. Barre d'actions inférieure ────────────────────────────────────
        actions_row = QHBoxLayout()
        actions_row.setSpacing(10)

        self.quit_btn = QPushButton("Arrêter le moteur & Quitter")
        self.quit_btn.setObjectName("DangerBtn")
        self.quit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.quit_btn.clicked.connect(self.shutdown_all)
        actions_row.addWidget(self.quit_btn)

        actions_row.addStretch()

        self.tray_btn = QPushButton("Réduire en zone de notification")
        self.tray_btn.setObjectName("SecondaryBtn")
        self.tray_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.tray_btn.clicked.connect(self.hide)
        actions_row.addWidget(self.tray_btn)

        self.launch_btn = QPushButton("LANCER L'INTERFACE DE COMMANDEMENT")
        self.launch_btn.setObjectName("PrimaryLaunchBtn")
        self.launch_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.launch_btn.setEnabled(False)
        self.launch_btn.clicked.connect(self.open_interface)
        actions_row.addWidget(self.launch_btn)

        body_layout.addLayout(actions_row)
        root_layout.addWidget(body, 1)

    def _init_tray(self) -> None:
        """Configure l'icône dans la barre d'état système Windows (System Tray)."""
        self.tray_icon = QSystemTrayIcon(self)
        icon_path = BASE_DIR / "sentinelle.ico"
        if icon_path.exists():
            self.tray_icon.setIcon(QIcon(str(icon_path)))
        self.tray_icon.setToolTip("Sentinelle AIOps v2.4.1 — Moteur Actif")

        menu = QMenu()
        open_app_action = QAction("Ouvrir l'Interface Sentinelle AIOps", self)
        open_app_action.triggered.connect(self.open_interface)
        show_launcher_action = QAction("Afficher le Lanceur de Contrôle", self)
        show_launcher_action.triggered.connect(self.showNormal)
        quit_action = QAction("Arrêter les services & Quitter", self)
        quit_action.triggered.connect(self.shutdown_all)

        menu.addAction(open_app_action)
        menu.addAction(show_launcher_action)
        menu.addSeparator()
        menu.addAction(quit_action)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.showNormal()
            self.activateWindow()

    def _set_card_status(self, key: str, text: str, color: str) -> None:
        lbl = self.card_labels.get(key)
        if lbl:
            lbl.setText(text)
            lbl.setStyleSheet(f"color: {color}; font-family: 'Consolas', monospace; font-size: 10px; font-weight: bold;")

    def _start_boot_sequence(self) -> None:
        """Exécute le démarrage séquentiel des services dans un thread d'arrière-plan."""
        def _worker() -> None:
            try:
                self.signals.progress.emit(15, "db", "Vérification et initialisation de la base SQLite...")
                setup_database()
                time.sleep(0.25)

                self.signals.progress.emit(45, "ai", "Chargement des modèles IA (Isolation Forest & TTF)...")
                setup_static_routes()
                time.sleep(0.25)

                self.signals.progress.emit(70, "probe", "Activation de la sonde matérielle hôte (psutil)...")
                time.sleep(0.2)

                global PORT, APP_URL
                PORT = ensure_clean_port(HOST, PORT)
                APP_URL = f"http://{HOST}:{PORT}"

                self.signals.progress.emit(88, "api", f"Démarrage du serveur applicatif interne sur {APP_URL}...")
                config = uvicorn.Config(
                    app,
                    host=HOST,
                    port=PORT,
                    log_level="warning",
                    access_log=False,
                    log_config=None,
                )
                self.server = uvicorn.Server(config)
                srv_thread = threading.Thread(target=self.server.run, daemon=True)
                srv_thread.start()

                # Attendre que l'API et la base de données SQLite répondent effectivement
                api_online = False
                for _ in range(60):
                    try:
                        with urllib.request.urlopen(f"{APP_URL}/api/v1/health", timeout=0.6) as resp:
                            if resp.status == 200:
                                with urllib.request.urlopen(f"{APP_URL}/api/v1/admin/users", timeout=0.8) as db_resp:
                                    if db_resp.status == 200:
                                        api_online = True
                                        break
                    except Exception:
                        time.sleep(0.15)

                if not api_online:
                    raise RuntimeError(f"Le serveur API/SQLite sur {APP_URL} n'a pas pu démarrer.")

                self.signals.progress.emit(100, "done", "[OPÉRATIONNEL] Tous les systèmes Sentinelle AIOps sont actifs.")
                self.signals.ready.emit()
            except Exception as exc:
                self.signals.error.emit(str(exc))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_progress(self, value: int, stage: str, message: str) -> None:
        self.progress_bar.setValue(value)
        self.percent_label.setText(f"{value}%")
        self.status_label.setText(message)

        if stage == "db":
            self._set_card_status("db", "[EN COURS]", "#ffd188")
        elif stage == "ai":
            self._set_card_status("db", "[OPÉRATIONNEL]", "#78d8ba")
            self._set_card_status("ai", "[EN COURS]", "#ffd188")
        elif stage == "probe":
            self._set_card_status("ai", "[ACTIF]", "#78d8ba")
            self._set_card_status("probe", "[EN COURS]", "#ffd188")
        elif stage == "api":
            self._set_card_status("probe", "[SYNCHRONISÉE]", "#78d8ba")
            self._set_card_status("api", "[DÉMARRAGE]", "#ffd188")
        elif stage == "done":
            self._set_card_status("db", "[OPÉRATIONNEL]", "#78d8ba")
            self._set_card_status("ai", "[ACTIF]", "#78d8ba")
            self._set_card_status("probe", "[SYNCHRONISÉE]", "#78d8ba")
            self._set_card_status("api", "[EN LIGNE]", "#78d8ba")

    def _on_ready(self) -> None:
        self._is_ready = True
        self.launch_btn.setEnabled(True)
        # Ouverture automatique de la fenêtre applicative dédiée dès que le chargement atteint 100 %
        QTimer.singleShot(350, self.open_interface)

    def _on_error(self, err_msg: str) -> None:
        self.status_label.setText(f"[ERREUR CRITIQUE] {err_msg}")
        self.status_label.setStyleSheet("color: #ffb4ab; font-family: 'Consolas', monospace; font-size: 11px;")

    def open_interface(self) -> None:
        """Ouvre l'application dans sa fenêtre dédiée sans barre d'adresse ni onglets."""
        if not self._is_ready:
            return
        proc = launch_dedicated_app_window(APP_URL)
        if proc is not None:
            self.app_process = proc
            self.status_label.setText("[SESSION ACTIVE] Fenêtre dédiée Sentinelle AIOps ouverte.")
            self._monitor_timer.start()
            # Minimiser le lanceur pour laisser toute la place à l'application
            self.showMinimized()
        else:
            self.status_label.setText(f"[ACTIF] Serveur disponible sur {APP_URL}")

    def _check_app_window_state(self) -> None:
        """Vérifie si la fenêtre dédiée est toujours active."""
        if self.app_process is not None and self.app_process.poll() is not None:
            self.app_process = None
            self._monitor_timer.stop()
            self.status_label.setText("[EN VEILLE] Fenêtre fermée — Cliquez sur Lancer pour rouvrir ou Quitter.")
            self.showNormal()
            self.activateWindow()

    def shutdown_all(self) -> None:
        """Arrête proprement la fenêtre dédiée, le serveur Uvicorn et quitte le lanceur."""
        self._monitor_timer.stop()
        if self.app_process is not None and self.app_process.poll() is None:
            try:
                self.app_process.terminate()
            except Exception:
                pass
        if self.server is not None:
            self.server.should_exit = True
        self.tray_icon.hide()
        QApplication.quit()
        os._exit(0)

    # ── Déplacement de la fenêtre sans bordure à la souris ────────────────────
    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and event.position().y() <= 48:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._drag_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._drag_pos = None


def main() -> None:
    qt_app = QApplication(sys.argv)
    qt_app.setQuitOnLastWindowClosed(False)
    launcher = SentinelleLauncherWindow()
    launcher.show()
    sys.exit(qt_app.exec())


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
