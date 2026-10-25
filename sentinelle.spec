# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import os
import sys

block_cipher = None

ROOT_DIR = Path(os.path.abspath(".")).resolve()

datas = [
    (str(ROOT_DIR / "frontend" / "dist"), "frontend/dist"),
    (str(ROOT_DIR / "backend" / "config" / "cis_rules.yaml"), "backend/config"),
    (str(ROOT_DIR / "sentinelle.ico"), "."),
]

hiddenimports = [
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "fastapi",
    "starlette",
    "pydantic",
    "sqlalchemy",
    "sqlalchemy.dialects.sqlite",
    "reportlab",
    "reportlab.lib",
    "reportlab.lib.colors",
    "reportlab.lib.pagesizes",
    "reportlab.platypus",
    "reportlab.pdfgen",
    "sklearn",
    "sklearn.ensemble",
    "sklearn.tree",
    "sklearn.utils",
    "psutil",
    "yaml",
    "bcrypt",
    "cryptography",
    "jose",
    "paramiko",
    "paramiko.client",
    "paramiko.transport",
    "paramiko.rsakey",
    "paramiko.ed25519key",
    "paramiko.ecdsakey",
    "paramiko.dsskey",
]

a = Analysis(
    ["launcher.py"],
    pathex=[str(ROOT_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="Sentinelle-AIOps",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="sentinelle.ico",
)

