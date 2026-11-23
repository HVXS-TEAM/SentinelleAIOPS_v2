@echo off
chcp 65001 >nul
title Sentinelle AIOps v2 — Lanceur SOC
cd /d "%~dp0"

echo ================================================================
echo       SENTINELLE AIOPS v2 — TOUR DE CONTRÔLE SOC
echo ================================================================
echo [1/2] Démarrage des sous-systèmes (Base SQLite, Ordonnanceur, API)...
echo [2/2] Ouverture de la fenêtre opérationnelle native...
echo.

start "" ".\.venv\Scripts\python.exe" launcher.py
exit
