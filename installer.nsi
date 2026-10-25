; Script NSIS - Installateur Professionnel pour Sentinelle AIOps
; Modern UI 2 (MUI2), Icône d'application officielle et raccourcis Bureau / Menu Démarrer

!include "MUI2.nsh"
!include "FileFunc.nsh"

; ── Paramètres Généraux ──────────────────────────────────────────────────────
Name "Sentinelle AIOps"
OutFile "dist\Sentinelle-AIOps-Setup.exe"
Unicode True

; Emplacement standard pour une installation propre sans élévation de privilèges (per-user)
InstallDir "$LOCALAPPDATA\Programs\Sentinelle AIOps"
InstallDirRegKey HKCU "Software\Sentinelle AIOps" "Install_Dir"
RequestExecutionLevel user

; ── Icônes Officielles Sentinelle ───────────────────────────────────────────
!define MUI_ICON "sentinelle.ico"
!define MUI_UNICON "sentinelle.ico"

; ── Configuration de l'Interface Graphique MUI2 ──────────────────────────────
!define MUI_ABORTWARNING
!define MUI_HEADERIMAGE
!define MUI_COMPONENTSPAGE_NODESC

; Page de fin avec case à cocher pour lancer l'application immédiatement
!define MUI_FINISHPAGE_RUN "$INSTDIR\Sentinelle-AIOps.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Lancer Sentinelle AIOps dès maintenant"
!define MUI_FINISHPAGE_SHOWREADME ""

; ── Pages de l'Installateur ─────────────────────────────────────────────────
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; ── Pages du Désinstallateur ────────────────────────────────────────────────
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; ── Langues ─────────────────────────────────────────────────────────────────
!insertmacro MUI_LANGUAGE "French"
!insertmacro MUI_LANGUAGE "English"

; ── Informations de Version pour Windows Explorer ───────────────────────────
VIProductVersion "2.4.1.0"
VIAddVersionKey "ProductName" "Sentinelle AIOps"
VIAddVersionKey "Comments" "Plateforme Centralisée d'Administration Réseau, Télémétrie & IA"
VIAddVersionKey "CompanyName" "Sentinelle AIOps"
VIAddVersionKey "LegalCopyright" "© 2026 Sentinelle AIOps. Tous droits réservés."
VIAddVersionKey "FileDescription" "Programme d'installation Sentinelle AIOps"
VIAddVersionKey "FileVersion" "2.4.1.0"
VIAddVersionKey "ProductVersion" "2.4.1.0"

; ── Section d'Installation ──────────────────────────────────────────────────
Section "Sentinelle AIOps (Requis)" SecCore
    SectionIn RO

    ; Répertoire de destination
    SetOutPath "$INSTDIR"

    ; Copie de l'exécutable principal compilé et de l'icône officielle
    File "dist\Sentinelle-AIOps.exe"
    File "sentinelle.ico"

    ; Sauvegarde du chemin dans le registre
    WriteRegStr HKCU "Software\Sentinelle AIOps" "Install_Dir" "$INSTDIR"

    ; ── Création des raccourcis ──────────────────────────────────────────────
    ; Dossier Menu Démarrer
    CreateDirectory "$SMPROGRAMS\Sentinelle AIOps"
    CreateShortcut "$SMPROGRAMS\Sentinelle AIOps\Sentinelle AIOps.lnk" "$INSTDIR\Sentinelle-AIOps.exe" "" "$INSTDIR\sentinelle.ico" 0
    CreateShortcut "$SMPROGRAMS\Sentinelle AIOps\Désinstaller Sentinelle AIOps.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\sentinelle.ico" 0

    ; Raccourci Bureau avec icône personnalisée
    CreateShortcut "$DESKTOP\Sentinelle AIOps.lnk" "$INSTDIR\Sentinelle-AIOps.exe" "" "$INSTDIR\sentinelle.ico" 0

    ; ── Création du Désinstallateur ─────────────────────────────────────────
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; ── Enregistrement dans les Applications Installées Windows (Panneau de config)
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps" "DisplayName" "Sentinelle AIOps"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps" "DisplayIcon" "$INSTDIR\sentinelle.ico,0"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps" "DisplayVersion" "2.4.1"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps" "Publisher" "Sentinelle AIOps Team"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps" "InstallLocation" "$INSTDIR"
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps" "NoModify" 1
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps" "NoRepair" 1

    ; Calcul de la taille estimée installée
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps" "EstimatedSize" "$0"
SectionEnd

; ── Section de Désinstallation ──────────────────────────────────────────────
Section "Uninstall"
    ; Suppression des raccourcis Bureau et Menu Démarrer
    Delete "$DESKTOP\Sentinelle AIOps.lnk"
    Delete "$SMPROGRAMS\Sentinelle AIOps\Sentinelle AIOps.lnk"
    Delete "$SMPROGRAMS\Sentinelle AIOps\Désinstaller Sentinelle AIOps.lnk"
    RMDir "$SMPROGRAMS\Sentinelle AIOps"

    ; Suppression des fichiers applicatifs
    Delete "$INSTDIR\Sentinelle-AIOps.exe"
    Delete "$INSTDIR\sentinelle.ico"
    Delete "$INSTDIR\sentinelle.db"
    Delete "$INSTDIR\sentinelle.db-wal"
    Delete "$INSTDIR\sentinelle.db-shm"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"

    ; Suppression des clés de registre
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinelle AIOps"
    DeleteRegKey HKCU "Software\Sentinelle AIOps"
SectionEnd
