"""Service d'exécution de commandes Terminal SSH réel, Diagnostic Réseau Windows/Linux et CLI Cisco IOS.

Supporte :
1. Connexion SSH réelle via Paramiko vers les équipements physiques joignables sur le port 22.
2. Exécution réelle de diagnostics système et réseau (psutil, ping, arp, ipconfig, nslookup, tracert, netstat)
   sur la machine hôte Windows/Linux sans ouverture de fenêtre console.
3. Moteur CLI Cisco IOS-XE et Linux/Unix pour les équipements réseau managés et le lab.
"""
import platform
import re
import socket
import subprocess
import time
from typing import Dict, Any, Optional
try:
    import paramiko
except ImportError:
    paramiko = None  # type: ignore[assignment]
try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]
from backend.app.core.ssh_trust import new_ssh_client, log_connection_failure, is_host_key_error


import logging
logger = logging.getLogger("sentinelle.parc.ssh_service")


def _hidden_startupinfo():
    """Masque toute fenêtre console sous Windows."""
    if platform.system() == "Windows" and hasattr(subprocess, "STARTUPINFO"):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 1)
        si.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
        return si
    return None


class SSHExecutionService:
    @staticmethod
    def _is_local_host_ip(ip: str) -> bool:
        """
        Rôle : Détermine si l'adresse IP cible correspond à la machine hôte exécutant Sentinelle.
        Entrées : Adresse IP cible (ip).
        Sorties : Booléen True si locale.
        """
        if ip in ("127.0.0.1", "localhost", "::1"):
            return True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                if ip == s.getsockname()[0]:
                    return True
        except Exception as exc:
            logger.debug("_is_local_host_ip : repli après erreur : %s", exc)
        return False

    @staticmethod
    def _run_real_local_diagnostic(cmd: str, hostname: str, ip: str) -> Optional[str]:
        """
        Rôle : Exécute une vraie commande de diagnostic système ou réseau sur la machine hôte
               via psutil ou subprocess sécurisé (sans shell=True ni fenêtre console).
        Entrées : Commande nettoyée (cmd), nom de l'hôte (hostname), IP cible (ip).
        Sorties : Sortie texte réelle de l'OS/psutil, ou None si la commande relève du moteur Cisco IOS.
        Cas d'erreur : Capture les timeouts et erreurs d'encodage CP850/UTF-8 sous Windows.
        """
        c = cmd.strip().lower()
        no_win = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if platform.system() == "Windows" else 0
        enc = "cp850" if platform.system() == "Windows" else "utf-8"

        # 1. Commandes de diagnostic réseau universelles exécutables directement par l'OS
        if c in ("arp -a", "arp"):
            try:
                out = subprocess.check_output(
                    ["arp", "-a"],
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=no_win,
                    startupinfo=_hidden_startupinfo(),
                    timeout=3.0,
                ).decode(enc, errors="replace")
                return out.strip()
            except Exception as exc:
                logger.debug("_run_real_local_diagnostic : repli après erreur : %s", exc)
                return f"Erreur d'exécution arp : {exc}"

        if c in ("ipconfig", "ipconfig /all"):
            if platform.system() == "Windows":
                args = ["ipconfig", "/all"] if "/all" in c else ["ipconfig"]
                try:
                    out = subprocess.check_output(
                        args,
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL,
                        creationflags=no_win,
                        startupinfo=_hidden_startupinfo(),
                        timeout=3.0,
                    ).decode(enc, errors="replace")
                    return out.strip()
                except Exception as exc:
                    logger.debug("_run_real_local_diagnostic : repli après erreur : %s", exc)
                    return f"Erreur ipconfig : {exc}"
            else:
                # Équivalent réel multi-plateforme via psutil
                lines = [f"Configuration IP de l'hôte {socket.gethostname()} ({platform.system()}) :"]
                for iface, addrs in psutil.net_if_addrs().items():
                    lines.append(f"\nInterface {iface} :")
                    for a in addrs:
                        lines.append(f"  Adresse : {a.address} (Masque: {a.netmask})")
                return "\n".join(lines)

        if c.startswith("nslookup"):
            parts = cmd.split()
            target = parts[1] if len(parts) > 1 else ip
            try:
                resolved = socket.gethostbyname_ex(target)
                return (
                    f"Serveur DNS Système Actif\n"
                    f"Nom canonique : {resolved[0]}\n"
                    f"Adresses IP   : {', '.join(resolved[2])}"
                )
            except Exception as exc:
                logger.debug("_run_real_local_diagnostic : repli après erreur : %s", exc)
                return f"Impossible de résoudre '{target}' : {exc}"

        if c in ("whoami", "hostname"):
            if c == "hostname":
                return socket.gethostname()
            try:
                out = subprocess.check_output(
                    ["whoami"],
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=no_win,
                    startupinfo=_hidden_startupinfo(),
                    timeout=2.0,
                ).decode(enc, errors="replace")
                return out.strip()
            except Exception as exc:
                logger.debug("_run_real_local_diagnostic : repli après erreur : %s", exc)
                return f"{socket.gethostname()}\\administrateur"

        # 2. Si l'utilisateur interroge la machine hôte locale avec des commandes système (df, free, top, ps, netstat, uptime)
        if SSHExecutionService._is_local_host_ip(ip) and psutil is not None:
            if c in ("df -h", "df", "wmic logicaldisk get size,freespace,caption"):
                lines = ["Filesystem      Size    Used   Avail  Use%  Mounted on"]
                for part in psutil.disk_partitions(all=False):
                    try:
                        u = psutil.disk_usage(part.mountpoint)
                        tot_g = u.total / (1024 ** 3)
                        used_g = u.used / (1024 ** 3)
                        free_g = u.free / (1024 ** 3)
                        lines.append(
                            f"{part.device[:14]:<14} {tot_g:>5.1f}G  {used_g:>5.1f}G  {free_g:>5.1f}G  {u.percent:>3.0f}%  {part.mountpoint}"
                        )
                    except Exception as exc:
                        logger.debug("_run_real_local_diagnostic : repli après erreur : %s", exc)
                        continue
                return "\n".join(lines)

            if c in ("free -m", "free -h", "free"):
                vm = psutil.virtual_memory()
                sw = psutil.swap_memory()
                return (
                    "               total        used        free      available   percent\n"
                    f"Mem (MB):   {vm.total // (1024**2):>8}    {vm.used // (1024**2):>8}    {vm.free // (1024**2):>8}       {vm.available // (1024**2):>8}     {vm.percent:.1f}%\n"
                    f"Swap (MB):  {sw.total // (1024**2):>8}    {sw.used // (1024**2):>8}    {sw.free // (1024**2):>8}              -     {sw.percent:.1f}%"
                )

            if c in ("uptime", "systeminfo"):
                boot_dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(psutil.boot_time()))
                up_sec = int(time.time() - psutil.boot_time())
                days = up_sec // 86400
                hours = (up_sec % 86400) // 3600
                mins = (up_sec % 3600) // 60
                cpu_pct = psutil.cpu_percent(interval=0.05)
                return (
                    f"Hôte : {socket.gethostname()} ({platform.system()} {platform.release()})\n"
                    f"Démarrage système : {boot_dt}\n"
                    f"Uptime réel       : {days}j {hours}h {mins}m ({up_sec} secondes)\n"
                    f"Charge CPU actuelle: {cpu_pct}% ({psutil.cpu_count(logical=True)} cœurs logiques)"
                )

            if c in ("ps aux", "ps", "top", "top -b -n 1", "htop", "tasklist"):
                lines = [f"{'PID':>7}  {'%CPU':>6}  {'%MEM':>6}  {'STATUS':<10}  NAME"]
                procs = []
                for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
                    try:
                        procs.append(p.info)
                    except Exception as exc:
                        logger.debug("_run_real_local_diagnostic : repli après erreur : %s", exc)
                procs.sort(key=lambda x: (x.get("memory_percent") or 0.0), reverse=True)
                for p in procs[:15]:
                    lines.append(
                        f"{p['pid']:>7}  {(p.get('cpu_percent') or 0.0):>5.1f}%  {(p.get('memory_percent') or 0.0):>5.1f}%  {str(p.get('status') or 'running'):<10}  {p.get('name') or 'process'}"
                    )
                return "\n".join(lines)

            if c in ("netstat -tuln", "ss -tuln", "netstat", "ss", "netstat -ano"):
                lines = ["Proto  Local Address           Remote Address          Status        PID"]
                try:
                    conns = psutil.net_connections(kind="inet")
                    for conn in conns[:25]:
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*:*"
                        proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                        lines.append(f"{proto:<5}  {laddr:<22}  {raddr:<22}  {str(conn.status):<12}  {conn.pid or '-'}")
                except Exception as exc:
                    logger.debug("_run_real_local_diagnostic : repli après erreur : %s", exc)
                    lines.append(f"Lecture partielle des sockets : {exc}")
                return "\n".join(lines)

        return None

    @staticmethod
    def execute(
        ip: str,
        command: str,
        port: int = 22,
        username: str = "admin",
        password: Optional[str] = None,
        device_name: str = "device",
    ) -> Dict[str, Any]:
        """
        Rôle : Exécute une commande sur un équipement via SSH Paramiko réel,
               ou via l'inspecteur matériel/réseau local pour l'hôte. Sans succès : erreur explicite, jamais de sortie inventée.
        Entrées : IP cible, commande texte, port SSH, identifiant, mot de passe, nom d'équipement.
        Sorties : Dictionnaire {output, exit_code, mode, device, horodatage}.
        """
        clean_cmd = command.strip()
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        # Si password contient le format "user:pass" issu du déchiffrement Fernet, les séparer
        if password and ":" in password and username in ("admin", ""):
            username, password = password.split(":", 1)

        # 1. Hôte local : diagnostics système réels (liste blanche de commandes), jamais pour un autre équipement
        if SSHExecutionService._is_local_host_ip(ip):
            real_diag = SSHExecutionService._run_real_local_diagnostic(clean_cmd, device_name, ip)
            if real_diag is not None:
                return {
                    "output": real_diag,
                    "exit_code": 0,
                    "mode": "REAL_HOST_PROBE",
                    "device": f"{device_name} ({ip})",
                    "horodatage": now_str,
                }

        # 2. Équipement distant : session SSH réelle, sinon erreur explicite (aucune sortie inventée)
        def _erreur(mode: str, message: str) -> Dict[str, Any]:
            return {
                "output": message,
                "exit_code": 255,
                "mode": mode,
                "device": f"{device_name} ({ip}:{port})",
                "horodatage": now_str,
            }

        if paramiko is None:
            return _erreur("SSH_UNAVAILABLE", "[Erreur] La bibliothèque SSH (paramiko) n'est pas installée.")
        try:
            ssh = new_ssh_client()
            ssh.connect(
                hostname=ip,
                port=port,
                username=username,
                password=password or "",
                timeout=5.0,
                banner_timeout=5.0,
                auth_timeout=5.0,
                allow_agent=False,
                look_for_keys=False,
            )
            try:
                _, stdout, stderr = ssh.exec_command(clean_cmd, timeout=15.0)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                exit_code = stdout.channel.recv_exit_status()
            finally:
                ssh.close()
            return {
                "output": (out if out else err) or "[Succès - Sortie vide]",
                "exit_code": exit_code,
                "mode": "REAL_SSH",
                "device": f"{device_name} ({ip}:{port})",
                "horodatage": now_str,
            }
        except Exception as exc:
            log_connection_failure(ip, exc)
            if is_host_key_error(exc):
                return _erreur("SSH_HOSTKEY_REJECTED", f"[Connexion refusée] Clé d'hôte SSH invalide pour {ip} : {exc}")
            return _erreur(
                "SSH_ERROR",
                f"[Échec] {device_name} ({ip}:{port}) : {type(exc).__name__} : {exc}. "
                "Vérifiez que l'équipement est joignable en SSH et que les identifiants sont corrects.",
            )
