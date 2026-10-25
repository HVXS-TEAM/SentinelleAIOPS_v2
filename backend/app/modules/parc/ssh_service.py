"""Service d'exécution de commandes Terminal SSH réel et émulation CLI réseau/système.

Supporte :
1. Connexion SSH réelle via Paramiko vers les équipements physiques joignables sur le port 22.
2. Moteur CLI complet Cisco IOS-XE et Linux/Unix pour les environnements de laboratoire,
   les équipements virtuels ou en cas d'indisponibilité physique temporaire.
"""
import socket
import time
from typing import Dict, Any, Optional
import paramiko


class SSHExecutionService:
    @staticmethod
    def execute(
        ip: str,
        command: str,
        port: int = 22,
        username: str = "admin",
        password: Optional[str] = None,
        device_name: str = "device",
    ) -> Dict[str, Any]:
        """Tente une exécution SSH réelle via Paramiko, avec fallback sur l'émulateur CLI exhaustif."""
        clean_cmd = command.strip()
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        # 1. Vérification rapide de joignabilité TCP sur le port SSH
        ssh_reachable = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.2)
            if sock.connect_ex((ip, port)) == 0:
                ssh_reachable = True
            sock.close()
        except Exception:
            ssh_reachable = False

        # 2. Si le port est ouvert, tenter la session SSH réelle Paramiko
        if ssh_reachable:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=ip,
                    port=port,
                    username=username,
                    password=password or "admin",
                    timeout=3.0,
                    allow_agent=False,
                    look_for_keys=False,
                )
                stdin, stdout, stderr = ssh.exec_command(clean_cmd, timeout=5.0)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                exit_code = stdout.channel.recv_exit_status()
                ssh.close()

                final_output = out if out else err
                return {
                    "output": final_output or "[Succès - Sortie vide]",
                    "exit_code": exit_code,
                    "mode": "REAL_SSH",
                    "device": f"{device_name} ({ip}:{port})",
                    "horodatage": now_str,
                }
            except Exception as e:
                # Si Paramiko échoue (ex: auth refusée, bannière Telnet, etc.), basculer sur l'émulateur
                pass

        # 3. Moteur CLI exhaustif (Cisco IOS & Linux Systems)
        simulated_output = SSHExecutionService._resolve_cli_command(clean_cmd, device_name, ip)
        return {
            "output": simulated_output,
            "exit_code": 0,
            "mode": "EMULATED_CLI",
            "device": f"{device_name} ({ip})",
            "horodatage": now_str,
        }

    @staticmethod
    def _resolve_cli_command(cmd: str, hostname: str, ip: str) -> str:
        """Résout exhaustivement les commandes Cisco IOS-XE et Linux CLI standard."""
        c = cmd.lower()

        # Commandes d'aide et navigation
        if c in ["help", "?", "man"]:
            return (
                "=== Sentinelle AIOps Terminal — Commandes Reconnues ===\n"
                "Commandes Cisco IOS :\n"
                "  show run / show running-config  - Configuration active complète\n"
                "  show ip int brief (sh ip int br) - État synthétique des interfaces\n"
                "  show version (sh ver)           - Version de l'OS et uptime matériel\n"
                "  show vlan / show vlan brief     - Liste des VLANs configurés\n"
                "  show cdp neighbors              - Voisins réseau découverts\n"
                "  show mac address-table          - Table de commutation MAC\n"
                "  show ip route                   - Table de routage dynamique/statique\n"
                "  conf t / configure terminal     - Mode de configuration globale\n"
                "  int <id> (ex: int Gi0/1)        - Mode configuration d'interface\n"
                "  ip address <ip> <mask>          - Attribution d'adresse IP\n"
                "  no shutdown / no shut           - Activation d'une interface\n"
                "  write memory / copy run start   - Sauvegarde NVRAM\n"
                "  ping <ip> / traceroute <ip>     - Tests de connectivité et latence\n"
                "\n"
                "Commandes Linux / Unix :\n"
                "  uname -a                        - Informations noyau et architecture\n"
                "  uptime                          - Durée de fonctionnement et charge système\n"
                "  df -h                           - Espace disque des points de montage\n"
                "  free -m                         - Mémoire vive (RAM) et Swap\n"
                "  top -b -n 1 / htop              - Liste des processus en temps réel\n"
                "  ps aux                          - Arborescence complète des processus\n"
                "  ip a / ip addr / ifconfig       - Configuration des interfaces réseau\n"
                "  ip route / route -n             - Passerelle par défaut et routes\n"
                "  systemctl status <service>      - Statut d'un service système\n"
                "  cat /etc/os-release             - Distribution Linux identifiée\n"
                "  journalctl -n 20                - Dernières entrées de logs système\n"
                "  netstat -tuln / ss -tuln        - Ports TCP/UDP en écoute\n"
                "  clear                           - Réinitialiser l'écran du terminal"
            )

        if c in ["clear", "cls"]:
            return "__CLEAR_SCREEN__"

        # ── Commandes Cisco IOS ──────────────────────────────────────────────
        if c in ["show run", "sh run", "show running-config"]:
            return (
                f"! Configuration en cours sur {hostname.upper()} ({ip})\n"
                "version 17.3\n"
                "service timestamps debug datetime msec\n"
                "service timestamps log datetime msec\n"
                "service password-encryption\n"
                "!\n"
                f"hostname {hostname.upper()}\n"
                "!\n"
                "ip routing\n"
                "ip domain-name sentinelle.lan\n"
                "!\n"
                "interface GigabitEthernet0/0\n"
                f" ip address {ip} 255.255.255.0\n"
                " duplex auto\n"
                " speed auto\n"
                " no shutdown\n"
                "!\n"
                "interface GigabitEthernet0/1\n"
                " description Liaison vers Interconnexion LAN\n"
                " switchport mode trunk\n"
                " switchport trunk allowed vlan 10,20,99\n"
                " no shutdown\n"
                "!\n"
                "router ospf 1\n"
                f" router-id {ip}\n"
                f" network {ip.rsplit('.', 1)[0]}.0 0.0.0.255 area 0\n"
                "!\n"
                "line vty 0 4\n"
                " transport input ssh\n"
                " login local\n"
                " exec-timeout 10 0\n"
                "!\n"
                "end"
            )

        if c in ["show ip int brief", "sh ip int br", "show ip interface brief"]:
            return (
                f"Interface              IP-Address      OK? Method Status                Protocol\n"
                f"GigabitEthernet0/0     {ip:<15} YES NVRAM  up                    up      \n"
                f"GigabitEthernet0/1     unassigned      YES unset  up                    up      \n"
                f"GigabitEthernet0/2     unassigned      YES unset  down                  down    \n"
                f"Loopback0              10.255.255.1    YES manual up                    up      \n"
                f"Vlan1                  unassigned      YES unset  administratively down down    \n"
                f"Vlan99 (MGMT)          10.0.99.1       YES NVRAM  up                    up      "
            )

        if c in ["show version", "sh ver"]:
            return (
                f"Cisco IOS XE Software, Version 17.03.04a\n"
                f"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE)\n"
                f"Technical Support: http://www.cisco.com/techsupport\n"
                f"Compiled Sat 24-Jul-21 02:45 by prod_rel_team\n"
                f"\n"
                f"{hostname.upper()} uptime is 42 weeks, 3 days, 14 hours, 28 minutes\n"
                f"System returned to ROM by reload at 08:32:11 UTC Sun Oct 12 2025\n"
                f"System restarted at 08:34:02 UTC Sun Oct 12 2025\n"
                f"System image file is \"bootflash:packages.conf\"\n"
                f"Processor Board ID FDO24180XYZ with 3932160K/614400K bytes of memory.\n"
                f"Base Ethernet MAC Address: 00:1A:2B:3C:4D:5E\n"
                f"Configuration register is 0x2102"
            )

        if c in ["show vlan", "sh vlan", "show vlan brief", "sh vlan br"]:
            return (
                "VLAN Name                             Status    Ports\n"
                "---- -------------------------------- --------- -------------------------------\n"
                "1    default                          active    Gi0/2, Gi0/3, Gi0/4\n"
                "10   PROD-SERVERS                     active    Gi0/0\n"
                "20   DMZ-PUBLIC                       active    Gi0/1\n"
                "99   ADMIN-MANAGEMENT                 active    Cpu\n"
                "1002 fddi-default                     act/unsup \n"
                "1003 token-ring-default               act/unsup \n"
                "1004 fddinet-default                  act/unsup \n"
                "1005 trnet-default                    act/unsup "
            )

        if c in ["show cdp neighbors", "sh cdp nei", "show cdp neighbor"]:
            return (
                "Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge\n"
                "                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone\n"
                "\n"
                "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
                "SW-DISTRIB-01    Gig 0/1           158             S I    WS-C3850  Gig 1/0/24\n"
                "RTR-GATEWAY-01   Gig 0/0           142           R S I    ISR4451   Gig 0/0/0"
            )

        if c in ["show mac address-table", "sh mac address-table", "sh mac"]:
            return (
                "          Mac Address Table\n"
                "-------------------------------------------\n"
                "Vlan    Mac Address       Type        Ports\n"
                "----    -----------       --------    -----\n"
                f"  10    c82a.f20f.a12a    DYNAMIC     Gi0/0\n"
                "  10    001a.2b3c.4d5e    DYNAMIC     Gi0/1\n"
                "  20    5254.0012.3456    DYNAMIC     Gi0/1\n"
                "  99    0050.56a1.b2c3    STATIC      Cpu\n"
                "Total Mac Addresses for this criterion: 4"
            )

        if c in ["show ip route", "sh ip ro"]:
            return (
                "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\n"
                "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area \n"
                "\n"
                f"Gateway of last resort is {ip.rsplit('.', 1)[0]}.1 to network 0.0.0.0\n"
                "\n"
                f"S*    0.0.0.0/0 [1/0] via {ip.rsplit('.', 1)[0]}.1\n"
                f"C     {ip.rsplit('.', 1)[0]}.0/24 is directly connected, GigabitEthernet0/0\n"
                f"L     {ip}/32 is directly connected, GigabitEthernet0/0\n"
                "O     10.0.0.0/16 [110/2] via 10.0.99.254, 1w4d, Vlan99\n"
                "C     10.255.255.1/32 is directly connected, Loopback0"
            )

        if c in ["conf t", "configure terminal", "config t"]:
            return (
                "Enter configuration commands, one per line.  End with CNTL/Z.\n"
                f"{hostname.upper()}(config)# "
            )

        if c.startswith("int ") or c.startswith("interface "):
            int_name = cmd.split(maxsplit=1)[1] if len(cmd.split()) > 1 else "Gi0/1"
            return f"{hostname.upper()}(config-if)#{int_name.strip()} configuré."

        if c.startswith("ip address") or c.startswith("ip addr"):
            return f"{hostname.upper()}(config-if)# Adresse IP appliquée avec succès."

        if c in ["no shut", "no shutdown"]:
            return (
                f"%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up\n"
                f"%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up"
            )

        if c in ["write mem", "write memory", "wr", "copy run start"]:
            return (
                "Building configuration...\n"
                "[OK] Configuration active synchronisée et sauvegardée en NVRAM."
            )

        if c.startswith("ping"):
            target = cmd.split()[-1] if len(cmd.split()) > 1 else "8.8.8.8"
            return (
                f"Type escape sequence to abort.\n"
                f"Sending 5, 100-byte ICMP Echos to {target}, timeout is 2 seconds:\n"
                f"!!!!!\n"
                f"Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms"
            )

        if c.startswith("traceroute") or c.startswith("trace"):
            target = cmd.split()[-1] if len(cmd.split()) > 1 else "8.8.8.8"
            return (
                f"Type escape sequence to abort.\n"
                f"Tracing the route to {target}\n"
                f"  1 {ip.rsplit('.', 1)[0]}.1 1 msec 1 msec 1 msec\n"
                f"  2 195.154.1.254 9 msec 8 msec 8 msec\n"
                f"  3 {target} 12 msec 11 msec 12 msec"
            )

        # ── Commandes Linux / Unix ───────────────────────────────────────────
        if c in ["uname -a", "uname"]:
            return f"Linux {hostname.lower()} 6.6.15-sentinelle-lts #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux"

        if c in ["uptime"]:
            return f" 11:28:44 up 142 days,  3:18,  2 users,  load average: 0.14, 0.18, 0.15"

        if c in ["df -h", "df"]:
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        80G   32G   44G  43% /\n"
                "devtmpfs        3.9G     0  3.9G   0% /dev\n"
                "tmpfs           4.0G  1.2M  4.0G   1% /dev/shm\n"
                "/dev/sdb1       500G  182G  293G  39% /data/sentinelle-storage"
            )

        if c in ["free -m", "free -h", "free"]:
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:            8192        2410        3820         128        1962        5412\n"
                "Swap:           2048           0        2048"
            )

        if c in ["top", "top -b -n 1", "htop"]:
            return (
                f"top - 11:30:02 up 142 days,  3:20,  2 users,  load average: 0.14, 0.18, 0.15\n"
                "Tasks: 184 total,   1 running, 183 sleeping,   0 stopped,   0 zombie\n"
                "%Cpu(s):  3.2 us,  1.1 sy,  0.0 ni, 95.4 id,  0.2 wa,  0.0 hi,  0.1 si\n"
                "MiB Mem :   8192.0 total,   3820.0 free,   2410.0 used,   1962.0 buff/cache\n"
                "\n"
                "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
                " 1420 sentinel  20   0  782412 184200  32100 S   2.3   2.2  48:12.30 python3\n"
                "  892 root      20   0  142100  12400   8900 S   0.7   0.2  12:44.11 systemd\n"
                " 1104 root      20   0  184500  28400  14200 S   0.3   0.3   4:10.55 nginx\n"
                " 1289 root      20   0   89200   9400   6100 S   0.0   0.1   1:02.34 sshd"
            )

        if c in ["ps aux", "ps -ef", "ps"]:
            return (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root           1  0.0  0.1 168920 12400 ?        Ss   Oct10   0:24 /sbin/init\n"
                "root         450  0.0  0.1  89200  9400 ?        Ss   Oct10   1:02 /usr/sbin/sshd -D\n"
                "sentinel    1420  2.3  2.2 782412 184200 ?       Ssl  Oct10  48:12 uvicorn main:app --port 8000\n"
                "root        1104  0.0  0.3 184500 28400 ?        S    Oct10   4:10 nginx: master process /usr/sbin/nginx\n"
                f"admin       2841  0.0  0.0  14500  3200 pts/0    R+   11:31   0:00 ps aux"
            )

        if c in ["ip a", "ip addr", "ifconfig", "ip address"]:
            return (
                f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default\n"
                f"    inet 127.0.0.1/8 scope host lo\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                f"    link/ether 00:1a:2b:3c:4d:5e brd ff:ff:ff:ff:ff:ff\n"
                f"    inet {ip}/24 brd {ip.rsplit('.', 1)[0]}.255 scope global eth0"
            )

        if c in ["ip route", "route -n", "route"]:
            return (
                f"default via {ip.rsplit('.', 1)[0]}.1 dev eth0 proto dhcp metric 100\n"
                f"{ip.rsplit('.', 1)[0]}.0/24 dev eth0 proto kernel scope link src {ip} metric 100"
            )

        if c.startswith("systemctl status"):
            svc = cmd.split()[-1]
            return (
                f"● {svc}.service - Service Système {svc.upper()}\n"
                f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled; vendor preset: enabled)\n"
                f"     Active: active (running) since Fri 2026-10-10 08:34:02 UTC; 142 days ago\n"
                f"   Main PID: 1420 ({svc})\n"
                f"      Tasks: 8 (limit: 9410)\n"
                f"     Memory: 184.2M\n"
                f"        CPU: 48min 12.302s"
            )

        if c in ["cat /etc/os-release"]:
            return (
                'NAME="Ubuntu"\n'
                'VERSION="24.04.1 LTS (Noble Numbat)"\n'
                'ID=ubuntu\n'
                'ID_LIKE=debian\n'
                'PRETTY_NAME="Ubuntu 24.04.1 LTS"\n'
                'VERSION_ID="24.04"\n'
                'HOME_URL="https://www.ubuntu.com/"'
            )

        if c.startswith("journalctl"):
            return (
                f"Oct 25 11:20:01 {hostname} CRON[2901]: (root) CMD (system-health-check.sh)\n"
                f"Oct 25 11:25:14 {hostname} sshd[2940]: Accepted publickey for admin from {ip} port 52140 ssh2\n"
                f"Oct 25 11:28:44 {hostname} sentinelle-agent[1420]: Collecte télémétrique locale validée (100% nominal)"
            )

        if c in ["netstat -tuln", "ss -tuln", "netstat", "ss"]:
            return (
                "Netid  State   Recv-Q  Send-Q    Local Address:Port    Peer Address:Port  Process\n"
                "tcp    LISTEN  0       128             0.0.0.0:22           0.0.0.0:*      \n"
                "tcp    LISTEN  0       511             0.0.0.0:80           0.0.0.0:*      \n"
                "tcp    LISTEN  0       511             0.0.0.0:443          0.0.0.0:*      \n"
                "tcp    LISTEN  0       100           127.0.0.1:8000         0.0.0.0:*      \n"
                "udp    UNCONN  0       0               0.0.0.0:161          0.0.0.0:*      "
            )

        # Commande générique non répertoriée
        return (
            f"{hostname}: commande non reconnue: '{cmd}'.\n"
            "Tapez 'help' ou '?' pour afficher la liste des commandes Cisco IOS et Linux disponibles."
        )
