"""
Module Client SNMP v2c / v1 Natif (Pur Python — Zéro Dépendance C/Externe).

Rôle :
  Permet à Sentinelle AIOps d'interroger directement en UDP (port 161) n'importe quel
  équipement réseau physique (switch Cisco/HP, routeur, pare-feu, NAS, borne Wi-Fi, Linux snmpd)
  sans nécessiter de dépendance binaire externe comme Net-SNMP.

Fonctionnalités :
  - Encodage / Décodage ASN.1 BER conforme RFC 1157 (SNMPv1) et RFC 1905 (SNMPv2c).
  - Prise en charge des requêtes GetRequest et traitement des réponses GetResponse.
  - Extraction automatique des OID standards (sysDescr, sysName, sysUpTime, CPU, RAM, Trafic I/O).
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinelle.snmp")

# ── Constantes ASN.1 BER & SNMP ──────────────────────────────────────────────
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30

TAG_GET_REQUEST = 0xA0
TAG_GET_RESPONSE = 0xA2
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_COUNTER64 = 0x46

# ── Catalogue des OID Standards & Constructeurs (MIB-II & Extensions) ─────────
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# OID CPU (Cisco, Host Resources MIB, UCD-SNMP)
OID_CISCO_CPU_5M = "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1"
OID_HOST_CPU_LOAD_1 = "1.3.6.1.2.1.25.3.3.1.2.1"
OID_UCD_CPU_IDLE = "1.3.6.1.4.1.2021.11.11.0"

# OID Mémoire (Cisco, UCD-SNMP)
OID_CISCO_MEM_USED = "1.3.6.1.4.1.9.9.48.1.1.1.5.1"
OID_CISCO_MEM_FREE = "1.3.6.1.4.1.9.9.48.1.1.1.6.1"
OID_UCD_MEM_TOTAL = "1.3.6.1.4.1.2021.4.5.0"
OID_UCD_MEM_AVAIL = "1.3.6.1.4.1.2021.4.6.0"

# OID Trafic Réseau Interface 1 (ifInOctets, ifOutOctets)
OID_IF_IN_OCTETS_1 = "1.3.6.1.2.1.2.2.1.10.1"
OID_IF_OUT_OCTETS_1 = "1.3.6.1.2.1.2.2.1.16.1"


# ── Fonctions d'Encodage ASN.1 BER ────────────────────────────────────────────

def ber_encode_length(length: int) -> bytes:
    """
    Rôle : Encode la longueur d'un champ ASN.1 selon le format court (<128) ou long.
    Entrées : Longueur entière positive.
    Sorties : Bytes encodés selon la norme BER.
    """
    if length < 0x80:
        return bytes([length])
    len_bytes = []
    tmp = length
    while tmp > 0:
        len_bytes.append(tmp & 0xFF)
        tmp >>= 8
    len_bytes.reverse()
    return bytes([0x80 | len(len_bytes)]) + bytes(len_bytes)


def ber_encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode un triplet Tag-Length-Value."""
    return bytes([tag]) + ber_encode_length(len(value)) + value


def ber_encode_integer(val: int) -> bytes:
    """Encode un entier signé ASN.1."""
    if val == 0:
        return ber_encode_tlv(TAG_INTEGER, b"\x00")
    b = []
    neg = val < 0
    if neg:
        val = (1 << (val.bit_length() + 8)) + val
    while val > 0:
        b.append(val & 0xFF)
        val >>= 8
    b.reverse()
    # Si le bit de poids fort est à 1 pour un positif, ajouter un zéro
    if not neg and (b[0] & 0x80):
        b.insert(0, 0)
    return ber_encode_tlv(TAG_INTEGER, bytes(b))


def ber_encode_octet_string(val: str | bytes) -> bytes:
    """Encode une chaîne d'octets ASN.1."""
    raw = val.encode("utf-8") if isinstance(val, str) else bytes(val)
    return ber_encode_tlv(TAG_OCTET_STRING, raw)


def ber_encode_null() -> bytes:
    """Encode un champ ASN.1 NULL."""
    return b"\x05\x00"


def ber_encode_oid(oid_str: str) -> bytes:
    """
    Rôle : Convertit un identifiant d'objet (ex: '1.3.6.1.2.1.1.1.0') en octets ASN.1 BER.
    Entrées : Chaîne d'OID pointée.
    Sorties : Bytes de l'OID encodé.
    """
    parts = [int(p) for p in oid_str.strip(".").split(".") if p]
    if len(parts) < 2:
        raise ValueError("OID invalide : doit comporter au moins deux arcs.")

    octets = [parts[0] * 40 + parts[1]]
    for arc in parts[2:]:
        if arc < 0x80:
            octets.append(arc)
        else:
            vlq = []
            tmp = arc
            vlq.append(tmp & 0x7F)
            tmp >>= 7
            while tmp > 0:
                vlq.append(0x80 | (tmp & 0x7F))
                tmp >>= 7
            vlq.reverse()
            octets.extend(vlq)

    return ber_encode_tlv(TAG_OID, bytes(octets))


def ber_encode_sequence(content: bytes) -> bytes:
    """Encode une séquence ASN.1."""
    return ber_encode_tlv(TAG_SEQUENCE, content)


# ── Fonctions de Décodage ASN.1 BER ────────────────────────────────────────────

def ber_decode_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """
    Rôle : Décode le prochain champ TLV depuis un flux binaire.
    Entrées : Buffer binaire data, offset de lecture.
    Sorties : Tuple (tag, value_bytes, next_offset).
    Cas d'erreur : Lève ValueError si le buffer est tronqué.
    """
    if offset >= len(data):
        raise ValueError("Fin inattendue du paquet ASN.1.")

    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("Longueur ASN.1 manquante.")

    len_byte = data[offset]
    offset += 1

    if len_byte < 0x80:
        length = len_byte
    else:
        num_octets = len_byte & 0x7F
        if offset + num_octets > len(data):
            raise ValueError("Champ de longueur ASN.1 tronqué.")
        length = 0
        for _ in range(num_octets):
            length = (length << 8) | data[offset]
            offset += 1

    if offset + length > len(data):
        raise ValueError(f"Contenu ASN.1 tronqué : attendu {length} octets, disponible {len(data) - offset}.")

    value = data[offset : offset + length]
    return tag, value, offset + length


def ber_decode_integer(val_bytes: bytes) -> int:
    """Décode un entier ASN.1."""
    if not val_bytes:
        return 0
    return int.from_bytes(val_bytes, byteorder="big", signed=True)


def ber_decode_oid(val_bytes: bytes) -> str:
    """Décode des octets BER en chaîne OID lisible."""
    if not val_bytes:
        return ""
    first_byte = val_bytes[0]
    parts = [first_byte // 40, first_byte % 40]
    idx = 1
    current = 0
    while idx < len(val_bytes):
        b = val_bytes[idx]
        current = (current << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(current)
            current = 0
        idx += 1
    return ".".join(str(p) for p in parts)


# ── Moteur de Requêtes SNMP Client (Pur UDP) ───────────────────────────────────

class SnmpClient:
    """Client SNMP UDP v1/v2c natif pour la collecte télémétrique des équipements physiques."""

    @staticmethod
    def build_get_request(
        oids: List[str],
        community: str = "public",
        request_id: int = 1001,
        snmp_version: int = 1,  # 1 = SNMPv2c, 0 = SNMPv1
    ) -> bytes:
        """
        Rôle : Construit un paquet binaire SNMP GetRequest prêt à être expédié sur UDP 161.
        Entrées : Liste d'OIDs cibles, communauté (défaut 'public'), ID de requête, version.
        Sorties : Bytes du datagramme SNMP.
        """
        # Construction des VariableBindings
        varbind_bytes = bytearray()
        for oid in oids:
            oid_b = ber_encode_oid(oid)
            null_b = ber_encode_null()
            varbind_bytes.extend(ber_encode_sequence(oid_b + null_b))

        varbind_list = ber_encode_sequence(bytes(varbind_bytes))

        # PDU GetRequest (Tag 0xA0)
        pdu_data = (
            ber_encode_integer(request_id)
            + ber_encode_integer(0)  # error-status
            + ber_encode_integer(0)  # error-index
            + varbind_list
        )
        pdu = ber_encode_tlv(TAG_GET_REQUEST, pdu_data)

        # Message SNMP global (Version + Community + PDU)
        msg_data = (
            ber_encode_integer(snmp_version)
            + ber_encode_octet_string(community)
            + pdu
        )
        return ber_encode_sequence(msg_data)

    @staticmethod
    def parse_get_response(data: bytes) -> Dict[str, Any]:
        """
        Rôle : Parse un paquet de réponse GetResponse SNMP (0xA2) et retourne les valeurs par OID.
        Entrées : Buffer binaire brut reçu sur la socket UDP.
        Sorties : Dictionnaire {oid_str: valeur}.
        """
        results: Dict[str, Any] = {}
        try:
            _, msg_bytes, _ = ber_decode_tlv(data, 0)
            # Décoder version
            _, ver_bytes, off = ber_decode_tlv(msg_bytes, 0)
            # Décoder communauté
            _, _, off = ber_decode_tlv(msg_bytes, off)
            # Décoder PDU
            pdu_tag, pdu_bytes, _ = ber_decode_tlv(msg_bytes, off)
            if pdu_tag != TAG_GET_RESPONSE:
                return results

            # request_id, error_status, error_index
            _, req_id_bytes, off_pdu = ber_decode_tlv(pdu_bytes, 0)
            _, err_status_bytes, off_pdu = ber_decode_tlv(pdu_bytes, off_pdu)
            err_status = ber_decode_integer(err_status_bytes)
            if err_status != 0:
                logger.debug("Réponse SNMP avec code d'erreur : %d", err_status)
                return results

            _, _, off_pdu = ber_decode_tlv(pdu_bytes, off_pdu)  # error-index
            # VarBindList
            _, varbind_list_bytes, _ = ber_decode_tlv(pdu_bytes, off_pdu)

            off_vb = 0
            while off_vb < len(varbind_list_bytes):
                _, single_vb_bytes, off_vb = ber_decode_tlv(varbind_list_bytes, off_vb)
                _, oid_raw, off_in_vb = ber_decode_tlv(single_vb_bytes, 0)
                oid_str = ber_decode_oid(oid_raw)
                val_tag, val_raw, _ = ber_decode_tlv(single_vb_bytes, off_in_vb)

                # Décodage selon le type SNMP retourné
                if val_tag in (TAG_INTEGER, TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64):
                    results[oid_str] = ber_decode_integer(val_raw)
                elif val_tag == TAG_OCTET_STRING:
                    try:
                        results[oid_str] = val_raw.decode("utf-8")
                    except Exception:
                        results[oid_str] = val_raw.hex()
                elif val_tag == TAG_OID:
                    results[oid_str] = ber_decode_oid(val_raw)
                else:
                    results[oid_str] = val_raw.hex()

        except Exception as exc:
            logger.debug("Erreur lors du décodage de la réponse SNMP : %s", exc)

        return results

    @classmethod
    def get(
        cls,
        ip: str,
        oids: List[str],
        community: str = "public",
        port: int = 161,
        timeout: float = 1.0,
    ) -> Dict[str, Any]:
        """
        Rôle : Envoie une requête SNMP GetRequest UDP vers l'équipement cible et attend la réponse.
        Entrées : IP cible, liste des OIDs, communauté, port UDP (161), timeout en secondes.
        Sorties : Dictionnaire {oid_str: valeur} ou dictionnaire vide en cas d'absence de réponse/timeout.
        """
        req_packet = cls.build_get_request(oids=oids, community=community)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(req_packet, (ip, port))
            resp_data, _ = sock.recvfrom(4096)
            return cls.parse_get_response(resp_data)
        except Exception:
            return {}
        finally:
            sock.close()

    @classmethod
    def probe_device_metrics(
        cls,
        ip: str,
        community: str = "public",
        port: int = 161,
        timeout: float = 0.8,
    ) -> Optional[Dict[str, Any]]:
        """
        Rôle : Sonde un équipement réseau via SNMP en une seule transaction UDP rapide
               pour extraire son nom, description, uptime et ses métriques réelles (CPU, RAM, Débit).
        Entrées : IP de l'équipement, communauté, port, timeout.
        Sorties : Dictionnaire des métriques ou None si l'équipement ne répond pas au SNMP.
        """
        oids_to_query = [
            OID_SYS_DESCR,
            OID_SYS_UPTIME,
            OID_SYS_NAME,
            OID_CISCO_CPU_5M,
            OID_HOST_CPU_LOAD_1,
            OID_UCD_CPU_IDLE,
            OID_CISCO_MEM_USED,
            OID_CISCO_MEM_FREE,
            OID_UCD_MEM_TOTAL,
            OID_UCD_MEM_AVAIL,
            OID_IF_IN_OCTETS_1,
            OID_IF_OUT_OCTETS_1,
        ]

        data = cls.get(ip=ip, oids=oids_to_query, community=community, port=port, timeout=timeout)
        if not data:
            return None

        # Uptime en secondes (sysUpTime est exprimé en centièmes de seconde)
        raw_uptime = data.get(OID_SYS_UPTIME)
        uptime_sec = int(raw_uptime / 100) if isinstance(raw_uptime, (int, float)) else None

        sys_name = str(data.get(OID_SYS_NAME, "")).strip() or None
        sys_descr = str(data.get(OID_SYS_DESCR, "")).strip() or None

        # Calcul CPU réel
        cpu_percent: Optional[float] = None
        if OID_CISCO_CPU_5M in data and isinstance(data[OID_CISCO_CPU_5M], (int, float)):
            cpu_percent = round(float(data[OID_CISCO_CPU_5M]), 1)
        elif OID_HOST_CPU_LOAD_1 in data and isinstance(data[OID_HOST_CPU_LOAD_1], (int, float)):
            cpu_percent = round(float(data[OID_HOST_CPU_LOAD_1]), 1)
        elif OID_UCD_CPU_IDLE in data and isinstance(data[OID_UCD_CPU_IDLE], (int, float)):
            cpu_percent = round(max(0.0, 100.0 - float(data[OID_UCD_CPU_IDLE])), 1)

        # Calcul RAM réelle
        ram_percent: Optional[float] = None
        if (
            OID_CISCO_MEM_USED in data
            and OID_CISCO_MEM_FREE in data
            and isinstance(data[OID_CISCO_MEM_USED], (int, float))
            and isinstance(data[OID_CISCO_MEM_FREE], (int, float))
        ):
            used = float(data[OID_CISCO_MEM_USED])
            free = float(data[OID_CISCO_MEM_FREE])
            total = used + free
            if total > 0:
                ram_percent = round((used / total) * 100.0, 1)
        elif (
            OID_UCD_MEM_TOTAL in data
            and OID_UCD_MEM_AVAIL in data
            and isinstance(data[OID_UCD_MEM_TOTAL], (int, float))
            and isinstance(data[OID_UCD_MEM_AVAIL], (int, float))
        ):
            total = float(data[OID_UCD_MEM_TOTAL])
            avail = float(data[OID_UCD_MEM_AVAIL])
            if total > 0:
                ram_percent = round(((total - avail) / total) * 100.0, 1)

        # Trafic Réseau I/O cumulé sur interface 1
        octets_in = data.get(OID_IF_IN_OCTETS_1)
        octets_out = data.get(OID_IF_OUT_OCTETS_1)

        return {
            "sys_name": sys_name,
            "sys_descr": sys_descr,
            "uptime_secondes": uptime_sec,
            "cpu_percent": cpu_percent,
            "ram_percent": ram_percent,
            "octets_in": octets_in if isinstance(octets_in, int) else None,
            "octets_out": octets_out if isinstance(octets_out, int) else None,
            "raw_oids_count": len(data),
        }

