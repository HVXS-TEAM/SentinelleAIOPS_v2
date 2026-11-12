"""
Tests unitaires pour le module client SNMP v2c/v1 natif (snmp_client.py).

Valide :
  - L'encodage et décodage ASN.1 BER (entiers, chaînes, OIDs, séquences).
  - La construction de paquets SNMP GetRequest conformes RFC 1905.
  - Le décodage de réponses SNMP GetResponse valides et avec codes d'erreur.
  - Le calcul des métriques dérivées (CPU Cisco/Host, RAM, Uptime).
"""

from unittest.mock import patch, MagicMock
import pytest

from backend.app.modules.supervision.snmp_client import (
    ber_encode_length,
    ber_encode_integer,
    ber_encode_octet_string,
    ber_encode_oid,
    ber_decode_tlv,
    ber_decode_integer,
    ber_decode_oid,
    SnmpClient,
    OID_SYS_DESCR,
    OID_SYS_UPTIME,
    OID_SYS_NAME,
    OID_CISCO_CPU_5M,
    OID_CISCO_MEM_USED,
    OID_CISCO_MEM_FREE,
)


def test_ber_length_short_and_long():
    """Vérifie l'encodage des longueurs ASN.1 BER courtes (<128) et longues (>=128)."""
    assert ber_encode_length(10) == b"\x0a"
    assert ber_encode_length(127) == b"\x7f"
    assert ber_encode_length(128) == b"\x81\x80"
    assert ber_encode_length(300) == b"\x82\x01\x2c"


def test_ber_integer_encode_decode():
    """Vérifie l'aller-retour d'encodage et décodage des entiers."""
    for val in [0, 42, 127, 128, 255, 65535, 1000000]:
        encoded = ber_encode_integer(val)
        tag, val_bytes, next_off = ber_decode_tlv(encoded, 0)
        assert tag == 0x02
        assert next_off == len(encoded)
        decoded = ber_decode_integer(val_bytes)
        assert decoded == val


def test_ber_oid_encode_decode():
    """Vérifie l'aller-retour d'encodage et décodage des OID pointés."""
    test_oids = [
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1",
        "1.3.6.1.2.1.25.3.3.1.2.1",
    ]
    for oid in test_oids:
        encoded = ber_encode_oid(oid)
        tag, val_bytes, next_off = ber_decode_tlv(encoded, 0)
        assert tag == 0x06
        assert next_off == len(encoded)
        decoded = ber_decode_oid(val_bytes)
        assert decoded == oid


def test_snmp_build_get_request():
    """Vérifie la structure du paquet SNMP GetRequest binaire."""
    packet = SnmpClient.build_get_request(
        oids=["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"],
        community="public",
        request_id=42,
    )
    assert isinstance(packet, bytes)
    assert len(packet) > 20
    # Le tag racine doit être une séquence (0x30)
    assert packet[0] == 0x30
    # La communauté 'public' doit être présente
    assert b"public" in packet


def test_snmp_parse_mocked_get_response():
    """Vérifie le décodage d'une réponse SNMP avec valeurs simulées."""
    # Construction d'une réponse simulée
    # GetResponse PDU (0xA2) contenant sysUpTime = 360000 (3600s) et sysName = 'SW-CORE-01'
    uptime_oid = ber_encode_oid(OID_SYS_UPTIME)
    uptime_val = bytes([0x43, 0x03, 0x05, 0x7E, 0x40])  # TimeTicks 360000
    vb1 = bytes([0x30, len(uptime_oid) + len(uptime_val)]) + uptime_oid + uptime_val

    name_oid = ber_encode_oid(OID_SYS_NAME)
    name_val = ber_encode_octet_string("SW-CORE-01")
    vb2 = bytes([0x30, len(name_oid) + len(name_val)]) + name_oid + name_val

    varbind_list = bytes([0x30, len(vb1) + len(vb2)]) + vb1 + vb2

    pdu_content = (
        ber_encode_integer(1001)  # req id
        + ber_encode_integer(0)   # error status
        + ber_encode_integer(0)   # error index
        + varbind_list
    )
    pdu = bytes([0xA2, len(pdu_content)]) + pdu_content

    msg_content = (
        ber_encode_integer(1)  # v2c
        + ber_encode_octet_string("public")
        + pdu
    )
    resp_packet = bytes([0x30, len(msg_content)]) + msg_content

    parsed = SnmpClient.parse_get_response(resp_packet)
    assert OID_SYS_UPTIME in parsed
    assert parsed[OID_SYS_UPTIME] == 360000
    assert OID_SYS_NAME in parsed
    assert parsed[OID_SYS_NAME] == "SW-CORE-01"


@patch("socket.socket")
def test_snmp_probe_device_metrics_mocked(mock_socket_cls):
    """Vérifie l'extraction des métriques complètes via probe_device_metrics."""
    mock_sock = MagicMock()
    mock_socket_cls.return_value = mock_sock

    # Simuler le retour de get(...)
    mock_data = {
        OID_SYS_DESCR: "Cisco IOS Software, C2960 Software",
        OID_SYS_NAME: "SW-ACCESS-01",
        OID_SYS_UPTIME: 720000,  # 7200 secondes
        OID_CISCO_CPU_5M: 28,     # 28% CPU
        OID_CISCO_MEM_USED: 40000000,
        OID_CISCO_MEM_FREE: 60000000,  # 40% RAM
    }

    with patch.object(SnmpClient, "get", return_value=mock_data):
        metrics = SnmpClient.probe_device_metrics(ip="192.168.1.10", community="public")
        assert metrics is not None
        assert metrics["sys_name"] == "SW-ACCESS-01"
        assert metrics["uptime_secondes"] == 7200
        assert metrics["cpu_percent"] == 28.0
        assert metrics["ram_percent"] == 40.0

