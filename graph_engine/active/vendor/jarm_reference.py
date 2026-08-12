"""JARM TLS fingerprinting — implementazione di riferimento Salesforce.

Vendorizzato da https://github.com/salesforce/jarm (BSD 3-Clause license).

ATTENZIONE: la logica di costruzione del TLS ClientHello è delicata e
facile da sbagliare in modo silenzioso. Questo file preserva ESATTAMENTE
la logica originale — è stato rifattorizzato SOLO per:
- rimuovere argparse e i print (da CLI a libreria)
- rendere ``destination_host``/``destination_port`` parametri espliciti
  invece di globali di modulo
- rimuovere il supporto proxy SOCKS5 (non necessario per GraphEngine)

Original copyright:
  Copyright (c) 2020, salesforce.com, inc.
  All rights reserved.
  Licensed under the BSD 3-Clause license.
  For full license text, see https://opensource.org/licenses/BSD-3-Clause
"""

from __future__ import annotations

import codecs
import hashlib
import ipaddress
import os
import random
import socket
import struct


# ---------------------------------------------------------------------------
# Grease value (random TLS extension padding — anti-ossification)
# ---------------------------------------------------------------------------


def _choose_grease() -> bytes:
    grease_list = [
        b"\x0a\x0a", b"\x1a\x1a", b"\x2a\x2a", b"\x3a\x3a",
        b"\x4a\x4a", b"\x5a\x5a", b"\x6a\x6a", b"\x7a\x7a",
        b"\x8a\x8a", b"\x9a\x9a", b"\xaa\xaa", b"\xba\xba",
        b"\xca\xca", b"\xda\xda", b"\xea\xea", b"\xfa\xfa",
    ]
    return random.choice(grease_list)


# ---------------------------------------------------------------------------
# Cipher list manipulation (identica all'originale)
# ---------------------------------------------------------------------------


def _cipher_mung(ciphers: list, request: str) -> list:
    output: list = []
    cipher_len = len(ciphers)
    if request == "REVERSE":
        output = ciphers[::-1]
    elif request == "BOTTOM_HALF":
        if cipher_len % 2 == 1:
            output = ciphers[int(cipher_len / 2) + 1:]
        else:
            output = ciphers[int(cipher_len / 2):]
    elif request == "TOP_HALF":
        if cipher_len % 2 == 1:
            output.append(ciphers[int(cipher_len / 2)])
        output += _cipher_mung(_cipher_mung(ciphers, "REVERSE"), "BOTTOM_HALF")
    elif request == "MIDDLE_OUT":
        middle = int(cipher_len / 2)
        if cipher_len % 2 == 1:
            output.append(ciphers[middle])
            for i in range(1, middle + 1):
                output.append(ciphers[middle + i])
                output.append(ciphers[middle - i])
        else:
            for i in range(1, middle + 1):
                output.append(ciphers[middle - 1 + i])
                output.append(ciphers[middle - i])
    return output


def _get_ciphers(jarm_details: list) -> bytes:
    selected_ciphers = b""
    if jarm_details[3] == "ALL":
        clist = [
            b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2",
            b"\x00\x9e", b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3",
            b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88", b"\x00\xc4",
            b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac",
            b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad",
            b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9",
            b"\x13\x02", b"\x13\x01", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12",
            b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28",
            b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x76", b"\xc0\x77",
            b"\xcc\xa8", b"\x13\x05", b"\x13\x04", b"\x13\x03", b"\xcc\x13",
            b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c",
            b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d",
            b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84",
            b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05",
        ]
    elif jarm_details[3] == "NO1.3":
        clist = [
            b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2",
            b"\x00\x9e", b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3",
            b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88", b"\x00\xc4",
            b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac",
            b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad",
            b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9",
            b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13", b"\xc0\x27",
            b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60",
            b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\xcc\x13",
            b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c",
            b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d",
            b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84",
            b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05",
        ]
    else:
        clist = []
    if jarm_details[4] != "FORWARD":
        clist = _cipher_mung(clist, jarm_details[4])
    if jarm_details[5] == "GREASE":
        clist.insert(0, _choose_grease())
    for cipher in clist:
        selected_ciphers += cipher
    return selected_ciphers


# ---------------------------------------------------------------------------
# TLS Extension builders (identici all'originale)
# ---------------------------------------------------------------------------


def _extension_server_name(host: str) -> bytes:
    ext_sni = b"\x00\x00"
    ext_sni_length = len(host) + 5
    ext_sni += struct.pack(">H", ext_sni_length)
    ext_sni_length2 = len(host) + 3
    ext_sni += struct.pack(">H", ext_sni_length2)
    ext_sni += b"\x00"
    ext_sni_length3 = len(host)
    ext_sni += struct.pack(">H", ext_sni_length3)
    ext_sni += host.encode()
    return ext_sni


def _app_layer_proto_negotiation(jarm_details: list) -> bytes:
    ext = b"\x00\x10"
    if jarm_details[6] == "RARE_APLN":
        alpns = [
            b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39",
            b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
            b"\x06\x73\x70\x64\x79\x2f\x31",
            b"\x06\x73\x70\x64\x79\x2f\x32",
            b"\x06\x73\x70\x64\x79\x2f\x33",
            b"\x03\x68\x32\x63",
            b"\x02\x68\x71",
        ]
    else:
        alpns = [
            b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39",
            b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
            b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31",
            b"\x06\x73\x70\x64\x79\x2f\x31",
            b"\x06\x73\x70\x64\x79\x2f\x32",
            b"\x06\x73\x70\x64\x79\x2f\x33",
            b"\x02\x68\x32",
            b"\x03\x68\x32\x63",
            b"\x02\x68\x71",
        ]
    if jarm_details[8] != "FORWARD":
        alpns = _cipher_mung(alpns, jarm_details[8])
    all_alpns = b""
    for alpn in alpns:
        all_alpns += alpn
    second_length = len(all_alpns)
    first_length = second_length + 2
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">H", second_length)
    ext += all_alpns
    return ext


def _key_share(grease: bool) -> bytes:
    ext = b"\x00\x33"
    if grease:
        share_ext = _choose_grease()
        share_ext += b"\x00\x01\x00"
    else:
        share_ext = b""
    group = b"\x00\x1d"
    share_ext += group
    key_exchange_length = b"\x00\x20"
    share_ext += key_exchange_length
    share_ext += os.urandom(32)
    second_length = len(share_ext)
    first_length = second_length + 2
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">H", second_length)
    ext += share_ext
    return ext


def _supported_versions(jarm_details: list, grease: bool) -> bytes:
    if jarm_details[7] == "1.2_SUPPORT":
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
    else:
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
    if jarm_details[8] != "FORWARD":
        tls = _cipher_mung(tls, jarm_details[8])
    ext = b"\x00\x2b"
    if grease:
        versions = _choose_grease()
    else:
        versions = b""
    for version in tls:
        versions += version
    second_length = len(versions)
    first_length = second_length + 1
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">B", second_length)
    ext += versions
    return ext


def _get_extensions(jarm_details: list) -> bytes:
    extension_bytes = b""
    all_extensions = b""
    grease = False
    if jarm_details[5] == "GREASE":
        all_extensions += _choose_grease()
        all_extensions += b"\x00\x00"
        grease = True
    all_extensions += _extension_server_name(jarm_details[0])
    all_extensions += b"\x00\x17\x00\x00"                       # extended master secret
    all_extensions += b"\x00\x01\x00\x01\x01"                   # max fragment length
    all_extensions += b"\xff\x01\x00\x01\x00"                   # renegotiation info
    all_extensions += b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"  # supported groups
    all_extensions += b"\x00\x0b\x00\x02\x01\x00"               # ec point formats
    all_extensions += b"\x00\x23\x00\x00"                       # session ticket
    all_extensions += _app_layer_proto_negotiation(jarm_details)
    all_extensions += b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"  # signature algorithms
    all_extensions += _key_share(grease)
    all_extensions += b"\x00\x2d\x00\x02\x01\x01"               # psk key exchange modes
    if (jarm_details[2] == "TLS_1.3") or (jarm_details[7] == "1.2_SUPPORT"):
        all_extensions += _supported_versions(jarm_details, grease)
    extension_length = len(all_extensions)
    extension_bytes += struct.pack(">H", extension_length)
    extension_bytes += all_extensions
    return extension_bytes


# ---------------------------------------------------------------------------
# Packet assembly (identica all'originale)
# ---------------------------------------------------------------------------


def _packet_building(jarm_details: list) -> bytes:
    payload = b"\x16"
    if jarm_details[2] == "TLS_1.3":
        payload += b"\x03\x01"
        client_hello = b"\x03\x03"
    elif jarm_details[2] == "SSLv3":
        payload += b"\x03\x00"
        client_hello = b"\x03\x00"
    elif jarm_details[2] == "TLS_1":
        payload += b"\x03\x01"
        client_hello = b"\x03\x01"
    elif jarm_details[2] == "TLS_1.1":
        payload += b"\x03\x02"
        client_hello = b"\x03\x02"
    elif jarm_details[2] == "TLS_1.2":
        payload += b"\x03\x03"
        client_hello = b"\x03\x03"
    else:
        payload += b"\x03\x03"
        client_hello = b"\x03\x03"
    client_hello += os.urandom(32)
    session_id = os.urandom(32)
    session_id_length = struct.pack(">B", len(session_id))
    client_hello += session_id_length
    client_hello += session_id
    cipher_choice = _get_ciphers(jarm_details)
    client_suites_length = struct.pack(">H", len(cipher_choice))
    client_hello += client_suites_length
    client_hello += cipher_choice
    client_hello += b"\x01"  # cipher methods
    client_hello += b"\x00"  # compression methods
    extensions = _get_extensions(jarm_details)
    client_hello += extensions
    inner_length = b"\x00"
    inner_length += struct.pack(">H", len(client_hello))
    handshake_protocol = b"\x01"
    handshake_protocol += inner_length
    handshake_protocol += client_hello
    outer_length = struct.pack(">H", len(handshake_protocol))
    payload += outer_length
    payload += handshake_protocol
    return payload


# ---------------------------------------------------------------------------
# Socket send/receive (rifattorizzato: host/port sono parametri)
# ---------------------------------------------------------------------------


def _send_packet(
    packet: bytes,
    destination_host: str,
    destination_port: int,
    timeout_s: float = 20.0,
):
    """Invia il ClientHello TLS e riceve il ServerHello.

    Rifattorizzato dall'originale per accettare host/port come parametri
    invece di usare globali di modulo.
    """
    try:
        # Determina se l'input è un IP
        try:
            ipaddress.ip_address(destination_host)
            raw_ip = True
        except ValueError:
            raw_ip = False

        if ":" in destination_host:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(timeout_s)
        sock.connect((destination_host, destination_port))

        if not raw_ip:
            ip = sock.getpeername()[0]
        else:
            ip = destination_host

        sock.sendall(packet)
        data = sock.recv(1484)
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        return bytearray(data), ip

    except socket.timeout:
        sock.close()
        return "TIMEOUT", destination_host
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None, destination_host


# ---------------------------------------------------------------------------
# ServerHello parsing (identico all'originale)
# ---------------------------------------------------------------------------


def _read_packet(data, jarm_details):
    try:
        if data is None:
            return "|||"
        if data[0] == 21:  # Alert
            return "|||"
        elif (data[0] == 22) and (data[5] == 2):  # ServerHello
            server_hello_length = int.from_bytes(data[3:5], "big")
            counter = data[43]
            selected_cipher = data[counter + 44:counter + 46]
            version = data[9:11]
            jarm = ""
            jarm += codecs.encode(selected_cipher, 'hex').decode('ascii')
            jarm += "|"
            jarm += codecs.encode(version, 'hex').decode('ascii')
            jarm += "|"
            extensions = _extract_extension_info(data, counter, server_hello_length)
            jarm += extensions
            return jarm
        else:
            return "|||"
    except Exception:
        return "|||"


def _extract_extension_info(data, counter, server_hello_length):
    try:
        if data[counter + 47] == 11:
            return "|"
        elif (data[counter + 50:counter + 53] == b"\x0e\xac\x0b") or \
             (data[82:85] == b"\x0f\xf0\x0b"):
            return "|"
        elif counter + 42 >= server_hello_length:
            return "|"
        count = 49 + counter
        length = int(codecs.encode(data[counter + 47:counter + 49], 'hex'), 16)
        maximum = length + (count - 1)
        types = []
        values = []
        while count < maximum:
            types.append(data[count:count + 2])
            ext_length = int(codecs.encode(data[count + 2:count + 4], 'hex'), 16)
            if ext_length == 0:
                count += 4
                values.append("")
            else:
                values.append(data[count + 4:count + 4 + ext_length])
                count += ext_length + 4
        result = ""
        alpn = _find_extension(b"\x00\x10", types, values)
        result += str(alpn)
        result += "|"
        add_hyphen = 0
        while add_hyphen < len(types):
            result += codecs.encode(types[add_hyphen], 'hex').decode('ascii')
            add_hyphen += 1
            if add_hyphen == len(types):
                break
            else:
                result += "-"
        return result
    except IndexError:
        return "|"


def _find_extension(ext_type, types, values):
    iter_idx = 0
    if ext_type == b"\x00\x10":
        while iter_idx < len(types):
            if types[iter_idx] == ext_type:
                return (values[iter_idx][3:]).decode()
            iter_idx += 1
    else:
        while iter_idx < len(types):
            if types[iter_idx] == ext_type:
                return values[iter_idx].hex()
            iter_idx += 1
    return ""


# ---------------------------------------------------------------------------
# JARM fuzzy hash (identico all'originale)
# ---------------------------------------------------------------------------


def _jarm_hash(jarm_raw: str) -> str:
    if jarm_raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||":
        return "0" * 62
    fuzzy_hash = ""
    handshakes = jarm_raw.split(",")
    alpns_and_ext = ""
    for handshake in handshakes:
        components = handshake.split("|")
        fuzzy_hash += _cipher_bytes(components[0])
        fuzzy_hash += _version_byte(components[1])
        alpns_and_ext += components[2]
        alpns_and_ext += components[3]
    sha256 = hashlib.sha256(alpns_and_ext.encode()).hexdigest()
    fuzzy_hash += sha256[0:32]
    return fuzzy_hash


def _cipher_bytes(cipher: str) -> str:
    if cipher == "":
        return "00"
    clist = [
        b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16",
        b"\x00\x2f", b"\x00\x33", b"\x00\x35", b"\x00\x39", b"\x00\x3c",
        b"\x00\x3d", b"\x00\x41", b"\x00\x45", b"\x00\x67", b"\x00\x6b",
        b"\x00\x84", b"\x00\x88", b"\x00\x9a", b"\x00\x9c", b"\x00\x9d",
        b"\x00\x9e", b"\x00\x9f", b"\x00\xba", b"\x00\xbe", b"\x00\xc0",
        b"\x00\xc4", b"\xc0\x07", b"\xc0\x08", b"\xc0\x09", b"\xc0\x0a",
        b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14", b"\xc0\x23",
        b"\xc0\x24", b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c",
        b"\xc0\x2f", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x72",
        b"\xc0\x73", b"\xc0\x76", b"\xc0\x77", b"\xc0\x9c", b"\xc0\x9d",
        b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1", b"\xc0\xa2",
        b"\xc0\xa3", b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf",
        b"\xcc\x13", b"\xcc\x14", b"\xcc\xa8", b"\xcc\xa9",
        b"\x13\x01", b"\x13\x02", b"\x13\x03", b"\x13\x04", b"\x13\x05",
    ]
    count = 1
    for bval in clist:
        strtype_bytes = codecs.encode(bval, 'hex').decode('ascii')
        if cipher == strtype_bytes:
            break
        count += 1
    hexvalue = str(hex(count))[2:]
    if len(hexvalue) < 2:
        return "0" + hexvalue
    return hexvalue


def _version_byte(version: str) -> str:
    if version == "":
        return "0"
    options = "abcdef"
    count = int(version[3:4])
    byte = options[count]
    return byte


# ---------------------------------------------------------------------------
# Pubblico: JARM fingerprint di un host
# ---------------------------------------------------------------------------


def jarm_fingerprint(
    host: str,
    port: int = 443,
    timeout_s: float = 10.0,
) -> str | None:
    """Calcola il JARM hash (62 caratteri esadecimali) per *host:port*.

    Implementa l'algoritmo originale Salesforce: invia 10 TLS Client Hello
    con parametri variati, aggrega i Server Hello e produce un fuzzy hash.

    Args:
        host: Hostname o IP del server TLS.
        port: Porta TCP (default 443).
        timeout_s: Timeout socket in secondi (default 10).

    Returns:
        Stringa di 62 caratteri esadecimali, oppure None se tutte le
        connessioni falliscono.
    """
    # Le 10 configurazioni TLS dell'algoritmo originale
    # Formato: [host, port, version, cipher_list, cipher_order, GREASE,
    #           RARE_APLN, version_support, extension_order]
    tls1_2_forward =    [host, port, "TLS_1.2", "ALL", "FORWARD",    "NO_GREASE", "APLN",      "1.2_SUPPORT", "REVERSE"]
    tls1_2_reverse =    [host, port, "TLS_1.2", "ALL", "REVERSE",    "NO_GREASE", "APLN",      "1.2_SUPPORT", "FORWARD"]
    tls1_2_top_half =   [host, port, "TLS_1.2", "ALL", "TOP_HALF",   "NO_GREASE", "APLN",      "NO_SUPPORT",   "FORWARD"]
    tls1_2_bottom_half= [host, port, "TLS_1.2", "ALL", "BOTTOM_HALF","NO_GREASE", "RARE_APLN", "NO_SUPPORT",   "FORWARD"]
    tls1_2_middle_out = [host, port, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE",    "RARE_APLN", "NO_SUPPORT",   "REVERSE"]
    tls1_1_middle_out = [host, port, "TLS_1.1", "ALL", "FORWARD",    "NO_GREASE", "APLN",      "NO_SUPPORT",   "FORWARD"]
    tls1_3_forward =    [host, port, "TLS_1.3", "ALL", "FORWARD",    "NO_GREASE", "APLN",      "1.3_SUPPORT", "REVERSE"]
    tls1_3_reverse =    [host, port, "TLS_1.3", "ALL", "REVERSE",    "NO_GREASE", "APLN",      "1.3_SUPPORT", "FORWARD"]
    tls1_3_invalid =    [host, port, "TLS_1.3", "NO1.3","FORWARD",   "NO_GREASE", "APLN",      "1.3_SUPPORT", "FORWARD"]
    tls1_3_middle_out = [host, port, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE",    "APLN",      "1.3_SUPPORT", "REVERSE"]

    queue = [
        tls1_2_forward, tls1_2_reverse, tls1_2_top_half,
        tls1_2_bottom_half, tls1_2_middle_out, tls1_1_middle_out,
        tls1_3_forward, tls1_3_reverse, tls1_3_invalid, tls1_3_middle_out,
    ]

    jarm = ""
    iterate = 0
    while iterate < len(queue):
        payload = _packet_building(queue[iterate])
        server_hello, _ip = _send_packet(payload, host, port, timeout_s)
        if server_hello == "TIMEOUT":
            jarm = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
            break
        ans = _read_packet(server_hello, queue[iterate])
        jarm += ans
        iterate += 1
        if iterate == len(queue):
            break
        else:
            jarm += ","

    result = _jarm_hash(jarm)

    # Se il risultato sono 62 zeri, significa che il server non ha
    # risposto a nessun hello — consideriamolo un fallimento
    if result == "0" * 62:
        return None

    return result
