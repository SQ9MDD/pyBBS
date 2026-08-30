#!/usr/bin/env python3
"""
agw_kiss_proxy.py

AX.25/KISS engine, v2.9.1: startup config fix + direct-route priority + UI DIGI fan-out.

Cel:
    UZ7HO EasyTerm -> AGWPE TCP -> ten skrypt -> KISS TCP -> tnc-proxy/TNC

Zakres pierwszej wersji:
- 1 port AGWPE
- 1 jednoczesna sesja AX.25
- AX.25 v2.0 modulo 8
- bez digipeaterów
- SABM / UA / DISC / DM
- I frames / RR / REJ
- retransmisje T1/N2\n- obsługa stanu RNR i bezpieczniejsza retransmisja REJ\n- thread-safe logging
- AGWPE: R, G, g, X, x, m, M, V, C, D, d, y, Y
- monitor UI przez AGWPE U\n- UZ7HO-like G response (50 bytes)\n- TX monitor echo przez AGWPE T
- KISS TCP, port 0, command DATA

To jest wersja testowa do pracy radiowej. Logowanie jest celowo bardzo gadatliwe.
"""

import socket
import struct
import threading
import time
import datetime
import json
import base64
from pathlib import Path
from collections import deque
import sys
import os

PRINT_LOCK = threading.Lock()


# ============================================================================
# KONFIGURACJA
# ============================================================================

AGW_LISTEN_HOST = "0.0.0.0"
AGW_LISTEN_PORT = 8000

# Native application API.
# One JSON object per line (JSON Lines / NDJSON).
# Bound to localhost by default because there is no authentication layer.
API_LISTEN_HOST = "127.0.0.1"
API_LISTEN_PORT = 8010
API_ENABLED = True

# A GUI may disappear and reconnect without destroying radio sessions.
API_KEEP_SESSIONS_WITHOUT_CLIENT = True

# Tu wpisz adres TCP SIMPLE KISS wystawiany przez tnc-proxy.
CONFIG_FILE = "pypacket_terminal_config.json"

KISS_MAX_RECONNECT_ATTEMPTS = 10
KISS_RECONNECT_DELAY = 2.0

DIGI_UI_DUPE_TTL = 5.0
DIGI_UI_DUPE_MAX = 512


def application_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def load_ports_config():
    path = application_dir() / CONFIG_FILE

    # First run: do not assume any KISS endpoint.
    if not path.exists():
        return []

    try:
        data = json.loads(
            path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        print(
            f"Warning: could not read port config: {exc}"
        )
        return []

    if not isinstance(data, dict):
        return []

    ports = []
    raw_ports = data.get("ports")

    if isinstance(raw_ports, list):
        for raw in raw_ports:
            if not isinstance(raw, dict):
                continue

            if (
                str(raw.get("type", "kiss_tcp")).lower()
                != "kiss_tcp"
            ):
                continue

            host = str(
                raw.get("host", "")
            ).strip()
            if not host:
                continue

            try:
                tcp_port = int(raw.get("port", 0))
            except (TypeError, ValueError):
                continue

            if not 1 <= tcp_port <= 65535:
                continue

            pid = str(len(ports))
            name = str(
                raw.get("name", f"Port {len(ports) + 1}")
            ).strip() or f"Port {len(ports) + 1}"

            ports.append({
                "id": pid,
                "name": name,
                "type": "kiss_tcp",
                "host": host,
                "port": tcp_port,
            })

        return ports

    # Migration from the old single-port format only when the old
    # keys are actually present. Never invent 127.0.0.1:8001.
    if "kiss_host" in data or "kiss_port" in data:
        host = str(
            data.get("kiss_host", "")
        ).strip()

        try:
            tcp_port = int(data.get("kiss_port", 0))
        except (TypeError, ValueError):
            tcp_port = 0

        if host and 1 <= tcp_port <= 65535:
            return [{
                "id": "0",
                "name": "Port 1",
                "type": "kiss_tcp",
                "host": host,
                "port": tcp_port,
            }]

    return []

PORTS = load_ports_config()
DEFAULT_PORT_ID = PORTS[0]["id"] if PORTS else "0"
PORTS_BY_ID = {p["id"]: p for p in PORTS}


def load_digi_config():
    path = application_dir() / CONFIG_FILE
    result = {
        "local": "N0CAL",
        "digi_callsign": "N0CAL",
        "enabled": False,
        "route_ttl": 3600,
        "station_info": "",
        "welcome_text": "",
        "bye_text": "",
        "mheard": {},
        "beacon_dest": "CQ",
        "beacon_callsign": "N0CAL",
        "beacon_via": "",
        "beacon_text": "",
        "beacon_port_ids": [],
        "beacon_interval_min": 0,
    }

    if not path.exists():
        return result

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return result

        # normalize_call() is defined later in this module, while this
        # loader runs during module import. Keep startup parsing self-contained
        # here to avoid NameError before helper definitions exist.
        call = str(
            data.get("local", "N0CAL")
        ).strip().upper()
        if call:
            result["local"] = call

        digi_call = str(
            data.get(
                "digi_callsign",
                call or "N0CAL"
            )
        ).strip().upper()
        result["digi_callsign"] = (
            digi_call or call or "N0CAL"
        )

        result["enabled"] = bool(
            data.get("digi_enabled", False)
        )
        result["station_info"] = str(
            data.get("station_info", "")
        )
        result["welcome_text"] = str(
            data.get("welcome_text", "")
        )
        result["bye_text"] = str(
            data.get("bye_text", "")
        )
        if isinstance(data.get("mheard"), dict):
            result["mheard"] = data["mheard"]

        # Bridge.__init__ normalizes this after normalize_call() is defined.
        # This loader runs earlier during module import.
        result["beacon_dest"] = (
            str(data.get("beacon_dest", "CQ")).strip().upper()
            or "CQ"
        )
        result["beacon_callsign"] = (
            str(data.get("beacon_callsign", call or "N0CAL")).strip().upper()
            or call
            or "N0CAL"
        )
        result["beacon_via"] = str(
            data.get("beacon_via", "")
        )
        result["beacon_text"] = str(
            data.get("beacon_text", "")
        )

        raw_beacon_ports = data.get("beacon_port_ids", [])
        if isinstance(raw_beacon_ports, list):
            result["beacon_port_ids"] = [
                str(x) for x in raw_beacon_ports
            ]

        try:
            result["beacon_interval_min"] = max(
                0,
                int(data.get("beacon_interval_min", 0))
            )
        except (TypeError, ValueError):
            result["beacon_interval_min"] = 0

        try:
            ttl = int(data.get("digi_route_ttl", 3600))
            if ttl >= 60:
                result["route_ttl"] = ttl
        except (TypeError, ValueError):
            pass
    except Exception as exc:
        print(f"Warning: could not read DIGI config: {exc}")

    return result


DIGI_CONFIG = load_digi_config()


PORT_NAME = "Python KISS AX.25 proxy"

# AX.25
T1 = 5.0               # retransmisja ramki oczekującej na ACK
N2 = 10                # maksymalna liczba prób
MAX_INFO = 128          # maks. payload jednego I-frame
PID_DEFAULT = 0xF0

# Pierwsza wersja celowo używa okna 1.
# Jest wolniej, ale bardzo łatwo diagnozować poprawność N(S)/N(R).
WINDOW = 1
MAX_SESSIONS = 10       # równoległe połączenia AX.25

VERBOSE_HEX = True
RAW_AGW_DEBUG = True      # pokaż każdy surowy pakiet EasyTerm -> proxy


# ============================================================================
# STAŁE
# ============================================================================

AGW_HEADER_SIZE = 36
AGW_MAX_DATA = 1024 * 1024

FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD

AX25_SABM = 0x2F
AX25_UA = 0x63
AX25_DISC = 0x43
AX25_DM = 0x0F
AX25_UI = 0x03

STATE_DISCONNECTED = "DISCONNECTED"
STATE_AWAIT_UA = "AWAIT_UA"
STATE_CONNECTED = "CONNECTED"
STATE_AWAIT_DISC_UA = "AWAIT_DISC_UA"


# ============================================================================
# POMOCNICZE
# ============================================================================

def ts():
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def safe_print(*args, **kwargs):
    """Thread-safe print, żeby logi z AGW/KISS/timerów się nie sklejały."""
    kwargs.setdefault("flush", True)
    with PRINT_LOCK:
        print(*args, **kwargs)


def log(msg=""):
    safe_print(f"[{ts()}] {msg}")


def log_hex(data):
    if not VERBOSE_HEX:
        return
    safe_print(hexdump(data))


def hexdump(data, width=16):
    if not data:
        return "<empty>"
    out = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hx = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        out.append(f"{off:04X}  {hx:<{width * 3}} {asc}")
    return "\n".join(out)


def split_call(call):
    call = call.strip().upper()
    if "-" in call:
        base, ssid_s = call.rsplit("-", 1)
        try:
            ssid = int(ssid_s)
        except ValueError:
            ssid = 0
    else:
        base = call
        ssid = 0
    base = base[:6]
    ssid = max(0, min(15, ssid))
    return base, ssid


def normalize_call(call):
    base, ssid = split_call(call)
    return f"{base}-{ssid}" if ssid else base


# ============================================================================
# AGWPE
# ============================================================================


def callsign_base(call):
    return normalize_call(call).split("-", 1)[0]


def same_call_base(a, b):
    aa = callsign_base(a)
    bb = callsign_base(b)
    return bool(aa and bb and aa == bb)


def is_exact_own_call(call, station_callsign, digi_callsign):
    c = normalize_call(call)
    return c in {
        normalize_call(station_callsign),
        normalize_call(digi_callsign),
    }


def agw_decode_call(raw):
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()


def agw_parse_header(raw):
    if len(raw) != 36:
        raise ValueError("Bad AGW header size")
    return {
        "port": raw[0],
        "kind": raw[4],
        "pid": raw[6],
        "from": agw_decode_call(raw[8:18]),
        "to": agw_decode_call(raw[18:28]),
        "len": struct.unpack_from("<I", raw, 28)[0],
        "user": struct.unpack_from("<I", raw, 32)[0],
    }


def log_raw_agw_rx(raw_header, payload):
    """Dump exactly what arrived from EasyTerm before any interpretation."""
    if not RAW_AGW_DEBUG:
        return

    kind = raw_header[4] if len(raw_header) >= 5 else 0
    printable = chr(kind) if 32 <= kind <= 126 else f"0x{kind:02X}"

    safe_print()
    safe_print("=" * 72)
    safe_print(f"RAW AGW RX FROM EASYTERM  kind={printable}")
    safe_print(f"TOTAL BYTES: {len(raw_header) + len(payload)}")
    safe_print("HEADER (36 bytes):")
    safe_print(hexdump(raw_header))

    if payload:
        safe_print(f"PAYLOAD ({len(payload)} bytes):")
        safe_print(hexdump(payload))

        try:
            txt = payload.decode("latin-1", errors="replace")
            txt = txt.replace("\r", "\\r").replace("\n", "\\n")
            safe_print(f"PAYLOAD TEXT: {txt!r}")
        except Exception:
            pass
    else:
        safe_print("PAYLOAD: <empty>")

    safe_print("=" * 72)


def agw_build_header(kind, payload_len=0, port=0, pid=0,
                     call_from="", call_to="", user=0):
    h = bytearray(36)
    h[0] = port & 0xFF
    h[4] = kind if isinstance(kind, int) else ord(kind)
    h[6] = pid & 0xFF

    cf = call_from.encode("ascii", errors="ignore")[:10]
    ct = call_to.encode("ascii", errors="ignore")[:10]
    h[8:8 + len(cf)] = cf
    h[18:18 + len(ct)] = ct

    struct.pack_into("<I", h, 28, payload_len)
    struct.pack_into("<I", h, 32, user)
    return bytes(h)


# ============================================================================
# KISS
# ============================================================================

def kiss_encode(ax25_frame, port=0):
    command = (port & 0x0F) << 4
    raw = bytes([command]) + ax25_frame
    out = bytearray([FEND])

    for b in raw:
        if b == FEND:
            out += bytes([FESC, TFEND])
        elif b == FESC:
            out += bytes([FESC, TFESC])
        else:
            out.append(b)

    out.append(FEND)
    return bytes(out)


class KissStreamDecoder:
    def __init__(self):
        self.in_frame = False
        self.escape = False
        self.buf = bytearray()

    def feed(self, data):
        frames = []

        for b in data:
            if b == FEND:
                if self.in_frame and self.buf:
                    frames.append(bytes(self.buf))
                self.buf.clear()
                self.escape = False
                self.in_frame = True
                continue

            if not self.in_frame:
                continue

            if self.escape:
                if b == TFEND:
                    self.buf.append(FEND)
                elif b == TFESC:
                    self.buf.append(FESC)
                else:
                    self.buf.append(b)
                self.escape = False
                continue

            if b == FESC:
                self.escape = True
            else:
                self.buf.append(b)

        return frames


# ============================================================================
# AX.25
# ============================================================================

def ax25_encode_address(call, last=False, c_bit=False):
    base, ssid = split_call(call)
    base = base.ljust(6)

    out = bytearray()
    for ch in base:
        out.append((ord(ch) << 1) & 0xFE)

    # 0x60: dwa bity rezerwowe ustawione zgodnie z AX.25
    ssid_byte = 0x60 | ((ssid & 0x0F) << 1)

    if c_bit:
        ssid_byte |= 0x80

    if last:
        ssid_byte |= 0x01

    out.append(ssid_byte)
    return bytes(out)


def ax25_decode_address(raw7):
    if len(raw7) != 7:
        raise ValueError("Bad AX.25 address")

    base = "".join(chr((b >> 1) & 0x7F) for b in raw7[:6]).rstrip()
    ssid = (raw7[6] >> 1) & 0x0F
    call = f"{base}-{ssid}" if ssid else base

    return {
        "call": call,
        "ssid": ssid,
        # For destination/source this is the C bit.
        # For digipeater addresses the same bit position is the H bit.
        "c": bool(raw7[6] & 0x80),
        "h": bool(raw7[6] & 0x80),
        "last": bool(raw7[6] & 0x01),
    }


def ax25_addresses(dst, src, command=True, digis=None):
    """
    Build AX.25 address field for connected-mode frames.

    Destination/source C bits follow AX.25 command/response rules.
    Digipeater H bits are clear on transmission. The final address
    in the complete address field gets the extension bit.
    """
    digis = [normalize_call(x) for x in (digis or []) if normalize_call(x)]

    out = bytearray()
    out += ax25_encode_address(
        dst,
        last=False,
        c_bit=command
    )
    out += ax25_encode_address(
        src,
        last=(len(digis) == 0),
        c_bit=not command
    )

    for idx, digi in enumerate(digis):
        out += ax25_encode_address(
            digi,
            last=(idx == len(digis) - 1),
            c_bit=False
        )

    return bytes(out)


def ctrl_i(ns, nr, pf=False):
    return ((nr & 7) << 5) | ((1 if pf else 0) << 4) | ((ns & 7) << 1)


def ctrl_rr(nr, pf=False):
    return ((nr & 7) << 5) | ((1 if pf else 0) << 4) | 0x01


def ctrl_rej(nr, pf=False):
    return ((nr & 7) << 5) | ((1 if pf else 0) << 4) | 0x09


def ctrl_u(base, pf=False):
    return base | (0x10 if pf else 0)


def ax25_build_u(
    dst, src, base_ctrl, command=True, pf=True, digis=None
):
    return (
        ax25_addresses(dst, src, command, digis=digis) +
        bytes([ctrl_u(base_ctrl, pf)])
    )


def ax25_build_s(
    dst, src, kind, nr, command=False, pf=False, digis=None
):
    ctrl = ctrl_rr(nr, pf) if kind == "RR" else ctrl_rej(nr, pf)
    return (
        ax25_addresses(dst, src, command, digis=digis) +
        bytes([ctrl])
    )


def ax25_build_i(
    dst, src, ns, nr, payload,
    pid=0xF0, pf=False, digis=None
):
    return (
        ax25_addresses(dst, src, True, digis=digis) +
        bytes([ctrl_i(ns, nr, pf), pid & 0xFF]) +
        payload
    )


def ax25_build_ui(dst, src, payload, pid=0xF0, digis=None):
    """Build AX.25 UI frame, optionally with a digipeater path."""
    digis = digis or []

    addresses = bytearray()
    addresses += ax25_encode_address(dst, last=False, c_bit=True)
    addresses += ax25_encode_address(
        src,
        last=(len(digis) == 0),
        c_bit=False
    )

    for idx, digi in enumerate(digis):
        addresses += ax25_encode_address(
            digi,
            last=(idx == len(digis) - 1),
            c_bit=False
        )

    return bytes(addresses) + bytes([AX25_UI, pid & 0xFF]) + payload


def agw_parse_v_payload(payload):
    """
    AGWPE V payload:
        byte 0      number of digipeaters
        next N*10   NUL-padded ASCII digipeater callsigns
        remainder   UI information field
    """
    if not payload:
        return [], b""

    count = payload[0]
    if count > 8:
        raise ValueError(f"Unreasonable AGW V digipeater count: {count}")

    needed = 1 + count * 10
    if len(payload) < needed:
        raise ValueError(
            f"AGW V payload too short for {count} digipeaters"
        )

    digis = []
    pos = 1

    for _ in range(count):
        raw = payload[pos:pos + 10]
        pos += 10
        call = agw_decode_call(raw)
        if call:
            digis.append(normalize_call(call))

    return digis, payload[pos:]


def agw_monitor_ui_payload(f):
    """
    AGWPE U monitor payload:
        textual AX.25 header + CR + information + CR + NUL
    """
    via = ""
    if f["digis"]:
        via = " Via " + ",".join(f["digis"])

    pid = f["pid"] if f["pid"] is not None else PID_DEFAULT
    header = (
        f"1:Fm {f['src']} To {f['dst']}{via} "
        f"<UI pid={pid:02X} Len={len(f['info'])}>"
    ).encode("ascii", errors="replace")

    return header + b"\r" + f["info"] + b"\r\x00"


def ax25_parse(frame):
    if len(frame) < 15:
        raise ValueError("AX.25 frame too short")

    pos = 0
    addresses = []

    while True:
        if pos + 7 > len(frame):
            raise ValueError("Broken AX.25 address field")

        a = ax25_decode_address(frame[pos:pos + 7])
        addresses.append(a)
        pos += 7

        if a["last"]:
            break

        if len(addresses) > 10:
            raise ValueError("Too many AX.25 addresses")

    if len(addresses) < 2:
        raise ValueError("Need destination and source")

    if pos >= len(frame):
        raise ValueError("Missing AX.25 control")

    ctrl = frame[pos]
    pos += 1

    result = {
        "dst": addresses[0]["call"],
        "src": addresses[1]["call"],
        "digis": [x["call"] for x in addresses[2:]],
        "digi_info": [
            {"call": x["call"], "repeated": x["h"]}
            for x in addresses[2:]
        ],
        "ctrl": ctrl,
        "pf": bool(ctrl & 0x10),
        "pid": None,
        "info": b"",
        "type": "UNKNOWN",
        "ns": None,
        "nr": None,
    }

    # I frame: bit 0 = 0
    if (ctrl & 0x01) == 0:
        result["type"] = "I"
        result["ns"] = (ctrl >> 1) & 0x07
        result["nr"] = (ctrl >> 5) & 0x07

        if pos < len(frame):
            result["pid"] = frame[pos]
            pos += 1

        result["info"] = frame[pos:]
        return result

    # S frame: bits 0..1 = 01
    if (ctrl & 0x03) == 0x01:
        s = ctrl & 0x0F
        result["nr"] = (ctrl >> 5) & 0x07

        if s == 0x01:
            result["type"] = "RR"
        elif s == 0x05:
            result["type"] = "RNR"
        elif s == 0x09:
            result["type"] = "REJ"
        elif s == 0x0D:
            result["type"] = "SREJ"
        else:
            result["type"] = "S"
        return result

    # U frame, ignorujemy P/F przy identyfikacji
    u = ctrl & 0xEF

    if u == AX25_SABM:
        result["type"] = "SABM"
    elif u == AX25_UA:
        result["type"] = "UA"
    elif u == AX25_DISC:
        result["type"] = "DISC"
    elif u == AX25_DM:
        result["type"] = "DM"
    elif u == AX25_UI:
        result["type"] = "UI"
        if pos < len(frame):
            result["pid"] = frame[pos]
            pos += 1
        result["info"] = frame[pos:]
    else:
        result["type"] = "U"

    return result


# ============================================================================
# SESJA
# ============================================================================

class Session:
    def __init__(self):
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        self.local = ""
        self.remote = ""
        self.pid = PID_DEFAULT
        self.state = STATE_DISCONNECTED
        self.port_id = DEFAULT_PORT_ID

        # Frontends interested in this session: "agw" and/or "api".
        # Incoming sessions may belong to both when both frontends registered
        # the same local callsign.
        self.owners = set()

        # Outbound AX.25 digipeater route for this link.
        # Empty list means direct connection.
        self.digis = []

        self.vs = 0
        self.vr = 0

        # stop-and-wait: najwyżej jedna ramka oczekująca na ACK
        self.unacked = None
        self.unacked_ns = None
        self.unacked_time = 0.0
        self.unacked_retries = 0

        self.tx_queue = deque()
        self.remote_busy = False

        self.control_frame = None
        self.control_time = 0.0
        self.control_retries = 0

        # Headless station command service state.
        self.command_buffer = bytearray()
        self.close_after_tx = False


def agw_tx_monitor_payload(src, dst, payload, pid=0xF0, digis=None):
    """
    Build the AGWPE 'T' monitor echo in the format observed from
    real UZ7HO SoundModem.

    Example:
      " 1:Fm SQ9MDD-2 To CQ <UI pid=F0 Len=11 >[11:41:11]\\r"
      "KO02LG test\\r\\r\\x00"
    """
    digis = digis or []

    via = ""
    if digis:
        via = " Via " + ",".join(digis)

    stamp = datetime.datetime.now().strftime("%H:%M:%S")

    header = (
        f" 1:Fm {src} To {dst}{via} "
        f"<UI pid={pid:02X} Len={len(payload)} >[{stamp}]\r"
    ).encode("ascii", errors="replace")

    return header + payload + b"\r\r\x00"


# ============================================================================
# BRIDGE
# ============================================================================

class Bridge:
    def __init__(self):
        self.agw_sock = None
        self.agw_lock = threading.Lock()

        self.kiss_socks = {}
        self.kiss_locks = {p["id"]: threading.Lock() for p in PORTS}
        self.kiss_states = {p["id"]: False for p in PORTS}
        self.kiss_port_status = {
            p["id"]: "disconnected"
            for p in PORTS
        }

        # Dynamic port routing for cross-port AX.25 digipeating.
        # Learned only from RX source callsigns.
        self.digi_routes = {}
        self.digi_routes_lock = threading.RLock()

        # Short duplicate cache used only for UI digipeating. A multi-band
        # node may hear the same UI frame on more than one interface or get
        # it echoed by a proxy. One original frame should cause one fan-out.
        self.digi_ui_dupes = {}
        self.digi_ui_dupes_lock = threading.RLock()

        self.digi_enabled = bool(DIGI_CONFIG["enabled"])
        self.station_callsign = normalize_call(
            DIGI_CONFIG["local"]
        )
        self.digi_callsign = normalize_call(
            DIGI_CONFIG["digi_callsign"]
        ) or self.station_callsign
        self.digi_route_ttl = int(DIGI_CONFIG["route_ttl"])
        self.station_info = str(
            DIGI_CONFIG.get("station_info", "")
        )
        self.welcome_text = str(
            DIGI_CONFIG.get("welcome_text", "")
        )
        self.bye_text = str(
            DIGI_CONFIG.get("bye_text", "")
        )

        self.beacon_lock = threading.RLock()
        self.beacon_dest = normalize_call(
            DIGI_CONFIG.get("beacon_dest", "CQ")
        ) or "CQ"
        self.beacon_callsign = normalize_call(
            DIGI_CONFIG.get("beacon_callsign", self.station_callsign)
        ) or self.station_callsign
        self.beacon_via = str(
            DIGI_CONFIG.get("beacon_via", "")
        )
        self.beacon_text = str(
            DIGI_CONFIG.get("beacon_text", "")
        )
        self.beacon_port_ids = [
            str(x)
            for x in DIGI_CONFIG.get("beacon_port_ids", [])
            if str(x) in PORTS_BY_ID
        ]
        self.beacon_interval_min = max(
            0,
            int(DIGI_CONFIG.get("beacon_interval_min", 0))
        )
        self.beacon_next_due = (
            time.monotonic() + self.beacon_interval_min * 60
            if self.beacon_interval_min > 0
            else None
        )

        # Load saved RX MHeard into the initial dynamic routing table.
        now_wall = time.time()
        loaded_routes = 0

        for key, info in DIGI_CONFIG.get("mheard", {}).items():
            if not isinstance(info, dict):
                continue

            call = normalize_call(
                str(
                    info.get(
                        "call",
                        str(key).split("|")[-1]
                    )
                )
            )
            port_id = str(
                info.get(
                    "port_id",
                    str(key).split("|")[0]
                    if "|" in str(key)
                    else ""
                )
            )

            if (
                not call
                or port_id not in PORTS_BY_ID
                or is_exact_own_call(
                    call,
                    self.station_callsign,
                    self.digi_callsign,
                )
            ):
                continue

            direction = str(
                info.get("direction", "RX")
            ).upper()
            if direction and direction != "RX":
                continue

            age = 0.0
            stamp = (
                info.get("last_iso")
                or info.get("last")
                or ""
            )

            if stamp and "T" in str(stamp):
                try:
                    dt = datetime.datetime.fromisoformat(
                        str(stamp).replace("Z", "+00:00")
                    )
                    age = max(
                        0.0,
                        now_wall - dt.timestamp()
                    )
                except Exception:
                    age = 0.0

            if age > self.digi_route_ttl:
                continue

            route_kind = str(
                info.get(
                    "route_kind",
                    "via" if info.get("via") else "direct"
                )
            ).lower()

            self.digi_routes[call] = {
                "port_id": port_id,
                "last_seen": time.monotonic() - age,
                "direct": route_kind == "direct",
            }
            loaded_routes += 1

        if loaded_routes:
            log(
                f"Loaded {loaded_routes} "
                f"MHeard route(s) from config"
            )

        # AGWPE and native API registrations are kept separately.
        self.agw_registered_calls = set()
        self.api_registered_calls = set()
        self.monitor_enabled = False

        # Native JSON API clients.
        # Each entry: {"sock": socket, "lock": Lock, "monitor": bool, "addr": ...}
        self.api_clients = []
        self.api_clients_lock = threading.RLock()

        self.sessions = {}
        self.sessions_lock = threading.RLock()
        self.running = True

    # ----------------------------------------------------------------------
    # SESSION REGISTRY
    # ----------------------------------------------------------------------

    @staticmethod
    def session_key(port_id, local, remote):
        return (str(port_id or DEFAULT_PORT_ID), normalize_call(local), normalize_call(remote))

    def get_session(self, local, remote, port_id=None):
        key = self.session_key(port_id or DEFAULT_PORT_ID, local, remote)
        with self.sessions_lock:
            return self.sessions.get(key)

    def add_session(self, s):
        key = self.session_key(s.port_id, s.local, s.remote)
        with self.sessions_lock:
            if key in self.sessions:
                return False
            if len(self.sessions) >= MAX_SESSIONS:
                return False
            self.sessions[key] = s
            return True

    def remove_session(self, s):
        key = self.session_key(s.port_id, s.local, s.remote)
        with self.sessions_lock:
            if self.sessions.get(key) is s:
                del self.sessions[key]

    def sessions_snapshot(self):
        with self.sessions_lock:
            return list(self.sessions.values())

    def registered_calls_snapshot(self):
        return sorted(self.agw_registered_calls | self.api_registered_calls)

    def is_registered_call(self, call):
        c = normalize_call(call)
        return (
            c == self.station_callsign
            or c in self.agw_registered_calls
            or c in self.api_registered_calls
        )

    @staticmethod
    def session_to_dict(s):
        with s.lock:
            pcfg = PORTS_BY_ID.get(s.port_id, {})
            return {
                "port_id": s.port_id,
                "port_name": pcfg.get("name", s.port_id),
                "local": s.local,
                "remote": s.remote,
                "via": list(s.digis),
                "pid": s.pid,
                "state": s.state,
                "vs": s.vs,
                "vr": s.vr,
                "outstanding": 1 if s.unacked is not None else 0,
                "remote_busy": bool(s.remote_busy),
                "unacked_retries": s.unacked_retries,
                "control_retries": s.control_retries,
                "queued": len(s.tx_queue),
                "owners": sorted(s.owners),
            }

    # ----------------------------------------------------------------------
    # NATIVE APPLICATION API - EVENT HELPERS
    # ----------------------------------------------------------------------

    @staticmethod
    def bytes_event_fields(data):
        data = data or b""
        return {
            "data": data.decode("utf-8", errors="replace"),
            "data_latin1": data.decode("latin-1", errors="replace"),
            "data_b64": base64.b64encode(data).decode("ascii"),
            "length": len(data),
        }

    def api_send(self, client, obj):
        sock = client.get("sock")
        if sock is None:
            return False

        try:
            raw = (
                json.dumps(
                    obj,
                    ensure_ascii=False,
                    separators=(",", ":")
                ) + "\n"
            ).encode("utf-8")

            with client["lock"]:
                sock.sendall(raw)
            return True
        except OSError:
            return False

    def api_broadcast(self, obj, monitor_only=False):
        dead = []

        with self.api_clients_lock:
            clients = list(self.api_clients)

        for client in clients:
            if monitor_only and not client.get("monitor", True):
                continue
            if not self.api_send(client, obj):
                dead.append(client)

        if dead:
            with self.api_clients_lock:
                for client in dead:
                    if client in self.api_clients:
                        self.api_clients.remove(client)

    def emit_api_event(self, event, **fields):
        obj = {"event": event}
        obj.update(fields)
        self.api_broadcast(obj)

    def emit_session_state(self, s):
        if "api" not in s.owners:
            return
        self.emit_api_event(
            "session_state",
            session=self.session_to_dict(s)
        )

    def emit_monitor_event(self, direction, f, port_id=DEFAULT_PORT_ID, kiss_channel=0):
        pcfg = PORTS_BY_ID.get(port_id, {})
        obj = {
            "event": "monitor",
            "direction": direction,
            "port_id": port_id,
            "port_name": pcfg.get("name", port_id),
            "kiss_channel": kiss_channel,
            "src": f.get("src", ""),
            "dst": f.get("dst", ""),
            "via": list(f.get("digis", [])),
            "via_repeated": [
                x.get("call", "")
                for x in (f.get("digi_info") or [])
                if x.get("repeated")
            ],
            "via_pending": [
                x.get("call", "")
                for x in (f.get("digi_info") or [])
                if not x.get("repeated")
            ],
            "type": f.get("type", ""),
            "pid": f.get("pid"),
            "pf": bool(f.get("pf", False)),
        }

        for key in ("ns", "nr"):
            if f.get(key) is not None:
                obj[key] = f[key]

        if f.get("info") is not None:
            obj.update(self.bytes_event_fields(f["info"]))

        self.api_broadcast(obj, monitor_only=True)

    # ----------------------------------------------------------------------
    # SHARED ENGINE OPERATIONS
    # ----------------------------------------------------------------------

    def engine_connect(
        self,
        local,
        remote,
        digis=None,
        pid=PID_DEFAULT,
        owners=None,
        port_id=None
    ):
        local = normalize_call(local)
        remote = normalize_call(remote)
        digis = [
            normalize_call(x)
            for x in (digis or [])
            if normalize_call(x)
        ]
        owners = set(owners or [])
        port_id = str(port_id or DEFAULT_PORT_ID)
        if port_id not in PORTS_BY_ID:
            return None, f"unknown port_id: {port_id}"

        if not local or not remote:
            return None, "missing local or remote callsign"

        existing = self.get_session(local, remote, port_id=port_id)
        if existing is not None:
            with existing.lock:
                existing.owners.update(owners)
            self.emit_session_state(existing)
            return existing, "already exists"

        s = Session()
        s.port_id = port_id
        s.local = local
        s.remote = remote
        s.pid = int(pid) & 0xFF
        s.digis = list(digis)
        s.owners = owners

        if not self.add_session(s):
            return None, f"session limit reached ({MAX_SESSIONS})"

        with s.lock:
            sabm = ax25_build_u(
                remote,
                local,
                AX25_SABM,
                command=True,
                pf=True,
                digis=s.digis
            )

            s.state = STATE_AWAIT_UA
            s.control_frame = sabm
            s.control_time = time.monotonic()
            s.control_retries = 0

            via = (
                f" via {','.join(s.digis)}"
                if s.digis else ""
            )
            log(f"CONNECT {local}->{remote}{via}: sending SABM")
            self.send_kiss_ax25(sabm, s.port_id)

        self.emit_session_state(s)
        return s, None

    def engine_send(self, local, remote, payload, owner=None, port_id=None):
        s = self.get_session(local, remote, port_id=port_id or DEFAULT_PORT_ID)
        if s is None:
            return False, "session not found"

        with s.lock:
            if owner and owner not in s.owners:
                return False, "session belongs to another frontend"

            if s.state != STATE_CONNECTED:
                return False, f"session is {s.state}"

            for off in range(0, len(payload), MAX_INFO):
                s.tx_queue.append(payload[off:off + MAX_INFO])

            self.try_send_next_i_locked(s)

        self.emit_session_state(s)
        return True, None

    def engine_disconnect(self, local, remote, owner=None, port_id=None):
        p = port_id or DEFAULT_PORT_ID
        s = self.get_session(local, remote, port_id=p)
        if s is None:
            s = self.get_session(remote, local, port_id=p)

        if s is None:
            return False, "session not found"

        with s.lock:
            if owner and owner not in s.owners:
                return False, "session belongs to another frontend"

            disc = ax25_build_u(
                s.remote,
                s.local,
                AX25_DISC,
                command=True,
                pf=True,
                digis=s.digis
            )

            s.state = STATE_AWAIT_DISC_UA
            s.control_frame = disc
            s.control_time = time.monotonic()
            s.control_retries = 0

            log(f"DISCONNECT {s.local}->{s.remote}: sending DISC")
            self.send_kiss_ax25(disc, s.port_id)

        self.emit_session_state(s)
        return True, None

    def engine_beacon(
        self,
        local,
        remote,
        payload,
        digis=None,
        pid=PID_DEFAULT,
        port_id=None
    ):
        local = normalize_call(local)
        remote = normalize_call(remote)
        port_id = str(port_id or DEFAULT_PORT_ID)
        if port_id not in PORTS_BY_ID:
            return False, f"unknown port_id: {port_id}"
        digis = [
            normalize_call(x)
            for x in (digis or [])
            if normalize_call(x)
        ]

        if not local or not remote:
            return False, "missing local or destination callsign"

        frame = ax25_build_ui(
            remote,
            local,
            payload,
            pid=int(pid) & 0xFF,
            digis=digis
        )

        if not self.send_kiss_ax25(frame, port_id):
            return False, "KISS is not connected"

        return True, None

    # ----------------------------------------------------------------------
    # PERIODIC BEACON
    # ----------------------------------------------------------------------

    @staticmethod
    def parse_beacon_via(value):
        if isinstance(value, list):
            raw = value
        else:
            raw = str(value or "").replace(";", ",").split(",")

        return [
            normalize_call(str(x))
            for x in raw
            if normalize_call(str(x))
        ]

    def update_beacon_config(
        self,
        destination=None,
        via=None,
        text=None,
        port_ids=None,
        interval_min=None,
    ):
        with self.beacon_lock:
            if destination is not None:
                self.beacon_dest = normalize_call(
                    str(destination)
                ) or "CQ"

            if via is not None:
                self.beacon_via = (
                    ",".join(str(x) for x in via)
                    if isinstance(via, list)
                    else str(via)
                )

            if text is not None:
                self.beacon_text = str(text)

            if port_ids is not None:
                self.beacon_port_ids = [
                    str(pid)
                    for pid in port_ids
                    if str(pid) in PORTS_BY_ID
                ]

            if interval_min is not None:
                try:
                    self.beacon_interval_min = max(
                        0,
                        int(interval_min)
                    )
                except (TypeError, ValueError):
                    self.beacon_interval_min = 0

            self.beacon_next_due = (
                time.monotonic()
                + self.beacon_interval_min * 60
                if self.beacon_interval_min > 0
                else None
            )

    def periodic_beacon_loop(self):
        while self.running:
            time.sleep(1.0)

            with self.beacon_lock:
                interval = self.beacon_interval_min
                due = self.beacon_next_due

                if (
                    interval <= 0
                    or due is None
                    or time.monotonic() < due
                ):
                    continue

                self.beacon_next_due = (
                    time.monotonic() + interval * 60
                )

                local = self.beacon_callsign
                destination = self.beacon_dest
                via = self.parse_beacon_via(self.beacon_via)
                text = self.beacon_text
                port_ids = list(self.beacon_port_ids)

            if not local or not port_ids:
                log(
                    "Periodic beacon skipped: "
                    "missing callsign or beacon ports"
                )
                continue

            payload = text.encode("utf-8", errors="replace")

            for port_id in port_ids:
                ok, error = self.engine_beacon(
                    local,
                    destination,
                    payload,
                    digis=via,
                    pid=PID_DEFAULT,
                    port_id=port_id,
                )

                pcfg = PORTS_BY_ID.get(port_id, {})

                if ok:
                    log(
                        f"BEACON AUTO [P{port_id}] "
                        f"{local}->{destination} "
                        f"every {interval} min"
                    )
                    self.emit_api_event(
                        "beacon_tx",
                        status="sent",
                        port_id=port_id,
                        port_name=pcfg.get("name", port_id),
                        local=local,
                        to=destination,
                        via=via,
                        data=text,
                        interval_min=interval,
                    )
                else:
                    log(
                        f"BEACON AUTO FAIL [P{port_id}]: {error}"
                    )
                    self.emit_api_event(
                        "beacon_tx",
                        status="failed",
                        port_id=port_id,
                        port_name=pcfg.get("name", port_id),
                        local=local,
                        to=destination,
                        error=error or "unknown error",
                        interval_min=interval,
                    )

    # ----------------------------------------------------------------------
    # HEADLESS STATION SERVICE
    # ----------------------------------------------------------------------

    @staticmethod
    def service_encode(text):
        # Packet terminals conventionally use CR.
        return (
            str(text)
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("\n", "\r")
            .encode("utf-8", errors="replace")
        )

    def queue_service_text_locked(self, s, text):
        payload = self.service_encode(text)
        if not payload:
            return

        # The service itself generates this data, so a GUI attached to the
        # same incoming session needs a local echo. Use a dedicated event so
        # normal operator TX does not get displayed twice.
        if "api" in s.owners:
            fields = self.bytes_event_fields(payload)
            pcfg = PORTS_BY_ID.get(s.port_id, {})
            self.emit_api_event(
                "service_tx_data",
                port_id=s.port_id,
                port_name=pcfg.get("name", s.port_id),
                local=s.local,
                remote=s.remote,
                via=list(s.digis),
                pid=s.pid,
                **fields
            )

        for off in range(0, len(payload), MAX_INFO):
            s.tx_queue.append(
                payload[off:off + MAX_INFO]
            )

        self.try_send_next_i_locked(s)

    def start_disconnect_locked(self, s):
        if s.state != STATE_CONNECTED:
            return

        disc = ax25_build_u(
            s.remote,
            s.local,
            AX25_DISC,
            command=True,
            pf=True,
            digis=s.digis
        )
        s.state = STATE_AWAIT_DISC_UA
        s.control_frame = disc
        s.control_time = time.monotonic()
        s.control_retries = 0
        s.close_after_tx = False

        log(
            f"SERVICE disconnect "
            f"{s.local}<->{s.remote}"
        )
        self.send_kiss_ax25(
            disc,
            s.port_id
        )
        self.emit_session_state(s)

    def service_help_text(self):
        return (
            "Commands:\r"
            "/I or /INFO  - station information\r"
            "/MH          - heard stations\r"
            "/P           - ports\r"
            "/D or /DIGI  - digipeater status\r"
            "/B or /BYE   - disconnect\r"
            "/? or /HELP  - this help\r"
        )

    def service_mheard_text(self):
        now = time.monotonic()

        with self.digi_routes_lock:
            rows = []
            for call, info in self.digi_routes.items():
                age = max(
                    0,
                    int(now - info["last_seen"])
                )
                if age > self.digi_route_ttl:
                    continue

                port_id = str(info["port_id"])
                port_cfg = PORTS_BY_ID.get(
                    port_id,
                    {}
                )
                rows.append(
                    (
                        age,
                        call,
                        port_id,
                        port_cfg.get(
                            "name",
                            port_id
                        )
                    )
                )

        rows.sort(key=lambda row: row[0])

        if not rows:
            return "MHeard: empty\r"

        lines = ["MHeard:"]
        for age, call, port_id, port_name in rows:
            lines.append(
                f"{call:<10} P{port_id} "
                f"{port_name} {age}s"
            )

        return "\r".join(lines) + "\r"

    def service_ports_text(self):
        lines = ["Ports:"]

        for p in PORTS:
            state = (
                "UP"
                if self.kiss_states.get(p["id"])
                else "DOWN"
            )
            lines.append(
                f"P{p['id']} {p['name']} "
                f"{p['host']}:{p['port']} {state}"
            )

        return "\r".join(lines) + "\r"

    def service_digi_text(self):
        return (
            f"DIGI: "
            f"{'ON' if self.digi_enabled else 'OFF'} "
            f"{self.digi_callsign}\r"
        )

    def handle_service_command_locked(
        self,
        s,
        line
    ):
        cmd = (
            line
            .decode(
                "utf-8",
                errors="replace"
            )
            .strip()
        )

        if not cmd.startswith("/"):
            return False

        upper = cmd.upper()

        if upper in ("/I", "/INFO"):
            text = self.station_info.rstrip(
                "\r\n"
            )
            self.queue_service_text_locked(
                s,
                (text + "\r")
                if text
                else "No station information.\r"
            )
            return True

        if upper in ("/B", "/BYE"):
            text = self.bye_text.rstrip(
                "\r\n"
            )
            if text:
                self.queue_service_text_locked(
                    s,
                    text + "\r"
                )

            # Close only after queued BYE data has been acknowledged.
            if (
                s.unacked is None
                and not s.tx_queue
            ):
                self.start_disconnect_locked(s)
            else:
                s.close_after_tx = True
            return True

        if upper in ("/?", "/HELP"):
            self.queue_service_text_locked(
                s,
                self.service_help_text()
            )
            return True

        if upper == "/MH":
            self.queue_service_text_locked(
                s,
                self.service_mheard_text()
            )
            return True

        if upper == "/P":
            self.queue_service_text_locked(
                s,
                self.service_ports_text()
            )
            return True

        if upper in ("/D", "/DIGI"):
            self.queue_service_text_locked(
                s,
                self.service_digi_text()
            )
            return True

        self.queue_service_text_locked(
            s,
            "Unknown command. /? for help.\r"
        )
        return True

    def process_service_payload_locked(
        self,
        s,
        payload
    ):
        s.command_buffer.extend(payload)

        # Accept CR, LF and CRLF. Connected packet clients normally use CR.
        while True:
            cr = s.command_buffer.find(b"\r")
            lf = s.command_buffer.find(b"\n")

            positions = [
                x for x in (cr, lf)
                if x >= 0
            ]
            if not positions:
                break

            pos = min(positions)
            line = bytes(
                s.command_buffer[:pos]
            )

            # consume one or both CR/LF delimiters
            consume = pos + 1
            if (
                consume < len(s.command_buffer)
                and s.command_buffer[consume]
                in (10, 13)
                and s.command_buffer[consume]
                != s.command_buffer[pos]
            ):
                consume += 1

            del s.command_buffer[:consume]

            self.handle_service_command_locked(
                s,
                line
            )

    # ----------------------------------------------------------------------
    # FRONTEND NOTIFICATIONS
    # ----------------------------------------------------------------------

    def notify_connected(self, s, incoming=False):
        # First tell attached frontends that the session exists. Service
        # output is echoed afterwards, so GUI transcript order is:
        # Connected -> Welcome.
        if "agw" in s.owners:
            self.notify_agw_connected(s, incoming=incoming)

        if "api" in s.owners:
            self.emit_api_event(
                "connected",
                incoming=bool(incoming),
                session=self.session_to_dict(s)
            )

        if incoming and "service" in s.owners:
            text = self.welcome_text.rstrip(
                "\r\n"
            )

            # Welcome plus one empty line.
            if text:
                self.queue_service_text_locked(
                    s,
                    text + "\r\r"
                )
            else:
                self.queue_service_text_locked(
                    s,
                    "\r"
                )

    def notify_disconnected(self, s, reason):
        if "agw" in s.owners:
            self.notify_agw_disconnected(s, reason)

        if "api" in s.owners:
            self.emit_api_event(
                "disconnected",
                reason=reason,
                session=self.session_to_dict(s)
            )

    def deliver_rx_data(self, s, payload, pid):
        # Preserve transcript chronology:
        # 1) deliver received user data to frontends,
        # 2) interpret service commands,
        # 3) generated service reply is echoed afterwards.
        if "agw" in s.owners:
            self.send_agw(
                "D",
                payload,
                port=0,
                pid=pid,
                call_from=s.remote,
                call_to=s.local
            )

        if "api" in s.owners:
            fields = self.bytes_event_fields(payload)
            pcfg = PORTS_BY_ID.get(s.port_id, {})
            self.emit_api_event(
                "rx_data",
                port_id=s.port_id,
                port_name=pcfg.get("name", s.port_id),
                local=s.local,
                remote=s.remote,
                via=list(s.digis),
                pid=pid,
                **fields
            )

        if "service" in s.owners:
            self.process_service_payload_locked(
                s,
                payload
            )

    # ----------------------------------------------------------------------
    # AGW SEND
    # ----------------------------------------------------------------------

    def send_agw(self, kind, payload=b"", port=0, pid=0,
                 call_from="", call_to="", user=0):
        sock = self.agw_sock
        if not sock:
            return

        header = agw_build_header(
            kind,
            len(payload),
            port,
            pid,
            call_from,
            call_to,
            user
        )

        try:
            with self.agw_lock:
                sock.sendall(header + payload)

            k = chr(kind) if isinstance(kind, int) else kind
            log(
                f"AGW TX {k} port={port} pid={pid:02X} "
                f"{call_from}->{call_to} len={len(payload)}"
            )
            if payload and VERBOSE_HEX:
                log_hex(payload)

        except OSError as e:
            log(f"AGW TX error: {e}")

    # ----------------------------------------------------------------------
    # KISS SEND
    # ----------------------------------------------------------------------

    def send_kiss_ax25(self, frame, port_id=None):
        port_id = str(port_id or DEFAULT_PORT_ID)
        sock = self.kiss_socks.get(port_id)
        if sock is None:
            log(f"KISS TX [{port_id}] dropped: port not connected")
            return False
        packet = kiss_encode(frame)
        try:
            with self.kiss_locks.setdefault(port_id, threading.Lock()):
                sock.sendall(packet)
            try:
                f = ax25_parse(frame)
                extra = ""
                if f["type"] == "I":
                    extra = f" NS={f['ns']} NR={f['nr']} PID={f['pid']:02X} len={len(f['info'])}"
                elif f["type"] in ("RR", "REJ", "RNR"):
                    extra = f" NR={f['nr']}"
                log(f"KISS TX [{port_id}] AX25 {f['src']}->{f['dst']} {f['type']}{extra}")
                self.emit_monitor_event("tx", f, port_id=port_id, kiss_channel=0)
            except Exception:
                log(f"KISS TX [{port_id}] AX25 {len(frame)} bytes")
            if VERBOSE_HEX:
                log_hex(frame)
            return True
        except OSError as exc:
            log(f"KISS TX [{port_id}] error: {exc}")
            return False

    # ----------------------------------------------------------------------
    # DYNAMIC CROSS-PORT DIGI
    # ----------------------------------------------------------------------

    def learn_digi_route(self, callsign, port_id, direct=True):
        call = normalize_call(callsign)
        port_id = str(port_id)

        if not call or port_id not in PORTS_BY_ID:
            return

        if is_exact_own_call(
            call,
            self.station_callsign,
            self.digi_callsign,
        ):
            return

        now = time.monotonic()

        with self.digi_routes_lock:
            existing = self.digi_routes.get(call)

            # A direct observation is always the best route and immediately
            # replaces an indirect one.
            if direct:
                self.digi_routes[call] = {
                    "port_id": port_id,
                    "last_seen": now,
                    "direct": True,
                }
                return

            # An indirect copy must never overwrite a fresh direct route.
            # This is the important case when stations in one local segment
            # also exchange traffic through our DIGI and we hear both copies.
            if existing and existing.get("direct", False):
                if (
                    now - existing.get("last_seen", 0)
                    <= self.digi_route_ttl
                ):
                    return

            self.digi_routes[call] = {
                "port_id": port_id,
                "last_seen": now,
                "direct": False,
            }

    def lookup_digi_route(self, callsign):
        call = normalize_call(callsign)
        if not call:
            return None

        with self.digi_routes_lock:
            item = self.digi_routes.get(call)
            if item is None:
                return None

            if (
                time.monotonic() - item["last_seen"]
                > self.digi_route_ttl
            ):
                self.digi_routes.pop(call, None)
                return None

            port_id = str(item["port_id"])

        return port_id if port_id in PORTS_BY_ID else None

    def digi_ui_is_duplicate(self, frame):
        now = time.monotonic()
        key = bytes(frame)

        with self.digi_ui_dupes_lock:
            # Opportunistic cleanup.
            expired = [
                k
                for k, ts in self.digi_ui_dupes.items()
                if now - ts > DIGI_UI_DUPE_TTL
            ]
            for k in expired:
                self.digi_ui_dupes.pop(k, None)

            if key in self.digi_ui_dupes:
                return True

            self.digi_ui_dupes[key] = now

            # Hard bound in case of very high UI traffic.
            if len(self.digi_ui_dupes) > DIGI_UI_DUPE_MAX:
                oldest = sorted(
                    self.digi_ui_dupes.items(),
                    key=lambda item: item[1],
                )[
                    : len(self.digi_ui_dupes)
                    - DIGI_UI_DUPE_MAX
                ]
                for k, _ts in oldest:
                    self.digi_ui_dupes.pop(k, None)

        return False

    def digi_repeat_if_needed(self, frame, parsed, ingress_port):
        """
        Multi-port AX.25 digipeater behavior.

        UI frames:
            If our DIGI callsign is the next unused VIA, set our H bit and
            retransmit the UI frame on every currently connected logical
            KISS port, INCLUDING the ingress port. This is intentional:
            a high-site multi-band digi should make a UI/broadcast visible
            both on the band on which it was heard and on its other bands.

        Connected-mode/control frames:
            Keep one end-to-end AX.25 link. Forward only to the single port
            learned for the destination in MHeard/routing state.

        No DM/DISC is synthesized when a routed destination is unknown.
        """
        if not self.digi_enabled or not self.digi_callsign:
            return False

        digi_info = parsed.get("digi_info") or []
        if not digi_info:
            return False

        next_index = None
        next_call = None

        for index, info in enumerate(digi_info):
            if not bool(info.get("repeated", False)):
                next_index = index
                next_call = normalize_call(
                    info.get("call", "")
                )
                break

        if next_index is None:
            return False

        if next_call != self.digi_callsign:
            return False

        src = normalize_call(parsed.get("src", ""))
        dst = normalize_call(parsed.get("dst", ""))
        frame_type = str(parsed.get("type", "")).upper()

        # Build the repeated frame once. Only our repeater H bit changes.
        out = bytearray(frame)
        offset = (2 + next_index) * 7

        if offset + 7 > len(out):
            log("DIGI DROP: malformed repeater address")
            return True

        out[offset + 6] |= 0x80
        repeated_frame = bytes(out)

        # --------------------------------------------------------------
        # UI = broadcast fan-out to every UP interface, including ingress.
        # --------------------------------------------------------------
        if frame_type == "UI":
            if self.digi_ui_is_duplicate(frame):
                log(
                    f"DIGI UI DUPE P{ingress_port}: "
                    f"{src}->{dst} VIA {self.digi_callsign}"
                )
                self.emit_api_event(
                    "digi",
                    action="drop",
                    reason="ui_duplicate",
                    ingress_port=str(ingress_port),
                    src=src,
                    dst=dst,
                    via=list(parsed.get("digis", [])),
                )
                return True

            egress_ports = [
                str(pid)
                for pid in PORTS_BY_ID
                if self.kiss_states.get(str(pid), False)
            ]

            if not egress_ports:
                log(
                    f"DIGI UI DROP P{ingress_port}: "
                    f"{src}->{dst}: no UP ports"
                )
                self.emit_api_event(
                    "digi",
                    action="drop",
                    reason="no_up_ports",
                    ingress_port=str(ingress_port),
                    src=src,
                    dst=dst,
                    via=list(parsed.get("digis", [])),
                )
                return True

            sent_ports = []

            for egress_port in egress_ports:
                if self.send_kiss_ax25(
                    repeated_frame,
                    port_id=egress_port,
                ):
                    sent_ports.append(egress_port)
                    log(
                        f"DIGI UI P{ingress_port}->P{egress_port}: "
                        f"{src}->{dst} VIA {self.digi_callsign}"
                    )
                    self.emit_api_event(
                        "digi",
                        action="repeat",
                        mode="ui_fanout",
                        ingress_port=str(ingress_port),
                        egress_port=str(egress_port),
                        src=src,
                        dst=dst,
                        via=list(parsed.get("digis", [])),
                    )
                else:
                    log(
                        f"DIGI UI TX FAIL "
                        f"P{ingress_port}->P{egress_port}: "
                        f"{src}->{dst}"
                    )
                    self.emit_api_event(
                        "digi",
                        action="drop",
                        reason="tx_failed",
                        mode="ui_fanout",
                        ingress_port=str(ingress_port),
                        egress_port=str(egress_port),
                        src=src,
                        dst=dst,
                        via=list(parsed.get("digis", [])),
                    )

            return True

        # --------------------------------------------------------------
        # Connected mode = one routed egress selected from MHeard.
        # --------------------------------------------------------------
        egress_port = self.lookup_digi_route(dst)

        if egress_port is None:
            log(
                f"DIGI DROP P{ingress_port}: "
                f"{src}->{dst} VIA {self.digi_callsign}: no route"
            )
            self.emit_api_event(
                "digi",
                action="drop",
                reason="no_route",
                mode="connected_routed",
                ingress_port=str(ingress_port),
                src=src,
                dst=dst,
                via=list(parsed.get("digis", [])),
            )
            return True

        if not self.send_kiss_ax25(
            repeated_frame,
            port_id=egress_port,
        ):
            log(
                f"DIGI TX FAIL P{ingress_port}->P{egress_port}: "
                f"{src}->{dst}"
            )
            self.emit_api_event(
                "digi",
                action="drop",
                reason="tx_failed",
                mode="connected_routed",
                ingress_port=str(ingress_port),
                egress_port=str(egress_port),
                src=src,
                dst=dst,
                via=list(parsed.get("digis", [])),
            )
            return True

        log(
            f"DIGI ROUTED P{ingress_port}->P{egress_port}: "
            f"{src}->{dst} VIA {self.digi_callsign}"
        )
        self.emit_api_event(
            "digi",
            action="repeat",
            mode="connected_routed",
            ingress_port=str(ingress_port),
            egress_port=str(egress_port),
            src=src,
            dst=dst,
            via=list(parsed.get("digis", [])),
        )
        return True

    # ----------------------------------------------------------------------
    # AGW REQUESTS
    # ----------------------------------------------------------------------

    def handle_agw(self, h, payload):
        kind = h["kind"]
        k = chr(kind) if 32 <= kind <= 126 else f"0x{kind:02X}"

        log(
            f"AGW RX {k} port={h['port']} pid={h['pid']:02X} "
            f"{h['from']}->{h['to']} len={len(payload)}"
        )

        if payload and VERBOSE_HEX:
            log_hex(payload)

        # Version
        if kind == ord("R"):
            # major/minor jako DWORD LE
            self.send_agw("R", struct.pack("<II", 1, 0))
            return

        # Port info
        if kind == ord("G"):
            # Match the real UZ7HO SoundModem response observed on the wire:
            # DataLen=50, payload:
            # "1;Port1 with SoundCard Ch: A;" + NUL padding.
            text = b"1;Port1 with SoundCard Ch: A;"
            p = text + (bytes([0]) * (50 - len(text)))
            self.send_agw("G", p)
            return

        # Port capabilities
        if kind == ord("g"):
            self.send_agw("g", b"\x00" * 12, port=h["port"])
            return

        # Register callsign
        if kind == ord("X"):
            c = normalize_call(h["from"])
            if c:
                self.agw_registered_calls.add(c)
                log(f"Registered AGW callsign: {c}")
            self.send_agw(
                "X",
                b"\x01",
                port=h["port"],
                call_from=h["from"],
                call_to=h["to"]
            )
            return

        # Unregister
        if kind == ord("x"):
            self.agw_registered_calls.discard(normalize_call(h["from"]))
            return

        # Monitor
        if kind == ord("m"):
            self.monitor_enabled = True
            log("AGW monitor enabled")
            return

        # Number of outstanding frames on port
        if kind == ord("y"):
            count = sum(1 for s in self.sessions_snapshot() if s.unacked is not None)
            self.send_agw("y", struct.pack("<I", count), port=h["port"])
            return

        # Number of outstanding frames on connection
        if kind == ord("Y"):
            s = self.get_session(h["from"], h["to"])
            count = 1 if (s is not None and s.unacked is not None) else 0
            self.send_agw(
                "Y",
                struct.pack("<I", count),
                port=h["port"],
                call_from=h["from"],
                call_to=h["to"]
            )
            return

        # UI / UNPROTO without digipeaters
        if kind == ord("M"):
            self.agw_unproto(h, payload, [])
            return

        # UI / UNPROTO via digipeaters
        if kind == ord("V"):
            try:
                digis, info = agw_parse_v_payload(payload)
            except ValueError as e:
                log(f"Bad AGW V frame: {e}")
                return

            self.agw_unproto(h, info, digis)
            return

        # CONNECTED-MODE CONNECT via digipeaters.
        # EasyTerm/AGWPE lowercase 'v' payload:
        #   byte 0    = number of digipeaters
        #   N * 10    = NUL-padded callsigns
        if kind == ord("v"):
            try:
                digis, extra = agw_parse_v_payload(payload)
            except ValueError as e:
                log(f"Bad AGW v frame: {e}")
                return

            if extra:
                log(
                    f"AGW v contains unexpected trailing "
                    f"{len(extra)} byte(s), ignored"
                )

            self.agw_connect(h, digis=digis)
            return

        # Direct CONNECT
        if kind == ord("C"):
            self.agw_connect(h, digis=[])
            return

        # CONNECTED DATA
        if kind == ord("D"):
            self.agw_data(h, payload)
            return

        # DISCONNECT
        if kind == ord("d"):
            self.agw_disconnect(h)
            return

        log(f"AGW kind {k} not implemented")

    def agw_unproto(self, h, payload, digis):
        """Transmit one AX.25 UI frame from AGWPE M/V request."""
        local = normalize_call(h["from"])
        remote = normalize_call(h["to"])

        if not local or not remote:
            log("UNPROTO ignored: missing source or destination")
            return

        pid = h["pid"] or PID_DEFAULT

        frame = ax25_build_ui(
            remote,
            local,
            payload,
            pid=pid,
            digis=digis
        )

        if digis:
            log(
                f"UNPROTO {local}->{remote} "
                f"via {','.join(digis)} len={len(payload)}"
            )
        else:
            log(
                f"UNPROTO {local}->{remote} len={len(payload)}"
            )

        if not self.send_kiss_ax25(frame, DEFAULT_PORT_ID):
            return

        # UZ7HO SoundModem echoes a successfully transmitted UI frame
        # back to EasyTerm as AGWPE kind 'T'. This is important for
        # EasyTerm's monitor/TX display and mimics the real modem.
        tx_monitor = agw_tx_monitor_payload(
            local,
            remote,
            payload,
            pid=pid,
            digis=digis
        )

        self.send_agw(
            "T",
            tx_monitor,
            port=h["port"],
            pid=0,
            call_from=local,
            call_to=remote,
            user=0
        )

    def agw_connect(self, h, digis=None):
        s, error = self.engine_connect(
            h["from"],
            h["to"],
            digis=digis,
            pid=h["pid"] or PID_DEFAULT,
            owners={"agw"},
            port_id=DEFAULT_PORT_ID
        )

        if s is None:
            log(
                f"CONNECT {normalize_call(h['from'])}->"
                f"{normalize_call(h['to'])} refused: {error}"
            )
            self.send_agw(
                "d",
                f"*** DISCONNECTED {error}\r".encode(
                    "ascii",
                    errors="replace"
                ),
                port=h["port"],
                pid=h["pid"] or PID_DEFAULT,
                call_from=h["to"],
                call_to=h["from"]
            )

    def agw_data(self, h, payload):
        ok, error = self.engine_send(
            h["from"],
            h["to"],
            payload,
            owner="agw",
            port_id=DEFAULT_PORT_ID
        )
        if not ok:
            log(
                f"AGW D ignored {normalize_call(h['from'])}->"
                f"{normalize_call(h['to'])}: {error}"
            )

    def agw_disconnect(self, h):
        ok, error = self.engine_disconnect(
            h["from"],
            h["to"],
            owner="agw",
            port_id=DEFAULT_PORT_ID
        )
        if not ok:
            log(
                f"DISCONNECT ignored "
                f"{normalize_call(h['from'])}<->{normalize_call(h['to'])}: "
                f"{error}"
            )

    # ----------------------------------------------------------------------
    # AX25 TX LOGIC
    # ----------------------------------------------------------------------

    def try_send_next_i_locked(self, s):
        if s.state != STATE_CONNECTED:
            return

        if s.unacked is not None:
            return

        if s.remote_busy:
            return

        if not s.tx_queue:
            return

        payload = s.tx_queue.popleft()
        ns = s.vs

        frame = ax25_build_i(
            s.remote,
            s.local,
            ns,
            s.vr,
            payload,
            s.pid,
            pf=False,
            digis=s.digis
        )

        s.unacked = frame
        s.unacked_ns = ns
        s.unacked_time = time.monotonic()
        s.unacked_retries = 0
        s.vs = (s.vs + 1) & 7

        via = (
            f" via {','.join(s.digis)}"
            if s.digis else ""
        )
        log(
            f"[{s.local}<->{s.remote}{via}] "
            f"Sending I frame NS={ns} NR={s.vr}"
        )
        self.send_kiss_ax25(frame, s.port_id)

    def acknowledge_locked(self, s, nr):
        """ACK stop-and-wait for one selected AX.25 session."""
        if s.unacked is None:
            return False

        expected = (s.unacked_ns + 1) & 7

        if nr != expected:
            return False

        log(
            f"[{s.local}<->{s.remote}] "
            f"ACK received NR={nr}, NS={s.unacked_ns} acknowledged"
        )
        s.unacked = None
        s.unacked_ns = None
        s.unacked_retries = 0
        s.remote_busy = False
        self.try_send_next_i_locked(s)

        if (
            s.close_after_tx
            and s.unacked is None
            and not s.tx_queue
        ):
            self.start_disconnect_locked(s)

        self.emit_session_state(s)
        return True

    # ----------------------------------------------------------------------
    # KISS RX
    # ----------------------------------------------------------------------

    def handle_kiss_payload(self, raw, port_id=DEFAULT_PORT_ID):
        if not raw:
            return

        command = raw[0]
        port = (command >> 4) & 0x0F
        cmd = command & 0x0F

        if cmd != 0:
            log(f"KISS RX command={cmd}, ignored")
            return

        frame = raw[1:]

        try:
            f = ax25_parse(frame)
        except Exception as e:
            log(f"AX25 parse error: {e}")
            if VERBOSE_HEX:
                log_hex(frame)
            return

        extra = ""
        if f["type"] == "I":
            extra = f" NS={f['ns']} NR={f['nr']} PID={f['pid']} len={len(f['info'])}"
        elif f["type"] in ("RR", "REJ", "RNR"):
            extra = f" NR={f['nr']}"

        log(
            f"KISS RX p={port} AX25 "
            f"{f['src']}->{f['dst']} {f['type']}{extra}"
        )

        if VERBOSE_HEX:
            log_hex(frame)

        # Native API monitor receives all parsed AX.25 frames.
        self.emit_monitor_event("rx", f, port_id=port_id, kiss_channel=port)

        # RX source -> logical port routing knowledge. Our own source is
        # ignored completely so proxy echoes cannot poison the table.
        rx_src = normalize_call(f.get("src", ""))
        repeated_path = [
            x.get("call", "")
            for x in (f.get("digi_info") or [])
            if x.get("repeated")
        ]
        rx_is_direct = not bool(repeated_path)

        if (
            rx_src
            and not is_exact_own_call(
                rx_src,
                self.station_callsign,
                self.digi_callsign,
            )
        ):
            self.learn_digi_route(
                rx_src,
                port_id,
                direct=rx_is_direct,
            )

        # Cross-port digipeating happens before/alongside local AX.25
        # connected-mode handling.
        self.digi_repeat_if_needed(frame, f, port_id)

        # AGW monitor mode. UI frames are delivered as kind U.
        if self.monitor_enabled and f["type"] == "UI":
            monitor_payload = agw_monitor_ui_payload(f)

            self.send_agw(
                "U",
                monitor_payload,
                port=port,
                pid=f["pid"] if f["pid"] is not None else PID_DEFAULT,
                call_from=f["src"],
                call_to=f["dst"]
            )

        self.handle_ax25(f, port_id)

    def find_session_for_frame(self, f, port_id):
        return self.get_session(f["dst"], f["src"], port_id=port_id)

    def handle_ax25(self, f, port_id):
        # Incoming connection to any callsign registered by EasyTerm.
        if f["type"] == "SABM":
            dst = normalize_call(f["dst"])
            src = normalize_call(f["src"])

            if not self.is_registered_call(dst):
                log(f"SABM for unregistered callsign {dst}, ignoring")
                return

            incoming_owners = set()

            if dst == self.station_callsign:
                incoming_owners.add("service")

            if dst in self.agw_registered_calls:
                incoming_owners.add("agw")

            if dst in self.api_registered_calls:
                incoming_owners.add("api")

            s = self.get_session(dst, src, port_id=port_id)

            if s is None:
                s = Session()
                s.port_id = port_id
                s.local = dst
                s.remote = src
                s.pid = PID_DEFAULT
                s.owners = set(incoming_owners)

                # AX.25 return route is the received digi path reversed.
                # H/repeated bits from the received frame are not copied;
                # all H bits are clear when transmitting a new frame.
                s.digis = list(reversed(f.get("digis", [])))

                if not self.add_session(s):
                    log(
                        f"Incoming SABM {src}->{dst} refused: "
                        f"MAX_SESSIONS={MAX_SESSIONS}"
                    )
                    dm = ax25_build_u(
                        src, dst, AX25_DM,
                        command=False, pf=f["pf"],
                        digis=list(reversed(f.get("digis", [])))
                    )
                    self.send_kiss_ax25(dm, port_id)
                    return

            with s.lock:
                s.owners.update(incoming_owners)

                # SABM is also a link reset. Refresh the return route from
                # the received path and reinitialize this one link only.
                s.digis = list(reversed(f.get("digis", [])))
                s.state = STATE_CONNECTED
                s.vs = 0
                s.vr = 0
                s.unacked = None
                s.unacked_ns = None
                s.unacked_retries = 0
                s.tx_queue.clear()
                s.remote_busy = False
                s.control_frame = None
                s.control_retries = 0

                ua = ax25_build_u(
                    src,
                    dst,
                    AX25_UA,
                    command=False,
                    pf=f["pf"],
                    digis=s.digis
                )
                self.send_kiss_ax25(ua, port_id)

                log(
                    f"Incoming AX.25 connection {src}->{dst} "
                    f"(sessions={len(self.sessions_snapshot())})"
                )
                self.notify_connected(s, incoming=True)
            return

        s = self.find_session_for_frame(f, port_id)
        if s is None:
            return

        with s.lock:
            # UA during outgoing connect
            if f["type"] == "UA" and s.state == STATE_AWAIT_UA:
                log(
                    f"[{s.local}<->{s.remote}] "
                    "UA received: AX.25 connection established"
                )
                s.state = STATE_CONNECTED
                s.control_frame = None
                s.control_retries = 0
                s.vs = 0
                s.vr = 0
                self.notify_connected(s, incoming=False)
                self.try_send_next_i_locked(s)
                return

            # UA during disconnect
            if f["type"] == "UA" and s.state == STATE_AWAIT_DISC_UA:
                log(f"[{s.local}<->{s.remote}] UA received for DISC")
                self.notify_disconnected(s, "Disconnected")
                self.remove_session(s)
                return

            if f["type"] == "DM":
                log(f"[{s.local}<->{s.remote}] DM received")
                self.notify_disconnected(s, "DM received")
                self.remove_session(s)
                return

            if f["type"] == "DISC":
                log(f"[{s.local}<->{s.remote}] DISC received from remote")
                ua = ax25_build_u(
                    s.remote,
                    s.local,
                    AX25_UA,
                    command=False,
                    pf=f["pf"],
                    digis=s.digis
                )
                self.send_kiss_ax25(ua, port_id)
                self.notify_disconnected(s, "Remote disconnected")
                self.remove_session(s)
                return

            if s.state != STATE_CONNECTED:
                return

            if f["type"] == "I":
                # N(R) piggyback ACK.
                self.acknowledge_locked(s, f["nr"])

                if f["ns"] == s.vr:
                    log(
                        f"[{s.local}<->{s.remote}] "
                        f"In-sequence I frame NS={f['ns']} accepted"
                    )
                    s.vr = (s.vr + 1) & 7

                    self.deliver_rx_data(
                        s,
                        f["info"],
                        f["pid"] if f["pid"] is not None else s.pid
                    )

                    rr = ax25_build_s(
                        s.remote,
                        s.local,
                        "RR",
                        s.vr,
                        command=False,
                        pf=f["pf"],
                        digis=s.digis
                    )
                    self.send_kiss_ax25(rr, port_id)

                elif f["ns"] == ((s.vr - 1) & 7):
                    log(
                        f"[{s.local}<->{s.remote}] "
                        f"Duplicate I NS={f['ns']}, RR NR={s.vr}"
                    )
                    rr = ax25_build_s(
                        s.remote,
                        s.local,
                        "RR",
                        s.vr,
                        command=False,
                        pf=f["pf"],
                        digis=s.digis
                    )
                    self.send_kiss_ax25(rr, port_id)

                else:
                    log(
                        f"[{s.local}<->{s.remote}] "
                        f"Out-of-sequence I NS={f['ns']}, "
                        f"expected={s.vr}: REJ"
                    )
                    rej = ax25_build_s(
                        s.remote,
                        s.local,
                        "REJ",
                        s.vr,
                        command=False,
                        pf=f["pf"],
                        digis=s.digis
                    )
                    self.send_kiss_ax25(rej, port_id)
                return

            if f["type"] == "RR":
                s.remote_busy = False
                self.acknowledge_locked(s, f["nr"])

                if f["pf"]:
                    rr = ax25_build_s(
                        s.remote,
                        s.local,
                        "RR",
                        s.vr,
                        command=False,
                        pf=True,
                        digis=s.digis
                    )
                    self.send_kiss_ax25(rr, port_id)

                self.try_send_next_i_locked(s)
                return

            if f["type"] == "REJ":
                log(f"[{s.local}<->{s.remote}] REJ received NR={f['nr']}")

                if self.acknowledge_locked(s, f["nr"]):
                    return

                if s.unacked is not None:
                    if s.unacked_retries >= N2:
                        self.notify_disconnected(s, "REJ retry limit")
                        self.remove_session(s)
                        return

                    s.unacked_time = time.monotonic()
                    s.unacked_retries += 1
                    log(
                        f"[{s.local}<->{s.remote}] "
                        f"Retransmit after REJ {s.unacked_retries}/{N2}"
                    )
                    self.send_kiss_ax25(s.unacked, s.port_id)
                return

            if f["type"] == "RNR":
                s.remote_busy = True
                log(
                    f"[{s.local}<->{s.remote}] "
                    f"RNR received NR={f['nr']}, remote busy"
                )
                self.acknowledge_locked(s, f["nr"])

                if f["pf"]:
                    rr = ax25_build_s(
                        s.remote,
                        s.local,
                        "RR",
                        s.vr,
                        command=False,
                        pf=True,
                        digis=s.digis
                    )
                    self.send_kiss_ax25(rr, port_id)
                return

    # ----------------------------------------------------------------------
    # AGW EVENTS
    # ----------------------------------------------------------------------

    def notify_agw_connected(self, s, incoming=False):
        text = (
            f"*** CONNECTED {'From' if incoming else 'To'} Station "
            f"{s.remote}\r"
        ).encode("ascii", errors="replace")

        self.send_agw(
            "C",
            text,
            port=0,
            pid=s.pid,
            call_from=s.remote,
            call_to=s.local
        )

    def notify_agw_disconnected(self, s, reason):
        if not s.local:
            return

        text = f"*** DISCONNECTED {reason}\r".encode(
            "ascii",
            errors="replace"
        )

        self.send_agw(
            "d",
            text,
            port=0,
            pid=s.pid,
            call_from=s.remote,
            call_to=s.local
        )

    # ----------------------------------------------------------------------
    # TIMERS
    # ----------------------------------------------------------------------

    def timer_loop(self):
        while self.running:
            time.sleep(0.2)
            now = time.monotonic()

            for s in self.sessions_snapshot():
                remove = False

                with s.lock:
                    # SABM / DISC retransmission
                    if (
                        s.control_frame is not None and
                        s.state in (STATE_AWAIT_UA, STATE_AWAIT_DISC_UA) and
                        now - s.control_time >= T1
                    ):
                        if s.control_retries >= N2:
                            log(
                                f"[{s.local}<->{s.remote}] "
                                f"Control retry limit N2={N2}"
                            )
                            self.notify_disconnected(
                                s,
                                "Connection timeout"
                                if s.state == STATE_AWAIT_UA
                                else "Disconnect timeout"
                            )
                            remove = True
                        else:
                            s.control_retries += 1
                            s.control_time = now
                            log(
                                f"[{s.local}<->{s.remote}] "
                                f"Control retry {s.control_retries}/{N2}"
                            )
                            self.send_kiss_ax25(s.control_frame, s.port_id)

                    # I-frame retransmission
                    if (
                        not remove and
                        s.state == STATE_CONNECTED and
                        s.unacked is not None and
                        not s.remote_busy and
                        now - s.unacked_time >= T1
                    ):
                        if s.unacked_retries >= N2:
                            log(
                                f"[{s.local}<->{s.remote}] "
                                f"I-frame retry limit N2={N2}"
                            )
                            self.notify_disconnected(
                                s,
                                "I-frame ACK timeout"
                            )
                            remove = True
                        else:
                            s.unacked_retries += 1
                            s.unacked_time = now
                            log(
                                f"[{s.local}<->{s.remote}] "
                                f"I-frame retransmission "
                                f"{s.unacked_retries}/{N2}"
                            )
                            self.send_kiss_ax25(s.unacked, s.port_id)

                if remove:
                    self.remove_session(s)

    # ----------------------------------------------------------------------
    # KISS CONNECTION
    # ----------------------------------------------------------------------

    def kiss_loop(self, port_cfg):
        port_id = port_cfg["id"]
        host = port_cfg["host"]
        tcp_port = port_cfg["port"]

        failed_attempts = 0

        while self.running:
            decoder = KissStreamDecoder()
            sock = None

            # Initial attempt is reported as connecting; subsequent ones
            # are reconnect attempts 1..10.
            state = (
                "connecting"
                if failed_attempts == 0
                else "retrying"
            )
            self.kiss_port_status[port_id] = state
            self.emit_api_event(
                "kiss_state",
                port_id=port_id,
                port_name=port_cfg["name"],
                connected=False,
                state=state,
                attempt=failed_attempts,
                max_attempts=KISS_MAX_RECONNECT_ATTEMPTS,
                host=host,
                port=tcp_port,
            )

            try:
                if failed_attempts:
                    log(
                        f"KISS [{port_id}] reconnect "
                        f"{failed_attempts}/"
                        f"{KISS_MAX_RECONNECT_ATTEMPTS} "
                        f"to {host}:{tcp_port} ..."
                    )
                else:
                    log(
                        f"Connecting KISS "
                        f"[{port_id}/{port_cfg['name']}] "
                        f"to {host}:{tcp_port} ..."
                    )

                sock = socket.create_connection(
                    (host, tcp_port),
                    timeout=5
                )
                sock.settimeout(None)

                self.kiss_socks[port_id] = sock
                self.kiss_states[port_id] = True
                self.kiss_port_status[port_id] = "connected"

                # A successful connection resets the retry budget.
                failed_attempts = 0

                log(f"KISS [{port_id}] connected")
                self.emit_api_event(
                    "kiss_state",
                    port_id=port_id,
                    port_name=port_cfg["name"],
                    connected=True,
                    state="connected",
                    attempt=0,
                    max_attempts=KISS_MAX_RECONNECT_ATTEMPTS,
                    host=host,
                    port=tcp_port,
                )

                while self.running:
                    data = sock.recv(4096)
                    if not data:
                        raise ConnectionError(
                            "KISS peer closed connection"
                        )

                    for raw in decoder.feed(data):
                        self.handle_kiss_payload(
                            raw,
                            port_id=port_id
                        )

            except Exception as exc:
                if not self.running:
                    break

                failed_attempts += 1
                log(
                    f"KISS [{port_id}] connection error "
                    f"({failed_attempts}/"
                    f"{KISS_MAX_RECONNECT_ATTEMPTS}): {exc}"
                )

            finally:
                try:
                    if sock is not None:
                        sock.close()
                except OSError:
                    pass

                if self.kiss_socks.get(port_id) is sock:
                    self.kiss_socks.pop(port_id, None)

                self.kiss_states[port_id] = False

            if not self.running:
                break

            if failed_attempts >= KISS_MAX_RECONNECT_ATTEMPTS:
                self.kiss_port_status[port_id] = "aborted"
                log(
                    f"KISS [{port_id}] ABORT after "
                    f"{KISS_MAX_RECONNECT_ATTEMPTS} failed attempts"
                )
                self.emit_api_event(
                    "kiss_state",
                    port_id=port_id,
                    port_name=port_cfg["name"],
                    connected=False,
                    state="aborted",
                    attempt=failed_attempts,
                    max_attempts=KISS_MAX_RECONNECT_ATTEMPTS,
                    host=host,
                    port=tcp_port,
                )
                break

            self.kiss_port_status[port_id] = "retrying"
            self.emit_api_event(
                "kiss_state",
                port_id=port_id,
                port_name=port_cfg["name"],
                connected=False,
                state="retrying",
                attempt=failed_attempts,
                max_attempts=KISS_MAX_RECONNECT_ATTEMPTS,
                host=host,
                port=tcp_port,
            )
            time.sleep(KISS_RECONNECT_DELAY)

    # ----------------------------------------------------------------------
    # AGW SERVER
    # ----------------------------------------------------------------------

    def recv_exact(self, sock, n):
        out = bytearray()

        while len(out) < n:
            chunk = sock.recv(n - len(out))
            if not chunk:
                raise ConnectionError("AGW client disconnected")
            out.extend(chunk)

        return bytes(out)

    def agw_client_loop(self, sock, addr):
        if self.agw_sock is not None:
            log("Another AGW client attempted connection - rejecting")
            sock.close()
            return

        self.agw_sock = sock
        log(f"AGW client connected from {addr[0]}:{addr[1]}")

        try:
            while self.running:
                raw_h = self.recv_exact(sock, AGW_HEADER_SIZE)
                h = agw_parse_header(raw_h)

                if h["len"] > AGW_MAX_DATA:
                    raise ValueError(
                        f"AGW insane payload length: {h['len']}"
                    )

                payload = (
                    self.recv_exact(sock, h["len"])
                    if h["len"]
                    else b""
                )

                log_raw_agw_rx(raw_h, payload)
                self.handle_agw(h, payload)

        except Exception as e:
            log(f"AGW client ended: {e}")

        finally:
            try:
                sock.close()
            except OSError:
                pass

            self.agw_sock = None
            self.agw_registered_calls.clear()
            self.monitor_enabled = False

            # AGW disconnect may not destroy sessions owned by the native API.
            closed = 0
            retained = 0

            for s in self.sessions_snapshot():
                remove = False

                with s.lock:
                    if "agw" not in s.owners:
                        continue

                    s.owners.discard("agw")

                    if s.owners:
                        retained += 1
                        self.emit_session_state(s)
                        continue

                    if s.state in (
                        STATE_CONNECTED,
                        STATE_AWAIT_UA,
                        STATE_AWAIT_DISC_UA
                    ):
                        disc = ax25_build_u(
                            s.remote,
                            s.local,
                            AX25_DISC,
                            command=True,
                            pf=True,
                            digis=s.digis
                        )
                        self.send_kiss_ax25(disc, s.port_id)

                    remove = True

                if remove:
                    self.remove_session(s)
                    closed += 1

            log(
                f"AGW client disconnected: "
                f"closed {closed} AGW-only session(s), "
                f"retained {retained} shared/API session(s)"
            )

    def agw_server_loop(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((AGW_LISTEN_HOST, AGW_LISTEN_PORT))
        srv.listen(5)

        log(
            f"AGWPE listening on "
            f"{AGW_LISTEN_HOST}:{AGW_LISTEN_PORT}"
        )

        while self.running:
            client, addr = srv.accept()

            threading.Thread(
                target=self.agw_client_loop,
                args=(client, addr),
                daemon=True
            ).start()

    # ----------------------------------------------------------------------
    # NATIVE JSON LINES API SERVER
    # ----------------------------------------------------------------------

    @staticmethod
    def api_decode_payload(msg):
        if "data_b64" in msg:
            try:
                return base64.b64decode(
                    msg["data_b64"],
                    validate=True
                )
            except Exception as e:
                raise ValueError(f"invalid data_b64: {e}")

        data = msg.get("data", "")
        if not isinstance(data, str):
            raise ValueError("data must be a string")

        encoding = msg.get("encoding", "utf-8")
        try:
            return data.encode(encoding)
        except LookupError:
            raise ValueError(f"unknown encoding: {encoding}")
        except UnicodeEncodeError as e:
            raise ValueError(f"cannot encode data as {encoding}: {e}")

    def api_reply(self, client, request, ok=True, **fields):
        obj = {
            "event": "reply",
            "ok": bool(ok),
            "cmd": request.get("cmd"),
        }

        if "id" in request:
            obj["id"] = request["id"]

        obj.update(fields)
        self.api_send(client, obj)

    def shutdown_from_api(self):
        """
        Terminate the backend process on explicit local API request.

        PyInstaller --onefile may involve a bootloader/child process pair,
        so relying only on GUI-side terminate() can leave the real backend
        running. Exit from inside the backend itself instead.
        """
        self.running = False

        # Close all active KISS sockets first.
        for sock in list(self.kiss_socks.values()):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

        # Give the API reply a brief moment to leave the socket, then exit
        # the actual backend process unconditionally.
        time.sleep(0.15)
        os._exit(0)

    def handle_api_command(self, client, msg):
        cmd = str(msg.get("cmd", "")).strip().lower()

        if not cmd:
            self.api_reply(
                client,
                msg,
                ok=False,
                error="missing cmd"
            )
            return

        if cmd == "shutdown":
            self.api_reply(
                client,
                msg,
                ok=True,
                shutting_down=True,
            )
            threading.Thread(
                target=self.shutdown_from_api,
                daemon=True,
            ).start()
            return

        if cmd in ("hello", "ping"):
            self.api_reply(
                client,
                msg,
                ok=True,
                api_version=1,
                engine="AX.25/KISS engine v2.9.1",
                kiss_connected=any(self.kiss_states.values()),
                ports=[dict(p, connected=bool(self.kiss_states.get(p["id"])), state=self.kiss_port_status.get(p["id"], "disconnected")) for p in PORTS],
                agw_connected=self.agw_sock is not None,
                digi_enabled=self.digi_enabled,
                station_callsign=self.station_callsign,
                digi_callsign=self.digi_callsign
            )
            return

        if cmd == "register":
            calls = msg.get("callsigns")
            if calls is None:
                calls = [msg.get("callsign", "")]

            if not isinstance(calls, list):
                calls = [calls]

            added = []
            newly_attached = []

            for call in calls:
                c = normalize_call(str(call))
                if not c:
                    continue

                self.api_registered_calls.add(c)
                added.append(c)

                # GUI may start after a station connection was already
                # established by the headless service. Attach it to those
                # sessions so it immediately sees the existing connection
                # and all subsequent service replies.
                for s in self.sessions_snapshot():
                    if (
                        normalize_call(s.local) != c
                        or s.state == STATE_DISCONNECTED
                    ):
                        continue

                    with s.lock:
                        was_api = "api" in s.owners
                        s.owners.add("api")

                    if not was_api:
                        newly_attached.append(s)

            self.api_reply(
                client,
                msg,
                ok=True,
                registered=sorted(self.api_registered_calls),
                added=added
            )

            for s in newly_attached:
                self.emit_api_event(
                    "connected",
                    incoming=True,
                    resumed=True,
                    session=self.session_to_dict(s)
                )
            return

        if cmd == "unregister":
            calls = msg.get("callsigns")
            if calls is None:
                calls = [msg.get("callsign", "")]

            if not isinstance(calls, list):
                calls = [calls]

            removed = []
            for call in calls:
                c = normalize_call(str(call))
                if c in self.api_registered_calls:
                    self.api_registered_calls.discard(c)
                    removed.append(c)

            self.api_reply(
                client,
                msg,
                ok=True,
                registered=sorted(self.api_registered_calls),
                removed=removed
            )
            return

        if cmd == "status":
            self.api_reply(
                client,
                msg,
                ok=True,
                status={
                    "kiss_connected": any(self.kiss_states.values()),
                    "ports": [dict(p, connected=bool(self.kiss_states.get(p["id"])), state=self.kiss_port_status.get(p["id"], "disconnected")) for p in PORTS],
                    "agw_connected": self.agw_sock is not None,
                    "agw_listen": f"{AGW_LISTEN_HOST}:{AGW_LISTEN_PORT}",
                    "api_listen": f"{API_LISTEN_HOST}:{API_LISTEN_PORT}",
                    "registered": self.registered_calls_snapshot(),
                    "api_registered": sorted(
                        self.api_registered_calls
                    ),
                    "agw_registered": sorted(
                        self.agw_registered_calls
                    ),
                    "session_count": len(self.sessions_snapshot()),
                    "max_sessions": MAX_SESSIONS,
                    "digi_enabled": self.digi_enabled,
                    "station_callsign": self.station_callsign,
                    "digi_callsign": self.digi_callsign,
                    "digi_route_ttl": self.digi_route_ttl,
                    "station_service": True,
                    "t1": T1,
                    "n2": N2,
                    "max_info": MAX_INFO,
                    "window": WINDOW,
                }
            )
            return

        if cmd == "sessions":
            self.api_reply(
                client,
                msg,
                ok=True,
                sessions=[
                    self.session_to_dict(s)
                    for s in self.sessions_snapshot()
                ]
            )
            return

        if cmd == "monitor_on":
            client["monitor"] = True
            self.api_reply(client, msg, ok=True, monitor=True)
            return

        if cmd == "monitor_off":
            client["monitor"] = False
            self.api_reply(client, msg, ok=True, monitor=False)
            return

        if cmd == "station_config":
            station_callsign = normalize_call(
                str(
                    msg.get(
                        "station_callsign",
                        self.station_callsign
                    )
                )
            )
            digi_callsign = normalize_call(
                str(
                    msg.get(
                        "digi_callsign",
                        self.digi_callsign
                    )
                )
            )

            if station_callsign:
                self.station_callsign = station_callsign
            if digi_callsign:
                self.digi_callsign = digi_callsign
            elif self.station_callsign:
                self.digi_callsign = self.station_callsign

            self.station_info = str(
                msg.get(
                    "station_info",
                    self.station_info
                )
            )
            self.welcome_text = str(
                msg.get(
                    "welcome_text",
                    self.welcome_text
                )
            )
            self.bye_text = str(
                msg.get(
                    "bye_text",
                    self.bye_text
                )
            )

            self.update_beacon_config(
                destination=msg.get(
                    "beacon_dest",
                    self.beacon_dest
                ),
                via=msg.get(
                    "beacon_via",
                    self.beacon_via
                ),
                text=msg.get(
                    "beacon_text",
                    self.beacon_text
                ),
                port_ids=msg.get(
                    "beacon_port_ids",
                    self.beacon_port_ids
                ),
                interval_min=msg.get(
                    "beacon_interval_min",
                    self.beacon_interval_min
                ),
            )

            self.api_reply(
                client,
                msg,
                ok=True,
                station_callsign=self.station_callsign,
                digi_callsign=self.digi_callsign,
            )
            return

        if cmd == "digi_set":
            self.digi_enabled = bool(
                msg.get("enabled", False)
            )

            station_callsign = normalize_call(
                str(
                    msg.get(
                        "station_callsign",
                        self.station_callsign
                    )
                )
            )
            digi_callsign = normalize_call(
                str(
                    msg.get(
                        "digi_callsign",
                        msg.get(
                            "callsign",
                            self.digi_callsign
                        )
                    )
                )
            )

            if station_callsign:
                self.station_callsign = station_callsign

            if digi_callsign:
                self.digi_callsign = digi_callsign
            elif self.station_callsign:
                self.digi_callsign = self.station_callsign

            self.emit_api_event(
                "digi_state",
                enabled=self.digi_enabled,
                station_callsign=self.station_callsign,
                digi_callsign=self.digi_callsign,
            )

            self.api_reply(
                client,
                msg,
                ok=True,
                enabled=self.digi_enabled,
                station_callsign=self.station_callsign,
                digi_callsign=self.digi_callsign,
            )
            return

        if cmd == "connect":
            port_id = str(msg.get("port_id", DEFAULT_PORT_ID))
            local = msg.get("local", "")
            remote = msg.get("remote", "")
            via = msg.get("via", []) or []
            pid = int(msg.get("pid", PID_DEFAULT))

            if not isinstance(via, list):
                raise ValueError("via must be a list")

            # Register the local callsign automatically for incoming traffic
            # while the backend is alive.
            local_norm = normalize_call(str(local))
            if local_norm:
                self.api_registered_calls.add(local_norm)

            s, error = self.engine_connect(
                local,
                remote,
                digis=via,
                pid=pid,
                owners={"api"},
                port_id=port_id
            )

            if s is None:
                self.api_reply(
                    client,
                    msg,
                    ok=False,
                    error=error
                )
            else:
                self.api_reply(
                    client,
                    msg,
                    ok=True,
                    existing=(error == "already exists"),
                    session=self.session_to_dict(s)
                )
            return

        if cmd == "send":
            port_id = str(msg.get("port_id", DEFAULT_PORT_ID))
            payload = self.api_decode_payload(msg)
            ok, error = self.engine_send(
                msg.get("local", ""),
                msg.get("remote", ""),
                payload,
                owner="api",
                port_id=port_id
            )

            if not ok:
                self.api_reply(
                    client,
                    msg,
                    ok=False,
                    error=error
                )
                return

            s = self.get_session(
                msg.get("local", ""),
                msg.get("remote", ""),
                port_id=port_id
            )

            fields = self.bytes_event_fields(payload)
            tx_port_id = s.port_id if s else port_id
            tx_pcfg = PORTS_BY_ID.get(tx_port_id, {})
            self.emit_api_event(
                "tx_data",
                port_id=tx_port_id,
                port_name=tx_pcfg.get("name", tx_port_id),
                local=s.local if s else normalize_call(
                    msg.get("local", "")
                ),
                remote=s.remote if s else normalize_call(
                    msg.get("remote", "")
                ),
                via=list(s.digis) if s else [],
                pid=s.pid if s else PID_DEFAULT,
                **fields
            )

            self.api_reply(client, msg, ok=True)
            return

        if cmd == "disconnect":
            port_id = str(msg.get("port_id", DEFAULT_PORT_ID))
            ok, error = self.engine_disconnect(
                msg.get("local", ""),
                msg.get("remote", ""),
                owner="api",
                port_id=port_id
            )

            self.api_reply(
                client,
                msg,
                ok=ok,
                **({} if ok else {"error": error})
            )
            return

        if cmd == "beacon":
            port_id = str(msg.get("port_id", DEFAULT_PORT_ID))
            payload = self.api_decode_payload(msg)
            via = msg.get("via", []) or []

            if not isinstance(via, list):
                raise ValueError("via must be a list")

            ok, error = self.engine_beacon(
                msg.get("local", ""),
                msg.get("to", msg.get("remote", "CQ")),
                payload,
                digis=via,
                pid=int(msg.get("pid", PID_DEFAULT)),
                port_id=port_id
            )

            self.api_reply(
                client,
                msg,
                ok=ok,
                **({} if ok else {"error": error})
            )
            return

        self.api_reply(
            client,
            msg,
            ok=False,
            error=f"unknown command: {cmd}"
        )

    def api_client_loop(self, sock, addr):
        client = {
            "sock": sock,
            "lock": threading.Lock(),
            "monitor": True,
            "addr": addr,
        }

        with self.api_clients_lock:
            self.api_clients.append(client)

        log(f"API client connected from {addr[0]}:{addr[1]}")

        self.api_send(
            client,
            {
                "event": "hello",
                "api_version": 1,
                "engine": "AX.25/KISS engine v2.9.1",
                "kiss_connected": any(self.kiss_states.values()),
                "ports": [dict(p, connected=bool(self.kiss_states.get(p["id"])), state=self.kiss_port_status.get(p["id"], "disconnected")) for p in PORTS],
                "agw_connected": self.agw_sock is not None,
                "sessions": [
                    self.session_to_dict(s)
                    for s in self.sessions_snapshot()
                ],
                "registered": self.registered_calls_snapshot(),
                "digi_enabled": self.digi_enabled,
                "station_callsign": self.station_callsign,
                "digi_callsign": self.digi_callsign,
            }
        )

        buf = bytearray()

        try:
            while self.running:
                chunk = sock.recv(4096)
                if not chunk:
                    break

                buf.extend(chunk)

                while True:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        break

                    raw = bytes(buf[:nl])
                    del buf[:nl + 1]

                    if not raw.strip():
                        continue

                    try:
                        msg = json.loads(raw.decode("utf-8"))
                        if not isinstance(msg, dict):
                            raise ValueError(
                                "JSON command must be an object"
                            )
                        self.handle_api_command(client, msg)

                    except Exception as e:
                        self.api_send(
                            client,
                            {
                                "event": "error",
                                "error": str(e)
                            }
                        )

                if len(buf) > 1024 * 1024:
                    raise ValueError("API input line exceeds 1 MiB")

        except Exception as e:
            log(f"API client ended: {e}")

        finally:
            try:
                sock.close()
            except OSError:
                pass

            with self.api_clients_lock:
                if client in self.api_clients:
                    self.api_clients.remove(client)

            log(f"API client disconnected from {addr[0]}:{addr[1]}")

    def api_server_loop(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((API_LISTEN_HOST, API_LISTEN_PORT))
        srv.listen(5)

        log(
            f"Native API listening on "
            f"{API_LISTEN_HOST}:{API_LISTEN_PORT}"
        )

        while self.running:
            client, addr = srv.accept()
            threading.Thread(
                target=self.api_client_loop,
                args=(client, addr),
                daemon=True
            ).start()

    # ----------------------------------------------------------------------
    # START
    # ----------------------------------------------------------------------

    def run(self):
        safe_print()
        safe_print("AX.25/KISS engine v2.9.1 - startup config fix + direct-route priority")
        safe_print("=======================================")
        safe_print(f"AGWPE : {AGW_LISTEN_HOST}:{AGW_LISTEN_PORT}")
        if API_ENABLED:
            safe_print(f"API   : {API_LISTEN_HOST}:{API_LISTEN_PORT} (JSON Lines)")
        if not PORTS:
            safe_print(
                "KISS  : no ports configured "
                "(configure ports in pypacket_terminal_config.json)"
            )

        for p in PORTS:
            safe_print(
                f"KISS  : [{p['id']}] {p['name']} {p['host']}:{p['port']}"
            )
        safe_print(f"T1/N2 : {T1}s / {N2}")
        safe_print(
            "BEACON: "
            + (
                f"every {self.beacon_interval_min} min "
                f"on {','.join('P' + x for x in self.beacon_port_ids) or 'no ports'}"
                if self.beacon_interval_min > 0
                else "periodic OFF"
            )
        )
        safe_print()

        for port_cfg in PORTS:
            threading.Thread(
                target=self.kiss_loop,
                args=(port_cfg,),
                daemon=True
            ).start()

        threading.Thread(
            target=self.timer_loop,
            daemon=True
        ).start()

        threading.Thread(
            target=self.periodic_beacon_loop,
            daemon=True
        ).start()

        if API_ENABLED:
            threading.Thread(
                target=self.api_server_loop,
                daemon=True
            ).start()

        try:
            self.agw_server_loop()
        except KeyboardInterrupt:
            safe_print()
            log("Stopping...")
            self.running = False


if __name__ == "__main__":
    Bridge().run()
