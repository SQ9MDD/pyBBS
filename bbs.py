import asyncio
import sqlite3
import datetime
import secrets
import string
import json
import os
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import hmac
import time
from collections import deque
from dataclasses import dataclass

DB_PATH = "bbs.sqlite"
CONFIG_PATH = "bbs_config.json"
WELCOME_PATH = "welcome.txt"
MOTD_PATH = "motd.txt"
INFO_PATH = "info.txt"
LOG_DIR = "logs"
LOG_PATH = os.path.join(LOG_DIR, "bbs.log")

# Global state for convers
CONVERS_CLIENTS: set[asyncio.StreamWriter] = set()
SESSIONS_BY_WRITER: dict[asyncio.StreamWriter, "Session"] = {}
READLINE_SKIP_LF: dict[int, bool] = {}
LOGGER = logging.getLogger(__name__)
TELNET_IAC = 255
TELNET_SB = 250
TELNET_SE = 240
TELNET_WILL = 251
TELNET_WONT = 252
TELNET_DO = 253
TELNET_DONT = 254
TELNET_OPT_ECHO = 1
FORWARD_PROTO = "FWD1"
FORWARD_HOP_LIMIT = 10
FORWARD_LINE_MAX = 1024


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    root = logging.getLogger()
    if root.handlers:
        return
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    file_handler = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    root.addHandler(stream_handler)


def peer_label(writer: asyncio.StreamWriter) -> str:
    try:
        peer = writer.get_extra_info("peername")
    except Exception:
        peer = None
    if isinstance(peer, tuple) and len(peer) >= 2:
        return f"{peer[0]}:{peer[1]}"
    return str(peer or "unknown")


@dataclass
class BBSConfig:
    host: str = "0.0.0.0"
    port: int = 8023
    bbs_callsign: str = "N0CALL"
    title: str = "PY-BBS"
    version: str = "0.6"
    prompt_bbs: str = "bbs> "
    prompt_convers: str = "conv> "
    max_inbox_list: int = 50
    max_bulletin_list: int = 50
    max_sent_list: int = 50
    max_msg_lines_private: int = 2000
    max_msg_lines_bulletin: int = 4000
    heard_limit: int = 20
    scopes: list[str] = None
    neighbors: list[dict] = None
    forward_enabled: bool = True
    forward_interval_sec: int = 60
    forward_connect_timeout_sec: int = 5
    forward_session_timeout_sec: int = 20
    forward_max_msgs_per_session: int = 50
    forward_max_body_bytes: int = 20000
    forward_backfill_enabled: bool = True
    forward_backfill_max_per_session: int = 200
    bulletin_retention_days: int = 60
    outbox_retention_days: int = 14
    topology_edge_ttl_sec: int = 1800
    topology_edge_retention_sec: int = 86400

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = ["ALL", "EU", "POL"]
        if self.neighbors is None:
            self.neighbors = []


def _default_config_dict() -> dict:
    return {
        "host": "0.0.0.0",
        "port": 8023,
        "bbs_callsign": "N0CALL",
        "title": "PY-BBS",
        "version": "0.6",
        "prompt_bbs": "bbs> ",
        "prompt_convers": "conv> ",
        "max_inbox_list": 50,
        "max_bulletin_list": 50,
        "max_sent_list": 50,
        "max_msg_lines_private": 2000,
        "max_msg_lines_bulletin": 4000,
        "heard_limit": 20,
        "scopes": ["ALL", "EU", "POL"],
        "neighbors": [],
        "forward_enabled": True,
        "forward_interval_sec": 60,
        "forward_connect_timeout_sec": 5,
        "forward_session_timeout_sec": 20,
        "forward_max_msgs_per_session": 50,
        "forward_max_body_bytes": 20000,
        "forward_backfill_enabled": True,
        "forward_backfill_max_per_session": 200,
        "bulletin_retention_days": 60,
        "outbox_retention_days": 14,
        "topology_edge_ttl_sec": 1800,
        "topology_edge_retention_sec": 86400,
    }


def _write_if_missing(path: str, content: str):
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)


def _ensure_text_files(cfg: "BBSConfig"):
    _write_if_missing(
        WELCOME_PATH,
        "\n".join([
            f"Welcome to {cfg.title} {cfg.version}",
            f"BBS: {cfg.bbs_callsign}",
            "Type HELP for commands.",
            ""
        ])
    )
    _write_if_missing(
        MOTD_PATH,
        "\n".join([
            "Message of the day:",
            "Retro telnet BBS in Python.",
            "T or C for convers, /EX to leave.",
            "73",
            ""
        ])
    )
    _write_if_missing(
        INFO_PATH,
        "\n".join([
            "BBS INFO",
            "Sysop: (edit info.txt)",
            "QTH: (edit info.txt)",
            "Locator: (edit info.txt)",
            "RF: (edit info.txt)",
            "Rules: be nice, no spam.",
            ""
        ])
    )


def load_or_create_config() -> BBSConfig:
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(_default_config_dict(), f, ensure_ascii=False, indent=2)

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)

    merged = _default_config_dict()
    merged.update(raw)

    cfg = BBSConfig(**merged)
    _ensure_text_files(cfg)
    return cfg


CFG = load_or_create_config()
VALID_SCOPES = {s.upper() for s in CFG.scopes}
LOCAL_BBS_NAME = (CFG.bbs_callsign or "").strip().upper()


def normalize_bbs_name(name: str) -> str:
    s = (name or "").strip().upper()
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-")
    return "".join(ch for ch in s if ch in allowed)[:16]


def _neighbor_map_from_cfg(cfg: BBSConfig) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for raw in (cfg.neighbors or []):
        if not isinstance(raw, dict):
            continue
        nname = normalize_bbs_name(str(raw.get("name", "")))
        host = str(raw.get("host", "")).strip()
        port = int(raw.get("port", 0) or 0)
        shared_key = str(raw.get("shared_key", ""))
        enabled = bool(raw.get("enabled", True))
        if not nname or not host or port <= 0:
            continue
        out[nname] = {
            "name": nname,
            "host": host,
            "port": port,
            "shared_key": shared_key,
            "enabled": enabled,
        }
    return out


NEIGHBORS_BY_NAME = _neighbor_map_from_cfg(CFG)


def parse_recipient_target(raw_to: str) -> tuple[str, str | None]:
    raw = (raw_to or "").strip().upper()
    if "@" not in raw:
        return normalize_callsign(raw), None
    user, bbs = raw.split("@", 1)
    return normalize_callsign(user), normalize_bbs_name(bbs)


def normalize_sender_address(raw_from: str) -> str:
    raw = (raw_from or "").strip().upper()
    if "@" in raw:
        user, bbs = raw.split("@", 1)
        n_user = normalize_callsign(user)
        n_bbs = normalize_bbs_name(bbs)
        if n_user and n_bbs:
            return f"{n_user}@{n_bbs}"
        return ""
    return normalize_callsign(raw)


ALIASES = {
    # Heard list
    "MH": "J",
    "MHEARD": "J",
    "H": "J",

    # Private mail shortcuts
    "LM": "L",
    "RM": "R",
    "KM": "K",
    "SP": "S",

    # Bulletin shortcuts
    "LB": "B",

    # Convers shortcuts
    "T": "C",
    "TALK": "C",
    "CONV": "C",
    "CONVERS": "C",

    # Quit
    "BYE": "Q",

    # Connection aliases
    "CONNECTED": "CONNECTION",
    "CONN": "CONNECTION",
}

UI_WIDTH = 78


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def fmt_user_dt(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        dt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        # Fallback for unexpected formats: trim to common "YYYY-MM-DD HH:MM".
        return raw.replace("T", " ")[:16]


def parse_iso_dt(value: str | None) -> datetime.datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def fmt_age_short(seconds: int) -> str:
    sec = max(0, int(seconds))
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m{sec % 60:02d}s"
    return f"{sec // 3600}h{(sec % 3600) // 60:02d}m"


def _ui_fit(text: str, width: int) -> str:
    s = str(text or "")
    if width <= 0:
        return ""
    if len(s) <= width:
        return s
    if width <= 3:
        return s[:width]
    return s[: width - 3] + "..."


def _ui_border() -> str:
    return "+" + "-" * (UI_WIDTH - 2) + "+\r\n"


def _ui_box_line(text: str = "") -> str:
    inner = _ui_fit(text, UI_WIDTH - 4)
    return f"| {inner.ljust(UI_WIDTH - 4)} |\r\n"


def _ui_panel(title: str, body_lines: list[str] | None = None) -> str:
    out = ["\r\n", _ui_border(), _ui_box_line(title), _ui_border()]
    for line in (body_lines or []):
        out.append(_ui_box_line(line))
    out.append(_ui_border())
    return "".join(out)


def _ui_table(title: str, headers: list[str], widths: list[int], rows: list[list[str]], empty: str) -> str:
    if not rows:
        return _ui_panel(title, [empty])

    head = " ".join(_ui_fit(headers[i], widths[i]).ljust(widths[i]) for i in range(len(headers)))
    sep = " ".join("-" * widths[i] for i in range(len(headers)))
    lines = [head, sep]
    for row in rows:
        lines.append(" ".join(_ui_fit(str(row[i]), widths[i]).ljust(widths[i]) for i in range(len(widths))))
    return _ui_panel(title, lines)


def help_text() -> str:
    lines = [
        "[ GENERAL ]",
        "HELP/?           Show this help",
        "WHO              Show your callsign",
        "MOTD             Show message of the day",
        "INFO             Show BBS info",
        "Q/BYE            Quit",
        "",
        "[ MAIL ]",
        "L/LM             List inbox",
        "N                List unread mail",
        "R <id>/RM <id>   Read mail",
        "RN               Read next unread",
        "S/SP             Send mail",
        "RE <id>          Reply",
        "K <id>/KM <id>   Delete from inbox",
        "LS               List sent mail",
        "",
        "[ BULLETINS ]",
        "B [SCOPE]/LB     List bulletins",
        "RB <id>          Read bulletin",
        "SB               Send bulletin",
        "",
        "[ OTHER ]",
        "J/MH/MHEARD/H    Heard list",
        "CONNECTION       List configured neighbors (CONNECTED/CONN)",
        "TOPOLOGY         Show topology links + routes",
        "TOPOLOGY PRUNE <minutes>  Delete links older than minutes",
        "USERS            List registered users",
        "C/T/TALK         Convers mode",
        "/WHO             Convers users",
        "/EX              Leave convers",
    ]
    return _ui_panel(f"{CFG.title} COMMANDS", lines)


def make_bid(callsign: str) -> str:
    rnd = "".join(secrets.choice(string.digits) for _ in range(6))
    return f"{rnd}_{callsign.upper()}"


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    rows = con.execute(f"PRAGMA table_info({table});").fetchall()
    return {r[1] for r in rows}


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL;")

    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            callsign TEXT PRIMARY KEY,
            name TEXT,
            password_hash TEXT,
            created_at TEXT NOT NULL
        );
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bid TEXT NOT NULL UNIQUE,
            msg_type TEXT NOT NULL,
            scope TEXT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            recipient_bbs TEXT,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            path TEXT,
            created_at TEXT NOT NULL
        );
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS inbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            callsign TEXT NOT NULL,
            msg_id INTEGER NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(msg_id) REFERENCES messages(id)
        );
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS heard (
            callsign TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            connects INTEGER NOT NULL DEFAULT 0
        );
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_id INTEGER NOT NULL,
            neighbor_name TEXT NOT NULL,
            status TEXT NOT NULL,
            last_try_at TEXT,
            try_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(msg_id) REFERENCES messages(id)
        );
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS neighbor_status (
            neighbor_name TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            last_ok_at TEXT,
            last_fail_at TEXT,
            fail_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            rtt_ms INTEGER,
            updated_at TEXT NOT NULL
        );
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS topology_edges (
            src TEXT NOT NULL,
            dst TEXT NOT NULL,
            cost INTEGER NOT NULL DEFAULT 1,
            seen_at TEXT NOT NULL,
            via_neighbor TEXT NOT NULL,
            PRIMARY KEY(src, dst, via_neighbor)
        );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_outbox_neighbor_status_try ON outbox(neighbor_name, status, last_try_at);")
    con.execute("CREATE INDEX IF NOT EXISTS idx_topology_seen ON topology_edges(seen_at);")

    # Migration safety
    user_cols = _table_columns(con, "users")
    if "name" not in user_cols:
        con.execute("ALTER TABLE users ADD COLUMN name TEXT;")
    if "password_hash" not in user_cols:
        con.execute("ALTER TABLE users ADD COLUMN password_hash TEXT;")

    cols = _table_columns(con, "messages")
    if "msg_type" not in cols:
        con.execute("ALTER TABLE messages ADD COLUMN msg_type TEXT;")
    if "scope" not in cols:
        con.execute("ALTER TABLE messages ADD COLUMN scope TEXT;")
    if "recipient_bbs" not in cols:
        con.execute("ALTER TABLE messages ADD COLUMN recipient_bbs TEXT;")
    if "path" not in cols:
        con.execute("ALTER TABLE messages ADD COLUMN path TEXT;")
    con.execute("UPDATE messages SET msg_type = COALESCE(msg_type, 'P');")

    con.commit()
    con.close()


class Session:
    def __init__(self):
        self.callsign: str | None = None
        self.in_convers: bool = False
        self.cmd_history: list[str] = []
        self.cmd_history_pos: int | None = None
        self.cmd_history_stash: str = ""

    def prompt(self) -> str:
        base = CFG.prompt_convers if self.in_convers else CFG.prompt_bbs
        return f"[{LOCAL_BBS_NAME}] {base}"

    def history_reset_nav(self):
        self.cmd_history_pos = None
        self.cmd_history_stash = ""

    def history_add(self, line: str):
        s = (line or "").strip()
        if not s:
            return
        self.cmd_history.append(s)
        if len(self.cmd_history) > 100:
            self.cmd_history = self.cmd_history[-100:]
        self.history_reset_nav()

    def history_prev(self, current: str) -> str | None:
        if not self.cmd_history:
            return None
        if self.cmd_history_pos is None:
            self.cmd_history_stash = current
            self.cmd_history_pos = len(self.cmd_history) - 1
        elif self.cmd_history_pos > 0:
            self.cmd_history_pos -= 1
        return self.cmd_history[self.cmd_history_pos]

    def history_next(self) -> str | None:
        if self.cmd_history_pos is None:
            return None
        if self.cmd_history_pos < len(self.cmd_history) - 1:
            self.cmd_history_pos += 1
            return self.cmd_history[self.cmd_history_pos]
        self.cmd_history_pos = None
        return self.cmd_history_stash


def normalize_callsign(s: str) -> str:
    s = s.strip().upper()
    # Keep '-' for SSID style callsigns like SQ9MDD-11.
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-")
    s = "".join(ch for ch in s if ch in allowed)
    return s[:16]


def normalize_scope(s: str) -> str:
    s = (s or "").strip().upper()
    return s if s in VALID_SCOPES else ""


async def send(writer: asyncio.StreamWriter, text: str):
    writer.write(text.encode("utf-8"))
    await writer.drain()


async def _redraw_input_line(writer: asyncio.StreamWriter, prompt: str, text: str, prev_render_len: int) -> int:
    rendered = prompt + text
    pad = " " * max(0, prev_render_len - len(rendered))
    writer.write(("\r" + rendered + pad).encode("utf-8"))
    await writer.drain()
    return len(rendered)


async def readline(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter | None = None,
    sess: Session | None = None,
    history_enabled: bool = False,
):
    """
    Returns:
      - None on EOF (client disconnected)
      - '' on empty line (user pressed Enter)
      - string without CRLF otherwise
    """
    rid = id(reader)
    data = bytearray()
    prev_render_len = len(sess.prompt()) if (history_enabled and sess) else 0
    if history_enabled and sess:
        sess.history_reset_nav()

    while True:
        raw = await reader.read(1)
        if not raw:
            READLINE_SKIP_LF.pop(rid, None)
            if not data:
                return None
            return data.decode("utf-8", errors="ignore")

        b = raw[0]

        # Strip telnet negotiation sequences from input stream.
        if b == TELNET_IAC:
            cmd = await reader.read(1)
            if not cmd:
                READLINE_SKIP_LF.pop(rid, None)
                if not data:
                    return None
                return data.decode("utf-8", errors="ignore")
            c = cmd[0]
            if c == TELNET_IAC:
                data.append(TELNET_IAC)
                READLINE_SKIP_LF[rid] = False
                continue
            if c in (TELNET_WILL, TELNET_WONT, TELNET_DO, TELNET_DONT):
                opt = await reader.read(1)
                if not opt:
                    READLINE_SKIP_LF.pop(rid, None)
                    if not data:
                        return None
                    return data.decode("utf-8", errors="ignore")
                continue
            if c == TELNET_SB:
                prev_iac = False
                while True:
                    part = await reader.read(1)
                    if not part:
                        READLINE_SKIP_LF.pop(rid, None)
                        if not data:
                            return None
                        return data.decode("utf-8", errors="ignore")
                    pb = part[0]
                    if prev_iac and pb == TELNET_SE:
                        break
                    prev_iac = (pb == TELNET_IAC)
                continue
            continue

        # Ignore NUL used by some telnet clients with CR-NUL line endings.
        if b == 0:
            continue

        # Arrow key history navigation in command mode: ESC [ A / ESC [ B
        if (
            b == 27
            and history_enabled
            and writer is not None
            and sess is not None
        ):
            seq1 = await reader.read(1)
            seq2 = await reader.read(1)
            if seq1 and seq2 and seq1[0] == 91 and seq2[0] in (65, 66):
                cur_text = data.decode("utf-8", errors="ignore")
                repl = sess.history_prev(cur_text) if seq2[0] == 65 else sess.history_next()
                if repl is not None:
                    data = bytearray(repl.encode("utf-8"))
                    prev_render_len = await _redraw_input_line(writer, sess.prompt(), repl, prev_render_len)
            continue

        if b == 10:  # LF
            if READLINE_SKIP_LF.get(rid, False):
                READLINE_SKIP_LF[rid] = False
                continue
            return data.decode("utf-8", errors="ignore")

        if b == 13:  # CR
            READLINE_SKIP_LF[rid] = True
            return data.decode("utf-8", errors="ignore")

        data.append(b)
        READLINE_SKIP_LF[rid] = False


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash or "$" not in stored_hash:
        return False
    salt, expected = stored_hash.split("$", 1)
    current = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hmac.compare_digest(current, expected)


def normalize_name(name: str, fallback: str) -> str:
    cleaned = "".join(ch for ch in name.strip() if ch >= " ")
    return cleaned[:40] or fallback


async def read_hidden_input(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, prompt: str) -> str | None:
    await set_password_input_mode(writer, True)
    await send(writer, prompt)
    value = await readline(reader)
    await set_password_input_mode(writer, False)
    await send(writer, "\r\n")
    if value is None:
        return None
    return value


async def set_password_input_mode(writer: asyncio.StreamWriter, enabled: bool):
    try:
        if enabled:
            # Ask telnet client to disable local echo while password is typed.
            writer.write(bytes([TELNET_IAC, TELNET_WILL, TELNET_OPT_ECHO]))
        else:
            writer.write(bytes([TELNET_IAC, TELNET_WONT, TELNET_OPT_ECHO]))
        await writer.drain()
    except Exception:
        pass


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def bid_exists(con: sqlite3.Connection, bid: str) -> bool:
    row = con.execute("SELECT 1 FROM messages WHERE bid = ? LIMIT 1", (bid,)).fetchone()
    return row is not None


def user_exists(callsign: str) -> bool:
    cs = normalize_callsign(callsign)
    if not cs:
        return False
    con = db()
    row = con.execute("SELECT 1 FROM users WHERE callsign = ? LIMIT 1", (cs,)).fetchone()
    con.close()
    return row is not None


def _queue_private_message(sender: str, recipient: str, recipient_bbs: str | None, subject: str, body: str, path: str | None = None) -> tuple[int | None, str]:
    rcpt = normalize_callsign(recipient)
    rbbs = normalize_bbs_name(recipient_bbs or "")
    subj = (subject or "(no subject)").strip()[:80]
    msg_body = (body or "").strip() or "(empty)"
    sender_n = normalize_sender_address(sender)
    if not sender_n or not rcpt:
        return None, "bad_addr"

    is_remote = bool(rbbs and rbbs != LOCAL_BBS_NAME)
    if not is_remote and not user_exists(rcpt):
        return None, "no_such_user"

    msg_path = _path_append(path or "", LOCAL_BBS_NAME)
    con = db()
    bid = make_bid("MAILER")
    con.execute(
        """
        INSERT INTO messages(bid, msg_type, scope, sender, recipient, recipient_bbs, subject, body, path, created_at)
        VALUES (?, 'P', NULL, ?, ?, ?, ?, ?, ?, ?)
        """,
        (bid, sender_n, rcpt, rbbs or None, subj, msg_body, msg_path, now_iso()),
    )
    mid = con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    if not is_remote:
        con.execute(
            "INSERT INTO inbox(callsign, msg_id, is_read, created_at) VALUES (?, ?, 0, ?)",
            (rcpt, mid, now_iso()),
        )
    else:
        next_hop, reason = select_next_hop(rbbs, _split_path_nodes(msg_path))
        if next_hop:
            con.execute(
                """
                INSERT INTO outbox(msg_id, neighbor_name, status, last_try_at, try_count, last_error, created_at)
                VALUES (?, ?, 'queued', NULL, 0, '', ?)
                """,
                (mid, next_hop, now_iso()),
            )
        else:
            con.execute(
                """
                INSERT INTO outbox(msg_id, neighbor_name, status, last_try_at, try_count, last_error, created_at)
                VALUES (?, ?, 'failed', ?, 1, ?, ?)
                """,
                (mid, rbbs, now_iso(), f"route:{reason}", now_iso()),
            )
    con.commit()
    con.close()
    return int(mid), "ok"


def queue_ndn_for_message(msg_row: sqlite3.Row, reason: str):
    sender_addr = normalize_sender_address(msg_row["sender"] or "")
    if not sender_addr:
        return
    if sender_addr.startswith("MAILER-DAEMON@"):
        return
    subj = (msg_row["subject"] or "").strip()
    if subj.upper().startswith("NDN:"):
        return

    rcpt_user, rcpt_bbs = parse_recipient_target(sender_addr)
    if not rcpt_user:
        return
    ndn_sender = f"MAILER-DAEMON@{LOCAL_BBS_NAME}"
    ndn_subj = f"NDN: {subj or '(no subject)'}"[:80]
    to_addr = f"{msg_row['recipient']}@{msg_row['recipient_bbs']}" if msg_row["recipient_bbs"] else msg_row["recipient"]
    con = db()
    existing = con.execute(
        """
        SELECT 1
        FROM messages
        WHERE msg_type = 'P' AND sender = ? AND subject = ? AND body LIKE ?
        LIMIT 1
        """,
        (ndn_sender, ndn_subj, f"%Original BID: {msg_row['bid']}%"),
    ).fetchone()
    con.close()
    if existing:
        return
    ndn_body = (
        "Sorry, user does not exist on destination BBS.\n"
        f"Reason: {reason}\n"
        f"Original To: {to_addr}\n"
        f"Original Subject: {subj or '(no subject)'}\n"
        f"Original BID: {msg_row['bid']}\n"
    )
    _queue_private_message(ndn_sender, rcpt_user, rcpt_bbs, ndn_subj, ndn_body, path=LOCAL_BBS_NAME)


def outbox_enqueue(msg_id: int, neighbor_name: str, status: str = "queued", last_error: str = "") -> bool:
    con = db()
    nname = normalize_bbs_name(neighbor_name)
    if not nname:
        con.close()
        return False
    row = con.execute(
        "SELECT id FROM outbox WHERE msg_id = ? AND neighbor_name = ? LIMIT 1",
        (msg_id, nname),
    ).fetchone()
    if row:
        con.close()
        return False
    con.execute(
        """
        INSERT INTO outbox(msg_id, neighbor_name, status, last_try_at, try_count, last_error, created_at)
        VALUES (?, ?, ?, NULL, 0, ?, ?)
        """,
        (msg_id, nname, status, (last_error or "")[:200], now_iso()),
    )
    con.commit()
    con.close()
    return True


def outbox_mark_attempt(ob_id: int):
    con = db()
    con.execute(
        "UPDATE outbox SET try_count = try_count + 1, last_try_at = ? WHERE id = ?",
        (now_iso(), ob_id),
    )
    con.commit()
    con.close()


def outbox_mark_result(ob_id: int, status: str, last_error: str = ""):
    con = db()
    con.execute(
        "UPDATE outbox SET status = ?, last_error = ? WHERE id = ?",
        (status, (last_error or "")[:200], ob_id),
    )
    con.commit()
    con.close()


def _split_path_nodes(path: str) -> set[str]:
    return {p.strip().upper() for p in (path or "").split(",") if p.strip()}


def enqueue_missing_bulletins_for_neighbor(neighbor_name: str, remote_bids: set[str], max_add: int) -> int:
    if max_add <= 0:
        return 0
    nname = normalize_bbs_name(neighbor_name)
    con = db()
    rows = con.execute("""
        SELECT id, bid, path
        FROM messages
        WHERE msg_type = 'B'
        ORDER BY id DESC
    """).fetchall()
    con.close()

    added = 0
    for r in rows:
        if r["bid"] in remote_bids:
            continue
        if nname in _split_path_nodes(r["path"] or ""):
            continue
        if outbox_enqueue(int(r["id"]), nname, status="queued"):
            added += 1
            if added >= max_add:
                break
    return added


def cleanup_retention():
    con = db()
    try:
        b_days = int(CFG.bulletin_retention_days)
        if b_days > 0:
            cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=b_days)).isoformat(timespec="seconds")
            old_msg_rows = con.execute(
                "SELECT id FROM messages WHERE msg_type = 'B' AND created_at < ?",
                (cutoff,),
            ).fetchall()
            old_msg_ids = [int(r["id"]) for r in old_msg_rows]
            if old_msg_ids:
                marks = ",".join("?" for _ in old_msg_ids)
                con.execute(f"DELETE FROM outbox WHERE msg_id IN ({marks})", old_msg_ids)
                con.execute(f"DELETE FROM messages WHERE id IN ({marks})", old_msg_ids)

        o_days = int(CFG.outbox_retention_days)
        if o_days > 0:
            o_cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=o_days)).isoformat(timespec="seconds")
            con.execute(
                "DELETE FROM outbox WHERE status IN ('sent', 'failed') AND created_at < ?",
                (o_cutoff,),
            )

        keep_sec = max(
            max(60, int(CFG.topology_edge_ttl_sec)),
            int(getattr(CFG, "topology_edge_retention_sec", 86400) or 86400),
        )
        t_cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=keep_sec)).isoformat(timespec="seconds")
        con.execute("DELETE FROM topology_edges WHERE seen_at < ?", (t_cutoff,))
        con.commit()
    finally:
        con.close()


def prune_topology_edges_older_than(seconds: int) -> int:
    keep_sec = max(0, int(seconds))
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=keep_sec)).isoformat(timespec="seconds")
    con = db()
    cur = con.execute("DELETE FROM topology_edges WHERE seen_at < ?", (cutoff,))
    deleted = int(cur.rowcount if cur.rowcount is not None else 0)
    con.commit()
    con.close()
    return deleted


def mark_neighbor_ok(neighbor_name: str, rtt_ms: int):
    nname = normalize_bbs_name(neighbor_name)
    if not nname:
        return
    now = now_iso()
    con = db()
    con.execute(
        """
        INSERT INTO neighbor_status(neighbor_name, state, last_ok_at, last_fail_at, fail_count, last_error, rtt_ms, updated_at)
        VALUES (?, 'UP', ?, NULL, 0, '', ?, ?)
        ON CONFLICT(neighbor_name) DO UPDATE SET
            state = 'UP',
            last_ok_at = excluded.last_ok_at,
            fail_count = 0,
            last_error = '',
            rtt_ms = excluded.rtt_ms,
            updated_at = excluded.updated_at
        """,
        (nname, now, int(rtt_ms), now),
    )
    con.commit()
    con.close()


def mark_neighbor_fail(neighbor_name: str, error: str):
    nname = normalize_bbs_name(neighbor_name)
    if not nname:
        return
    now = now_iso()
    con = db()
    row = con.execute(
        "SELECT fail_count FROM neighbor_status WHERE neighbor_name = ?",
        (nname,),
    ).fetchone()
    fail_count = int(row["fail_count"]) + 1 if row else 1
    con.execute(
        """
        INSERT INTO neighbor_status(neighbor_name, state, last_ok_at, last_fail_at, fail_count, last_error, rtt_ms, updated_at)
        VALUES (?, 'DOWN', NULL, ?, ?, ?, NULL, ?)
        ON CONFLICT(neighbor_name) DO UPDATE SET
            state = 'DOWN',
            last_fail_at = excluded.last_fail_at,
            fail_count = ?,
            last_error = excluded.last_error,
            updated_at = excluded.updated_at
        """,
        (nname, now, fail_count, (error or "")[:120], now, fail_count),
    )
    con.commit()
    con.close()


def _store_topology_for_source(src: str, neighbors: list[str], via_neighbor: str):
    src_n = normalize_bbs_name(src)
    via_n = normalize_bbs_name(via_neighbor)
    if not src_n or not via_n:
        return
    now = now_iso()
    clean_neighbors = sorted({normalize_bbs_name(n) for n in neighbors if normalize_bbs_name(n)})
    con = db()
    con.execute("DELETE FROM topology_edges WHERE src = ? AND via_neighbor = ?", (src_n, via_n))
    for dst in clean_neighbors:
        if dst == src_n:
            continue
        con.execute(
            """
            INSERT INTO topology_edges(src, dst, cost, seen_at, via_neighbor)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(src, dst, via_neighbor) DO UPDATE SET
                cost = 1,
                seen_at = excluded.seen_at
            """,
            (src_n, dst, now, via_n),
        )
    con.commit()
    con.close()


def _replace_topology_edges_via(via_neighbor: str, edges: list[tuple[str, str]]):
    via_n = normalize_bbs_name(via_neighbor)
    if not via_n:
        return
    now = now_iso()
    clean_edges = sorted({
        (normalize_bbs_name(src), normalize_bbs_name(dst))
        for src, dst in edges
        if normalize_bbs_name(src) and normalize_bbs_name(dst) and normalize_bbs_name(src) != normalize_bbs_name(dst)
    })
    con = db()
    con.execute("DELETE FROM topology_edges WHERE via_neighbor = ?", (via_n,))
    for src_n, dst_n in clean_edges:
        con.execute(
            """
            INSERT INTO topology_edges(src, dst, cost, seen_at, via_neighbor)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(src, dst, via_neighbor) DO UPDATE SET
                cost = 1,
                seen_at = excluded.seen_at
            """,
            (src_n, dst_n, now, via_n),
        )
    con.commit()
    con.close()


def refresh_local_topology():
    _store_topology_for_source(LOCAL_BBS_NAME, netinfo_neighbors(), LOCAL_BBS_NAME)


def route_map() -> dict[str, dict]:
    graph = _topology_graph()
    origin = normalize_bbs_name(LOCAL_BBS_NAME)
    if not origin:
        return {}
    q = deque([origin])
    visited: dict[str, list[str]] = {origin: [origin]}
    while q:
        cur = q.popleft()
        for nxt in sorted(graph.get(cur, set())):
            if nxt in visited:
                continue
            visited[nxt] = visited[cur] + [nxt]
            q.append(nxt)

    out: dict[str, dict] = {}
    for dest, path in visited.items():
        if dest == origin:
            continue
        out[dest] = {
            "hops": len(path) - 1,
            "next_hop": path[1] if len(path) > 1 else dest,
            "path": ",".join(path),
        }
    return out


def _topology_graph() -> dict[str, set[str]]:
    ttl_sec = max(60, int(CFG.topology_edge_ttl_sec))
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=ttl_sec)).isoformat(timespec="seconds")
    con = db()
    try:
        rows = con.execute(
            "SELECT src, dst, via_neighbor FROM topology_edges WHERE seen_at >= ?",
            (cutoff,),
        ).fetchall()
    except sqlite3.OperationalError:
        con.close()
        return {}
    con.close()

    nstatus = neighbor_status_map()
    down_neighbors = {
        n for n, st in nstatus.items()
        if (st["state"] or "").upper() == "DOWN"
    }
    origin = normalize_bbs_name(LOCAL_BBS_NAME)

    graph: dict[str, set[str]] = {}
    for r in rows:
        via = normalize_bbs_name(r["via_neighbor"] or "")
        if via in down_neighbors:
            continue
        src = normalize_bbs_name(r["src"] or "")
        dst = normalize_bbs_name(r["dst"] or "")
        if not src or not dst:
            continue
        # Never allow local direct links to neighbors currently marked DOWN,
        # even if this edge was re-learned indirectly from another node.
        if origin and ((src == origin and dst in down_neighbors) or (dst == origin and src in down_neighbors)):
            continue
        graph.setdefault(src, set()).add(dst)
        graph.setdefault(dst, set()).add(src)
    return graph


def topology_edges_for_netinfo(exclude_node: str | None = None) -> list[tuple[str, str]]:
    ttl_sec = max(60, int(CFG.topology_edge_ttl_sec))
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=ttl_sec)).isoformat(timespec="seconds")
    con = db()
    try:
        rows = con.execute(
            "SELECT src, dst, via_neighbor FROM topology_edges WHERE seen_at >= ?",
            (cutoff,),
        ).fetchall()
    except sqlite3.OperationalError:
        con.close()
        return []
    con.close()

    nstatus = neighbor_status_map()
    down_neighbors = {
        n for n, st in nstatus.items()
        if (st["state"] or "").upper() == "DOWN"
    }
    out: set[tuple[str, str]] = set()
    excl = normalize_bbs_name(exclude_node or "")
    for r in rows:
        via = normalize_bbs_name(r["via_neighbor"] or "")
        if via in down_neighbors:
            continue
        src = normalize_bbs_name(r["src"] or "")
        dst = normalize_bbs_name(r["dst"] or "")
        if not src or not dst or src == dst:
            continue
        if excl and (src == excl or dst == excl):
            continue
        out.add((src, dst))
    return sorted(out)


def select_next_hop(dest_bbs: str, visited_nodes: set[str] | None = None) -> tuple[str | None, str]:
    """
    Returns (next_hop, reason). reason is one of:
    - ok
    - bad_dest
    - no_route
    - loop
    """
    dest = normalize_bbs_name(dest_bbs)
    origin = normalize_bbs_name(LOCAL_BBS_NAME)
    if not dest or not origin or dest == origin:
        return None, "bad_dest"

    visited = {normalize_bbs_name(v) for v in (visited_nodes or set()) if normalize_bbs_name(v)}
    if dest in visited:
        return None, "loop"
    enabled = {n["name"] for n in enabled_neighbors()}

    # Direct route first.
    if dest in enabled:
        if dest in visited:
            return None, "loop"
        return dest, "ok"

    graph = _topology_graph()
    q = deque([origin])
    prev: dict[str, str | None] = {origin: None}

    while q:
        cur = q.popleft()
        if cur == dest:
            break
        for nxt in sorted(graph.get(cur, set())):
            if nxt in prev:
                continue
            if nxt in visited and nxt != dest:
                continue
            prev[nxt] = cur
            q.append(nxt)

    if dest not in prev:
        return None, "no_route"

    # Reconstruct path and pick next hop.
    path: list[str] = []
    p = dest
    while p is not None:
        path.append(p)
        p = prev.get(p)
    path.reverse()
    if len(path) < 2:
        return None, "no_route"
    next_hop = path[1]
    if next_hop in visited:
        return None, "loop"
    if next_hop not in enabled:
        return None, "no_route"
    return next_hop, "ok"


def neighbor_status_map() -> dict[str, sqlite3.Row]:
    con = db()
    try:
        rows = con.execute(
            "SELECT neighbor_name, state, last_ok_at, last_fail_at, fail_count, last_error, rtt_ms FROM neighbor_status"
        ).fetchall()
    except sqlite3.OperationalError:
        con.close()
        return {}
    con.close()
    return {normalize_bbs_name(r["neighbor_name"] or ""): r for r in rows}


def enabled_neighbors() -> list[dict]:
    return [n for n in NEIGHBORS_BY_NAME.values() if n.get("enabled")]


def netinfo_neighbors() -> list[str]:
    nstatus = neighbor_status_map()
    out: list[str] = []
    for n in enabled_neighbors():
        st = nstatus.get(n["name"])
        if st and (st["state"] or "").upper() == "DOWN":
            continue
        out.append(n["name"])
    return out


def bump_heard(callsign: str):
    con = db()
    row = con.execute("SELECT callsign FROM heard WHERE callsign = ?", (callsign,)).fetchone()
    if row:
        con.execute(
            "UPDATE heard SET last_seen = ?, connects = connects + 1 WHERE callsign = ?",
            (now_iso(), callsign),
        )
    else:
        con.execute(
            "INSERT INTO heard(callsign, first_seen, last_seen, connects) VALUES (?, ?, ?, 1)",
            (callsign, now_iso(), now_iso()),
        )
    con.commit()
    con.close()


def heard_list(limit: int) -> str:
    con = db()
    rows = con.execute("""
        SELECT callsign, connects, last_seen, first_seen
        FROM heard
        ORDER BY last_seen DESC
        LIMIT ?
    """, (limit,)).fetchall()
    con.close()

    table_rows = []
    for r in rows:
        table_rows.append([
            r["callsign"],
            str(r["connects"]),
            fmt_user_dt(r["last_seen"]),
            fmt_user_dt(r["first_seen"]),
        ])
    return _ui_table(
        "HEARD LIST",
        ["CALLSIGN", "CONN", "LAST_SEEN", "FIRST_SEEN"],
        [16, 4, 16, 16],
        table_rows,
        "No heard entries.",
    )


def connections_list() -> str:
    neighbors = sorted(NEIGHBORS_BY_NAME.values(), key=lambda n: n["name"])
    nstatus = neighbor_status_map()
    routes = route_map()
    con = db()
    stats_rows = con.execute("""
        SELECT neighbor_name, status, COUNT(*) AS c
        FROM outbox
        GROUP BY neighbor_name, status
    """).fetchall()
    con.close()

    stats: dict[str, dict[str, int]] = {}
    for r in stats_rows:
        nname = normalize_bbs_name(r["neighbor_name"] or "")
        if not nname:
            continue
        bucket = stats.setdefault(nname, {"queued": 0, "failed": 0})
        st = (r["status"] or "").lower()
        if st == "queued":
            bucket["queued"] += int(r["c"])
        if st == "failed":
            bucket["failed"] += int(r["c"])

    table_rows = []
    for n in neighbors:
        st = nstatus.get(n["name"])
        nstats = stats.get(n["name"], {"queued": 0, "failed": 0})
        enabled = "Y" if n.get("enabled") else "N"
        state = (st["state"] if st else "UNK")[:4]
        rtt = str(st["rtt_ms"]) if st and st["rtt_ms"] is not None else "-"
        last_ok = fmt_user_dt(st["last_ok_at"]) if st else "-"
        hop = routes.get(n["name"], {}).get("hops", 1)
        table_rows.append([
            n["name"],
            n["host"],
            str(n["port"]),
            enabled,
            state,
            str(hop),
            rtt,
            last_ok if last_ok else "-",
            str(nstats["queued"]),
            str(nstats["failed"]),
        ])
    direct = _ui_table(
        "CONNECTIONS",
        ["NAME", "HOST", "PORT", "EN", "ST", "H", "RTT", "LAST_OK", "Q", "F"],
        [10, 12, 4, 2, 4, 2, 4, 16, 3, 3],
        table_rows,
        "No connections defined.",
    )

    route_rows = []
    for dest in sorted(routes.keys()):
        r = routes[dest]
        route_rows.append([dest, r["next_hop"], str(r["hops"]), r["path"]])
    topo = _ui_table(
        "TOPOLOGY ROUTES",
        ["DEST", "NEXT_HOP", "HOPS", "PATH"],
        [12, 12, 4, 43],
        route_rows,
        "No discovered routes yet.",
    )
    return direct + topology_links_list() + topo


def topology_links_list() -> str:
    ttl_sec = max(60, int(CFG.topology_edge_ttl_sec))
    now = datetime.datetime.now(datetime.timezone.utc)
    nstatus = neighbor_status_map()
    down_neighbors = {
        n for n, st in nstatus.items()
        if (st["state"] or "").upper() == "DOWN"
    }
    origin = normalize_bbs_name(LOCAL_BBS_NAME)
    con = db()
    rows = con.execute("""
        SELECT src, dst, via_neighbor, seen_at
        FROM topology_edges
        ORDER BY seen_at DESC, src ASC, dst ASC
    """).fetchall()
    con.close()

    links: dict[tuple[str, str], dict[str, object]] = {}
    for r in rows:
        src = normalize_bbs_name(r["src"] or "")
        dst = normalize_bbs_name(r["dst"] or "")
        if not src or not dst or src == dst:
            continue
        via = normalize_bbs_name(r["via_neighbor"] or "")
        seen = parse_iso_dt(r["seen_at"])
        local_down_link = bool(origin and ((src == origin and dst in down_neighbors) or (dst == origin and src in down_neighbors)))
        if local_down_link:
            age_sec = 0 if not seen else int((now - seen).total_seconds())
            row_status = "DOWN"
        elif via in down_neighbors:
            age_sec = 0 if not seen else int((now - seen).total_seconds())
            row_status = "DOWN"
        elif not seen:
            age_sec = 0
            row_status = "UNK"
        else:
            age_sec = int((now - seen).total_seconds())
            row_status = "ACTIVE" if age_sec <= ttl_sec else "DEAD"

        key = (src, dst)
        cur = links.get(key)
        if cur is None or age_sec < int(cur["age_sec"]):
            links[key] = {"age_sec": age_sec, "status": row_status}

    table_rows = []
    for (src, dst), meta in sorted(links.items(), key=lambda it: (it[0][0], it[0][1])):
        table_rows.append([src, dst, fmt_age_short(int(meta["age_sec"])), str(meta["status"])])
    return _ui_table(
        "TOPOLOGY LINKS",
        ["FROM", "TO", "AGE", "STATUS"],
        [16, 16, 8, 8],
        table_rows,
        "No topology links yet.",
    )


def topology_overview() -> str:
    routes = route_map()
    route_rows = []
    for dest in sorted(routes.keys()):
        r = routes[dest]
        route_rows.append([dest, r["next_hop"], str(r["hops"]), r["path"]])
    topo_routes = _ui_table(
        "TOPOLOGY ROUTES",
        ["DEST", "NEXT_HOP", "HOPS", "PATH"],
        [12, 12, 4, 43],
        route_rows,
        "No discovered routes yet.",
    )
    return topology_links_list() + topo_routes


def users_list() -> str:
    con = db()
    rows = con.execute("""
        SELECT callsign, name, created_at
        FROM users
        ORDER BY callsign ASC
    """).fetchall()
    con.close()

    table_rows = []
    for r in rows:
        table_rows.append([
            r["callsign"],
            normalize_name(r["name"] or "", r["callsign"]),
            fmt_user_dt(r["created_at"]),
        ])
    return _ui_table(
        "REGISTERED USERS",
        ["CALLSIGN", "NAME", "CREATED"],
        [16, 24, 16],
        table_rows,
        "No registered users.",
    )


def _read_text_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def show_welcome() -> str:
    return _read_text_file(WELCOME_PATH).replace("\n", "\r\n")


def show_motd() -> str:
    return _read_text_file(MOTD_PATH).replace("\n", "\r\n")


def show_info() -> str:
    return _read_text_file(INFO_PATH).replace("\n", "\r\n")


async def convers_send_prompt(writer: asyncio.StreamWriter):
    try:
        await send(writer, CFG.prompt_convers)
    except Exception:
        pass


async def convers_broadcast(line: str):
    dead = []
    # Iterate over a snapshot because the live set can change during awaits.
    for w in list(CONVERS_CLIENTS):
        try:
            # Print message on a fresh line and then restore prompt
            w.write(("\r\n" + line + "\r\n").encode("utf-8"))
            await w.drain()
            await convers_send_prompt(w)
        except Exception:
            dead.append(w)

    for w in dead:
        CONVERS_CLIENTS.discard(w)
        SESSIONS_BY_WRITER.pop(w, None)


def convers_users_text() -> str:
    users = []
    for w in CONVERS_CLIENTS:
        sess = SESSIONS_BY_WRITER.get(w)
        if sess and sess.callsign:
            users.append(sess.callsign)
    users = sorted(set(users))
    if not users:
        return "Convers users: (none)\r\n"
    return "Convers users:\r\n" + "\r\n".join(users) + "\r\n"


async def login_flow(reader, writer, sess: Session, first_line: str | None = None, peer: str = "unknown"):
    await send(writer, show_welcome() + "\r\n")
    await send(writer, "Enter your callsign: ")

    cs = first_line if first_line is not None else await readline(reader)
    if cs is None:
        LOGGER.info("login_aborted peer=%s reason=disconnect_before_callsign", peer)
        return False

    cs = normalize_callsign(cs)
    if not cs:
        await send(writer, "\r\nNo callsign, bye.\r\n")
        LOGGER.warning("login_failed peer=%s reason=empty_callsign", peer)
        return False
    LOGGER.info("login_start peer=%s callsign=%s", peer, cs)

    con = db()
    row = con.execute(
        "SELECT callsign, name, password_hash FROM users WHERE callsign = ?",
        (cs,),
    ).fetchone()

    if not row:
        await send(writer, "First login. Enter your name: ")
        name_in = await readline(reader)
        if name_in is None:
            con.close()
            LOGGER.info("login_aborted peer=%s callsign=%s reason=disconnect_name", peer, cs)
            return False
        name = normalize_name(name_in, cs)

        pw1 = await read_hidden_input(reader, writer, "Set password: ")
        if pw1 is None:
            con.close()
            LOGGER.info("login_aborted peer=%s callsign=%s reason=disconnect_set_password", peer, cs)
            return False
        pw2 = await read_hidden_input(reader, writer, "Repeat password: ")
        if pw2 is None:
            con.close()
            LOGGER.info("login_aborted peer=%s callsign=%s reason=disconnect_repeat_password", peer, cs)
            return False
        if not pw1:
            await send(writer, "Empty password is not allowed.\r\n")
            con.close()
            LOGGER.warning("login_failed peer=%s callsign=%s reason=empty_password_new_account", peer, cs)
            return False
        if pw1 != pw2:
            await send(writer, "Passwords do not match.\r\n")
            con.close()
            LOGGER.warning("login_failed peer=%s callsign=%s reason=password_mismatch_new_account", peer, cs)
            return False

        con.execute(
            "INSERT INTO users(callsign, name, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (cs, name, hash_password(pw1), now_iso()),
        )
        display_name = name
        LOGGER.info("account_created peer=%s callsign=%s", peer, cs)
    else:
        display_name = normalize_name(row["name"] or "", cs)
        stored_hash = row["password_hash"] or ""

        # Legacy account migration: user existed before password support.
        if not stored_hash:
            await send(writer, "Account requires password setup.\r\n")
            await send(writer, f"Name [{display_name}]: ")
            name_in = await readline(reader)
            if name_in is None:
                con.close()
                LOGGER.info("login_aborted peer=%s callsign=%s reason=disconnect_legacy_name", peer, cs)
                return False
            name = normalize_name(name_in if name_in.strip() else display_name, cs)

            pw1 = await read_hidden_input(reader, writer, "Set password: ")
            if pw1 is None:
                con.close()
                LOGGER.info("login_aborted peer=%s callsign=%s reason=disconnect_legacy_set_password", peer, cs)
                return False
            pw2 = await read_hidden_input(reader, writer, "Repeat password: ")
            if pw2 is None:
                con.close()
                LOGGER.info("login_aborted peer=%s callsign=%s reason=disconnect_legacy_repeat_password", peer, cs)
                return False
            if not pw1:
                await send(writer, "Empty password is not allowed.\r\n")
                con.close()
                LOGGER.warning("login_failed peer=%s callsign=%s reason=empty_password_legacy_setup", peer, cs)
                return False
            if pw1 != pw2:
                await send(writer, "Passwords do not match.\r\n")
                con.close()
                LOGGER.warning("login_failed peer=%s callsign=%s reason=password_mismatch_legacy_setup", peer, cs)
                return False

            con.execute(
                "UPDATE users SET name = ?, password_hash = ? WHERE callsign = ?",
                (name, hash_password(pw1), cs),
            )
            display_name = name
            LOGGER.info("account_password_initialized peer=%s callsign=%s", peer, cs)
        else:
            authenticated = False
            for attempt in range(1, 4):
                pw = await read_hidden_input(reader, writer, "Password: ")
                if pw is None:
                    con.close()
                    LOGGER.info("login_aborted peer=%s callsign=%s reason=disconnect_password_prompt", peer, cs)
                    return False
                if verify_password(pw, stored_hash):
                    authenticated = True
                    break
                await send(writer, "Invalid password.\r\n")
                LOGGER.warning("login_failed peer=%s callsign=%s reason=bad_password attempt=%s", peer, cs, attempt)
            if not authenticated:
                await send(writer, "Too many failed attempts.\r\n")
                con.close()
                LOGGER.warning("login_failed peer=%s callsign=%s reason=too_many_attempts", peer, cs)
                return False

    con.commit()
    con.close()

    bump_heard(cs)

    sess.callsign = cs
    LOGGER.info("login_ok peer=%s callsign=%s", peer, cs)
    await send(writer, f"\r\nHello {display_name} ({cs}) on {CFG.bbs_callsign}!\r\n")
    await send(writer, show_motd() + "\r\n")
    return True


def unread_count(callsign: str) -> int:
    con = db()
    row = con.execute("SELECT COUNT(*) AS c FROM inbox WHERE callsign = ? AND is_read = 0", (callsign,)).fetchone()
    con.close()
    return int(row["c"]) if row else 0


# ---- Mail ----

def list_inbox(callsign: str) -> str:
    con = db()
    rows = con.execute("""
        SELECT i.msg_id AS mid, i.is_read, m.sender, m.subject, m.created_at
        FROM inbox i
        JOIN messages m ON m.id = i.msg_id
        WHERE i.callsign = ? AND m.msg_type = 'P'
        ORDER BY i.msg_id DESC
        LIMIT ?
    """, (callsign, CFG.max_inbox_list)).fetchall()
    con.close()

    table_rows = []
    for r in rows:
        flag = " " if r["is_read"] else "*"
        table_rows.append([
            str(r["mid"]),
            flag,
            r["sender"],
            r["subject"],
            fmt_user_dt(r["created_at"]),
        ])
    return _ui_table(
        "INBOX",
        ["ID", "N", "FROM", "SUBJECT", "DATE"],
        [5, 1, 18, 27, 16],
        table_rows,
        "Inbox empty.",
    )


def list_new(callsign: str) -> str:
    con = db()
    rows = con.execute("""
        SELECT i.msg_id AS mid, m.sender, m.subject, m.created_at
        FROM inbox i
        JOIN messages m ON m.id = i.msg_id
        WHERE i.callsign = ? AND i.is_read = 0 AND m.msg_type = 'P'
        ORDER BY i.msg_id ASC
        LIMIT ?
    """, (callsign, CFG.max_inbox_list)).fetchall()
    con.close()

    table_rows = []
    for r in rows:
        table_rows.append([
            str(r["mid"]),
            r["sender"],
            r["subject"],
            fmt_user_dt(r["created_at"]),
        ])
    return _ui_table(
        "NEW MAIL",
        ["ID", "FROM", "SUBJECT", "DATE"],
        [5, 18, 29, 16],
        table_rows,
        "No new mail.",
    )


def read_private_message(callsign: str, mid: int) -> str:
    con = db()
    row = con.execute("""
        SELECT m.id, m.bid, m.sender, m.recipient, m.subject, m.body, m.created_at
        FROM messages m
        JOIN inbox i ON i.msg_id = m.id
        WHERE i.callsign = ? AND m.id = ? AND m.msg_type = 'P'
    """, (callsign, mid)).fetchone()

    if not row:
        con.close()
        LOGGER.warning("mail_read_failed user=%s mid=%s reason=not_found", callsign, mid)
        return _ui_panel("MAIL", ["No such mail in your inbox."])

    con.execute("UPDATE inbox SET is_read = 1 WHERE callsign = ? AND msg_id = ?", (callsign, mid))
    con.commit()
    con.close()
    LOGGER.info("mail_read user=%s mid=%s bid=%s", callsign, mid, row["bid"])

    hdr = _ui_panel(
        f"MAIL #{row['id']} BID {row['bid']}",
        [
            f"From : {row['sender']}",
            f"To   : {row['recipient']}",
            f"Subj : {row['subject']}",
            f"Date : {fmt_user_dt(row['created_at'])}",
        ],
    )
    body = row["body"].replace("\n", "\r\n")
    return hdr + body + "\r\n" + _ui_border()


def next_unread_id(callsign: str) -> int | None:
    con = db()
    row = con.execute("""
        SELECT i.msg_id AS mid
        FROM inbox i
        JOIN messages m ON m.id = i.msg_id
        WHERE i.callsign = ? AND i.is_read = 0 AND m.msg_type = 'P'
        ORDER BY i.msg_id ASC
        LIMIT 1
    """, (callsign,)).fetchone()
    con.close()
    return int(row["mid"]) if row else None


def delete_from_inbox(callsign: str, mid: int) -> str:
    con = db()
    cur = con.execute("DELETE FROM inbox WHERE callsign = ? AND msg_id = ?", (callsign, mid))
    con.commit()
    con.close()
    LOGGER.info("mail_delete user=%s mid=%s deleted=%s", callsign, mid, 1 if cur.rowcount else 0)
    return "Deleted.\r\n" if cur.rowcount else "Nothing deleted.\r\n"


def list_sent(callsign: str) -> str:
    sender_local = normalize_callsign(callsign)
    sender_remote = f"{sender_local}@{LOCAL_BBS_NAME}"
    con = db()
    rows = con.execute("""
        SELECT id, recipient, recipient_bbs, subject, created_at
        FROM messages
        WHERE msg_type = 'P' AND sender IN (?, ?)
        ORDER BY id DESC
        LIMIT ?
    """, (sender_local, sender_remote, CFG.max_sent_list)).fetchall()
    con.close()

    table_rows = []
    for r in rows:
        to_addr = r["recipient"]
        if r["recipient_bbs"] and r["recipient_bbs"] != LOCAL_BBS_NAME:
            to_addr = f"{r['recipient']}@{r['recipient_bbs']}"
        table_rows.append([
            str(r["id"]),
            to_addr,
            r["subject"],
            fmt_user_dt(r["created_at"]),
        ])
    return _ui_table(
        "SENT MAIL",
        ["ID", "TO", "SUBJECT", "DATE"],
        [5, 18, 29, 16],
        table_rows,
        "Sent mail empty.",
    )


async def _compose_message(reader, writer, to_default: str | None, subject_default: str | None) -> tuple[str, str, str] | None:
    # returns (to, subject, body) or None on disconnect/abort
    if to_default:
        await send(writer, f"To [{to_default}]: ")
        to_in = await readline(reader)
        if to_in is None:
            return None
        to = to_in.strip().upper() if to_in.strip() else to_default.strip().upper()
    else:
        await send(writer, "To: ")
        to_in = await readline(reader)
        if to_in is None:
            return None
        to = to_in.strip().upper()

    rcpt, rcpt_bbs = parse_recipient_target(to)
    if not rcpt or ("@" in to and not rcpt_bbs):
        await send(writer, "Aborted.\r\n")
        return None
    to = f"{rcpt}@{rcpt_bbs}" if rcpt_bbs else rcpt

    if subject_default:
        await send(writer, f"Subject [{subject_default}]: ")
        subj_in = await readline(reader)
        if subj_in is None:
            return None
        subj = (subj_in.strip() or subject_default).strip()
    else:
        await send(writer, "Subject: ")
        subj_in = await readline(reader)
        if subj_in is None:
            return None
        subj = subj_in.strip() or "(no subject)"

    await send(writer, "Enter message, end with /EX on its own line.\r\n")
    lines = []
    while True:
        await send(writer, "> ")
        line = await readline(reader)
        if line is None:
            return None
        if line.strip().upper() == "/EX":
            break
        lines.append(line)
        if len(lines) > CFG.max_msg_lines_private:
            await send(writer, "Message too long, abort.\r\n")
            return None

    body = "\n".join(lines).strip() or "(empty)"
    return to, subj, body


async def send_private_interactive(reader, writer, sess: Session, to_default: str | None = None, subject_default: str | None = None):
    composed = await _compose_message(reader, writer, to_default, subject_default)
    if not composed:
        return
    to, subj, body = composed
    recipient, recipient_bbs = parse_recipient_target(to)
    is_remote = bool(recipient_bbs and recipient_bbs != LOCAL_BBS_NAME)
    next_hop: str | None = None
    if not is_remote and not user_exists(recipient):
        await send(writer, f"No such local user: {recipient}\r\n")
        LOGGER.warning("mail_send_failed user=%s to=%s reason=no_such_local_user", sess.callsign, recipient)
        return
    if is_remote:
        next_hop, reason = select_next_hop(recipient_bbs, _split_path_nodes(LOCAL_BBS_NAME))
        if not next_hop:
            await send(writer, f"No route to {recipient_bbs} ({reason}).\r\n")
            LOGGER.warning("mail_send_failed user=%s to=%s@%s reason=route_%s", sess.callsign, recipient, recipient_bbs, reason)
            return
    sender_for_store = f"{sess.callsign}@{LOCAL_BBS_NAME}" if is_remote else sess.callsign

    bid = make_bid(sess.callsign)
    con = db()
    con.execute("""
        INSERT INTO messages(bid, msg_type, scope, sender, recipient, recipient_bbs, subject, body, path, created_at)
        VALUES (?, 'P', NULL, ?, ?, ?, ?, ?, ?, ?)
    """, (bid, sender_for_store, recipient, recipient_bbs, subj[:80], body, LOCAL_BBS_NAME, now_iso()))
    mid = con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    if is_remote:
        con.execute(
            """
            INSERT INTO outbox(msg_id, neighbor_name, status, last_try_at, try_count, last_error, created_at)
            VALUES (?, ?, 'queued', NULL, 0, '', ?)
            """,
            (mid, next_hop, now_iso()),
        )
    else:
        con.execute("INSERT INTO inbox(callsign, msg_id, is_read, created_at) VALUES (?, ?, 0, ?)", (recipient, mid, now_iso()))
    con.commit()
    con.close()

    if is_remote:
        await send(writer, f"Queued Msg {mid} BID {bid} to {recipient}@{recipient_bbs}\r\n")
        LOGGER.info(
            "mail_queued user=%s mid=%s bid=%s to=%s@%s next_hop=%s body_bytes=%s",
            sess.callsign, mid, bid, recipient, recipient_bbs, next_hop, len(body.encode("utf-8"))
        )
    else:
        await send(writer, f"Sent Msg {mid} BID {bid}\r\n")
        LOGGER.info("mail_sent_local user=%s mid=%s bid=%s to=%s body_bytes=%s", sess.callsign, mid, bid, recipient, len(body.encode("utf-8")))


def get_mail_for_reply(callsign: str, mid: int) -> tuple[str, str] | None:
    con = db()
    row = con.execute("""
        SELECT m.sender, m.subject
        FROM messages m
        JOIN inbox i ON i.msg_id = m.id
        WHERE i.callsign = ? AND m.id = ? AND m.msg_type = 'P'
    """, (callsign, mid)).fetchone()
    con.close()
    if not row:
        return None
    sender = row["sender"]
    subj = row["subject"] or ""
    if subj.lower().startswith("re:"):
        reply_subj = subj
    else:
        reply_subj = f"Re: {subj}"
    return sender, reply_subj


# ---- Bulletins ----

def list_bulletins(scope: str) -> str:
    scope = normalize_scope(scope) or (CFG.scopes[0] if CFG.scopes else "ALL")
    con = db()
    rows = con.execute("""
        SELECT id, scope, sender, subject, created_at
        FROM messages
        WHERE msg_type = 'B' AND scope = ?
        ORDER BY id DESC
        LIMIT ?
    """, (scope, CFG.max_bulletin_list)).fetchall()
    con.close()

    table_rows = []
    for r in rows:
        table_rows.append([
            str(r["id"]),
            r["sender"],
            r["subject"],
            fmt_user_dt(r["created_at"]),
        ])
    return _ui_table(
        f"BULLETINS / {scope}",
        ["ID", "FROM", "SUBJECT", "DATE"],
        [5, 18, 29, 16],
        table_rows,
        f"No bulletins for scope {scope}.",
    )


def read_bulletin(mid: int) -> str:
    con = db()
    row = con.execute("""
        SELECT id, bid, scope, sender, subject, body, created_at
        FROM messages
        WHERE id = ? AND msg_type = 'B'
    """, (mid,)).fetchone()
    con.close()

    if not row:
        return _ui_panel("BULLETIN", ["No such bulletin."])

    hdr = _ui_panel(
        f"BULLETIN #{row['id']} BID {row['bid']}",
        [
            f"From : {row['sender']}",
            f"Scope: {row['scope']}",
            f"Subj : {row['subject']}",
            f"Date : {fmt_user_dt(row['created_at'])}",
        ],
    )
    body = row["body"].replace("\n", "\r\n")
    return hdr + body + "\r\n" + _ui_border()


async def send_bulletin_interactive(reader, writer, sess: Session):
    await send(writer, f"Scope ({'/'.join(CFG.scopes)}): ")
    sc = await readline(reader)
    if sc is None:
        return
    sc = normalize_scope(sc)
    if not sc:
        await send(writer, "Invalid scope.\r\n")
        LOGGER.warning("bulletin_post_failed user=%s reason=invalid_scope", sess.callsign)
        return

    await send(writer, "Subject: ")
    subj_in = await readline(reader)
    if subj_in is None:
        return
    subj = subj_in.strip() or "(no subject)"

    await send(writer, "Enter bulletin, end with /EX on its own line.\r\n")
    lines = []
    while True:
        await send(writer, "> ")
        line = await readline(reader)
        if line is None:
            return
        if line.strip().upper() == "/EX":
            break
        lines.append(line)
        if len(lines) > CFG.max_msg_lines_bulletin:
            await send(writer, "Bulletin too long, abort.\r\n")
            return

    body = "\n".join(lines).strip() or "(empty)"
    bid = make_bid(sess.callsign)
    sender = f"{sess.callsign}@{LOCAL_BBS_NAME}"

    con = db()
    con.execute("""
        INSERT INTO messages(bid, msg_type, scope, sender, recipient, recipient_bbs, subject, body, path, created_at)
        VALUES (?, 'B', ?, ?, 'ALL', NULL, ?, ?, ?, ?)
    """, (bid, sc, sender, subj[:80], body, LOCAL_BBS_NAME, now_iso()))
    mid = con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    for nei in enabled_neighbors():
        con.execute(
            """
            INSERT INTO outbox(msg_id, neighbor_name, status, last_try_at, try_count, last_error, created_at)
            VALUES (?, ?, 'queued', NULL, 0, '', ?)
            """,
            (mid, nei["name"], now_iso()),
        )
    con.commit()
    con.close()

    await send(writer, f"Bulletin posted {mid} BID {bid} SCOPE {sc}\r\n")
    LOGGER.info(
        "bulletin_posted user=%s mid=%s bid=%s scope=%s fanout=%s body_bytes=%s",
        sess.callsign, mid, bid, sc, len(enabled_neighbors()), len(body.encode("utf-8"))
    )


def _path_append(path: str, node: str) -> str:
    parts = [p.strip().upper() for p in (path or "").split(",") if p.strip()]
    node_u = (node or "").strip().upper()
    if node_u:
        parts.append(node_u)
    return ",".join(parts)


def _path_hop_count(path: str) -> int:
    return len([p for p in (path or "").split(",") if p.strip()])


async def fwd_send_line(writer: asyncio.StreamWriter, line: str):
    writer.write((line + "\r\n").encode("utf-8"))
    await writer.drain()


async def fwd_read_line(reader: asyncio.StreamReader, timeout_sec: int) -> str | None:
    line = await asyncio.wait_for(readline(reader), timeout=timeout_sec)
    if line is None:
        return None
    if len(line) > FORWARD_LINE_MAX:
        raise ValueError("line too long")
    return line


def _hmac_sig(shared_key: str, neighbor_name: str, nonce: str, server_nonce: str) -> str:
    payload = f"{neighbor_name}|{nonce}|{server_nonce}".encode("utf-8")
    return hmac.new(shared_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _outbox_rows_for_neighbor(neighbor_name: str, limit: int) -> list[sqlite3.Row]:
    con = db()
    rows = con.execute(
        """
        SELECT o.id AS outbox_id, o.msg_id, o.status, m.*
        FROM outbox o
        JOIN messages m ON m.id = o.msg_id
        WHERE o.neighbor_name = ? AND o.status IN ('queued', 'failed')
        ORDER BY o.created_at ASC
        LIMIT ?
        """,
        (neighbor_name, limit),
    ).fetchall()
    con.close()
    return rows


def _list_bids(msg_type: str, scope: str = "") -> set[str]:
    con = db()
    if msg_type == "P":
        rows = con.execute("SELECT bid FROM messages WHERE msg_type = 'P'").fetchall()
    else:
        if scope:
            rows = con.execute("SELECT bid FROM messages WHERE msg_type = 'B' AND scope = ?", (scope,)).fetchall()
        else:
            rows = con.execute("SELECT bid FROM messages WHERE msg_type = 'B'").fetchall()
    con.close()
    return {r["bid"] for r in rows}


def _store_forward_message(fields: dict[str, str], body: str) -> tuple[bool, str]:
    bid = fields.get("BID", "").strip()
    msg_type = fields.get("TYPE", "").strip().upper()
    scope = normalize_scope(fields.get("SCOPE", ""))
    sender = normalize_sender_address(fields.get("FROM", ""))
    recipient = normalize_callsign(fields.get("TO", ""))
    recipient_bbs = normalize_bbs_name(fields.get("TOBBS", ""))
    subject = (fields.get("SUBJ", "") or "(no subject)").strip()[:80]
    created_at = (fields.get("CREATED", "") or now_iso()).strip()
    path = fields.get("PATH", "").strip()

    if not bid:
        return False, "bad_bid"
    if msg_type not in ("P", "B"):
        return False, "bad_type"
    if not sender:
        return False, "bad_from"
    if _path_hop_count(path) > FORWARD_HOP_LIMIT:
        return False, "hop_limit"
    if msg_type == "P" and not recipient:
        return False, "bad_to"
    if msg_type == "B" and not scope:
        return False, "bad_scope"

    con = db()
    if bid_exists(con, bid):
        con.close()
        return False, "duplicate"

    relay_neighbors: list[str] = []
    if msg_type == "P":
        full_path = _path_append(path, LOCAL_BBS_NAME)
        next_hop: str | None = None
        if not recipient_bbs or recipient_bbs == LOCAL_BBS_NAME:
            if not user_exists(recipient):
                con.close()
                return False, "no_such_user"
        else:
            visited = _split_path_nodes(full_path)
            next_hop, reason = select_next_hop(recipient_bbs, visited)
            if not next_hop:
                con.close()
                return False, f"route:{reason}"
        con.execute(
            """
            INSERT INTO messages(bid, msg_type, scope, sender, recipient, recipient_bbs, subject, body, path, created_at)
            VALUES (?, 'P', NULL, ?, ?, ?, ?, ?, ?, ?)
            """,
            (bid, sender, recipient, recipient_bbs or None, subject, body, full_path, created_at),
        )
        mid = con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        if not recipient_bbs or recipient_bbs == LOCAL_BBS_NAME:
            con.execute("INSERT INTO inbox(callsign, msg_id, is_read, created_at) VALUES (?, ?, 0, ?)", (recipient, mid, now_iso()))
        else:
            con.execute(
                """
                INSERT INTO outbox(msg_id, neighbor_name, status, last_try_at, try_count, last_error, created_at)
                VALUES (?, ?, 'queued', NULL, 0, '', ?)
                """,
                (mid, next_hop, now_iso()),
            )
    else:
        con.execute(
            """
            INSERT INTO messages(bid, msg_type, scope, sender, recipient, recipient_bbs, subject, body, path, created_at)
            VALUES (?, 'B', ?, ?, 'ALL', NULL, ?, ?, ?, ?)
            """,
            (bid, scope, sender, subject, body, _path_append(path, LOCAL_BBS_NAME), created_at),
        )
        mid = con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        visited = {p.strip().upper() for p in _path_append(path, LOCAL_BBS_NAME).split(",") if p.strip()}
        relay_neighbors = [nei["name"] for nei in enabled_neighbors() if nei["name"] not in visited]

    con.commit()
    con.close()

    if msg_type == "B":
        for nname in relay_neighbors:
            outbox_enqueue(mid, nname, status="queued")

    return True, "ok"


async def handle_forward_session(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, hello_line: str):
    parts = hello_line.strip().split()
    if len(parts) != 4 or parts[0] != FORWARD_PROTO or parts[1] != "HELLO":
        await fwd_send_line(writer, f"{FORWARD_PROTO} ERR hello")
        return

    neighbor_name = normalize_bbs_name(parts[2])
    nonce = parts[3].strip()
    neighbor = NEIGHBORS_BY_NAME.get(neighbor_name)
    if not neighbor or not neighbor.get("enabled") or not neighbor.get("shared_key"):
        await fwd_send_line(writer, f"{FORWARD_PROTO} ERR auth")
        return

    server_nonce = secrets.token_hex(12)
    await fwd_send_line(writer, f"{FORWARD_PROTO} CHALLENGE {server_nonce}")
    auth = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
    if not auth:
        return
    ap = auth.split()
    if len(ap) != 3 or ap[0] != FORWARD_PROTO or ap[1] != "AUTH":
        await fwd_send_line(writer, f"{FORWARD_PROTO} ERR auth")
        return
    got_sig = ap[2].strip().lower()
    exp_sig = _hmac_sig(neighbor["shared_key"], neighbor_name, nonce, server_nonce)
    if not hmac.compare_digest(got_sig, exp_sig):
        await fwd_send_line(writer, f"{FORWARD_PROTO} ERR auth")
        return

    await fwd_send_line(writer, f"{FORWARD_PROTO} OK {LOCAL_BBS_NAME}")
    accepted = 0
    while True:
        line = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
        if line is None:
            break
        if not line:
            continue
        cmd = line.split()
        if len(cmd) >= 2 and cmd[0] == FORWARD_PROTO and cmd[1] == "BYE":
            break

        if len(cmd) == 2 and cmd[0] == FORWARD_PROTO and cmd[1] == "NETINFO":
            await fwd_send_line(writer, f"NODE:{LOCAL_BBS_NAME}")
            for nei_name in sorted(netinfo_neighbors()):
                await fwd_send_line(writer, f"NEI:{nei_name}")
            # Avoid reflecting back edges touching the peer itself.
            for src, dst in topology_edges_for_netinfo(exclude_node=neighbor_name):
                await fwd_send_line(writer, f"EDGE:{src},{dst}")
            await fwd_send_line(writer, f"{FORWARD_PROTO} END")
            continue

        if len(cmd) >= 3 and cmd[0] == FORWARD_PROTO and cmd[1] == "LISTBID":
            mtype = cmd[2].strip().upper()
            scope = cmd[3].strip().upper() if len(cmd) >= 4 else ""
            bids = _list_bids(mtype, scope)
            for bid in sorted(bids):
                await fwd_send_line(writer, f"BID:{bid}")
            await fwd_send_line(writer, f"{FORWARD_PROTO} END")
            continue

        if len(cmd) == 3 and cmd[0] == FORWARD_PROTO and cmd[1] == "PUSH":
            try:
                total = int(cmd[2])
            except ValueError:
                await fwd_send_line(writer, f"{FORWARD_PROTO} ERR push")
                break
            if total < 0 or total > CFG.forward_max_msgs_per_session:
                await fwd_send_line(writer, f"{FORWARD_PROTO} ERR push")
                break
            for _ in range(total):
                msg_start = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
                if msg_start != f"{FORWARD_PROTO} MSG":
                    await fwd_send_line(writer, f"{FORWARD_PROTO} ERR msg")
                    return

                fields: dict[str, str] = {}
                body_lines: list[str] = []
                body_started = False
                body_bytes = 0
                reject_reason = ""

                while True:
                    l = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
                    if l is None:
                        return
                    if not body_started:
                        if l.startswith("BODYBYTES:"):
                            body_started = True
                            continue
                        if ":" in l:
                            k, v = l.split(":", 1)
                            fields[k.strip().upper()] = v.strip()
                            continue
                        await fwd_send_line(writer, f"{FORWARD_PROTO} ERR msg")
                        return

                    if l == ".":
                        endmsg = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
                        if endmsg != f"{FORWARD_PROTO} ENDMSG":
                            await fwd_send_line(writer, f"{FORWARD_PROTO} ERR msg")
                            return
                        break
                    if l.startswith(".."):
                        l = l[1:]
                    body_bytes += len((l + "\n").encode("utf-8"))
                    if body_bytes > CFG.forward_max_body_bytes:
                        reject_reason = "body_too_large"
                        # Drain body and ENDMSG marker.
                        while True:
                            dr = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
                            if dr is None:
                                return
                            if dr == ".":
                                endmsg = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
                                if endmsg is None:
                                    return
                                break
                        break
                    body_lines.append(l)
                else:
                    continue

                body = "\n".join(body_lines)
                bid = fields.get("BID", "?")
                if reject_reason:
                    await fwd_send_line(writer, f"{FORWARD_PROTO} REJECT {bid} {reject_reason}")
                    continue
                ok, reason = _store_forward_message(fields, body)
                if ok:
                    accepted += 1
                    await fwd_send_line(writer, f"{FORWARD_PROTO} ACCEPT {bid}")
                else:
                    await fwd_send_line(writer, f"{FORWARD_PROTO} REJECT {bid} {reason}")
            continue

        await fwd_send_line(writer, f"{FORWARD_PROTO} ERR cmd")
        break

    LOGGER.info("Forward session from %s accepted=%s", neighbor_name, accepted)


async def _fwd_read_bid_list(reader: asyncio.StreamReader) -> set[str]:
    out: set[str] = set()
    while True:
        line = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
        if line is None:
            break
        if line == f"{FORWARD_PROTO} END":
            break
        if line.startswith("BID:"):
            out.add(line[4:].strip())
    return out


async def _fwd_read_netinfo(reader: asyncio.StreamReader) -> tuple[str | None, list[str], list[tuple[str, str]]]:
    node: str | None = None
    neighbors: list[str] = []
    edges: list[tuple[str, str]] = []
    while True:
        line = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
        if line is None:
            break
        if line == f"{FORWARD_PROTO} END":
            break
        if line.startswith("NODE:"):
            node = normalize_bbs_name(line[5:].strip())
            continue
        if line.startswith("NEI:"):
            nei = normalize_bbs_name(line[4:].strip())
            if nei:
                neighbors.append(nei)
            continue
        if line.startswith("EDGE:"):
            raw = line[5:].strip()
            if "," in raw:
                src_raw, dst_raw = raw.split(",", 1)
                src = normalize_bbs_name(src_raw)
                dst = normalize_bbs_name(dst_raw)
                if src and dst and src != dst:
                    edges.append((src, dst))
    return node, sorted(set(neighbors)), sorted(set(edges))


async def forward_connect_and_push(neighbor: dict):
    nname = neighbor["name"]
    rows: list[sqlite3.Row] = _outbox_rows_for_neighbor(nname, CFG.forward_max_msgs_per_session)

    try:
        conn = asyncio.open_connection(neighbor["host"], neighbor["port"])
        reader, writer = await asyncio.wait_for(conn, timeout=CFG.forward_connect_timeout_sec)
    except Exception as e:
        for r in rows:
            outbox_mark_result(r["outbox_id"], "failed", f"connect:{type(e).__name__}")
        mark_neighbor_fail(nname, f"connect:{type(e).__name__}")
        LOGGER.warning("Forward connect failed neighbor=%s", nname)
        return

    try:
        t0 = time.monotonic()
        nonce = secrets.token_hex(10)
        await fwd_send_line(writer, f"{FORWARD_PROTO} HELLO {LOCAL_BBS_NAME} {nonce}")
        chall = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
        if not chall or not chall.startswith(f"{FORWARD_PROTO} CHALLENGE "):
            raise RuntimeError("no_challenge")
        server_nonce = chall.split(" ", 2)[2].strip()
        sig = _hmac_sig(neighbor["shared_key"], LOCAL_BBS_NAME, nonce, server_nonce)
        await fwd_send_line(writer, f"{FORWARD_PROTO} AUTH {sig}")
        ok_line = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
        if not ok_line or not ok_line.startswith(f"{FORWARD_PROTO} OK "):
            raise RuntimeError("auth")
        mark_neighbor_ok(nname, int((time.monotonic() - t0) * 1000))

        await fwd_send_line(writer, f"{FORWARD_PROTO} NETINFO")
        node_name, node_neighbors, node_edges = await _fwd_read_netinfo(reader)
        if node_edges:
            _replace_topology_edges_via(nname, node_edges)
        else:
            _store_topology_for_source(node_name or nname, node_neighbors, nname)

        remote_p_bids: set[str] = set()
        remote_b_bids: set[str] = set()
        await fwd_send_line(writer, f"{FORWARD_PROTO} LISTBID P")
        remote_p_bids |= await _fwd_read_bid_list(reader)
        for sc in sorted({s.upper() for s in CFG.scopes} | {"ALL"}):
            await fwd_send_line(writer, f"{FORWARD_PROTO} LISTBID B {sc}")
            remote_b_bids |= await _fwd_read_bid_list(reader)

        if CFG.forward_backfill_enabled:
            added = enqueue_missing_bulletins_for_neighbor(
                nname,
                remote_b_bids,
                int(CFG.forward_backfill_max_per_session),
            )
            if added > 0:
                LOGGER.info("Backfill neighbor=%s queued=%s", nname, added)

        rows = _outbox_rows_for_neighbor(nname, CFG.forward_max_msgs_per_session)
        if not rows:
            await fwd_send_line(writer, f"{FORWARD_PROTO} BYE")
            return

        for r in rows:
            outbox_mark_attempt(r["outbox_id"])

        push_rows: list[sqlite3.Row] = []
        for r in rows:
            if r["msg_type"] == "P" and r["bid"] in remote_p_bids:
                outbox_mark_result(r["outbox_id"], "sent", "")
                continue
            if r["msg_type"] == "B" and r["bid"] in remote_b_bids:
                outbox_mark_result(r["outbox_id"], "sent", "")
                continue
            push_rows.append(r)

        await fwd_send_line(writer, f"{FORWARD_PROTO} PUSH {len(push_rows)}")
        accepted = 0
        for r in push_rows:
            await fwd_send_line(writer, f"{FORWARD_PROTO} MSG")
            await fwd_send_line(writer, f"BID:{r['bid']}")
            await fwd_send_line(writer, f"TYPE:{r['msg_type']}")
            await fwd_send_line(writer, f"SCOPE:{r['scope'] or ''}")
            await fwd_send_line(writer, f"FROM:{r['sender']}")
            await fwd_send_line(writer, f"TO:{r['recipient']}")
            await fwd_send_line(writer, f"TOBBS:{r['recipient_bbs'] or ''}")
            await fwd_send_line(writer, f"SUBJ:{r['subject']}")
            await fwd_send_line(writer, f"CREATED:{r['created_at']}")
            await fwd_send_line(writer, f"PATH:{_path_append(r['path'] or '', LOCAL_BBS_NAME)}")
            await fwd_send_line(writer, f"BODYBYTES:{len((r['body'] or '').encode('utf-8'))}")
            for line in (r["body"] or "").splitlines():
                await fwd_send_line(writer, "." + line if line.startswith(".") else line)
            await fwd_send_line(writer, ".")
            await fwd_send_line(writer, f"{FORWARD_PROTO} ENDMSG")

            resp = await fwd_read_line(reader, CFG.forward_session_timeout_sec)
            if resp and resp.startswith(f"{FORWARD_PROTO} ACCEPT "):
                outbox_mark_result(r["outbox_id"], "sent", "")
                accepted += 1
            else:
                reason = "reject"
                if resp and resp.startswith(f"{FORWARD_PROTO} REJECT "):
                    reason = resp
                    parts = resp.split(" ", 3)
                    reject_reason = parts[3] if len(parts) >= 4 else ""
                    if r["msg_type"] == "P" and reject_reason == "no_such_user":
                        queue_ndn_for_message(r, reject_reason)
                        outbox_mark_result(r["outbox_id"], "rejected", reason[:200])
                        continue
                outbox_mark_result(r["outbox_id"], "failed", reason[:200])

        await fwd_send_line(writer, f"{FORWARD_PROTO} BYE")
        LOGGER.info("Forward to neighbor=%s sent=%s/%s", nname, accepted, len(push_rows))
    except Exception as e:
        mark_neighbor_fail(nname, f"session:{type(e).__name__}")
        for r in rows:
            if r["status"] != "sent":
                outbox_mark_result(r["outbox_id"], "failed", f"session:{type(e).__name__}")
        LOGGER.warning("Forward session failed neighbor=%s", nname)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def forward_loop():
    while True:
        try:
            cleanup_retention()
            if CFG.forward_enabled:
                for nei in enabled_neighbors():
                    await forward_connect_and_push(nei)
            refresh_local_topology()
        except Exception:
            LOGGER.exception("Forward loop error")
        await asyncio.sleep(max(5, int(CFG.forward_interval_sec)))


# ---- Server ----

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    sess = Session()
    SESSIONS_BY_WRITER[writer] = sess
    peer = peer_label(writer)
    LOGGER.info("client_connected peer=%s", peer)

    try:
        first_line = None
        try:
            first_line = await asyncio.wait_for(readline(reader), timeout=2.0)
        except asyncio.TimeoutError:
            first_line = None

        if first_line and first_line.startswith(f"{FORWARD_PROTO} "):
            LOGGER.info("forward_session_start peer=%s", peer)
            await handle_forward_session(reader, writer, first_line)
            return

        ok = await login_flow(reader, writer, sess, first_line=first_line, peer=peer)
        if not ok:
            LOGGER.info("client_disconnected peer=%s reason=login_failed", peer)
            writer.close()
            await writer.wait_closed()
            return

        # show unread info like classic bbs
        c = unread_count(sess.callsign)
        if c > 0:
            await send(writer, f"You have {c} new message(s).\r\n")

        while True:
            if not sess.in_convers:
                await send(writer, sess.prompt())

            line = await readline(reader, writer=writer, sess=sess, history_enabled=not sess.in_convers)
            if line is None:
                break

            if line.strip() == "":
                continue

            # Convers mode
            if sess.in_convers:
                up = line.strip().upper()
                if up in ("/EX", "/EXIT"):
                    sess.in_convers = False
                    CONVERS_CLIENTS.discard(writer)
                    await send(writer, "\r\nLeft convers.\r\n")
                    await convers_broadcast(f"* {sess.callsign} left convers")
                    LOGGER.info("convers_leave peer=%s user=%s", peer, sess.callsign)
                    continue

                if up in ("/WHO",):
                    await send(writer, "\r\n" + convers_users_text())
                    await convers_send_prompt(writer)
                    LOGGER.info("convers_who peer=%s user=%s", peer, sess.callsign)
                    continue

                await convers_broadcast(f"[{sess.callsign}] {line.strip()}")
                LOGGER.info("convers_msg peer=%s user=%s text=%s", peer, sess.callsign, line.strip()[:200])
                continue

            # Command mode
            parts = line.strip().split()
            cmd = parts[0].upper()
            cmd = ALIASES.get(cmd, cmd)
            sess.history_add(line.strip())
            LOGGER.info("cmd peer=%s user=%s cmd=%s args=%s", peer, sess.callsign, cmd, " ".join(parts[1:])[:120])

            if cmd in ("Q", "QUIT", "EXIT"):
                await send(writer, "Bye.\r\n")
                LOGGER.info("client_quit peer=%s user=%s", peer, sess.callsign)
                break

            if cmd in ("HELP", "?"):
                await send(writer, help_text())
                continue

            if cmd == "WHO":
                await send(writer, f"You are {sess.callsign}\r\n")
                continue

            if cmd == "MOTD":
                await send(writer, show_motd())
                continue

            if cmd == "INFO":
                await send(writer, show_info())
                continue

            if cmd == "C":
                sess.in_convers = True
                CONVERS_CLIENTS.add(writer)
                await send(writer, "Entered convers. Type /EX to leave.\r\n")
                await convers_broadcast(f"* {sess.callsign} joined convers")
                LOGGER.info("convers_join peer=%s user=%s", peer, sess.callsign)
                continue

            if cmd == "J":
                await send(writer, heard_list(CFG.heard_limit))
                continue

            if cmd in ("CONNECTION", "CONNECTIONS"):
                await send(writer, connections_list())
                continue

            if cmd == "TOPOLOGY":
                if len(parts) >= 2 and parts[1].upper() == "PRUNE":
                    if len(parts) < 3 or not parts[2].isdigit():
                        await send(writer, "Usage: TOPOLOGY PRUNE <minutes>\r\n")
                        continue
                    minutes = int(parts[2])
                    if minutes < 0:
                        await send(writer, "Minutes must be >= 0.\r\n")
                        continue
                    deleted = prune_topology_edges_older_than(minutes * 60)
                    await send(writer, f"Pruned {deleted} topology link(s) older than {minutes} minute(s).\r\n")
                    LOGGER.info("topology_prune peer=%s user=%s minutes=%s deleted=%s", peer, sess.callsign, minutes, deleted)
                    continue
                await send(writer, topology_overview())
                continue

            if cmd == "USERS":
                await send(writer, users_list())
                continue

            if cmd == "L":
                await send(writer, list_inbox(sess.callsign))
                continue

            if cmd == "N":
                await send(writer, list_new(sess.callsign))
                continue

            if cmd == "LS":
                await send(writer, list_sent(sess.callsign))
                continue

            if cmd == "R":
                if len(parts) < 2 or not parts[1].isdigit():
                    await send(writer, "Usage: R <id>\r\n")
                    continue
                await send(writer, read_private_message(sess.callsign, int(parts[1])))
                continue

            if cmd == "RN":
                mid = next_unread_id(sess.callsign)
                if mid is None:
                    await send(writer, "No unread mail.\r\n")
                    continue
                await send(writer, read_private_message(sess.callsign, mid))
                continue

            if cmd == "RE":
                if len(parts) < 2 or not parts[1].isdigit():
                    await send(writer, "Usage: RE <id>\r\n")
                    continue
                got = get_mail_for_reply(sess.callsign, int(parts[1]))
                if not got:
                    await send(writer, "No such mail to reply to.\r\n")
                    continue
                to_default, subj_default = got
                await send_private_interactive(reader, writer, sess, to_default=to_default, subject_default=subj_default)
                continue

            if cmd == "K":
                if len(parts) < 2 or not parts[1].isdigit():
                    await send(writer, "Usage: K <id>\r\n")
                    continue
                await send(writer, delete_from_inbox(sess.callsign, int(parts[1])))
                continue

            if cmd == "S":
                await send_private_interactive(reader, writer, sess)
                continue

            if cmd == "B":
                scope = parts[1].upper() if len(parts) >= 2 else ""
                await send(writer, list_bulletins(scope))
                continue

            if cmd == "RB":
                if len(parts) < 2 or not parts[1].isdigit():
                    await send(writer, "Usage: RB <id>\r\n")
                    continue
                await send(writer, read_bulletin(int(parts[1])))
                continue

            if cmd == "SB":
                await send_bulletin_interactive(reader, writer, sess)
                continue

            await send(writer, "Unknown command. Type HELP.\r\n")
            LOGGER.warning("cmd_unknown peer=%s user=%s raw=%s", peer, sess.callsign, line.strip()[:120])

    except Exception:
        LOGGER.exception("Unhandled exception in client handler peer=%s user=%s", peer, sess.callsign)
        try:
            await send(writer, "\r\nServer error.\r\n")
        except Exception:
            pass
    finally:
        if sess.in_convers:
            CONVERS_CLIENTS.discard(writer)
            try:
                await convers_broadcast(f"* {sess.callsign} left convers")
            except Exception:
                pass

        READLINE_SKIP_LF.pop(id(reader), None)
        SESSIONS_BY_WRITER.pop(writer, None)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        LOGGER.info("client_disconnected peer=%s user=%s", peer, sess.callsign or "-")


async def main():
    setup_logging()
    LOGGER.info("server_starting bbs=%s host=%s port=%s", CFG.bbs_callsign, CFG.host, CFG.port)
    init_db()
    server = await asyncio.start_server(handle_client, CFG.host, CFG.port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"{CFG.title} {CFG.version} listening on {addrs} as {CFG.bbs_callsign}")
    LOGGER.info("server_listening addrs=%s bbs=%s", addrs, CFG.bbs_callsign)
    asyncio.create_task(forward_loop())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
