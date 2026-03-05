import asyncio
import sqlite3
import datetime
import secrets
import string
import json
import os
import logging
import hashlib
import hmac
from dataclasses import dataclass

DB_PATH = "bbs.sqlite"
CONFIG_PATH = "bbs_config.json"
WELCOME_PATH = "welcome.txt"
MOTD_PATH = "motd.txt"
INFO_PATH = "info.txt"

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
}

HELP = (
    "Commands:\r\n"
    "HELP - show this help\r\n"
    "WHO - show your callsign\r\n"
    "MOTD - show message of the day\r\n"
    "INFO - show BBS info\r\n"
    "Q or BYE - quit\r\n"
    "\r\n"
    "Mail:\r\n"
    "L or LM - list inbox\r\n"
    "N - list new (unread)\r\n"
    "R <id> or RM <id> - read mail\r\n"
    "RN - read next unread\r\n"
    "S or SP - send mail\r\n"
    "RE <id> - reply to mail\r\n"
    "K <id> or KM <id> - delete from inbox\r\n"
    "LS - list sent mail\r\n"
    "\r\n"
    "Bulletins:\r\n"
    "B [SCOPE] or LB - list bulletins\r\n"
    "RB <id> - read bulletin\r\n"
    "SB - send bulletin\r\n"
    "\r\n"
    "Other:\r\n"
    "J or MH or MHEARD or H - heard list\r\n"
    "CONNECTION - list configured neighbors\r\n"
    "USERS - list registered users\r\n"
    "C or T or TALK - convers mode\r\n"
    "/EX - leave convers\r\n"
    "/WHO - convers users\r\n"
)


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


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
    con.execute("CREATE INDEX IF NOT EXISTS idx_outbox_neighbor_status_try ON outbox(neighbor_name, status, last_try_at);")

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

    def prompt(self) -> str:
        return CFG.prompt_convers if self.in_convers else CFG.prompt_bbs


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


async def readline(reader: asyncio.StreamReader):
    """
    Returns:
      - None on EOF (client disconnected)
      - '' on empty line (user pressed Enter)
      - string without CRLF otherwise
    """
    rid = id(reader)
    data = bytearray()

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


def outbox_enqueue(msg_id: int, neighbor_name: str, status: str = "queued", last_error: str = ""):
    con = db()
    nname = normalize_bbs_name(neighbor_name)
    row = con.execute(
        "SELECT id FROM outbox WHERE msg_id = ? AND neighbor_name = ? LIMIT 1",
        (msg_id, nname),
    ).fetchone()
    if row:
        con.close()
        return
    con.execute(
        """
        INSERT INTO outbox(msg_id, neighbor_name, status, last_try_at, try_count, last_error, created_at)
        VALUES (?, ?, ?, NULL, 0, ?, ?)
        """,
        (msg_id, nname, status, (last_error or "")[:200], now_iso()),
    )
    con.commit()
    con.close()


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


def enabled_neighbors() -> list[dict]:
    return [n for n in NEIGHBORS_BY_NAME.values() if n.get("enabled")]


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

    if not rows:
        return "Heard list empty.\r\n"

    out = ["HEARD LIST\r\n", "CALLSIGN CONN LAST_SEEN FIRST_SEEN\r\n"]
    for r in rows:
        out.append(f"{r['callsign']} {r['connects']} {r['last_seen']} {r['first_seen']}\r\n")
    return "".join(out)


def connections_list() -> str:
    neighbors = sorted(NEIGHBORS_BY_NAME.values(), key=lambda n: n["name"])
    if not neighbors:
        return "No connections defined.\r\n"

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

    out = ["CONNECTIONS\r\n", "NAME HOST PORT EN QUEUED FAILED\r\n"]
    for n in neighbors:
        nstats = stats.get(n["name"], {"queued": 0, "failed": 0})
        enabled = "Y" if n.get("enabled") else "N"
        out.append(
            f"{n['name']} {n['host']} {n['port']} {enabled} {nstats['queued']} {nstats['failed']}\r\n"
        )
    return "".join(out)


def users_list() -> str:
    con = db()
    rows = con.execute("""
        SELECT callsign, name, created_at
        FROM users
        ORDER BY callsign ASC
    """).fetchall()
    con.close()

    if not rows:
        return "No registered users.\r\n"

    out = ["USERS\r\n", "CALLSIGN NAME CREATED_AT\r\n"]
    for r in rows:
        out.append(f"{r['callsign']} {normalize_name(r['name'] or '', r['callsign'])} {r['created_at']}\r\n")
    return "".join(out)


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


async def login_flow(reader, writer, sess: Session, first_line: str | None = None):
    await send(writer, show_welcome() + "\r\n")
    await send(writer, "Enter your callsign: ")

    cs = first_line if first_line is not None else await readline(reader)
    if cs is None:
        return False

    cs = normalize_callsign(cs)
    if not cs:
        await send(writer, "\r\nNo callsign, bye.\r\n")
        return False

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
            return False
        name = normalize_name(name_in, cs)

        pw1 = await read_hidden_input(reader, writer, "Set password: ")
        if pw1 is None:
            con.close()
            return False
        pw2 = await read_hidden_input(reader, writer, "Repeat password: ")
        if pw2 is None:
            con.close()
            return False
        if not pw1:
            await send(writer, "Empty password is not allowed.\r\n")
            con.close()
            return False
        if pw1 != pw2:
            await send(writer, "Passwords do not match.\r\n")
            con.close()
            return False

        con.execute(
            "INSERT INTO users(callsign, name, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (cs, name, hash_password(pw1), now_iso()),
        )
        display_name = name
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
                return False
            name = normalize_name(name_in if name_in.strip() else display_name, cs)

            pw1 = await read_hidden_input(reader, writer, "Set password: ")
            if pw1 is None:
                con.close()
                return False
            pw2 = await read_hidden_input(reader, writer, "Repeat password: ")
            if pw2 is None:
                con.close()
                return False
            if not pw1:
                await send(writer, "Empty password is not allowed.\r\n")
                con.close()
                return False
            if pw1 != pw2:
                await send(writer, "Passwords do not match.\r\n")
                con.close()
                return False

            con.execute(
                "UPDATE users SET name = ?, password_hash = ? WHERE callsign = ?",
                (name, hash_password(pw1), cs),
            )
            display_name = name
        else:
            authenticated = False
            for _ in range(3):
                pw = await read_hidden_input(reader, writer, "Password: ")
                if pw is None:
                    con.close()
                    return False
                if verify_password(pw, stored_hash):
                    authenticated = True
                    break
                await send(writer, "Invalid password.\r\n")
            if not authenticated:
                await send(writer, "Too many failed attempts.\r\n")
                con.close()
                return False

    con.commit()
    con.close()

    bump_heard(cs)

    sess.callsign = cs
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

    if not rows:
        return "Inbox empty.\r\n"

    out = ["ID N FROM SUBJECT DATE\r\n"]
    for r in rows:
        flag = " " if r["is_read"] else "*"
        out.append(f"{r['mid']} {flag} {r['sender']} {r['subject']} {r['created_at']}\r\n")
    return "".join(out)


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

    if not rows:
        return "No new mail.\r\n"

    out = ["NEW MAIL\r\n", "ID FROM SUBJECT DATE\r\n"]
    for r in rows:
        out.append(f"{r['mid']} {r['sender']} {r['subject']} {r['created_at']}\r\n")
    return "".join(out)


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
        return "No such mail in your inbox.\r\n"

    con.execute("UPDATE inbox SET is_read = 1 WHERE callsign = ? AND msg_id = ?", (callsign, mid))
    con.commit()
    con.close()

    hdr = (
        f"Msg {row['id']} BID {row['bid']}\r\n"
        f"From {row['sender']}\r\n"
        f"To {row['recipient']}\r\n"
        f"Subj {row['subject']}\r\n"
        f"Date {row['created_at']}\r\n"
        "\r\n"
    )
    body = row["body"].replace("\n", "\r\n")
    return hdr + body + "\r\n\r\n"


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
    return "Deleted.\r\n" if cur.rowcount else "Nothing deleted.\r\n"


def list_sent(callsign: str) -> str:
    con = db()
    rows = con.execute("""
        SELECT id, recipient, subject, created_at
        FROM messages
        WHERE msg_type = 'P' AND sender = ?
        ORDER BY id DESC
        LIMIT ?
    """, (callsign, CFG.max_sent_list)).fetchall()
    con.close()

    if not rows:
        return "Sent mail empty.\r\n"

    out = ["SENT MAIL\r\n", "ID TO SUBJECT DATE\r\n"]
    for r in rows:
        out.append(f"{r['id']} {r['recipient']} {r['subject']} {r['created_at']}\r\n")
    return "".join(out)


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
    sender_for_store = f"{sess.callsign}@{LOCAL_BBS_NAME}" if is_remote else sess.callsign

    bid = make_bid(sess.callsign)
    con = db()
    con.execute("""
        INSERT INTO messages(bid, msg_type, scope, sender, recipient, recipient_bbs, subject, body, path, created_at)
        VALUES (?, 'P', NULL, ?, ?, ?, ?, ?, ?, ?)
    """, (bid, sender_for_store, recipient, recipient_bbs, subj[:80], body, LOCAL_BBS_NAME, now_iso()))
    mid = con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    if is_remote:
        neighbor = NEIGHBORS_BY_NAME.get(recipient_bbs)
        if neighbor and neighbor.get("enabled"):
            con.execute(
                """
                INSERT INTO outbox(msg_id, neighbor_name, status, last_try_at, try_count, last_error, created_at)
                VALUES (?, ?, 'queued', NULL, 0, '', ?)
                """,
                (mid, recipient_bbs, now_iso()),
            )
        else:
            con.execute(
                """
                INSERT INTO outbox(msg_id, neighbor_name, status, last_try_at, try_count, last_error, created_at)
                VALUES (?, ?, 'failed', ?, 1, ?, ?)
                """,
                (mid, recipient_bbs or "", now_iso(), "unknown or disabled neighbor", now_iso()),
            )
    else:
        con.execute("INSERT INTO inbox(callsign, msg_id, is_read, created_at) VALUES (?, ?, 0, ?)", (recipient, mid, now_iso()))
    con.commit()
    con.close()

    if is_remote:
        await send(writer, f"Queued Msg {mid} BID {bid} to {recipient}@{recipient_bbs}\r\n")
    else:
        await send(writer, f"Sent Msg {mid} BID {bid}\r\n")


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

    if not rows:
        return f"No bulletins for scope {scope}.\r\n"

    out = [f"BULLETINS {scope}\r\n", "ID FROM SUBJECT DATE\r\n"]
    for r in rows:
        out.append(f"{r['id']} {r['sender']} {r['subject']} {r['created_at']}\r\n")
    return "".join(out)


def read_bulletin(mid: int) -> str:
    con = db()
    row = con.execute("""
        SELECT id, bid, scope, sender, subject, body, created_at
        FROM messages
        WHERE id = ? AND msg_type = 'B'
    """, (mid,)).fetchone()
    con.close()

    if not row:
        return "No such bulletin.\r\n"

    hdr = (
        f"Bulletin {row['id']} BID {row['bid']}\r\n"
        f"From {row['sender']}\r\n"
        f"Scope {row['scope']}\r\n"
        f"Subj {row['subject']}\r\n"
        f"Date {row['created_at']}\r\n"
        "\r\n"
    )
    body = row["body"].replace("\n", "\r\n")
    return hdr + body + "\r\n\r\n"


async def send_bulletin_interactive(reader, writer, sess: Session):
    await send(writer, f"Scope ({'/'.join(CFG.scopes)}): ")
    sc = await readline(reader)
    if sc is None:
        return
    sc = normalize_scope(sc)
    if not sc:
        await send(writer, "Invalid scope.\r\n")
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

    con = db()
    con.execute("""
        INSERT INTO messages(bid, msg_type, scope, sender, recipient, recipient_bbs, subject, body, path, created_at)
        VALUES (?, 'B', ?, ?, 'ALL', NULL, ?, ?, ?, ?)
    """, (bid, sc, sess.callsign, subj[:80], body, LOCAL_BBS_NAME, now_iso()))
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

    if msg_type == "P":
        if recipient_bbs and recipient_bbs != LOCAL_BBS_NAME:
            con.close()
            return False, "wrong_tobbs"
        con.execute(
            """
            INSERT INTO messages(bid, msg_type, scope, sender, recipient, recipient_bbs, subject, body, path, created_at)
            VALUES (?, 'P', NULL, ?, ?, ?, ?, ?, ?, ?)
            """,
            (bid, sender, recipient, recipient_bbs or None, subject, body, _path_append(path, LOCAL_BBS_NAME), created_at),
        )
        mid = con.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        con.execute("INSERT INTO inbox(callsign, msg_id, is_read, created_at) VALUES (?, ?, 0, ?)", (recipient, mid, now_iso()))
    else:
        con.execute(
            """
            INSERT INTO messages(bid, msg_type, scope, sender, recipient, recipient_bbs, subject, body, path, created_at)
            VALUES (?, 'B', ?, ?, 'ALL', NULL, ?, ?, ?, ?)
            """,
            (bid, scope, sender, subject, body, _path_append(path, LOCAL_BBS_NAME), created_at),
        )

    con.commit()
    con.close()
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


async def forward_connect_and_push(neighbor: dict):
    nname = neighbor["name"]
    rows = _outbox_rows_for_neighbor(nname, CFG.forward_max_msgs_per_session)
    if not rows:
        return

    for r in rows:
        outbox_mark_attempt(r["outbox_id"])

    try:
        conn = asyncio.open_connection(neighbor["host"], neighbor["port"])
        reader, writer = await asyncio.wait_for(conn, timeout=CFG.forward_connect_timeout_sec)
    except Exception as e:
        for r in rows:
            outbox_mark_result(r["outbox_id"], "failed", f"connect:{type(e).__name__}")
        LOGGER.warning("Forward connect failed neighbor=%s", nname)
        return

    try:
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

        remote_p_bids: set[str] = set()
        remote_b_bids: set[str] = set()
        await fwd_send_line(writer, f"{FORWARD_PROTO} LISTBID P")
        remote_p_bids |= await _fwd_read_bid_list(reader)
        for sc in sorted({s.upper() for s in CFG.scopes} | {"ALL"}):
            await fwd_send_line(writer, f"{FORWARD_PROTO} LISTBID B {sc}")
            remote_b_bids |= await _fwd_read_bid_list(reader)

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
                outbox_mark_result(r["outbox_id"], "failed", reason[:200])

        await fwd_send_line(writer, f"{FORWARD_PROTO} BYE")
        LOGGER.info("Forward to neighbor=%s sent=%s/%s", nname, accepted, len(push_rows))
    except Exception as e:
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
            if CFG.forward_enabled:
                for nei in enabled_neighbors():
                    await forward_connect_and_push(nei)
        except Exception:
            LOGGER.exception("Forward loop error")
        await asyncio.sleep(max(5, int(CFG.forward_interval_sec)))


# ---- Server ----

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    sess = Session()
    SESSIONS_BY_WRITER[writer] = sess

    try:
        first_line = None
        try:
            first_line = await asyncio.wait_for(readline(reader), timeout=2.0)
        except asyncio.TimeoutError:
            first_line = None

        if first_line and first_line.startswith(f"{FORWARD_PROTO} "):
            await handle_forward_session(reader, writer, first_line)
            return

        ok = await login_flow(reader, writer, sess, first_line=first_line)
        if not ok:
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

            line = await readline(reader)
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
                    continue

                if up in ("/WHO",):
                    await send(writer, "\r\n" + convers_users_text())
                    await convers_send_prompt(writer)
                    continue

                await convers_broadcast(f"[{sess.callsign}] {line.strip()}")
                continue

            # Command mode
            parts = line.strip().split()
            cmd = parts[0].upper()
            cmd = ALIASES.get(cmd, cmd)

            if cmd in ("Q", "QUIT", "EXIT"):
                await send(writer, "Bye.\r\n")
                break

            if cmd in ("HELP", "?"):
                await send(writer, HELP)
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
                continue

            if cmd == "J":
                await send(writer, heard_list(CFG.heard_limit))
                continue

            if cmd in ("CONNECTION", "CONNECTIONS"):
                await send(writer, connections_list())
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

    except Exception:
        LOGGER.exception("Unhandled exception in client handler")
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


async def main():
    init_db()
    server = await asyncio.start_server(handle_client, CFG.host, CFG.port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"{CFG.title} {CFG.version} listening on {addrs} as {CFG.bbs_callsign}")
    if CFG.forward_enabled:
        asyncio.create_task(forward_loop())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
