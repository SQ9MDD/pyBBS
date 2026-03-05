# pyBBS

## PL

Lekki symulator klasycznego BBS-a (Bulletin Board System) po Telnet, napisany w Pythonie (`asyncio` + `sqlite`), ze stylem terminalowym inspirowanym retro/FBB.

### Funkcje

- logowanie użytkowników (callsign + hasło)
- poczta prywatna (`L`, `N`, `R`, `RN`, `S`, `RE`, `K`, `LS`)
- biuletyny (`B`, `RB`, `SB`)
- convers (`C`, `/WHO`, `/EX`)
- heard list (`J`, `MH`, `MHEARD`, `H`)
- lista połączeń i topologii (`CONNECTION`, `CONNECTED`, `CONN`)
- lista zarejestrowanych użytkowników (`USERS`)
- forwarding biuletynów multi-hop
- forwarding prywatnych wiadomości po wyliczonych trasach (hops)
- okresowy alive check sąsiadów (UP/DOWN, RTT)
- auto NDN dla nieistniejącego odbiorcy (`no_such_user`)

### Wymagania

- Python 3.10+ (zalecane 3.11+)
- klient Telnet (`telnet`, `nc`, PuTTY)

Brak zewnętrznych zależności PIP.

### Szybki start

```bash
python3 bbs.py
telnet 127.0.0.1 8023
```

Przy pierwszym logowaniu podajesz callsign, nazwę i hasło.

### Konfiguracja (`bbs_config.json`)

Plik tworzy się automatycznie przy pierwszym uruchomieniu.

Przykład:

```json
{
  "host": "0.0.0.0",
  "port": 8023,
  "bbs_callsign": "N0CALL",
  "title": "PY-BBS",
  "version": "0.6",
  "prompt_bbs": "bbs> ",
  "prompt_convers": "conv> ",
  "heard_limit": 20,
  "scopes": ["ALL", "EU", "POL"],
  "neighbors": [
    {
      "name": "SQ5WLA",
      "host": "127.0.0.1",
      "port": 9023,
      "shared_key": "secretAB",
      "enabled": true
    }
  ],
  "forward_enabled": true,
  "forward_interval_sec": 60,
  "forward_connect_timeout_sec": 5,
  "forward_session_timeout_sec": 20,
  "forward_max_msgs_per_session": 50,
  "forward_max_body_bytes": 20000,
  "forward_backfill_enabled": true,
  "forward_backfill_max_per_session": 200,
  "bulletin_retention_days": 60,
  "outbox_retention_days": 14,
  "topology_edge_ttl_sec": 1800
}
```

### Routing i topologia

- `CONNECTION` pokazuje:
- sąsiadów z configa (`HOST/PORT`, `UP/DOWN`, `RTT`, kolejki)
- wyliczone trasy (`DEST`, `NEXT_HOP`, `HOPS`, `PATH`)
- koszt trasy = liczba hopów
- topologia odświeża się cyklicznie przez wymianę `NETINFO`

### Zachowanie przy błędach odbiorcy

- jeśli user nie istnieje na docelowym BBS:
- wiadomość dostaje `REJECT no_such_user`
- tworzona jest zwrotka NDN do nadawcy (`MAILER-DAEMON@BBS`)
- ten sam mail nie generuje NDN w pętli

### Komendy

- ogólne: `HELP`, `WHO`, `MOTD`, `INFO`, `Q`, `BYE`
- poczta: `L`, `LM`, `N`, `R`, `RM`, `RN`, `S`, `SP`, `RE`, `K`, `KM`, `LS`
- biuletyny: `B`, `LB`, `RB`, `SB`
- inne: `J`, `MH`, `MHEARD`, `H`, `CONNECTION`, `CONNECTED`, `CONN`, `USERS`, `C`, `T`, `TALK`, `/WHO`, `/EX`

### Pliki

- `bbs.py` - serwer i logika BBS
- `bbs_config.json` - konfiguracja runtime
- `bbs.sqlite` - baza danych
- `welcome.txt`, `motd.txt`, `info.txt` - treści ekranów

---

## EN

Lightweight retro-style Telnet BBS simulator written in Python (`asyncio` + `sqlite`), inspired by classic FBB-like terminal workflows.

### Features

- user login (callsign + password)
- private mail (`L`, `N`, `R`, `RN`, `S`, `RE`, `K`, `LS`)
- bulletins (`B`, `RB`, `SB`)
- convers mode (`C`, `/WHO`, `/EX`)
- heard list (`J`, `MH`, `MHEARD`, `H`)
- connection/topology view (`CONNECTION`, `CONNECTED`, `CONN`)
- registered users list (`USERS`)
- multi-hop bulletin forwarding
- routed private mail forwarding via computed next hop (hop-based)
- periodic neighbor alive checks (UP/DOWN, RTT)
- automatic NDN for unknown destination users (`no_such_user`)

### Requirements

- Python 3.10+ (3.11+ recommended)
- Telnet client (`telnet`, `nc`, PuTTY)

No external PIP dependencies.

### Quick start

```bash
python3 bbs.py
telnet 127.0.0.1 8023
```

On first login, provide callsign, display name, and password.

### Configuration (`bbs_config.json`)

The file is auto-generated on first run.  
See the JSON example in the PL section above (same fields/values apply).

### Routing and topology

- `CONNECTION` shows:
- configured direct neighbors (host/port/state/queue)
- discovered routes (`DEST`, `NEXT_HOP`, `HOPS`, `PATH`)
- route cost is hop count
- topology is refreshed periodically via `NETINFO` exchange

### Unknown recipient behavior

- if destination user does not exist:
- message is rejected with `no_such_user`
- system generates one NDN back to sender (`MAILER-DAEMON@BBS`)
- duplicate NDN loops are prevented

### Commands

- general: `HELP`, `WHO`, `MOTD`, `INFO`, `Q`, `BYE`
- mail: `L`, `LM`, `N`, `R`, `RM`, `RN`, `S`, `SP`, `RE`, `K`, `KM`, `LS`
- bulletins: `B`, `LB`, `RB`, `SB`
- other: `J`, `MH`, `MHEARD`, `H`, `CONNECTION`, `CONNECTED`, `CONN`, `USERS`, `C`, `T`, `TALK`, `/WHO`, `/EX`

### Notes

- Passwords are hashed, never stored in plain text.
- This is a hobby/educational project, not production infrastructure.
- For public deployments, use network isolation and strong `shared_key` values.
