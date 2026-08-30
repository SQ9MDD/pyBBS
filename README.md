# pyBBS

## PL

Działający proof of concept klasycznego packet-radio BBS-a, napisany w Pythonie (`asyncio` + `sqlite`) i inspirowany terminalami FBB. pyBBS udostępnia tę samą logikę BBS równolegle przez Telnet oraz prawdziwe połączenia AX.25 connected-mode prowadzone przez KISS TCP.

Projekt nie jest już wyłącznie symulatorem interfejsu: logowanie, uwierzytelnianie, banner, komendy i rozłączanie zostały uruchomione i sprawdzone w rzeczywistej sesji AX.25. Nadal jest to projekt eksperymentalny/hobbystyczny, a nie gotowy system produkcyjny.

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
- równoległy dostęp AX.25 connected-mode przez natywne API `pypacket_backend.py`
- wiele odizolowanych sesji AX.25 oraz niezależne sesje Telnet
- okresowy beacon informujący o dostępie do BBS-u

### Wymagania

- Python 3.10+ (zalecane 3.11+)
- klient Telnet (`telnet`, `nc`, PuTTY)
- dla AX.25: TNC lub proxy udostępniające KISS TCP

Brak zewnętrznych zależności PIP.

### Szybki start

```bash
python3 bbs.py
telnet 127.0.0.1 8023
```

Przy pierwszym logowaniu podajesz callsign, nazwę i hasło.

### Instalacja na Alpine Linux (OpenRC)

Uruchom jako `root`:

```bash
apk add --no-cache curl ca-certificates && curl -fsSL https://raw.githubusercontent.com/SQ9MDD/pyBBS/main/install-alpine.sh | sh
```

Instalator pobiera bieżącą gałąź `main` do `/opt/pyBBS`, tworzy nieuprzywilejowanego użytkownika `pybbs` oraz instaluje i uruchamia usługi OpenRC `pybbs-backend` i `pybbs`. Ponowne uruchomienie instalatora aktualizuje kod, ale zachowuje konfigurację, bazę wiadomości oraz edytowalne teksty BBS.

Po instalacji:

```bash
vi /opt/pyBBS/pypacket_terminal_config.json
vi /opt/pyBBS/bbs_config.json
rc-service pybbs-backend restart
rc-service pybbs restart
```

Status i logi:

```bash
rc-service pybbs-backend status
rc-service pybbs status
tail -f /var/log/pyBBS/backend.log /var/log/pyBBS/pybbs.log
```

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
  "topology_edge_ttl_sec": 1800,
  "topology_edge_retention_sec": 86400,
  "ax25": {
    "enabled": false,
    "callsign": "N0CALL",
    "backend_host": "127.0.0.1",
    "backend_port": 9101
  }
}
```

### Dostęp AX.25

Backend i BBS uruchamia się osobno:

```bash
python3 pypacket_backend.py
python3 bbs.py
```

Najpierw skonfiguruj endpoint KISS TCP w `pypacket_terminal_config.json`, a następnie ustaw `ax25.enabled` na `true` i właściwy znak BBS w `bbs_config.json`. BBS łączy się wyłącznie z natywnym API JSON Lines backendu (domyślnie `127.0.0.1:9101`). Lokalny serwer AGWPE backendu nasłuchuje na porcie `9100`. Niedostępny backend nie zatrzymuje serwera Telnet; konektor ponawia połączenie co 5 sekund. Wbudowana usługa tekstowa backendu również odpowiada na jego `station_callsign`, dlatego dla pyBBS należy pozostawić ten znak różny od `ax25.callsign` (sam znak BBS jest rejestrowany przez API). Okresowy beacon może używać znaku BBS niezależnie przez ustawienie `beacon_callsign`.

### Routing i topologia

- `CONNECTION` pokazuje:
- sąsiadów z configa (`HOST/PORT`, `UP/DOWN`, `RTT`, kolejki)
- linki topologii (`SRC`, `DST`, `VIA`, `AGE`, `STATUS=ACTIVE/DEAD`)
- wyliczone trasy (`DEST`, `NEXT_HOP`, `HOPS`, `PATH`)
- koszt trasy = liczba hopów
- topologia odświeża się cyklicznie przez wymianę `NETINFO`
- `topology_edge_ttl_sec` określa granicę ACTIVE/DEAD
- `topology_edge_retention_sec` określa jak długo trzymać stare wpisy topologii
- `TOPOLOGY PRUNE <minutes>` usuwa ręcznie linki starsze niż podany wiek

### Zachowanie przy błędach odbiorcy

- jeśli user nie istnieje na docelowym BBS:
- wiadomość dostaje `REJECT no_such_user`
- tworzona jest zwrotka NDN do nadawcy (`MAILER-DAEMON@BBS`)
- ten sam mail nie generuje NDN w pętli

### Komendy

- ogólne: `HELP`, `WHO`, `MOTD`, `INFO`, `Q`, `BYE`
- poczta: `L`, `LM`, `N`, `R`, `RM`, `RN`, `S`, `SP`, `RE`, `K`, `KM`, `KS`, `LS`
- biuletyny: `B`, `LB`, `RB`, `SB`
- inne: `J`, `MH`, `MHEARD`, `H`, `CONNECTION`, `CONNECTED`, `CONN`, `TOPOLOGY`, `TOPOLOGY PRUNE <minutes>`, `USERS`, `C`, `T`, `TALK`, `/WHO`, `/EX`

### Pliki

- `bbs.py` - serwer i logika BBS
- `ax25_connector.py` - adapter strumieniowy między pyBBS a natywnym API backendu
- `pypacket_backend.py` - obsługa KISS i AX.25 connected-mode
- `pypacket_terminal_config.json` - porty KISS TCP, beacon i ustawienia radiowe
- `bbs_config.json` - konfiguracja runtime
- `bbs.sqlite` - baza danych
- `logs/bbs.log` - log zdarzeń (rotacja pliku, logowania, komendy, forwarding)
- `welcome.txt`, `motd.txt`, `info.txt` - treści ekranów

---

## EN

A working proof of concept packet-radio BBS written in Python (`asyncio` + `sqlite`) and inspired by classic FBB terminal workflows. pyBBS exposes the same BBS logic concurrently through Telnet and real AX.25 connected-mode links carried over KISS TCP.

This is no longer only a terminal UI simulator: login, authentication, banners, commands, and disconnect handling have been exercised over a real AX.25 session. It remains an experimental/hobby project rather than production infrastructure.

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
- parallel AX.25 connected-mode access through the native `pypacket_backend.py` API
- multiple isolated AX.25 sessions alongside independent Telnet sessions
- periodic beacon advertising BBS access

### Requirements

- Python 3.10+ (3.11+ recommended)
- Telnet client (`telnet`, `nc`, PuTTY)
- for AX.25: a TNC or proxy exposing KISS TCP

No external PIP dependencies.

### Quick start

```bash
python3 bbs.py
telnet 127.0.0.1 8023
```

On first login, provide callsign, display name, and password.

### Alpine Linux installation (OpenRC)

Run as `root`:

```bash
apk add --no-cache curl ca-certificates && curl -fsSL https://raw.githubusercontent.com/SQ9MDD/pyBBS/main/install-alpine.sh | sh
```

The installer downloads the current `main` branch into `/opt/pyBBS`, creates an unprivileged `pybbs` user, and installs and starts the `pybbs-backend` and `pybbs` OpenRC services. Running it again updates application code while preserving configuration, the message database, and editable BBS text files.

After installation, edit `/opt/pyBBS/pypacket_terminal_config.json` and `/opt/pyBBS/bbs_config.json`, then restart both services with `rc-service`.

### Configuration (`bbs_config.json`)

The file is auto-generated on first run.  
See the JSON example in the PL section above (same fields/values apply).

### AX.25 access

Configure the KISS TCP endpoint in `pypacket_terminal_config.json`, enable the `ax25` block shown above, and start the two processes separately:

```bash
python3 pypacket_backend.py
python3 bbs.py
```

The BBS connects only to the backend's native JSON Lines API (default `127.0.0.1:9101`). The backend's local AGWPE server listens on port `9100`. If the backend is unavailable, Telnet remains available and the connector retries every five seconds. The backend's built-in text service also answers on its own `station_callsign`, so keep that callsign different from the BBS `ax25.callsign`; the connector registers the BBS callsign itself. A periodic beacon can independently use the BBS callsign through `beacon_callsign`.

### Routing and topology

- `CONNECTION` shows:
- configured direct neighbors (host/port/state/queue)
- topology links (`SRC`, `DST`, `VIA`, `AGE`, `STATUS=ACTIVE/DEAD`)
- discovered routes (`DEST`, `NEXT_HOP`, `HOPS`, `PATH`)
- route cost is hop count
- topology is refreshed periodically via `NETINFO` exchange
- `topology_edge_ttl_sec` defines ACTIVE/DEAD threshold
- `topology_edge_retention_sec` defines how long stale topology links are retained
- `TOPOLOGY PRUNE <minutes>` manually deletes links older than given age

### Unknown recipient behavior

- if destination user does not exist:
- message is rejected with `no_such_user`
- system generates one NDN back to sender (`MAILER-DAEMON@BBS`)
- duplicate NDN loops are prevented

### Commands

- general: `HELP`, `WHO`, `MOTD`, `INFO`, `Q`, `BYE`
- mail: `L`, `LM`, `N`, `R`, `RM`, `RN`, `S`, `SP`, `RE`, `K`, `KM`, `KS`, `LS`
- bulletins: `B`, `LB`, `RB`, `SB`
- other: `J`, `MH`, `MHEARD`, `H`, `CONNECTION`, `CONNECTED`, `CONN`, `TOPOLOGY`, `TOPOLOGY PRUNE <minutes>`, `USERS`, `C`, `T`, `TALK`, `/WHO`, `/EX`

### Notes

- Passwords are hashed, never stored in plain text.
- Runtime logs are written to `logs/bbs.log` (with rotation).
- This is a working proof of concept and hobby/educational project, not production infrastructure.
- For public deployments, use network isolation and strong `shared_key` values.
