# pyBBS

Lekki symulator klasycznego BBS-a (Bulletin Board System) działający po Telnet, napisany w Pythonie (`asyncio` + `sqlite`), z podstawowym stylem pracy zbliżonym do FBB.

## Funkcje

- logowanie użytkowników (callsign + hasło)
- prywatna poczta (`L`, `N`, `R`, `RN`, `S`, `RE`, `K`, `LS`)
- biuletyny (`B`, `RB`, `SB`)
- lista heard (`J` / `MH`)
- tryb convers (`C`, `/WHO`, `/EX`)
- lista zdefiniowanych sąsiadów (`CONNECTION`)
- lista zarejestrowanych użytkowników (`USERS`)
- forwarding wiadomości i biuletynów między sąsiadami
- local-only storage w `sqlite` (`bbs.sqlite`)

## Wymagania

- Python 3.10+ (zalecane 3.11+)
- klient Telnet (np. `telnet`, `netcat`, PuTTY)

Projekt nie wymaga zewnętrznych bibliotek PIP.

## Szybki start

1. Sklonuj repo i przejdź do katalogu projektu.
2. Uruchom serwer:

```bash
python3 bbs.py
```

3. Połącz się klientem Telnet:

```bash
telnet 127.0.0.1 8023
```

Przy pierwszym logowaniu podajesz callsign, nazwę i ustawiasz hasło.

## Konfiguracja

Plik: `bbs_config.json`

Jeśli nie istnieje, zostanie utworzony automatycznie z wartościami domyślnymi.

Przykładowa konfiguracja:

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
  "forward_max_body_bytes": 20000
}
```

## Forwarding między BBS-ami

1. Uruchom dwa węzły na różnych portach.
2. Ustaw różne `bbs_callsign`.
3. W `neighbors` dodaj wzajemnie oba węzły (ta sama para `shared_key`).
4. Wysyłaj pocztę do zdalnego użytkownika jako `CALLSIGN@NAZWA_BBS`.

Wiadomości są kolejkowane w `outbox` i wysyłane cyklicznie.

## Komendy

### Ogólne

- `HELP` - pomoc
- `WHO` - Twój callsign
- `MOTD` - wiadomość dnia
- `INFO` - informacje o BBS
- `Q` / `BYE` - wyjście

### Poczta prywatna

- `L` / `LM` - lista inbox
- `N` - lista nieprzeczytanych
- `R <id>` / `RM <id>` - czytaj wiadomość
- `RN` - czytaj następną nieprzeczytaną
- `S` / `SP` - napisz wiadomość
- `RE <id>` - odpowiedz
- `K <id>` / `KM <id>` - usuń z inbox
- `LS` - lista wysłanych

### Biuletyny

- `B [SCOPE]` / `LB` - lista biuletynów
- `RB <id>` - czytaj biuletyn
- `SB` - nowy biuletyn

### Pozostałe

- `J` / `MH` / `MHEARD` / `H` - heard list
- `CONNECTION` - lista sąsiadów (host/port/status/kolejka)
- `USERS` - lista zarejestrowanych użytkowników
- `C` / `T` / `TALK` - wejście do convers
- `/WHO` - kto jest w convers
- `/EX` - wyjście z convers

## Pliki projektu

- `bbs.py` - główny serwer
- `bbs_config.json` - konfiguracja runtime
- `bbs.sqlite` - baza danych (użytkownicy, wiadomości, outbox, heard)
- `welcome.txt` - ekran powitalny
- `motd.txt` - message of the day
- `info.txt` - informacje o węźle

## Uwagi

- Hasła nie są przechowywane jawnie (hash po stronie serwera).
- To projekt edukacyjno-hobbystyczny, nie produkcyjny system BBS.
- W środowisku publicznym ogranicz dostęp (firewall/VPN) i używaj mocnych kluczy `shared_key`.
