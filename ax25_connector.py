"""Async byte-stream adapter for pypacket_backend.py's native JSON API."""

import asyncio
import base64
import contextlib
import json
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable


SessionKey = tuple[str, str, str]


class AX25Reader:
    """The small StreamReader subset used by bbs.py."""

    transport_type = "ax25"

    def __init__(self):
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._buffer = bytearray()
        self._eof = False

    def feed_data(self, data: bytes):
        if data and not self._eof:
            self._queue.put_nowait(bytes(data))

    def feed_eof(self):
        if not self._eof:
            self._eof = True
            self._queue.put_nowait(None)

    async def _fill(self):
        while not self._buffer and not (self._eof and self._queue.empty()):
            item = await self._queue.get()
            if item is None:
                break
            self._buffer.extend(item)

    async def read(self, n: int = -1) -> bytes:
        await self._fill()
        if not self._buffer:
            return b""
        if n < 0:
            n = len(self._buffer)
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data

    async def readline(self) -> bytes:
        line = bytearray()
        while True:
            byte = await self.read(1)
            if not byte:
                return bytes(line)
            line.extend(byte)
            if byte == b"\n":
                return bytes(line)


class AX25Writer:
    """The small StreamWriter subset used by bbs.py."""

    transport_type = "ax25"

    def __init__(self, connector: "AX25Connector", key: SessionKey, reader: AX25Reader):
        self._connector = connector
        self._key = key
        self._reader = reader
        self._buffer = bytearray()
        self._drain_lock = asyncio.Lock()
        self._close_task: asyncio.Task | None = None
        self._closed = False
        self._remote_closed = False

    def write(self, data: bytes):
        if self._remote_closed:
            return
        if self._closed:
            raise ConnectionError("AX.25 session is closed")
        self._buffer.extend(data)

    async def drain(self):
        async with self._drain_lock:
            if self._remote_closed:
                self._buffer.clear()
                return
            if self._closed:
                raise ConnectionError("AX.25 session is closed")
            if not self._buffer:
                return
            data = bytes(self._buffer)
            self._buffer.clear()
            await self._connector.send_data(self._key, data)

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._reader.feed_eof()
        if not self._remote_closed:
            self._close_task = asyncio.create_task(self._connector.disconnect(self._key))

    async def wait_closed(self):
        if self._close_task is not None:
            with contextlib.suppress(Exception):
                await self._close_task

    def is_closing(self) -> bool:
        return self._closed

    def get_extra_info(self, name: str, default=None):
        if name == "peername":
            port_id, local, remote = self._key
            return f"AX25:{remote}->{local}@{port_id}"
        return default

    def remote_closed(self):
        self._remote_closed = True
        self._closed = True
        self._reader.feed_eof()


@dataclass
class _RadioSession:
    reader: AX25Reader
    writer: AX25Writer
    task: asyncio.Task


class AX25Connector:
    """Reconnectable client for the backend's native NDJSON API."""

    def __init__(
        self,
        host: str,
        port: int,
        callsign: str,
        session_handler: Callable[..., Awaitable[None]],
        logger: logging.Logger | None = None,
        reconnect_delay: float = 5.0,
    ):
        self.host = host
        self.port = port
        self.callsign = callsign.strip().upper()
        self.session_handler = session_handler
        self.log = logger or logging.getLogger(__name__)
        self.reconnect_delay = reconnect_delay
        self.sessions: dict[SessionKey, _RadioSession] = {}
        self._api_writer: asyncio.StreamWriter | None = None
        self._write_lock = asyncio.Lock()
        self._pending: dict[int, asyncio.Future] = {}
        self._next_id = 1
        self._connect_failures = 0

    @staticmethod
    def _key(session: dict) -> SessionKey:
        return (
            str(session.get("port_id", "0")),
            str(session.get("local", "")).strip().upper(),
            str(session.get("remote", "")).strip().upper(),
        )

    async def run(self):
        while True:
            receiver = None
            try:
                api_reader, api_writer = await asyncio.open_connection(self.host, self.port)
                self._api_writer = api_writer
                self.log.info("AX25: connected to backend %s:%s", self.host, self.port)
                receiver = asyncio.create_task(self._receive_loop(api_reader))
                reply = await self._request("register", callsign=self.callsign)
                if not reply.get("ok"):
                    raise ConnectionError(reply.get("error", "registration failed"))
                await self._request("monitor_off")
                self._connect_failures = 0
                self.log.info("AX25: registered %s", self.callsign)
                await receiver
                raise ConnectionError("backend API connection closed")
            except asyncio.CancelledError:
                if receiver is not None:
                    receiver.cancel()
                await self._close_backend()
                self._end_all_sessions()
                raise
            except Exception as exc:
                self._connect_failures += 1
                if self._connect_failures == 1 or self._connect_failures % 12 == 0:
                    self.log.warning(
                        "AX25: backend %s:%s unavailable: %s",
                        self.host,
                        self.port,
                        exc,
                    )
            finally:
                if receiver is not None and not receiver.done():
                    receiver.cancel()
                await self._close_backend()
                self._fail_pending(ConnectionError("backend API connection lost"))
                self._end_all_sessions()
            await asyncio.sleep(self.reconnect_delay)

    async def _close_backend(self):
        writer, self._api_writer = self._api_writer, None
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _request(self, command: str, **fields) -> dict:
        writer = self._api_writer
        if writer is None:
            raise ConnectionError("backend API is not connected")
        request_id = self._next_id
        self._next_id += 1
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._pending[request_id] = future
        message = {"cmd": command, "id": request_id, **fields}
        try:
            async with self._write_lock:
                writer.write((json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8"))
                await writer.drain()
            return await asyncio.wait_for(future, timeout=10.0)
        finally:
            self._pending.pop(request_id, None)

    async def _receive_loop(self, reader: asyncio.StreamReader):
        while True:
            raw = await reader.readline()
            if not raw:
                return
            try:
                message = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self.log.warning("AX25: invalid backend message: %s", exc)
                continue
            if message.get("event") == "reply" and "id" in message:
                future = self._pending.get(message["id"])
                if future is not None and not future.done():
                    future.set_result(message)
                continue
            await self._handle_event(message)

    async def _handle_event(self, message: dict):
        event = message.get("event")
        if event == "hello":
            station_callsign = str(message.get("station_callsign", "")).strip().upper()
            if station_callsign == self.callsign:
                self.log.warning(
                    "AX25: backend station_callsign %s also enables its built-in text service; "
                    "configure a different backend station callsign for pyBBS access",
                    self.callsign,
                )
            return

        if event == "connected" and message.get("incoming"):
            session = message.get("session") or {}
            key = self._key(session)
            if key[1] == self.callsign and key[2]:
                self._start_session(key)
            return

        if event == "rx_data":
            key = self._key(message)
            radio_session = self.sessions.get(key)
            if radio_session is not None:
                try:
                    payload = base64.b64decode(message.get("data_b64", ""), validate=True)
                except Exception:
                    self.log.warning("AX25: invalid payload for %s", key[2])
                    return
                radio_session.reader.feed_data(payload)
            return

        if event == "disconnected":
            session = message.get("session") or {}
            self._end_session(
                self._key(session),
                reason=str(message.get("reason", "")).strip(),
            )

    def _start_session(self, key: SessionKey):
        if key in self.sessions:
            return
        reader = AX25Reader()
        writer = AX25Writer(self, key, reader)
        task = asyncio.create_task(
            self.session_handler(reader, writer, preset_callsign=key[2])
        )
        self.sessions[key] = _RadioSession(reader, writer, task)
        self.log.info("AX25: incoming %s -> %s port=%s", key[2], key[1], key[0])

    def _end_session(self, key: SessionKey, reason: str = ""):
        radio_session = self.sessions.pop(key, None)
        if radio_session is None:
            return
        radio_session.writer.remote_closed()
        if reason:
            self.log.info("AX25: disconnected %s reason=%s", key[2], reason)
        else:
            self.log.info("AX25: disconnected %s", key[2])

    def _end_all_sessions(self):
        for key in list(self.sessions):
            self._end_session(key)

    def _fail_pending(self, exc: Exception):
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(exc)

    async def send_data(self, key: SessionKey, data: bytes):
        port_id, local, remote = key
        reply = await self._request(
            "send",
            port_id=port_id,
            local=local,
            remote=remote,
            data_b64=base64.b64encode(data).decode("ascii"),
        )
        if not reply.get("ok"):
            raise ConnectionError(reply.get("error", "AX.25 send failed"))

    async def disconnect(self, key: SessionKey):
        if self._api_writer is None:
            return
        port_id, local, remote = key
        reply = await self._request(
            "disconnect", port_id=port_id, local=local, remote=remote
        )
        if not reply.get("ok") and reply.get("error") != "session not found":
            self.log.warning("AX25: disconnect %s failed: %s", remote, reply.get("error"))
