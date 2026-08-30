import asyncio
import base64
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
IMPORT_DIR = tempfile.TemporaryDirectory()
ORIGINAL_CWD = os.getcwd()
os.chdir(IMPORT_DIR.name)
sys.path.insert(0, str(ROOT))
import bbs  # noqa: E402
from ax25_connector import AX25Connector  # noqa: E402
os.chdir(ORIGINAL_CWD)


class MockBackend:
    def __init__(self):
        self.server = None
        self.writer = None
        self.register = asyncio.Event()
        self.register_message = None
        self.output = asyncio.Queue()
        self.commands = []

    async def start(self):
        self.server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def _client(self, reader, writer):
        self.writer = writer
        await self.emit({"event": "hello", "api_version": 1, "sessions": []})
        try:
            while raw := await reader.readline():
                message = json.loads(raw)
                self.commands.append(message)
                command = message.get("cmd")
                if command == "register":
                    self.register_message = message
                    self.register.set()
                    await self.reply(message, registered=[message["callsign"]])
                elif command == "monitor_off":
                    await self.reply(message, monitor=False)
                elif command == "send":
                    payload = base64.b64decode(message["data_b64"])
                    await self.output.put(payload)
                    await self.reply(message)
                elif command == "disconnect":
                    await self.reply(message)
                else:
                    await self.reply(message, ok=False, error="unsupported")
        finally:
            writer.close()
            await writer.wait_closed()

    async def reply(self, request, ok=True, **fields):
        await self.emit({
            "event": "reply",
            "id": request["id"],
            "cmd": request["cmd"],
            "ok": ok,
            **fields,
        })

    async def emit(self, message):
        if self.writer is None:
            return
        self.writer.write((json.dumps(message) + "\n").encode())
        await self.writer.drain()

    async def collect_until(self, marker: bytes, timeout=3.0):
        chunks = bytearray()

        async def collect():
            while marker not in chunks:
                chunks.extend(await self.output.get())
            return bytes(chunks)

        return await asyncio.wait_for(collect(), timeout)

    async def close(self):
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


class AX25AccessIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        os.chdir(IMPORT_DIR.name)
        for filename in ("bbs.sqlite",):
            try:
                os.unlink(filename)
            except FileNotFoundError:
                pass
        bbs.init_db()
        con = sqlite3.connect(bbs.DB_PATH)
        for callsign in ("SQ5ABC-7", "SQ5XYZ-2", "TELNET-1"):
            con.execute(
                "INSERT INTO users(callsign, name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (callsign, callsign, bbs.hash_password("secret"), bbs.now_iso()),
            )
        con.commit()
        con.close()

        self.backend = MockBackend()
        backend_port = await self.backend.start()
        self.connector = AX25Connector(
            "127.0.0.1",
            backend_port,
            "SQ9MDD-1",
            bbs.handle_client,
            reconnect_delay=60,
        )
        self.connector_task = asyncio.create_task(self.connector.run())
        await asyncio.wait_for(self.backend.register.wait(), 2.0)

        self.telnet_server = await asyncio.start_server(
            bbs.handle_client, "127.0.0.1", 0
        )

    async def asyncTearDown(self):
        self.telnet_server.close()
        await self.telnet_server.wait_closed()
        self.connector_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await self.connector_task
        await self.backend.close()
        os.chdir(ORIGINAL_CWD)

    async def _telnet_read_until(self, reader, marker: bytes):
        return await asyncio.wait_for(reader.readuntil(marker), 4.0)

    async def test_telnet_and_ax25_sessions_are_parallel_and_isolated(self):
        self.assertEqual(self.backend.register_message["cmd"], "register")
        self.assertEqual(self.backend.register_message["callsign"], "SQ9MDD-1")

        telnet_port = self.telnet_server.sockets[0].getsockname()[1]
        telnet_reader, telnet_writer = await asyncio.open_connection(
            "127.0.0.1", telnet_port
        )
        telnet_writer.write(b"TELNET-1\r")
        await telnet_writer.drain()
        telnet_login = await self._telnet_read_until(telnet_reader, b"Password: ")
        self.assertIn(b"Enter your callsign: ", telnet_login)
        telnet_writer.write(b"secret\r")
        await telnet_writer.drain()
        await self._telnet_read_until(telnet_reader, b"bbs> ")

        session = {
            "port_id": "2",
            "local": "SQ9MDD-1",
            "remote": "SQ5ABC-7",
            "state": "CONNECTED",
        }
        await self.backend.emit({
            "event": "connected", "incoming": True, "session": session
        })
        radio_login = await self.backend.collect_until(b"Password: ")
        self.assertNotIn(b"Enter your callsign: ", radio_login)

        await self.backend.emit({
            "event": "rx_data",
            "port_id": "2",
            "local": "SQ9MDD-1",
            "remote": "SQ5ABC-7",
            "data_b64": base64.b64encode(b"secret\r").decode(),
        })
        radio_ready = await self.backend.collect_until(b"bbs> ")
        self.assertIn(b"SQ5ABC-7", radio_ready)

        await self.backend.emit({
            "event": "rx_data",
            "port_id": "2",
            "local": "SQ9MDD-1",
            "remote": "SQ5ABC-7",
            "data_b64": base64.b64encode(b"HELP\r").decode(),
        })
        radio_help = await self.backend.collect_until(b"COMMANDS")
        all_radio_output = radio_login + radio_ready + radio_help
        self.assertNotIn(bytes([bbs.TELNET_IAC]), all_radio_output)

        telnet_writer.write(b"HELP\r")
        await telnet_writer.drain()
        telnet_help = await self._telnet_read_until(telnet_reader, b"COMMANDS")
        self.assertIn(b"COMMANDS", telnet_help)

        second_session = {
            "port_id": "3",
            "local": "SQ9MDD-1",
            "remote": "SQ5XYZ-2",
            "state": "CONNECTED",
        }
        await self.backend.emit({
            "event": "connected", "incoming": True, "session": second_session
        })
        await asyncio.sleep(0.05)
        self.assertEqual(len(self.connector.sessions), 2)

        await self.backend.emit({
            "event": "disconnected",
            "reason": "Remote disconnected",
            "session": session,
        })
        await asyncio.sleep(0.05)
        self.assertEqual(len(self.connector.sessions), 1)
        self.assertIn(("3", "SQ9MDD-1", "SQ5XYZ-2"), self.connector.sessions)

        telnet_writer.write(b"WHO\r")
        await telnet_writer.drain()
        telnet_who = await self._telnet_read_until(telnet_reader, b"TELNET-1\r\n")
        self.assertIn(b"You are TELNET-1", telnet_who)

        await self.backend.emit({
            "event": "disconnected",
            "reason": "Remote disconnected",
            "session": second_session,
        })

        telnet_writer.write(b"Q\r")
        await telnet_writer.drain()
        telnet_writer.close()
        await telnet_writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
