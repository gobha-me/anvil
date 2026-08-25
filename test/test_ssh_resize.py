#!/usr/bin/env python3

from __future__ import annotations

import fcntl
import os
import pathlib
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

from test_ssh_server import (
    reserve_port,
    run_checked,
    ssh_command,
    start_server,
    stop_server,
)


def set_window(descriptor: int, columns: int, rows: int,
               pixel_width: int = 0, pixel_height: int = 0) -> None:
    size = struct.pack("HHHH", rows, columns, pixel_width, pixel_height)
    fcntl.ioctl(descriptor, termios.TIOCSWINSZ, size)


def read_until(descriptor: int, expected: bytes, timeout: float,
               captured: bytearray) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        readable, _, _ = select.select([descriptor], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(descriptor, 16 * 1024)
            except OSError as error:
                if error.errno == 5:  # Linux pty EOF is EIO.
                    break
                raise
            if not chunk:
                break
            captured.extend(chunk)
            if expected in captured:
                return
    raise AssertionError(f"did not receive {expected!r}; output={bytes(captured)!r}")


def drain(descriptor: int) -> bytes:
    captured = bytearray()
    while True:
        readable, _, _ = select.select([descriptor], [], [], 0)
        if not readable:
            return bytes(captured)
        try:
            chunk = os.read(descriptor, 16 * 1024)
        except OSError as error:
            if error.errno == 5:
                return bytes(captured)
            raise
        if not chunk:
            return bytes(captured)
        captured.extend(chunk)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_ssh_resize.py ANVIL_EXECUTABLE")
    executable = pathlib.Path(sys.argv[1]).resolve()

    with tempfile.TemporaryDirectory(prefix="anvil-resize-test-") as directory_name:
        directory = pathlib.Path(directory_name)
        host_key = directory / "host_key"
        client_key = directory / "client_key"
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                     "-f", str(client_key)])

        port = reserve_port()
        server = start_server(executable, port, host_key, client_key)
        master, slave = pty.openpty()
        set_window(slave, 90, 30, 900, 600)
        client = subprocess.Popen(
            ssh_command(port, client_key) + ["-tt"],
            stdin=slave,
            stdout=slave,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        os.close(slave)
        captured = bytearray()
        try:
            read_until(master, b"Terminal: 90x30", 8, captured)

            time.sleep(0.25)
            drain(master)
            readable, _, _ = select.select([master], [], [], 0.35)
            assert not readable, "an idle demand-rendered session emitted output"

            os.write(master, b"echo-check")
            read_until(master, b"echo-check", 3, captured)

            set_window(master, 120, 40, 1200, 800)
            client.send_signal(signal.SIGWINCH)
            read_until(master, b"Terminal: 120x40", 4, captured)

            set_window(master, 0, 0)
            client.send_signal(signal.SIGWINCH)
            time.sleep(0.2)
            os.write(master, b"zero-safe")
            read_until(master, b"zero-safe", 3, captured)

            set_window(master, 65_535, 65_535)
            client.send_signal(signal.SIGWINCH)
            time.sleep(0.2)
            os.write(master, b"huge-safe")
            read_until(master, b"huge-safe", 3, captured)

            set_window(master, 100, 35)
            client.send_signal(signal.SIGWINCH)
            read_until(master, b"Terminal: 100x35", 4, captured)

            os.write(master, b"\x03")
            client.wait(timeout=5)
            assert client.returncode == 0, (client.returncode, bytes(captured))
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)
            os.close(master)
            stop_server(server)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
