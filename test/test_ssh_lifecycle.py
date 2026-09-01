#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import select
import signal
import subprocess
import sys
import tempfile
import time

from test_ssh_server import (
    reserve_port,
    run_checked,
    shell_session,
    ssh_command,
    stop_server,
    wait_until_listening,
)


def start_server(executable: pathlib.Path, port: int, host_key: pathlib.Path,
                 client_key: pathlib.Path, idle: int, warning: int,
                 cap: int) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [
            str(executable),
            "--bind-address", "127.0.0.1",
            "--port", str(port),
            "--health-port", str(reserve_port()),
            "--max-sessions", "8",
            "--idle-timeout-seconds", str(idle),
            "--idle-warning-seconds", str(warning),
            "--session-cap-seconds", str(cap),
            "--database", str(host_key.with_name(f"anvil-{port}.db")),
            "--tos-version", "v1",
            "--tos-file", str(client_key.with_name("tos.txt")),
            "--host-key", str(host_key),
            "--authorized-key", f"tester={client_key}.pub",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_until_listening(process)
    accepted = shell_session(ssh_command(port, client_key), b"ACCEPT\n\x1b")
    assert b"Current terms accepted" in accepted.stdout, accepted.stdout
    return process


def start_session(port: int, client_key: pathlib.Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        ssh_command(port, client_key) + ["-tt"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def read_until(process: subprocess.Popen[bytes], expected: bytes,
               timeout: float) -> bytes:
    assert process.stdout is not None
    captured = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        readable, _, _ = select.select([process.stdout], [], [], 0.1)
        if readable:
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            captured.extend(chunk)
            if expected in captured:
                return bytes(captured)
        if process.poll() is not None:
            break
    stderr = b""
    if process.poll() is not None and process.stderr is not None:
        stderr = process.stderr.read()
    raise AssertionError(
        f"did not receive {expected!r}; stdout={bytes(captured)!r}; stderr={stderr!r}"
    )


def wait_for_no_session_children(supervisor: subprocess.Popen[bytes], timeout: float = 5) -> None:
    children_path = pathlib.Path(
        f"/proc/{supervisor.pid}/task/{supervisor.pid}/children"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # The dedicated health process is a permanent supervised child.
        if len(children_path.read_text().split()) == 1:
            return
        time.sleep(0.05)
    raise AssertionError(f"workers were not reaped: {children_path.read_text()!r}")


def stop_session(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    process.communicate(timeout=5)


def wait_for_session_message(process: subprocess.Popen[bytes], expected: bytes,
                             timeout: float) -> tuple[bytes, bytes]:
    output = read_until(process, expected, timeout)
    process.wait(timeout=2)
    assert process.stderr is not None
    return output, process.stderr.read()


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_ssh_lifecycle.py ANVIL_EXECUTABLE")
    executable = pathlib.Path(sys.argv[1]).resolve()

    with tempfile.TemporaryDirectory(prefix="anvil-lifecycle-test-") as directory_name:
        directory = pathlib.Path(directory_name)
        host_key = directory / "host_key"
        client_key = directory / "client_key"
        (directory / "tos.txt").write_text("Test terms\n", encoding="utf-8")
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                     "-f", str(client_key)])

        idle_port = reserve_port()
        idle_server = start_server(
            executable, idle_port, host_key, client_key, idle=3, warning=2, cap=30
        )
        idle_session = start_session(idle_port, client_key)
        try:
            read_until(idle_session, b"idle session will close in 2 seconds", 5)
            assert idle_session.stdin is not None
            idle_session.stdin.write(b"awake\n")
            idle_session.stdin.flush()
            read_until(idle_session, b"awake", 2)
            read_until(idle_session, b"idle session will close in 2 seconds", 3)
            output, error = wait_for_session_message(
                idle_session, b"session closed after the idle timeout", 4
            )
            assert idle_session.returncode != 0, (idle_session.returncode, output, error)
        finally:
            stop_session(idle_session)

        sessions = [start_session(idle_port, client_key) for _ in range(4)]
        try:
            for session in sessions:
                read_until(session, b"Anvil board session", 5)
            for session in sessions:
                output, error = wait_for_session_message(
                    session, b"session closed after the idle timeout", 6
                )
                assert session.returncode != 0, (session.returncode, output, error)
            wait_for_no_session_children(idle_server)
            normal = shell_session(ssh_command(idle_port, client_key), b"still-alive\n")
            assert normal.returncode == 0, normal
            assert b"still-alive" in normal.stdout, normal.stdout
        finally:
            for session in sessions:
                stop_session(session)
            stop_server(idle_server)

        cap_port = reserve_port()
        cap_server = start_server(
            executable, cap_port, host_key, client_key, idle=10, warning=2, cap=3
        )
        cap_session = start_session(cap_port, client_key)
        try:
            read_until(cap_session, b"Anvil board session", 5)
            output, error = wait_for_session_message(
                cap_session, b"maximum session duration reached", 5
            )
            assert cap_session.returncode != 0, (cap_session.returncode, output, error)
        finally:
            stop_session(cap_session)
            stop_server(cap_server)

        shutdown_port = reserve_port()
        shutdown_server = start_server(
            executable, shutdown_port, host_key, client_key, idle=30, warning=5, cap=60
        )
        shutdown_session = start_session(shutdown_port, client_key)
        try:
            read_until(shutdown_session, b"Anvil board session", 5)
            shutdown_server.send_signal(signal.SIGTERM)
            output, error = wait_for_session_message(
                shutdown_session, b"server is shutting down", 5
            )
            assert shutdown_session.returncode in (0, 255), (
                shutdown_session.returncode, output, error
            )
            stop_server(shutdown_server)
        finally:
            stop_session(shutdown_session)
            if shutdown_server.poll() is None:
                stop_server(shutdown_server)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
