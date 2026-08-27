#!/usr/bin/env python3

from __future__ import annotations

import http.client
import json
import os
import pathlib
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

from test_ssh_server import reserve_port, run_checked, ssh_command, wait_until_listening


def request(port: int, path: str, method: str = "GET",
            body: bytes | None = None) -> tuple[int, str, bytes]:
    deadline = time.monotonic() + 5
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            connection.request(method, path, body=body)
            response = connection.getresponse()
            body = response.read()
            content_type = response.getheader("Content-Type", "")
            connection.close()
            return response.status, content_type, body
        except OSError as error:
            last_error = error
            time.sleep(0.05)
    raise AssertionError(f"health endpoint did not respond: {last_error}")


def test_component_failure(executable: pathlib.Path, mode: str,
                           expected_name: str, expected_reason: str) -> None:
    port = reserve_port()
    process = subprocess.Popen(
        [str(executable), str(port), mode], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline() == b"ready\n"
        status, content_type, body = request(port, "/readyz")
        assert status == 503, (status, body)
        assert content_type.startswith("application/json"), content_type
        document = json.loads(body)
        assert document["status"] == "not_ready", document
        assert document["failures"][0]["name"] == expected_name, document
        assert document["failures"][0]["reason"] == expected_reason, document
        post_status, _, _ = request(port, "/readyz", "POST")
        assert post_status in (404, 405), post_status
        large_status, _, _ = request(port, "/livez", "GET", b"x" * 2048)
        assert large_status == 413, large_status
    finally:
        if process.stdin is not None:
            process.stdin.write(b"\n")
            process.stdin.flush()
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, (process.returncode, stdout, stderr)


def read_until(process: subprocess.Popen[bytes], expected: bytes, timeout: float = 5) -> bytes:
    assert process.stdout is not None
    captured = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        readable, _, _ = select.select([process.stdout], [], [], 0.1)
        if not readable:
            if process.poll() is not None:
                break
            continue
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            break
        captured.extend(chunk)
        if expected in captured:
            return bytes(captured)
    raise AssertionError(f"did not receive {expected!r}: {bytes(captured)!r}")


def wait_for_metric(port: int, pattern: bytes, timeout: float = 5) -> bytes:
    deadline = time.monotonic() + timeout
    last = b""
    while time.monotonic() < deadline:
        status, _, last = request(port, "/metrics")
        if status == 200 and re.search(pattern, last):
            return last
        time.sleep(0.05)
    raise AssertionError(f"metric did not match {pattern!r}: {last!r}")


def test_live_server(executable: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="anvil-health-test-") as directory_name:
        directory = pathlib.Path(directory_name)
        host_key = directory / "host_key"
        client_key = directory / "client_key"
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client_key)])
        ssh_port = reserve_port()
        health_port = reserve_port()
        server = subprocess.Popen(
            [
                str(executable), "--bind-address", "127.0.0.1", "--port", str(ssh_port),
                "--health-bind-address", "127.0.0.1", "--health-port", str(health_port),
                "--host-key", str(host_key), "--authorized-key", f"tester={client_key}.pub",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        session: subprocess.Popen[bytes] | None = None
        try:
            wait_until_listening(server)
            status, _, body = request(health_port, "/livez")
            assert status == 200 and json.loads(body)["status"] == "live", body
            status, _, body = request(health_port, "/readyz")
            ready = json.loads(body)
            assert status == 200 and ready["status"] == "ready", body
            assert ready["components"] == [
                {"kind": "storage", "name": "database", "state": "not_configured",
                 "version": ""}
            ], ready
            metrics = wait_for_metric(health_port, rb"anvil_ssh_active_sessions 0")
            assert b"tester" not in metrics and b"127.0.0.1" not in metrics, metrics

            session = subprocess.Popen(
                ssh_command(ssh_port, client_key) + ["-tt"], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            read_until(session, b"Anvil M0 echo session")
            metrics = wait_for_metric(
                health_port, rb"anvil_session_frames_total\{session=\"[0-9]+\"\} [1-9]"
            )
            assert b"anvil_ssh_active_sessions 1" in metrics, metrics
            assert session.stdin is not None
            session.stdin.write(b"health-check\x1b")
            session.stdin.flush()
            session.communicate(timeout=10)
            session = None
            wait_for_metric(health_port, rb"anvil_ssh_active_sessions 0")

            children_path = pathlib.Path(f"/proc/{server.pid}/task/{server.pid}/children")
            children = [int(value) for value in children_path.read_text().split()]
            assert len(children) == 1, children
            os.kill(children[0], signal.SIGKILL)
            server.wait(timeout=5)
            assert server.returncode != 0, server.returncode
        finally:
            if session is not None:
                session.kill()
                session.communicate(timeout=5)
            if server.poll() is None:
                server.send_signal(signal.SIGTERM)
                server.communicate(timeout=10)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_health_http.py HEALTH_TEST_SERVER ANVIL")
    health_server = pathlib.Path(sys.argv[1]).resolve()
    anvil = pathlib.Path(sys.argv[2]).resolve()
    test_component_failure(health_server, "storage-failed", "database", "database unreachable")
    test_component_failure(
        health_server, "plugin-failed", 'hostile"plugin', "ABI tag mismatch"
    )
    test_live_server(anvil)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
