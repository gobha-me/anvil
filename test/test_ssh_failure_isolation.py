#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

from test_ssh_server import (
    reserve_port, run_checked, shell_session, ssh_command, wait_until_listening,
)


FAILURE_MARKER = b"anvil-test-throw"
RESOURCE_CASES = {
    b"anvil-test-memory": (b"exceeded its memory limit", "memory"),
    b"anvil-test-cpu": (b"exceeded its CPU time slice", "cpu"),
    b"anvil-test-output": (b"exceeded its output limit", "output"),
    b"anvil-test-image": (b"exceeded its terminal image quota", "image"),
}


def start_server(executable: pathlib.Path, port: int, host_key: pathlib.Path,
                 client_key: pathlib.Path) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [
            str(executable),
            "--bind-address", "127.0.0.1",
            "--port", str(port),
            "--health-port", str(reserve_port()),
            "--max-sessions", "2",
            "--max-sessions-per-ip", "2",
            "--connection-rate-limit", "1000/1",
            "--auth-attempt-rate-limit", "1000/1",
            "--idle-timeout-seconds", "60",
            "--idle-warning-seconds", "5",
            "--session-cap-seconds", "120",
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
               timeout: float = 5) -> bytes:
    assert process.stdout is not None
    captured = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        readable, _, _ = select.select([process.stdout], [], [], 0.1)
        if readable:
            chunk = os.read(process.stdout.fileno(), 16 * 1024)
            if not chunk:
                break
            captured.extend(chunk)
            if expected in captured:
                return bytes(captured)
        if process.poll() is not None:
            break
    raise AssertionError(
        f"did not receive {expected!r}; output={bytes(captured)!r}; "
        f"returncode={process.poll()}"
    )


def open_session(port: int, client_key: pathlib.Path) -> tuple[subprocess.Popen[bytes], int]:
    process = start_session(port, client_key)
    output = read_until(process, b"Anvil board session")
    match = re.search(rb"Anvil board session ([0-9]+)", output)
    assert match is not None, output
    return process, int(match.group(1))


def send(process: subprocess.Popen[bytes], payload: bytes) -> None:
    assert process.stdin is not None
    process.stdin.write(payload)
    process.stdin.flush()


def stop_session(process: subprocess.Popen[bytes]) -> None:
    if (process.poll() is None and process.stdin is not None
            and not process.stdin.closed):
        try:
            send(process, b"\x03")
        except (BrokenPipeError, ValueError):
            pass
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def wait_for_worker_gone(supervisor: subprocess.Popen[bytes], worker: int,
                         timeout: float = 5) -> None:
    children_path = pathlib.Path(
        f"/proc/{supervisor.pid}/task/{supervisor.pid}/children"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        children = {int(value) for value in children_path.read_text().split()}
        if worker not in children:
            return
        time.sleep(0.05)
    raise AssertionError(f"worker {worker} was not reaped: {children_path.read_text()!r}")


def exercise_exception(supervisor: subprocess.Popen[bytes], port: int,
                       client_key: pathlib.Path) -> int:
    failing, failing_pid = open_session(port, client_key)
    survivor, _ = open_session(port, client_key)
    replacement: subprocess.Popen[bytes] | None = None
    try:
        send(failing, FAILURE_MARKER)
        output = read_until(failing, b"this session failed; the board remains available")
        failing.wait(timeout=3)
        assert failing.returncode != 0, (failing.returncode, output)

        send(survivor, b"exception-survivor")
        read_until(survivor, b"exception-survivor")
        assert supervisor.poll() is None

        wait_for_worker_gone(supervisor, failing_pid)
        replacement, _ = open_session(port, client_key)
        send(replacement, b"exception-replacement")
        read_until(replacement, b"exception-replacement")
        return failing_pid
    finally:
        stop_session(failing)
        stop_session(survivor)
        if replacement is not None:
            stop_session(replacement)


def exercise_signal(supervisor: subprocess.Popen[bytes], port: int,
                    client_key: pathlib.Path, fatal_signal: signal.Signals) -> int:
    failing, failing_pid = open_session(port, client_key)
    survivor, _ = open_session(port, client_key)
    replacement: subprocess.Popen[bytes] | None = None
    try:
        os.kill(failing_pid, fatal_signal)
        failing.communicate(timeout=5)
        assert failing.returncode != 0

        send(survivor, b"signal-survivor")
        read_until(survivor, b"signal-survivor")
        assert supervisor.poll() is None

        wait_for_worker_gone(supervisor, failing_pid)
        replacement, _ = open_session(port, client_key)
        send(replacement, b"signal-replacement")
        read_until(replacement, b"signal-replacement")
        return failing_pid
    finally:
        stop_session(failing)
        stop_session(survivor)
        if replacement is not None:
            stop_session(replacement)


def exercise_resource(supervisor: subprocess.Popen[bytes], port: int,
                      client_key: pathlib.Path, marker: bytes,
                      expected: bytes) -> int:
    failing, failing_pid = open_session(port, client_key)
    survivor, _ = open_session(port, client_key)
    replacement: subprocess.Popen[bytes] | None = None
    try:
        send(failing, marker)
        output = read_until(failing, expected, 8)
        failing.wait(timeout=3)
        assert failing.returncode != 0, (failing.returncode, output)

        send(survivor, b"resource-survivor")
        read_until(survivor, b"resource-survivor")
        assert supervisor.poll() is None

        wait_for_worker_gone(supervisor, failing_pid)
        replacement, _ = open_session(port, client_key)
        send(replacement, b"resource-replacement")
        read_until(replacement, b"resource-replacement")
        return failing_pid
    finally:
        stop_session(failing)
        stop_session(survivor)
        if replacement is not None:
            stop_session(replacement)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_ssh_failure_isolation.py TEST_SERVER_EXECUTABLE")
    executable = pathlib.Path(sys.argv[1]).resolve()
    fatal_signal = (
        signal.SIGKILL
        if os.environ.get("ANVIL_TEST_FATAL_SIGNAL") == "SIGKILL"
        else signal.SIGSEGV
    )

    with tempfile.TemporaryDirectory(prefix="anvil-failure-test-") as directory_name:
        directory = pathlib.Path(directory_name)
        host_key = directory / "host_key"
        client_key = directory / "client_key"
        (directory / "tos.txt").write_text("Test terms\n", encoding="utf-8")
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                     "-f", str(client_key)])

        port = reserve_port()
        supervisor = start_server(executable, port, host_key, client_key)
        try:
            exception_pid = exercise_exception(supervisor, port, client_key)
            signal_pid = exercise_signal(supervisor, port, client_key, fatal_signal)
            resource_pids = {
                name: exercise_resource(supervisor, port, client_key, marker, expected)
                for marker, (expected, name) in RESOURCE_CASES.items()
            }
        finally:
            if supervisor.poll() is None:
                supervisor.send_signal(signal.SIGTERM)
            try:
                stdout, stderr = supervisor.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                stdout, stderr = supervisor.communicate(timeout=5)
                raise AssertionError(
                    f"supervisor did not shut down; stdout={stdout!r}; stderr={stderr!r}"
                )
            if sys.exc_info()[0] is not None:
                print(stderr.decode(errors="replace"), file=sys.stderr)

        assert supervisor.returncode == 0, (supervisor.returncode, stdout, stderr)
        assert (
            f"anvil: session {exception_pid} failed: "
            "standard exception escaped terminal session"
        ).encode() in stderr, stderr
        assert (
            f"anvil: session worker {signal_pid} terminated by signal {fatal_signal}"
        ).encode() in stderr, stderr
        for name, worker in resource_pids.items():
            assert (
                f"anvil: session {worker} exceeded its {name} limit"
            ).encode() in stderr, stderr
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
