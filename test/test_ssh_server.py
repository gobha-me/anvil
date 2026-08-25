#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import os
import pathlib
import re
import select
import signal
import subprocess
import sys
import tempfile
import time


def run_checked(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=15)


def reserve_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_until_listening(process: subprocess.Popen[bytes]) -> None:
    assert process.stdout is not None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise AssertionError(
                f"server exited before listening ({process.returncode})\n"
                f"stdout: {stdout.decode(errors='replace')}\n"
                f"stderr: {stderr.decode(errors='replace')}"
            )
        readable, _, _ = select.select([process.stdout], [], [], 0.1)
        if readable:
            line = process.stdout.readline()
            if b"anvil: listening on " in line:
                return
    raise AssertionError("server did not begin listening")


def ssh_command(port: int, identity: pathlib.Path, user: str = "tester") -> list[str]:
    return [
        "ssh",
        "-F", "/dev/null",
        "-i", str(identity),
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
        f"{user}@127.0.0.1",
    ]


def shell_session(base: list[str], payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(base + ["-T"], input=payload, capture_output=True,
                          timeout=15, check=False)


def assert_shell(result: subprocess.CompletedProcess[bytes], own: bytes,
                 foreign: bytes | None = None) -> int:
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert own in result.stdout, result.stdout
    if foreign is not None:
        assert foreign not in result.stdout, result.stdout
    match = re.search(rb"Anvil M0 echo session ([0-9]+)\r?\n", result.stdout)
    assert match is not None, result.stdout
    return int(match.group(1))


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_ssh_server.py ANVIL_EXECUTABLE")
    executable = pathlib.Path(sys.argv[1]).resolve()

    with tempfile.TemporaryDirectory(prefix="anvil-ssh-test-") as directory_name:
        directory = pathlib.Path(directory_name)
        host_key = directory / "host_key"
        client_key = directory / "client_key"
        wrong_key = directory / "wrong_key"
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client_key)])
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(wrong_key)])

        invalid_command = [
            str(executable),
            "--host-key", str(host_key),
            "--authorized-key", f"tester={client_key}.pub",
        ]
        os.chmod(host_key, 0o644)
        exposed_host_key = subprocess.run(invalid_command, capture_output=True,
                                          timeout=5, check=False)
        assert exposed_host_key.returncode == 2, exposed_host_key
        assert b"must not be accessible" in exposed_host_key.stderr, exposed_host_key.stderr
        os.chmod(host_key, 0o600)

        linked_key = directory / "linked_key.pub"
        linked_key.symlink_to(f"{client_key}.pub")
        symlinked_key = subprocess.run(
            [str(executable), "--host-key", str(host_key),
             "--authorized-key", f"tester={linked_key}"],
            capture_output=True, timeout=5, check=False,
        )
        assert symlinked_key.returncode == 2, symlinked_key
        assert b"cannot open key file" in symlinked_key.stderr, symlinked_key.stderr

        port = reserve_port()
        process = subprocess.Popen(
            [
                str(executable),
                "--bind-address", "127.0.0.1",
                "--port", str(port),
                "--max-sessions", "2",
                "--host-key", str(host_key),
                "--authorized-key", f"tester={client_key}.pub",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            wait_until_listening(process)
            base = ssh_command(port, client_key)

            first = shell_session(base, b"first-session\n")
            assert_shell(first, b"first-session\n")

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                alpha_future = executor.submit(shell_session, base, b"alpha-only\n")
                beta_future = executor.submit(shell_session, base, b"beta-only\n")
                alpha = alpha_future.result(timeout=20)
                beta = beta_future.result(timeout=20)
            alpha_pid = assert_shell(alpha, b"alpha-only\n", b"beta-only\n")
            beta_pid = assert_shell(beta, b"beta-only\n", b"alpha-only\n")
            assert alpha_pid != beta_pid, (alpha_pid, beta_pid)

            denied = subprocess.run(base + ["forbidden-command"], capture_output=True,
                                    timeout=15, check=False)
            assert denied.returncode != 0, denied
            assert b"does not execute commands" in denied.stderr, denied.stderr

            subsystem = subprocess.run(base[:-1] + ["-s", base[-1], "sftp"],
                                       capture_output=True, timeout=15, check=False)
            assert subsystem.returncode != 0, subsystem
            assert b"does not provide SSH subsystems" in subsystem.stderr, subsystem.stderr

            unauthorized = shell_session(ssh_command(port, wrong_key), b"intruder\n")
            assert unauthorized.returncode != 0, unauthorized
            assert b"intruder" not in unauthorized.stdout, unauthorized.stdout
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
                raise AssertionError(
                    f"server did not shut down\nstdout={stdout!r}\nstderr={stderr!r}"
                )
            assert process.returncode == 0, (process.returncode, stdout, stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
