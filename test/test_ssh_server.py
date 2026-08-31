#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import os
import pathlib
import re
import select
import signal
import sqlite3
import stat
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


def server_command(executable: pathlib.Path, port: int, host_key: pathlib.Path,
                   client_key: pathlib.Path, *,
                   database: pathlib.Path | None = None,
                   registration_mode: str = "open") -> list[str]:
    command = [
        str(executable),
        "--bind-address", "127.0.0.1",
        "--port", str(port),
        "--health-port", str(reserve_port()),
        "--max-sessions", "8",
        "--max-sessions-per-ip", "8",
        "--connection-rate-limit", "1000/1",
        "--auth-attempt-rate-limit", "1000/1",
        "--database", str(database or client_key.with_name(f"anvil-{port}.db")),
        "--registration-mode", registration_mode,
        "--host-key", str(host_key),
        "--authorized-key", f"tester={client_key}.pub",
    ]
    return command


def start_server(executable: pathlib.Path, port: int, host_key: pathlib.Path,
                 client_key: pathlib.Path, *,
                 database: pathlib.Path | None = None,
                 registration_mode: str = "open") -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        server_command(executable, port, host_key, client_key,
                       database=database, registration_mode=registration_mode),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_until_listening(process)
    return process


def stop_server(process: subprocess.Popen[bytes]) -> None:
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


def scanned_host_key(port: int) -> tuple[bytes, bytes]:
    result = subprocess.run(
        ["ssh-keyscan", "-T", "5", "-p", str(port), "127.0.0.1"],
        capture_output=True, timeout=10, check=False,
    )
    lines = [line for line in result.stdout.splitlines() if not line.startswith(b"#")]
    assert result.returncode == 0 and len(lines) == 1, result
    fields = lines[0].split()
    assert len(fields) >= 3, lines[0]
    return fields[1], fields[2]


def assert_refused(command: list[str], expected: bytes) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, capture_output=True, timeout=10, check=False)
    assert result.returncode == 2, result
    assert expected in result.stderr, result.stderr
    return result


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


def guest_command(port: int, user: str = "guest") -> list[str]:
    return [
        "ssh",
        "-F", "/dev/null",
        "-o", "PreferredAuthentications=none",
        "-o", "PubkeyAuthentication=no",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
        f"{user}@127.0.0.1",
    ]


def shell_session(base: list[str], payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(base + ["-tt"], input=payload, capture_output=True,
                          timeout=15, check=False)


def assert_shell(result: subprocess.CompletedProcess[bytes], own: bytes,
                 foreign: bytes | None = None) -> int:
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert own.rstrip(b"\n") in result.stdout, result.stdout
    if foreign is not None:
        assert foreign not in result.stdout, result.stdout
    match = re.search(rb"Anvil board session ([0-9]+)", result.stdout)
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
        invite_key = directory / "invite_key"
        losing_invite_key = directory / "losing_invite_key"
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client_key)])
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(wrong_key)])
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(invite_key)])
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(losing_invite_key)])

        provided_host_key = directory / "provided_host_key"
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                     "-f", str(provided_host_key)])
        invalid_command = server_command(
            executable, reserve_port(), provided_host_key, client_key
        )

        original_key = provided_host_key.read_bytes()
        os.chmod(provided_host_key, 0o644)
        assert_refused(invalid_command, b"must not be accessible")
        assert provided_host_key.read_bytes() == original_key
        os.chmod(provided_host_key, 0o600)

        if os.geteuid() != 0:
            os.chmod(provided_host_key, 0o000)
            assert_refused(invalid_command, b"cannot open key file")
            os.chmod(provided_host_key, 0o600)
            assert provided_host_key.read_bytes() == original_key

        malformed_host_key = directory / "malformed_host_key"
        malformed_host_key.write_bytes(b"not an OpenSSH private key\n")
        os.chmod(malformed_host_key, 0o600)
        malformed_contents = malformed_host_key.read_bytes()
        assert_refused(
            server_command(executable, reserve_port(), malformed_host_key, client_key),
            b"cannot configure SSH listener",
        )
        assert malformed_host_key.read_bytes() == malformed_contents

        oversized_host_key = directory / "oversized_host_key"
        oversized_host_key.write_bytes(b"x" * (64 * 1024 + 1))
        os.chmod(oversized_host_key, 0o600)
        assert_refused(
            server_command(executable, reserve_port(), oversized_host_key, client_key),
            b"invalid size",
        )
        assert oversized_host_key.stat().st_size == 64 * 1024 + 1

        host_key_symlink = directory / "host_key_symlink"
        host_key_symlink.symlink_to(provided_host_key.name)
        assert_refused(
            server_command(executable, reserve_port(), host_key_symlink, client_key),
            b"cannot open key file",
        )
        assert host_key_symlink.is_symlink()

        host_key_directory = directory / "host_key_directory"
        host_key_directory.mkdir()
        assert_refused(
            server_command(executable, reserve_port(), host_key_directory, client_key),
            b"not a regular file",
        )

        host_key_fifo = directory / "host_key_fifo"
        os.mkfifo(host_key_fifo, 0o600)
        assert_refused(
            server_command(executable, reserve_port(), host_key_fifo, client_key),
            b"not a regular file",
        )

        missing_parent = directory / "missing_parent"
        assert_refused(
            server_command(executable, reserve_port(),
                           missing_parent / "host_key", client_key),
            b"cannot open host key directory",
        )
        assert not missing_parent.exists()

        linked_key = directory / "linked_key.pub"
        linked_key.symlink_to(f"{client_key}.pub")
        assert_refused(
            [str(executable), "--database", str(directory / "linked-key.db"),
             "--host-key", str(provided_host_key),
             "--authorized-key", f"tester={linked_key}"],
            b"cannot open key file",
        )

        rsa_host_key = directory / "rsa_host_key"
        run_checked(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048",
                     "-N", "", "-f", str(rsa_host_key)])
        rsa_contents = rsa_host_key.read_bytes()
        rsa_port = reserve_port()
        rsa_server = start_server(executable, rsa_port, rsa_host_key, client_key)
        try:
            assert scanned_host_key(rsa_port)[0] == b"ssh-rsa"
            assert rsa_host_key.read_bytes() == rsa_contents
        finally:
            stop_server(rsa_server)

        port = reserve_port()
        process = start_server(executable, port, host_key, client_key)
        try:
            assert host_key.is_file()
            assert stat.S_IMODE(host_key.stat().st_mode) == 0o600
            assert not pathlib.Path(f"{host_key}.pub").exists()
            assert host_key.read_bytes().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
            first_host_key = scanned_host_key(port)
            assert first_host_key[0] == b"ssh-ed25519"
            base = ssh_command(port, client_key)

            no_pty = subprocess.run(base + ["-T"], input=b"ignored\n",
                                    capture_output=True, timeout=15, check=False)
            assert no_pty.returncode != 0, no_pty
            assert b"requires an interactive PTY" in no_pty.stderr, no_pty.stderr

            first = shell_session(base, b"first-session\n")
            assert_shell(first, b"first-session\n")
            assert b"Signed in as tester" in first.stdout, first.stdout

            spoofed = shell_session(ssh_command(port, client_key, "mallory"),
                                    b"same-key\n")
            assert_shell(spoofed, b"same-key\n")
            assert b"Signed in as tester" in spoofed.stdout, spoofed.stdout

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

            guest = shell_session(guest_command(port), b"cannot-post\n")
            assert guest.returncode == 0, guest
            assert b"Guest access: boards and doors are read-only" in guest.stdout, guest.stdout
            assert b"cannot-post" not in guest.stdout, guest.stdout

            non_guest_none = shell_session(guest_command(port, "visitor"), b"")
            assert non_guest_none.returncode != 0, non_guest_none

            registration_screen = shell_session(ssh_command(port, wrong_key), b"\x1b")
            assert registration_screen.returncode == 0, registration_screen
            assert b"There is no email recovery" in registration_screen.stdout, registration_screen.stdout

            registering = shell_session(ssh_command(port, wrong_key), b"new_user\n")
            assert registering.returncode == 0, registering
            assert b"Registration pending for new_user" in registering.stdout, registering.stdout

            pending = shell_session(ssh_command(port, wrong_key), b"ignored\n")
            assert pending.returncode == 0, pending
            assert b"Registration pending for new_user" in pending.stdout, pending.stdout
            assert b"ignored" not in pending.stdout, pending.stdout

            database = directory / f"anvil-{port}.db"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "UPDATE user_keys SET revoked_at=99 WHERE user_handle='new_user'"
                )
            revoked = shell_session(ssh_command(port, wrong_key), b"revoked\n")
            assert revoked.returncode != 0, revoked
            assert b"revoked" not in revoked.stdout, revoked.stdout
        finally:
            stop_server(process)

        closed_port = reserve_port()
        closed = start_server(
            executable, closed_port, host_key, client_key,
            registration_mode="closed",
        )
        try:
            closed_registration = shell_session(
                ssh_command(closed_port, invite_key), b"cannot-register\n"
            )
            assert closed_registration.returncode == 0, closed_registration
            assert b"not accepting new registrations" in closed_registration.stdout
            assert b"cannot-register" not in closed_registration.stdout
            closed_guest = shell_session(guest_command(closed_port), b"cannot-post\n")
            assert closed_guest.returncode == 0, closed_guest
            assert b"Guest access" in closed_guest.stdout, closed_guest.stdout
            known = shell_session(ssh_command(closed_port, client_key), b"known\n")
            assert b"Signed in as tester" in known.stdout, known.stdout
        finally:
            stop_server(closed)

        invite_database = directory / "invite-mode.db"
        bootstrap_port = reserve_port()
        bootstrap = start_server(
            executable, bootstrap_port, host_key, client_key,
            database=invite_database,
        )
        stop_server(bootstrap)
        invite_hash = (
            "fbaf7ba4264e2392988d8b5863e0a080"
            "bfe65b2a48d9b9f042f7cc7d4f711bb9"
        )
        with sqlite3.connect(invite_database) as connection:
            connection.execute(
                "INSERT INTO invites(code_hash,inviter_handle,status,created_at) "
                "VALUES(?, 'tester', 'active', 10)",
                (invite_hash,),
            )

        invite_port = reserve_port()
        invite_server = start_server(
            executable, invite_port, host_key, client_key,
            database=invite_database, registration_mode="invite",
        )
        try:
            invited = shell_session(
                ssh_command(invite_port, invite_key),
                b"invite-123\ninvited_user\n",
            )
            assert invited.returncode == 0, invited
            assert b"Registration pending for invited_user" in invited.stdout

            losing = shell_session(
                ssh_command(invite_port, losing_invite_key),
                b"invite-123\nlosing_user\nx",
            )
            assert losing.returncode == 0, losing
            assert b"Invite code is invalid or no longer available" in losing.stdout, losing.stdout
            assert b"Registration pending for losing_user" not in losing.stdout
        finally:
            stop_server(invite_server)

        with sqlite3.connect(invite_database) as connection:
            invite = connection.execute(
                "SELECT code_hash,status,claimed_by_handle FROM invites"
            ).fetchone()
            assert invite == (invite_hash, "claimed", "invited_user"), invite
            assert connection.execute(
                "SELECT count(*) FROM users WHERE handle='losing_user'"
            ).fetchone() == (0,)
            assert "invite-123" not in "\n".join(connection.iterdump())

        persisted_contents = host_key.read_bytes()
        restarted_port = reserve_port()
        restarted = start_server(executable, restarted_port, host_key, client_key)
        try:
            assert scanned_host_key(restarted_port) == first_host_key
            assert host_key.read_bytes() == persisted_contents
            assert_shell(shell_session(ssh_command(restarted_port, client_key),
                                       b"after-restart\n"), b"after-restart\n")
        finally:
            stop_server(restarted)

        race_key = directory / "race_host_key"
        race_ports = (reserve_port(), reserve_port())
        racers = [
            subprocess.Popen(
                server_command(executable, race_port, race_key, client_key),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            for race_port in race_ports
        ]
        try:
            for racer in racers:
                wait_until_listening(racer)
            assert scanned_host_key(race_ports[0]) == scanned_host_key(race_ports[1])
            assert stat.S_IMODE(race_key.stat().st_mode) == 0o600
        finally:
            for racer in racers:
                stop_server(racer)

        assert not list(directory.glob(".*.tmp.*"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
