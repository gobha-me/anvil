#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import socket
import subprocess
import sys
import tempfile
import time


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def scan_host_key(port: int) -> bytes | None:
    result = subprocess.run(
        ["ssh-keyscan", "-T", "1", "-t", "ed25519", "-p", str(port), "127.0.0.1"],
        check=False,
        capture_output=True,
    )
    lines = [line for line in result.stdout.splitlines()
             if line and not line.startswith(b"#")]
    if not lines:
        return None
    return lines[0].split(maxsplit=1)[1]


def wait_for_key(process: subprocess.Popen[bytes], port: int) -> bytes:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(
                f"server exited before listening\nstdout={stdout!r}\nstderr={stderr!r}"
            )
        key = scan_host_key(port)
        if key is not None:
            return key
        time.sleep(0.1)
    raise AssertionError("server did not publish its host key")


def stop(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise AssertionError(f"server did not stop\nstdout={stdout!r}\nstderr={stderr!r}")
    if process.returncode != 0:
        raise AssertionError(
            f"server stopped with {process.returncode}\nstdout={stdout!r}\nstderr={stderr!r}"
        )
    return stdout, stderr


def start(executable: pathlib.Path, database: pathlib.Path, host_key: pathlib.Path,
          authorized_key: pathlib.Path, port: int, health_port: int,
          backup_directory: pathlib.Path | None = None) -> subprocess.Popen[bytes]:
    arguments = [
        str(executable), "--bind-address", "127.0.0.1", "--port", str(port),
        "--health-bind-address", "127.0.0.1", "--health-port", str(health_port),
        "--database", str(database), "--host-key", str(host_key),
        "--authorized-key", f"tester={authorized_key}",
    ]
    if backup_directory is not None:
        arguments.extend([
            "--backup-directory", str(backup_directory),
            "--backup-interval-seconds", "3600",
            "--backup-retention-seconds", "604800",
        ])
    return subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main(executable: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="anvil-backup-cli-") as raw_directory:
        directory = pathlib.Path(raw_directory)
        directory.chmod(0o700)
        client_key = directory / "client_key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client_key)],
            check=True,
        )
        database = directory / "anvil.db"
        host_key = directory / "host_key"
        backups = directory / "backups"

        port = free_port()
        health_port = free_port()
        while health_port == port:
            health_port = free_port()
        process = start(executable, database, host_key, client_key.with_suffix(".pub"),
                        port, health_port, backups)
        first_fingerprint = wait_for_key(process, port)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not list(backups.glob("anvil-backup-*")):
            if process.poll() is not None:
                break
            time.sleep(0.1)
        stop(process)
        snapshots = list(backups.glob("anvil-backup-*"))
        if not snapshots:
            raise AssertionError("scheduled backup was not published")
        original_key = host_key.read_bytes()

        one_shot = subprocess.run(
            [str(executable), "--backup-now", str(backups), "--database", str(database),
             "--host-key", str(host_key)],
            check=False,
            capture_output=True,
        )
        if one_shot.returncode != 0 or b"created backup" not in one_shot.stdout:
            raise AssertionError(
                f"one-shot backup failed\nstdout={one_shot.stdout!r}\nstderr={one_shot.stderr!r}"
            )

        for path in (database, pathlib.Path(str(database) + "-wal"),
                     pathlib.Path(str(database) + "-shm"), host_key):
            path.unlink(missing_ok=True)
        restored = subprocess.run(
            [str(executable), "--restore-backup", str(snapshots[0]),
             "--database", str(database), "--host-key", str(host_key)],
            check=False,
            capture_output=True,
        )
        if restored.returncode != 0 or b"restored" not in restored.stdout:
            raise AssertionError(
                f"restore failed\nstdout={restored.stdout!r}\nstderr={restored.stderr!r}"
            )
        if host_key.read_bytes() != original_key:
            raise AssertionError("restore changed the private host key")

        port = free_port()
        health_port = free_port()
        while health_port == port:
            health_port = free_port()
        process = start(executable, database, host_key, client_key.with_suffix(".pub"),
                        port, health_port)
        restored_fingerprint = wait_for_key(process, port)
        stop(process)
        if restored_fingerprint != first_fingerprint:
            raise AssertionError("restore changed the SSH host-key fingerprint")


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]).resolve())
