#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import time

from test_ssh_server import (
    reserve_port,
    run_checked,
    shell_session,
    ssh_command,
    start_server,
    stop_server,
)


def wait_for_no_session_children(supervisor: subprocess.Popen[bytes],
                                 timeout: float = 5) -> None:
    children_path = pathlib.Path(
        f"/proc/{supervisor.pid}/task/{supervisor.pid}/children"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # The health monitor is the supervisor's one permanent child.
        if len(children_path.read_text().split()) == 1:
            return
        time.sleep(0.05)
    raise AssertionError(f"workers were not reaped: {children_path.read_text()!r}")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: test_ssh_protocol.py PROTOCOL_CLIENT ANVIL_EXECUTABLE"
        )
    client = pathlib.Path(sys.argv[1]).resolve()
    executable = pathlib.Path(sys.argv[2]).resolve()

    with tempfile.TemporaryDirectory(prefix="anvil-protocol-test-") as name:
        directory = pathlib.Path(name)
        host_key = directory / "host_key"
        client_key = directory / "client_key"
        (directory / "tos.txt").write_text("Test terms\n", encoding="utf-8")
        run_checked([
            "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
            str(client_key),
        ])

        port = reserve_port()
        server = start_server(executable, port, host_key, client_key)
        try:
            wait_for_no_session_children(server)
            for mode in (
                "open-close",
                "shell-before-pty",
                "pty-exec",
                "pty-subsystem",
                "second-operation",
                "shell-exit",
            ):
                result = subprocess.run(
                    [client, mode, str(port), client_key],
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                assert result.returncode == 0, (
                    mode, result.returncode, result.stdout, result.stderr
                )
                wait_for_no_session_children(server)

            replacement = shell_session(
                ssh_command(port, client_key), b"protocol-replacement\n"
            )
            assert replacement.returncode == 0, replacement
            assert b"protocol-replacement" in replacement.stdout
        finally:
            stop_server(server)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
