#!/usr/bin/env python3

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from collections.abc import Callable


class HardeningError(RuntimeError):
    pass


def _program_header_flags(program_headers: str, name: str) -> str | None:
    for line in program_headers.splitlines():
        fields = line.split()
        if fields and fields[0] == name and len(fields) >= 2:
            return fields[-2]
    return None


def validate_outputs(
    header: str,
    program_headers: str,
    dynamic: str,
    symbols: str,
    notes: str,
) -> None:
    failures: list[str] = []

    if re.search(r"^\s*Type:\s+DYN\b", header, re.MULTILINE) is None:
        failures.append("binary is not a PIE ELF (expected ELF type DYN)")

    if "GNU_RELRO" not in program_headers:
        failures.append("GNU_RELRO segment is missing")

    if "BIND_NOW" not in dynamic and re.search(
        r"\(FLAGS(?:_1)?\).*\bNOW\b", dynamic
    ) is None:
        failures.append("immediate binding is missing (expected BIND_NOW)")

    stack_flags = _program_header_flags(program_headers, "GNU_STACK")
    if stack_flags is None:
        failures.append("GNU_STACK segment is missing")
    elif "E" in stack_flags:
        failures.append("GNU_STACK is executable")

    if "__stack_chk_fail" not in symbols:
        failures.append("stack-canary reference __stack_chk_fail is missing")

    fortified = {
        match.group(0).split("@", maxsplit=1)[0]
        for match in re.finditer(
            r"\b__[A-Za-z0-9_]+_chk(?=@|\s|$)(?:@[^\s]+)?", symbols
        )
    }
    fortified.discard("__stack_chk_fail")
    if not fortified:
        failures.append("fortified libc _chk reference is missing")

    if re.search(
        r"^\s*Machine:\s+.*(?:X86-64|80386)", header, re.MULTILINE
    ) is not None and ("IBT" not in notes or "SHSTK" not in notes):
        failures.append("x86 CET properties IBT and SHSTK are missing")

    if failures:
        raise HardeningError("\n".join(failures))


def verify_binary(
    binary: pathlib.Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    if not binary.is_file():
        raise HardeningError(f"binary does not exist: {binary}")

    outputs: list[str] = []
    for option in ("-h", "-l", "-d", "-s", "-n"):
        try:
            result = runner(
                ["readelf", "-W", option, str(binary)],
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as error:
            raise HardeningError("readelf is required") from error
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or error.stdout or "readelf failed").strip()
            raise HardeningError(detail) from error
        outputs.append(result.stdout)

    validate_outputs(*outputs)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Anvil's required production ELF hardening properties"
    )
    parser.add_argument("binary", type=pathlib.Path)
    arguments = parser.parse_args()

    try:
        verify_binary(arguments.binary)
    except HardeningError as error:
        print(f"hardening verification failed for {arguments.binary}:", file=sys.stderr)
        print(error, file=sys.stderr)
        return 1

    print(f"verified hardened ELF: {arguments.binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
