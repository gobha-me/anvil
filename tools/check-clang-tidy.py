#!/usr/bin/env python3
"""Compare clang-tidy diagnostics with Anvil's exact legacy baseline."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import subprocess
import sys


DIAGNOSTIC = re.compile(
    r"^(?P<path>.+):(?P<line>[0-9]+):(?P<column>[0-9]+): "
    r"(?:warning|error): (?P<message>.*) "
    r"\[(?P<checks>[A-Za-z0-9_.,-]+)(?:,-warnings-as-errors)?\]$"
)


def repository_root() -> pathlib.Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    )
    return pathlib.Path(result.stdout.strip()).resolve()


def normalized_context(path: pathlib.Path, line_number: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise RuntimeError(f"cannot read diagnostic source {path}: {error}") from error

    if line_number < 1 or line_number > len(lines):
        raise RuntimeError(
            f"diagnostic line {line_number} is outside {path} ({len(lines)} lines)"
        )

    begin = max(0, line_number - 2)
    end = min(len(lines), line_number + 1)
    return "\n".join(" ".join(line.split()) for line in lines[begin:end])


def diagnostics(output: pathlib.Path, root: pathlib.Path) -> set[str]:
    entries: set[str] = set()
    malformed: list[str] = []

    for raw_line in output.read_text(encoding="utf-8", errors="replace").splitlines():
        match = DIAGNOSTIC.match(raw_line)
        if match is None:
            if str(root) in raw_line and re.search(r": (?:warning|error): ", raw_line):
                malformed.append(raw_line)
            continue

        source = pathlib.Path(match.group("path")).resolve()
        try:
            relative = source.relative_to(root)
        except ValueError:
            continue

        if not relative.parts or relative.parts[0] not in {"include", "src"}:
            continue

        message = " ".join(match.group("message").split())
        checks = match.group("checks")
        context = normalized_context(source, int(match.group("line")))
        digest = hashlib.sha256(
            f"{checks}\0{message}\0{context}".encode("utf-8")
        ).hexdigest()[:20]
        entries.add(f"{relative.as_posix()}\t{checks}\t{digest}\t{message}")

    if malformed:
        details = "\n".join(malformed[:10])
        raise RuntimeError(f"unparsed project diagnostics:\n{details}")

    return entries


def read_baseline(path: pathlib.Path) -> set[str]:
    entries: set[str] = set()
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw_line or raw_line.startswith("#"):
            continue
        if raw_line != raw_line.strip() or raw_line.count("\t") != 3:
            raise RuntimeError(f"malformed baseline entry at {path}:{line_number}")
        if raw_line in entries:
            raise RuntimeError(f"duplicate baseline entry at {path}:{line_number}")
        entries.add(raw_line)
    return entries


def write_baseline(path: pathlib.Path, entries: set[str]) -> None:
    content = [
        "# clang-tidy 20 legacy diagnostic baseline",
        "# New exceptions belong in source as exact, justified NOLINT directives.",
        *sorted(entries),
    ]
    path.write_text("\n".join(content) + "\n", encoding="utf-8")


def report(title: str, entries: set[str]) -> None:
    if not entries:
        return
    print(f"{title} ({len(entries)}):", file=sys.stderr)
    for entry in sorted(entries)[:50]:
        path, checks, _, message = entry.split("\t", maxsplit=3)
        print(f"  {path}: [{checks}] {message}", file=sys.stderr)
    if len(entries) > 50:
        print(f"  ... and {len(entries) - 50} more", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("baseline", type=pathlib.Path)
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()

    root = repository_root()
    actual = diagnostics(args.output, root)

    if args.write_baseline:
        write_baseline(args.baseline, actual)
        print(f"wrote {len(actual)} legacy diagnostics to {args.baseline}")
        return 0

    expected = read_baseline(args.baseline)
    unexpected = actual - expected
    resolved = expected - actual
    if unexpected or resolved:
        report("new or changed clang-tidy diagnostics", unexpected)
        report("resolved or stale baseline diagnostics", resolved)
        print(
            "clang-tidy baseline mismatch: fix the finding or use an exact, "
            "justified NOLINT; remove resolved baseline entries",
            file=sys.stderr,
        )
        return 1

    print(f"clang-tidy passed with {len(actual)} unchanged legacy diagnostics")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
