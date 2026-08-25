#!/usr/bin/env python3
"""Verify the published SDK declarations against append-only ABI history."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from typing import Any


class AbiHistoryError(RuntimeError):
    pass


def _enum_value(node: dict[str, Any]) -> str:
    for child in node.get("inner", []):
        if child.get("kind") == "ConstantExpr" and "value" in child:
            return child["value"]
    raise AbiHistoryError(f"enum value is unavailable for {node.get('name')}")


def _record(name: str, node: dict[str, Any]) -> dict[str, Any]:
    fields = [
        {"name": child["name"], "type": child["type"]["qualType"]}
        for child in node.get("inner", [])
        if child.get("kind") == "FieldDecl"
    ]
    methods = [
        {
            "name": child["name"],
            "type": child["type"]["qualType"],
            "virtual": bool(child.get("virtual")),
            "pure": bool(child.get("pure")),
        }
        for child in node.get("inner", [])
        if child.get("kind") in {"CXXMethodDecl", "CXXDestructorDecl"}
        and not child.get("isImplicit")
    ]
    field_names = [field["name"] for field in fields]
    extensible = bool(
        field_names[:1] == ["struct_size"]
        or field_names[:2] == ["magic", "struct_size"]
    )
    is_interface = bool(node.get("definitionData", {}).get("isAbstract"))
    return {
        "kind": "interface" if is_interface else "record",
        "name": f"anvil::{name}",
        "extensible": extensible,
        "fields": fields,
        "methods": methods,
    }


def extract_declarations(compiler: str, include_dir: pathlib.Path) -> list[dict[str, Any]]:
    sdk_dir = include_dir / "anvil/sdk"
    headers = sorted(sdk_dir.glob("*.hpp"))
    if not headers:
        raise AbiHistoryError(f"no SDK headers found under {sdk_dir}")
    includes = "".join(
        f"#include <{header.relative_to(include_dir).as_posix()}>\n"
        for header in headers
    )
    command = [
        compiler,
        "-std=c++23",
        f"-I{include_dir}",
        "-x",
        "c++",
        "-",
        "-Xclang",
        "-ast-dump=json",
        "-fsyntax-only",
    ]
    completed = subprocess.run(
        command,
        input=includes,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AbiHistoryError(
            f"{compiler} could not parse the SDK headers:\n{completed.stderr}"
        )
    try:
        ast = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AbiHistoryError(f"invalid Clang AST JSON: {error}") from error

    declarations: list[dict[str, Any]] = []
    for namespace in ast.get("inner", []):
        if namespace.get("kind") != "NamespaceDecl" or namespace.get("name") != "anvil":
            continue
        for node in namespace.get("inner", []):
            if (
                node.get("kind") == "CXXRecordDecl"
                and node.get("completeDefinition")
                and not node.get("isImplicit")
            ):
                declarations.append(_record(node["name"], node))
            elif node.get("kind") == "ClassTemplateDecl":
                definition = next(
                    (
                        child
                        for child in node.get("inner", [])
                        if child.get("kind") == "CXXRecordDecl"
                        and child.get("completeDefinition")
                    ),
                    None,
                )
                if definition is not None:
                    declarations.append(_record(node["name"], definition))
            elif node.get("kind") == "EnumDecl" and node.get("name"):
                declarations.append(
                    {
                        "kind": "enum",
                        "name": f"anvil::{node['name']}",
                        "underlying_type": node["fixedUnderlyingType"]["qualType"],
                        "values": [
                            {"name": child["name"], "value": _enum_value(child)}
                            for child in node.get("inner", [])
                            if child.get("kind") == "EnumConstantDecl"
                        ],
                    }
                )
    return sorted(declarations, key=lambda declaration: declaration["name"])


def _version(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)", value)
    if match is None:
        raise AbiHistoryError(f"invalid interface version {value!r}")
    return int(match.group(1)), int(match.group(2))


def _is_prefix(previous: list[Any], current: list[Any]) -> bool:
    return len(previous) <= len(current) and current[: len(previous)] == previous


def _transition_is_additive(previous: dict[str, Any], current: dict[str, Any]) -> bool:
    old = {declaration["name"]: declaration for declaration in previous["declarations"]}
    new = {declaration["name"]: declaration for declaration in current["declarations"]}
    if not old.keys() <= new.keys():
        return False

    for name, old_declaration in old.items():
        new_declaration = new[name]
        if old_declaration["kind"] != new_declaration["kind"]:
            return False
        if old_declaration["kind"] == "enum":
            if old_declaration["underlying_type"] != new_declaration["underlying_type"]:
                return False
            if not _is_prefix(old_declaration["values"], new_declaration["values"]):
                return False
            continue

        if old_declaration["extensible"] != new_declaration["extensible"]:
            return False
        if old_declaration["kind"] == "interface":
            if old_declaration["fields"] != new_declaration["fields"]:
                return False
            if not _is_prefix(old_declaration["methods"], new_declaration["methods"]):
                return False
        else:
            if old_declaration["methods"] != new_declaration["methods"]:
                return False
            if old_declaration["fields"] != new_declaration["fields"]:
                if not old_declaration["extensible"] or not _is_prefix(
                    old_declaration["fields"], new_declaration["fields"]
                ):
                    return False
    return True


def validate_history(history: dict[str, Any]) -> None:
    if history.get("schema_version") != 1:
        raise AbiHistoryError("unsupported ABI history schema")
    snapshots = history.get("snapshots")
    if not isinstance(snapshots, list) or not snapshots:
        raise AbiHistoryError("ABI history must contain at least one snapshot")

    for snapshot in snapshots:
        _version(snapshot["interface"])
        names = [item["name"] for item in snapshot["declarations"]]
        if names != sorted(names) or len(names) != len(set(names)):
            raise AbiHistoryError(
                f"{snapshot['interface']}: declarations must be sorted and unique"
            )

    for previous, current in zip(snapshots, snapshots[1:]):
        old_major, old_minor = _version(previous["interface"])
        new_major, new_minor = _version(current["interface"])
        if new_major == old_major:
            if new_minor != old_minor + 1:
                raise AbiHistoryError(
                    f"{current['interface']}: minor snapshots must advance by one"
                )
            if not _transition_is_additive(previous, current):
                raise AbiHistoryError(
                    f"{current['interface']}: reordered, removed, or changed ABI "
                    "declarations require a major version"
                )
        elif new_major == old_major + 1 and new_minor == 0:
            continue
        else:
            raise AbiHistoryError(
                f"{current['interface']}: major snapshots must advance by one and reset minor"
            )


def validate_current(
    history: dict[str, Any], interface: tuple[int, int], declarations: list[dict[str, Any]]
) -> None:
    latest = history["snapshots"][-1]
    if _version(latest["interface"]) != interface:
        raise AbiHistoryError(
            "the latest golden snapshot does not match the SDK interface constants"
        )
    if latest["declarations"] != declarations:
        raise AbiHistoryError(
            "published SDK declaration order changed without a new interface snapshot"
        )


def _interface_constants(abi_header: pathlib.Path) -> tuple[int, int]:
    source = abi_header.read_text(encoding="utf-8")
    values = []
    for name in ("Major", "Minor"):
        match = re.search(rf"kPluginInterface{name}\{{(\d+)\}}", source)
        if match is None:
            raise AbiHistoryError(f"could not read kPluginInterface{name}")
        values.append(int(match.group(1)))
    return values[0], values[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--include-dir", type=pathlib.Path, required=True)
    parser.add_argument("--history", type=pathlib.Path, required=True)
    args = parser.parse_args()

    try:
        history = json.loads(args.history.read_text(encoding="utf-8"))
        validate_history(history)
        declarations = extract_declarations(args.compiler, args.include_dir)
        interface = _interface_constants(args.include_dir / "anvil/sdk/abi.hpp")
        validate_current(history, interface, declarations)
    except (AbiHistoryError, OSError, json.JSONDecodeError) as error:
        print(f"SDK ABI history check failed: {error}", file=sys.stderr)
        return 1
    print(f"SDK ABI history matches interface {interface[0]}.{interface[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
