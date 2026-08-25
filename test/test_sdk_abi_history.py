#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "cmake/verify_sdk_abi.py"
SPEC = importlib.util.spec_from_file_location("verify_sdk_abi", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verify_sdk_abi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_sdk_abi)


def method(name: str) -> dict[str, object]:
    return {
        "name": name,
        "type": "void () noexcept",
        "virtual": True,
        "pure": True,
    }


def interface(methods: list[dict[str, object]]) -> dict[str, object]:
    return {
        "kind": "interface",
        "name": "anvil::ITest",
        "extensible": False,
        "fields": [],
        "methods": methods,
    }


def history(*snapshots: tuple[str, list[dict[str, object]]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "snapshots": [
            {"interface": version, "declarations": declarations}
            for version, declarations in snapshots
        ],
    }


class AbiHistoryTests(unittest.TestCase):
    def test_inserting_a_method_with_a_minor_bump_is_rejected(self) -> None:
        old = interface([method("first"), method("second")])
        reordered = interface([method("first"), method("inserted"), method("second")])

        with self.assertRaisesRegex(
            verify_sdk_abi.AbiHistoryError, "require a major version"
        ):
            verify_sdk_abi.validate_history(history(("1.0", [old]), ("1.1", [reordered])))

    def test_appending_a_method_without_a_version_bump_is_rejected(self) -> None:
        old = interface([method("first")])
        appended = interface([method("first"), method("second")])
        golden = history(("1.0", [old]))

        with self.assertRaisesRegex(
            verify_sdk_abi.AbiHistoryError, "without a new interface snapshot"
        ):
            verify_sdk_abi.validate_current(golden, (1, 0), [appended])

    def test_appending_a_method_with_a_minor_bump_is_allowed(self) -> None:
        old = interface([method("first")])
        appended = interface([method("first"), method("second")])

        verify_sdk_abi.validate_history(history(("1.0", [old]), ("1.1", [appended])))

    def test_a_major_bump_allows_a_breaking_change(self) -> None:
        old = interface([method("first"), method("second")])
        changed = interface([method("replacement")])

        verify_sdk_abi.validate_history(history(("1.0", [old]), ("2.0", [changed])))


if __name__ == "__main__":
    unittest.main()
