#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "cmake/verify_elf_hardening.py"
SPEC = importlib.util.spec_from_file_location("verify_elf_hardening", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verify_elf_hardening = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_elf_hardening)


HEADER = """\
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
"""
PROGRAM_HEADERS = """\
  GNU_STACK      0x000000 0x000000 0x000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x001000 0x001000 0x001000 0x000100 0x000100 R   0x1
"""
DYNAMIC = """\
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
"""
SYMBOLS = """\
  1: 0000000000000000 0 FUNC GLOBAL DEFAULT UND __stack_chk_fail@GLIBC_2.4
  2: 0000000000000000 0 FUNC GLOBAL DEFAULT UND __memcpy_chk@GLIBC_2.3.4
"""
NOTES = "Properties: x86 feature: IBT, SHSTK"


class ElfHardeningTests(unittest.TestCase):
    def validate(
        self,
        header: str = HEADER,
        program_headers: str = PROGRAM_HEADERS,
        dynamic: str = DYNAMIC,
        symbols: str = SYMBOLS,
        notes: str = NOTES,
    ) -> None:
        verify_elf_hardening.validate_outputs(
            header, program_headers, dynamic, symbols, notes
        )

    def test_complete_hardening_is_accepted(self) -> None:
        self.validate()

    def test_non_pie_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_elf_hardening.HardeningError, "not a PIE"):
            self.validate(header=HEADER.replace("DYN", "EXEC"))

    def test_missing_relro_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_elf_hardening.HardeningError, "GNU_RELRO"):
            self.validate(program_headers=PROGRAM_HEADERS.replace("GNU_RELRO", "LOAD"))

    def test_lazy_binding_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_elf_hardening.HardeningError, "BIND_NOW"):
            self.validate(dynamic="0x1 (NEEDED) Shared library: [libc.so.6]")

    def test_executable_stack_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_elf_hardening.HardeningError, "executable"):
            self.validate(program_headers=PROGRAM_HEADERS.replace("RW  0x10", "RWE 0x10"))

    def test_missing_stack_segment_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_elf_hardening.HardeningError, "GNU_STACK"):
            self.validate(
                program_headers=PROGRAM_HEADERS.replace("GNU_STACK", "LOAD")
            )

    def test_missing_canary_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_elf_hardening.HardeningError, "stack-canary"):
            self.validate(symbols=SYMBOLS.replace("__stack_chk_fail", "__ordinary"))

    def test_missing_fortify_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_elf_hardening.HardeningError, "fortified"):
            self.validate(symbols=SYMBOLS.replace("__memcpy_chk", "memcpy"))

    def test_missing_x86_cet_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_elf_hardening.HardeningError, "CET"):
            self.validate(notes="Properties: x86-64-baseline")

    def test_cet_is_not_required_on_other_architectures(self) -> None:
        self.validate(
            header=HEADER.replace(
                "Advanced Micro Devices X86-64", "AArch64"
            ),
            notes="Properties: AArch64 feature: BTI, PAC",
        )


if __name__ == "__main__":
    unittest.main()
