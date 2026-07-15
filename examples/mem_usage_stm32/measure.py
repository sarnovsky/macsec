#!/usr/bin/env python3
"""
Build and measure STM32 memory-footprint configurations.

FLASH usage = text + data
RAM usage   = data + bss

The script must be run from examples/memusage.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
BUILD_ROOT = SCRIPT_DIR / "build"
RESULTS_DIR = SCRIPT_DIR / "results"


@dataclass(frozen=True)
class BuildConfiguration:
    group: str
    name: str
    profile: str
    optimization: str
    debug_level: int
    self_test: int
    aes_table_mode: str
    heap_size: int = 4096


@dataclass
class BuildResult:
    configuration: BuildConfiguration
    text: int
    data: int
    bss: int
    flash: int
    ram: int
    elf_path: Path
    status: str
    error: str = ""


def optimization_name(flag: str) -> str:
    return flag.replace("-", "")


def make_build_name(cfg: BuildConfiguration) -> str:
    parts = [
        cfg.group,
        optimization_name(cfg.optimization),
        cfg.profile,
        f"debug{cfg.debug_level}",
        f"selftest{cfg.self_test}",
        cfg.aes_table_mode,
    ]
    return "__".join(parts)


def default_configurations() -> list[BuildConfiguration]:
    configs: list[BuildConfiguration] = []

    optimizations = ("-O0", "-O2", "-Os")

    #
    # Functional profile comparison.
    #
    for optimization in optimizations:
        configs.extend(
            [
                BuildConfiguration(
                    group="profiles",
                    name="Minimal",
                    profile="minimal",
                    optimization=optimization,
                    debug_level=0,
                    self_test=0,
                    aes_table_mode="rom_fewer",
                ),
                BuildConfiguration(
                    group="profiles",
                    name="Full_NoDebug",
                    profile="full",
                    optimization=optimization,
                    debug_level=0,
                    self_test=0,
                    aes_table_mode="rom_fewer",
                ),
                BuildConfiguration(
                    group="profiles",
                    name="Full_Debug",
                    profile="full_debug",
                    optimization=optimization,
                    debug_level=3,
                    self_test=0,
                    aes_table_mode="rom_fewer",
                ),
                BuildConfiguration(
                    group="profiles",
                    name="Full_SelfTest",
                    profile="full_selftest",
                    optimization=optimization,
                    debug_level=0,
                    self_test=1,
                    aes_table_mode="rom_fewer",
                ),
            ]
        )

    #
    # Production footprint matrix.
    #
    for optimization in optimizations:
        for debug_level in (0, 1, 2, 3):
            for aes_mode in (
                "runtime_full",
                "runtime_fewer",
                "rom_full",
                "rom_fewer",
            ):
                configs.append(
                    BuildConfiguration(
                        group="production",
                        name=f"Full_Debug{debug_level}_{aes_mode}",
                        profile="full",
                        optimization=optimization,
                        debug_level=debug_level,
                        self_test=0,
                        aes_table_mode=aes_mode,
                    )
                )

    return configs

def run_command(
    command: list[str],
    *,
    cwd: Path,
    verbose: bool,
) -> subprocess.CompletedProcess[str]:
    if verbose:
        print("+", " ".join(command))

    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def find_size_tool(toolchain: str) -> str:
    prefix = str(Path(toolchain)) if toolchain else ""

    if prefix and not prefix.endswith(("/", "\\")):
        prefix += os.sep

    candidate = f"{prefix}arm-none-eabi-size"

    if shutil.which(candidate) is not None:
        return candidate

    # Windows executable lookup may need the explicit suffix.
    if shutil.which(candidate + ".exe") is not None:
        return candidate + ".exe"

    return candidate


def parse_size_output(output: str) -> tuple[int, int, int]:
    """
    Parse Berkeley-format GNU size output:

       text    data     bss     dec     hex filename
       1234      20     100    ...
    """

    lines = [line.strip() for line in output.splitlines() if line.strip()]

    for index, line in enumerate(lines):
        if re.match(r"^text\s+data\s+bss\s+dec\s+hex", line):
            if index + 1 >= len(lines):
                break

            values = lines[index + 1].split()

            if len(values) < 3:
                break

            try:
                return int(values[0]), int(values[1]), int(values[2])
            except ValueError as exc:
                raise ValueError(
                    f"Invalid numeric values in size output: {lines[index + 1]}"
                ) from exc

    raise ValueError(f"Could not parse arm-none-eabi-size output:\n{output}")


def build_one(
    cfg: BuildConfiguration,
    *,
    make_command: str,
    toolchain: str,
    verbose: bool,
) -> BuildResult:
    build_name = make_build_name(cfg)
    relative_build_dir = Path("build") / build_name
    absolute_build_dir = SCRIPT_DIR / relative_build_dir
    elf_path = absolute_build_dir / "macsec_memusage.elf"

    command = [
        make_command,
        "all",
        f"BUILD_DIR={relative_build_dir.as_posix()}",
        f"PROFILE={cfg.profile}",
        f"OPT={cfg.optimization}",
        f"DEBUG_LEVEL={cfg.debug_level}",
        f"SELF_TEST={cfg.self_test}",
        f"AES_TABLE_MODE={cfg.aes_table_mode}",
        f"MACSEC_HEAP_SIZE={cfg.heap_size}",
    ]

    if toolchain:
        command.append(f"TOOLCHAIN={toolchain}")

    process = run_command(command, cwd=SCRIPT_DIR, verbose=verbose)

    if process.returncode != 0:
        return BuildResult(
            configuration=cfg,
            text=0,
            data=0,
            bss=0,
            flash=0,
            ram=0,
            elf_path=elf_path,
            status="FAILED",
            error=process.stdout,
        )

    size_tool = find_size_tool(toolchain)

    size_process = run_command(
        [size_tool, str(elf_path)],
        cwd=SCRIPT_DIR,
        verbose=verbose,
    )

    if size_process.returncode != 0:
        return BuildResult(
            configuration=cfg,
            text=0,
            data=0,
            bss=0,
            flash=0,
            ram=0,
            elf_path=elf_path,
            status="FAILED",
            error=size_process.stdout,
        )

    try:
        text, data, bss = parse_size_output(size_process.stdout)
    except ValueError as exc:
        return BuildResult(
            configuration=cfg,
            text=0,
            data=0,
            bss=0,
            flash=0,
            ram=0,
            elf_path=elf_path,
            status="FAILED",
            error=str(exc),
        )

    return BuildResult(
        configuration=cfg,
        text=text,
        data=data,
        bss=bss,
        flash=text + data,
        ram=data + bss,
        elf_path=elf_path,
        status="OK",
    )


def format_kib(value: int) -> str:
    return f"{value / 1024.0:.2f} KiB"


def write_csv(results: Iterable[BuildResult], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                "group",
                "name",
                "profile",
                "optimization",
                "debug_level",
                "self_test",
                "aes_table_mode",
                "heap_size",
                "text",
                "data",
                "bss",
                "flash",
                "ram",
                "status",
                "elf",
                "error",
            ]
        )

        for result in results:
            cfg = result.configuration

            writer.writerow(
                [
                    cfg.group,
                    cfg.name,
                    cfg.profile,
                    cfg.optimization,
                    cfg.debug_level,
                    cfg.self_test,
                    cfg.aes_table_mode,
                    cfg.heap_size,
                    result.text,
                    result.data,
                    result.bss,
                    result.flash,
                    result.ram,
                    result.status,
                    result.elf_path.as_posix(),
                    result.error,
                ]
            )


def result_cell(result: BuildResult | None) -> str:
    if result is None:
        return "—"

    if result.status != "OK":
        return "FAILED"

    return f"{format_kib(result.flash)} / {format_kib(result.ram)}"


def write_markdown(results: list[BuildResult], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    main_results = {
        (
            result.configuration.optimization,
            result.configuration.name,
        ): result
        for result in results
        if result.configuration.group == "main"
    }

    aes_results = {
        (
            result.configuration.optimization,
            result.configuration.aes_table_mode,
        ): result
        for result in results
        if result.configuration.group == "aes"
    }

    with output_path.open("w", encoding="utf-8") as file:
        file.write("# STM32 MACsec memory footprint\n\n")
        file.write("Values are **FLASH / static RAM**.\n\n")
        file.write("- FLASH = `.text + .data`\n")
        file.write("- RAM = `.data + .bss`\n")
        file.write("- Stack high-water usage is not included.\n")
        file.write("- Debug builds use a no-output `macsec_printf()` sink.\n\n")

        file.write("## Feature profiles\n\n")
        file.write(
            "| Optimization | Minimal | Full, no debug | "
            "Full, debug | Full + self-tests |\n"
        )
        file.write("|---|---:|---:|---:|---:|\n")

        for optimization in ("-O0", "-O2", "-Os"):
            file.write(
                f"| `{optimization}` "
                f"| {result_cell(main_results.get((optimization, 'Minimal')))} "
                f"| {result_cell(main_results.get((optimization, 'Full_NoDebug')))} "
                f"| {result_cell(main_results.get((optimization, 'Full_Debug')))} "
                f"| {result_cell(main_results.get((optimization, 'Full_SelfTest')))} "
                "|\n"
            )

        file.write("\n## AES table configurations\n\n")
        file.write(
            "| Optimization | Runtime full | Runtime fewer | "
            "ROM full | ROM fewer |\n"
        )
        file.write("|---|---:|---:|---:|---:|\n")

        for optimization in ("-O2", "-Os"):
            file.write(
                f"| `{optimization}` "
                f"| {result_cell(aes_results.get((optimization, 'runtime_full')))} "
                f"| {result_cell(aes_results.get((optimization, 'runtime_fewer')))} "
                f"| {result_cell(aes_results.get((optimization, 'rom_full')))} "
                f"| {result_cell(aes_results.get((optimization, 'rom_fewer')))} "
                "|\n"
            )

        failed = [result for result in results if result.status != "OK"]

        if failed:
            file.write("\n## Failed builds\n\n")

            for result in failed:
                cfg = result.configuration
                file.write(
                    f"- `{make_build_name(cfg)}` — see CSV/error output.\n"
                )


def print_summary(results: list[BuildResult]) -> None:
    print()
    print(
        f"{'Configuration':58} "
        f"{'FLASH':>12} {'RAM':>12} {'Status':>8}"
    )
    print("-" * 94)

    for result in results:
        name = make_build_name(result.configuration)

        if result.status == "OK":
            flash = format_kib(result.flash)
            ram = format_kib(result.ram)
        else:
            flash = "-"
            ram = "-"

        print(
            f"{name:58} "
            f"{flash:>12} {ram:>12} {result.status:>8}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build STM32 MACsec memory-footprint configurations."
    )

    parser.add_argument(
        "--make",
        default="make",
        help="Make executable, default: make",
    )

    parser.add_argument(
        "--toolchain",
        default="",
        help=(
            "Directory/prefix before arm-none-eabi tools. "
            "Example: C:/gcc-arm-none-eabi/bin/"
        ),
    )

    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove previous build and results directories first.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print build commands.",
    )

    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop after the first failed build.",
    )

    args = parser.parse_args()

    if args.clean:
        shutil.rmtree(BUILD_ROOT, ignore_errors=True)
        shutil.rmtree(RESULTS_DIR, ignore_errors=True)

    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    configurations = default_configurations()
    results: list[BuildResult] = []

    for index, cfg in enumerate(configurations, start=1):
        name = make_build_name(cfg)

        print(f"[{index:02d}/{len(configurations):02d}] {name}")

        result = build_one(
            cfg,
            make_command=args.make,
            toolchain=args.toolchain,
            verbose=args.verbose,
        )

        results.append(result)

        if result.status != "OK":
            print("  FAILED")
            print(result.error)

            if args.stop_on_error:
                break
        else:
            print(
                f"  FLASH={format_kib(result.flash)}, "
                f"RAM={format_kib(result.ram)}"
            )

    write_csv(results, RESULTS_DIR / "memory.csv")
    write_markdown(results, RESULTS_DIR / "memory.md")
    print_summary(results)

    failed_count = sum(result.status != "OK" for result in results)

    print()
    print(f"CSV:      {RESULTS_DIR / 'memory.csv'}")
    print(f"Markdown: {RESULTS_DIR / 'memory.md'}")

    return 1 if failed_count else 0


if __name__ == "__main__":
    sys.exit(main())