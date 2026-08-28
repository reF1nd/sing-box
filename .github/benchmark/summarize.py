#!/usr/bin/env python3

import json
import statistics
import sys
from pathlib import Path


def format_rate(rate: float, unit: str) -> str:
    if unit == "bit/s":
        for divisor, suffix in ((1e9, "Gbit/s"), (1e6, "Mbit/s"), (1e3, "kbit/s")):
            if rate >= divisor:
                return f"{rate / divisor:.3f} {suffix}"
    if rate >= 1e6:
        return f"{rate / 1e6:.3f} M {unit}"
    if rate >= 1e3:
        return f"{rate / 1e3:.3f} k {unit}"
    return f"{rate:.3f} {unit}"


def load_results(root: Path):
    results = {}
    raw_root = root / "raw"
    if not raw_root.exists():
        return results
    for path in sorted(raw_root.glob("*/*.json")):
        variant = path.parent.name
        with path.open(encoding="utf-8") as input_file:
            report = json.load(input_file)
        for measurement in report.get("results", []):
            key = (variant, measurement["scenario"])
            results.setdefault(key, []).append(measurement)
    return results


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize.py RESULT_DIRECTORY", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    results = load_results(root)

    print("# Transparent inbound benchmark")
    print()
    run_info = root / "environment" / "run.txt"
    if run_info.exists():
        print("```text")
        print(run_info.read_text(encoding="utf-8").strip())
        print("```")
        print()

    if not results:
        print("No valid benchmark reports were produced.")
    else:
        direct = {
            scenario: statistics.median(item["rate"] for item in measurements)
            for (variant, scenario), measurements in results.items()
            if variant == "direct"
        }
        print("| Variant | Scenario | Median | Relative to direct | Runs | Errors |")
        print("|---|---|---:|---:|---:|---:|")
        variant_order = {
            name: index
            for index, name in enumerate(
                (
                    "direct",
                    "ebpf-local",
                    "ebpf-shared",
                    "redirect",
                    "tproxy",
                    "tun-mixed",
                    "tun-mixed-auto-redirect",
                )
            )
        }
        scenario_order = {
            name: index
            for index, name in enumerate(
                ("tcp-short", "tcp-upload", "tcp-download", "udp-pps", "udp-unconnected-pps", "udp-churn")
            )
        }
        for (variant, scenario), measurements in sorted(
            results.items(),
            key=lambda item: (variant_order.get(item[0][0], 99), scenario_order.get(item[0][1], 99)),
        ):
            median_rate = statistics.median(item["rate"] for item in measurements)
            baseline = direct.get(scenario)
            relative = "baseline" if variant == "direct" else "N/A"
            if variant != "direct" and baseline:
                relative = f"{median_rate / baseline * 100:.1f}%"
            errors = sum(item.get("errors", 0) for item in measurements)
            print(
                f"| {variant} | {scenario} | {format_rate(median_rate, measurements[0]['unit'])} "
                f"| {relative} | {len(measurements)} | {errors} |"
            )

    failures = root / "failures.tsv"
    if failures.exists() and failures.read_text(encoding="utf-8").strip():
        print()
        print("## Failures")
        print()
        print("```text")
        print(failures.read_text(encoding="utf-8").strip())
        print("```")

    print()
    print(
        "Hosted-runner results are suitable for functional checks and same-job relative regression only. "
        "Use repeated runs on a fixed self-hosted bare-metal runner for publishable absolute comparisons."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
