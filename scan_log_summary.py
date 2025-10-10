#!/usr/bin/env python3
"""Summarize rkhunter, Lynis, and ClamAV scan logs."""

from pathlib import Path


def summarize_rkhunter(path: Path) -> int | None:
    if not path.exists():
        return None
    count = 0
    for line in path.read_text().splitlines():
        if "[Warning]" in line:
            count += 1
    return count


def summarize_lynis(path: Path) -> tuple[int, int] | None:
    if not path.exists():
        return None
    warnings = 0
    suggestions = 0
    for line in path.read_text().splitlines():
        if line.startswith("Warning"):
            warnings += 1
        elif line.startswith("Suggestion"):
            suggestions += 1
    return warnings, suggestions


def summarize_clamav(path: Path) -> int | None:
    if not path.exists():
        return None
    for line in reversed(path.read_text().splitlines()):
        if line.startswith("Infected files:"):
            try:
                return int(line.split(":", 1)[1].strip())
            except ValueError:
                return None
    return None


def main() -> None:
    rkhunter_path = Path("/var/log/rkhunter.log")
    lynis_path = Path("/var/log/lynis.log")
    clamav_paths = [Path("/var/log/clamav.log"), Path("/var/log/clamav_cron.log")]

    rkhunter_warnings = summarize_rkhunter(rkhunter_path)
    lynis_result = summarize_lynis(lynis_path)
    clamav_infected = None
    for p in clamav_paths:
        result = summarize_clamav(p)
        if result is not None:
            clamav_infected = result
            break

    if rkhunter_warnings is None:
        print("rkhunter log not found")
    else:
        print(f"rkhunter warnings: {rkhunter_warnings}")

    if lynis_result is None:
        print("Lynis log not found")
    else:
        warnings, suggestions = lynis_result
        print(f"Lynis warnings: {warnings}")
        print(f"Lynis suggestions: {suggestions}")

    if clamav_infected is None:
        print("ClamAV log not found")
    else:
        print(f"ClamAV infected files: {clamav_infected}")


if __name__ == "__main__":
    main()
