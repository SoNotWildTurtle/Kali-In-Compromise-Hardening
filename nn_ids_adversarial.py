#!/usr/bin/env python3
"""nn_ids_adversarial.py - Generate synthetic malicious packet features with reasons."""
from pathlib import Path
import random
import csv

ADVERSARIAL_FILE = Path("/opt/nnids/adversarial.csv")

# Templates of suspicious packets and why they are flagged
TEMPLATES = [
    ([1500, 1, 0, 0x29], "TTL of 1 with reserved port 0 indicates spoofing"),
    ([60, 64, 31337, 0x02], "Backdoor port 31337 scan"),
    ([100, 255, 22, 0x3F], "All TCP flags set resembles Xmas scan"),
    ([40, 128, 443, 0x01], "Tiny FIN packet on TLS port suggests exfiltration"),
]


def generate_adversarial(count: int = 40):
    """Return a list of synthetic malicious packet features with reasons."""
    samples = []
    per_template = max(1, count // len(TEMPLATES))
    for base, reason in TEMPLATES:
        for _ in range(per_template):
            length = base[0] + random.randint(-10, 10)
            ttl = max(1, base[1] + random.randint(-1, 1))
            dport = base[2]
            flags = base[3]
            samples.append([length, ttl, dport, flags, 1, reason])
    return samples


def main() -> None:
    ADVERSARIAL_FILE.parent.mkdir(parents=True, exist_ok=True)
    samples = generate_adversarial()
    with ADVERSARIAL_FILE.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["len", "ttl", "dport", "flags", "label", "reason"])
        writer.writerows(samples)


if __name__ == "__main__":
    main()
