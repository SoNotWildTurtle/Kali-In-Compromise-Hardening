#!/usr/bin/env python3
"""Generate synthetic malicious packet features with annotated adversarial metadata."""
from __future__ import annotations

import argparse
import csv
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

ADVERSARIAL_FILE = Path("/opt/nnids/adversarial.csv")


@dataclass
class AdversarialTemplate:
    """Describe a synthetic malicious packet pattern."""

    name: str
    length: int
    ttl: int
    ports: Sequence[int]
    flags: int
    reason: str
    tactic: str
    stage: str
    severity: str
    recommendation: str
    keywords: Sequence[str] = field(default_factory=list)
    length_jitter: int = 12
    ttl_jitter: int = 1

    def build_sample(self) -> Dict[str, str | int]:
        """Return a randomized sample encoded as a dictionary."""
        length = max(1, self.length + random.randint(-self.length_jitter, self.length_jitter))
        ttl = max(1, self.ttl + random.randint(-self.ttl_jitter, self.ttl_jitter))
        port = random.choice(list(self.ports))
        sample = {
            "len": length,
            "ttl": ttl,
            "dport": port,
            "flags": self.flags,
            "label": 1,
            "template": self.name,
            "reason": self.reason,
            "tactic": self.tactic,
            "stage": self.stage,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "keywords": ";".join(sorted(set(k.lower() for k in self.keywords if k))),
        }
        return sample


TEMPLATES: List[AdversarialTemplate] = [
    AdversarialTemplate(
        name="ttl_spoof_reserved_port",
        length=1500,
        ttl=1,
        ports=[0, 1],
        flags=0x29,
        reason="TTL spoof with reserved port",
        tactic="Reconnaissance",
        stage="Reconnaissance",
        severity="critical",
        recommendation="Drop spoofed sources at the edge firewall and enable ingress filtering.",
        keywords=["ttl", "spoof", "reserved", "recon"],
        ttl_jitter=2,
    ),
    AdversarialTemplate(
        name="backdoor_syn_sweep",
        length=60,
        ttl=64,
        ports=[31337, 2323],
        flags=0x02,
        reason="Backdoor SYN sweep",
        tactic="Command and Control",
        stage="Command and Control",
        severity="high",
        recommendation="Quarantine host and search for unauthorized remote shells.",
        keywords=["backdoor", "syn", "31337"],
    ),
    AdversarialTemplate(
        name="xmas_ssh_surface",
        length=100,
        ttl=255,
        ports=[22, 2222, 2022],
        flags=0x3F,
        reason="Xmas scan against SSH surface",
        tactic="Reconnaissance",
        stage="Reconnaissance",
        severity="high",
        recommendation="Enable port knocking or adaptive rate limits on exposed SSH services.",
        keywords=["xmas", "scan", "ssh"],
    ),
    AdversarialTemplate(
        name="covert_fin_tls",
        length=48,
        ttl=128,
        ports=[443, 8443],
        flags=0x01,
        reason="Covert FIN exfiltration on TLS",
        tactic="Exfiltration",
        stage="Exfiltration",
        severity="critical",
        recommendation="Inspect TLS sessions for anomalous FIN bursts and rotate credentials.",
        keywords=["fin", "tls", "exfil"],
    ),
    AdversarialTemplate(
        name="dns_tunnel_burst",
        length=520,
        ttl=64,
        ports=[53],
        flags=0x10,
        reason="DNS tunnelling burst",
        tactic="Command and Control",
        stage="Command and Control",
        severity="medium",
        recommendation="Enable DNS tunnelling detection and restrict outbound resolvers.",
        keywords=["dns", "tunnel", "burst"],
        length_jitter=80,
    ),
    AdversarialTemplate(
        name="smb_lateral_sweep",
        length=128,
        ttl=64,
        ports=[445, 139],
        flags=0x18,
        reason="SMB lateral movement sweep",
        tactic="Lateral Movement",
        stage="Lateral Movement",
        severity="high",
        recommendation="Isolate SMB scanning hosts and enforce SMB signing.",
        keywords=["smb", "lateral", "movement"],
    ),
    AdversarialTemplate(
        name="icmp_payload_beacon",
        length=90,
        ttl=32,
        ports=[0],
        flags=0x19,
        reason="ICMP payload command beacon",
        tactic="Command and Control",
        stage="Command and Control",
        severity="medium",
        recommendation="Block outbound ICMP payloads and inspect hosts for tunnelling tools.",
        keywords=["icmp", "beacon", "payload"],
    ),
]


def templates_by_name() -> Dict[str, AdversarialTemplate]:
    """Return a mapping of template name to template instance."""

    return {template.name: template for template in TEMPLATES}


def get_template(name: str) -> AdversarialTemplate:
    """Fetch a template by name, raising a KeyError if missing."""

    mapping = templates_by_name()
    if name not in mapping:
        raise KeyError(f"Unknown adversarial template: {name}")
    return mapping[name]


def generate_adversarial(count: int = 60) -> List[Dict[str, str | int]]:
    """Return synthetic malicious packet feature dictionaries."""
    samples: List[Dict[str, str | int]] = []
    if count <= 0:
        return samples

    per_template = max(1, count // len(TEMPLATES))
    for template in TEMPLATES:
        for _ in range(per_template):
            samples.append(template.build_sample())

    while len(samples) < count:
        samples.append(random.choice(TEMPLATES).build_sample())

    return samples


def write_samples(samples: Iterable[Dict[str, str | int]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "len",
        "ttl",
        "dport",
        "flags",
        "label",
        "template",
        "reason",
        "tactic",
        "stage",
        "severity",
        "recommendation",
        "keywords",
    ]
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for sample in samples:
            row = {key: sample.get(key, "") for key in fieldnames}
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate adversarial IDS samples")
    parser.add_argument("-c", "--count", type=int, default=60, help="number of samples to generate")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=ADVERSARIAL_FILE,
        help="output CSV path",
    )
    args = parser.parse_args()

    samples = generate_adversarial(args.count)
    write_samples(samples, args.output)
    print(f"Generated {len(samples)} adversarial samples at {args.output}")


if __name__ == "__main__":
    main()
