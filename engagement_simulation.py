#!/usr/bin/env python3
"""Simulate multi-stage adversarial engagements for IDS training and drills."""
from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from nn_ids_adversarial import get_template

ENGAGEMENT_DIR = Path("/opt/nnids/engagements")
SCENARIO_CATALOG = Path("/etc/nn_ids/engagement_scenarios.json")

SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}

RISK_LEVELS = [
    (4.5, "critical"),
    (3.5, "high"),
    (2.5, "medium"),
    (1.5, "low"),
    (0.0, "informational"),
]


@dataclass
class Phase:
    """Describe a phase within an engagement scenario."""

    name: str
    template: str
    iterations: int
    dwell_seconds: float = 6.0
    objective: str = ""
    enrichment: Sequence[str] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)


@dataclass
class Scenario:
    """Collection of phases that form an engagement storyline."""

    name: str
    description: str
    phases: List[Phase]
    objectives: Sequence[str] = field(default_factory=list)
    response: str = ""
    origin: str = "builtin"


def _clone_phase(phase: Phase) -> Phase:
    return Phase(
        name=phase.name,
        template=phase.template,
        iterations=phase.iterations,
        dwell_seconds=phase.dwell_seconds,
        objective=phase.objective,
        enrichment=list(phase.enrichment),
        metadata=dict(phase.metadata),
    )


def _clone_scenario(scenario: Scenario) -> Scenario:
    return Scenario(
        name=scenario.name,
        description=scenario.description,
        phases=[_clone_phase(phase) for phase in scenario.phases],
        objectives=list(scenario.objectives),
        response=scenario.response,
        origin=scenario.origin,
    )


SCENARIOS: Dict[str, Scenario] = {
    "multi_stage_intrusion": Scenario(
        name="multi_stage_intrusion",
        description="Reconnaissance leads to lateral movement and covert exfiltration.",
        phases=[
            Phase(
                name="Perimeter Recon",
                template="ttl_spoof_reserved_port",
                iterations=12,
                dwell_seconds=4.0,
                objective="Enumerate perimeter ACL weaknesses via spoofed TTL anomalies.",
                enrichment=["spoof-detection", "acl-review"],
            ),
            Phase(
                name="Backdoor Probing",
                template="backdoor_syn_sweep",
                iterations=8,
                dwell_seconds=6.0,
                objective="Cycle through high-value SYN backdoors to map remote access points.",
                enrichment=["syn-sweep", "c2-probing"],
            ),
            Phase(
                name="Lateral SMB Sweep",
                template="smb_lateral_sweep",
                iterations=6,
                dwell_seconds=7.0,
                objective="Hunt for SMB shares that permit traversal across the estate.",
                enrichment=["smb", "lateral"],
            ),
            Phase(
                name="Covert Exfiltration",
                template="covert_fin_tls",
                iterations=4,
                dwell_seconds=10.0,
                objective="Leak sensitive data via short FIN bursts hidden in TLS sessions.",
                enrichment=["exfiltration", "tls-fin"],
            ),
        ],
        objectives=[
            "Detect spoofed reconnaissance before credential reuse occurs.",
            "Throttle lateral SMB pivots to contain propagation.",
            "Inspect TLS flows for FIN-burst exfiltration attempts.",
        ],
        response="Isolate dual-role hosts that appear in both lateral and exfiltration phases and enforce adaptive firewall hardening.",
    ),
    "covert_beacon_chain": Scenario(
        name="covert_beacon_chain",
        description="Low-and-slow command beacons mature into DNS tunnelling control.",
        phases=[
            Phase(
                name="ICMP Beacon",
                template="icmp_payload_beacon",
                iterations=10,
                dwell_seconds=12.0,
                objective="Plant a heartbeat channel that evades simple ping filtering.",
                enrichment=["icmp", "beacon"],
            ),
            Phase(
                name="DNS Tunnel Establishment",
                template="dns_tunnel_burst",
                iterations=8,
                dwell_seconds=9.0,
                objective="Escalate to DNS tunnelling once foothold is confirmed.",
                enrichment=["dns", "tunnel"],
            ),
            Phase(
                name="Backdoor Sustainment",
                template="backdoor_syn_sweep",
                iterations=5,
                dwell_seconds=8.0,
                objective="Rotate backup command nodes while tunnel is active.",
                enrichment=["c2-rotation"],
            ),
        ],
        objectives=[
            "Baseline ICMP payload usage across trusted segments.",
            "Alert when DNS query lengths spike alongside beacon traffic.",
        ],
        response="Enable deep DNS inspection, block unauthorized resolvers, and quarantine hosts that beacon and tunnel concurrently.",
    ),
    "smash_and_grab": Scenario(
        name="smash_and_grab",
        description="Rapid reconnaissance pairs with TLS exfil to stress containment playbooks.",
        phases=[
            Phase(
                name="Aggressive Recon",
                template="xmas_ssh_surface",
                iterations=15,
                dwell_seconds=2.5,
                objective="Identify SSH endpoints susceptible to brute-force chaining.",
                enrichment=["ssh", "xmas"],
            ),
            Phase(
                name="Privilege Escalation",
                template="smb_lateral_sweep",
                iterations=10,
                dwell_seconds=5.0,
                objective="Sweep SMB for credential reuse to escalate privileges.",
                enrichment=["priv-esc", "smb"],
            ),
            Phase(
                name="Rapid Exfil",
                template="covert_fin_tls",
                iterations=6,
                dwell_seconds=4.0,
                objective="Ship collected artefacts out over encrypted FIN bursts.",
                enrichment=["rapid-exfil"],
            ),
        ],
        objectives=[
            "Throttle reconnaissance spikes before they translate into sustained access.",
            "Correlate lateral SMB sweeps with outbound TLS micro-bursts.",
        ],
        response="Trigger incident response when reconnaissance intensity and FIN-based exfiltration overlap within a short window.",
    ),
}


def parse_phase(data: Dict[str, object]) -> Phase:
    try:
        name = str(data["name"])
        template = str(data["template"])
    except KeyError as exc:
        raise ValueError(f"Phase definition missing required field: {exc}") from exc
    iterations = int(data.get("iterations", 1))
    dwell = float(data.get("dwell_seconds", 6.0))
    objective = str(data.get("objective", ""))
    enrichment = data.get("enrichment", [])
    if isinstance(enrichment, str):
        enrichment_values: Sequence[str] = [value.strip() for value in enrichment.split(",") if value.strip()]
    else:
        enrichment_values = [str(value) for value in enrichment]
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    return Phase(
        name=name,
        template=template,
        iterations=iterations,
        dwell_seconds=dwell,
        objective=objective,
        enrichment=enrichment_values,
        metadata=metadata,
    )


def parse_scenario(data: Dict[str, object], origin: str) -> Scenario:
    try:
        name = str(data["name"])
    except KeyError as exc:
        raise ValueError(f"Scenario missing required field: {exc}") from exc
    description = str(data.get("description", name))
    response = str(data.get("response", ""))
    objectives = data.get("objectives", [])
    if isinstance(objectives, str):
        objectives_values: Sequence[str] = [value.strip() for value in objectives.split(",") if value.strip()]
    else:
        objectives_values = [str(value) for value in objectives]
    phases_data = data.get("phases", [])
    if not phases_data:
        raise ValueError(f"Scenario '{name}' must declare at least one phase")
    phases = [parse_phase(phase) for phase in phases_data]
    return Scenario(
        name=name,
        description=description,
        phases=phases,
        objectives=objectives_values,
        response=response,
        origin=origin,
    )


def load_scenarios(custom_path: Path | None = None) -> Dict[str, Scenario]:
    mapping: Dict[str, Scenario] = {name: _clone_scenario(value) for name, value in SCENARIOS.items()}

    scenario_files: List[Path] = []
    if custom_path:
        scenario_files.append(custom_path)
    elif SCENARIO_CATALOG.exists():
        scenario_files.append(SCENARIO_CATALOG)

    for path in scenario_files:
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text())
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"Failed to load scenarios from {path}: {exc}")
            continue
        entries: Iterable[Dict[str, object]]
        if isinstance(payload, dict):
            entries = payload.get("scenarios", [])  # type: ignore[assignment]
        else:
            entries = payload  # type: ignore[assignment]
        for raw in entries:
            if not isinstance(raw, dict):
                continue
            try:
                scenario = parse_scenario(raw, origin=f"file:{path}")
            except Exception as exc:  # pragma: no cover - defensive logging
                print(f"Skipping scenario from {path}: {exc}")
                continue
            mapping[scenario.name] = scenario
    return mapping


def list_scenarios(scenarios: Dict[str, Scenario], format_: str) -> None:
    """Print scenario catalogue in the requested format."""

    scenario_list = list(scenarios.values())
    if format_ == "json":
        payload = [
            {
                "name": s.name,
                "description": s.description,
                "phases": [p.name for p in s.phases],
                "objectives": list(s.objectives),
                "origin": s.origin,
            }
            for s in scenario_list
        ]
        print(json.dumps(payload, indent=2))
    elif format_ == "tsv":
        for scenario in scenario_list:
            print(f"{scenario.name}\t{scenario.description}\t{scenario.origin}")
    else:
        for scenario in scenario_list:
            print(f"{scenario.name} ({scenario.origin}): {scenario.description}")


def build_event(
    scenario: Scenario,
    phase: Phase,
    phase_index: int,
    iteration: int,
    event_index: int,
    timestamp: datetime,
) -> Dict[str, object]:
    template = get_template(phase.template)
    sample = dict(template.build_sample())
    event: Dict[str, object] = {
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "scenario": scenario.name,
        "phase": phase.name,
        "phase_index": phase_index,
        "iteration": iteration,
        "event": event_index,
        "objective": phase.objective,
        "template": template.name,
        "enrichment": ";".join(sorted(phase.enrichment)),
    }
    event.update(sample)
    return event


def run_scenario(scenario: Scenario, iterations: int, seed: int | None = None) -> List[Dict[str, object]]:
    """Generate simulated events for the requested scenario."""

    if seed is not None:
        random.seed(seed)
    events: List[Dict[str, object]] = []
    current = datetime.now(timezone.utc)
    for iteration in range(1, iterations + 1):
        for index, phase in enumerate(scenario.phases, start=1):
            for step in range(1, phase.iterations + 1):
                events.append(build_event(scenario, phase, index, iteration, step, current))
                current += timedelta(seconds=max(0.5, phase.dwell_seconds))
    return events


def write_csv(events: Iterable[Dict[str, object]], path: Path) -> None:
    """Persist simulated events to CSV."""

    rows = list(events)
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "timestamp",
        "scenario",
        "phase",
        "phase_index",
        "iteration",
        "event",
        "objective",
        "template",
        "enrichment",
        "len",
        "ttl",
        "dport",
        "flags",
        "label",
        "reason",
        "tactic",
        "stage",
        "severity",
        "recommendation",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _ordered_unique(values: Iterable[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        key = value or "unknown"
        if key not in seen:
            ordered.append(key)
            seen.add(key)
    return ordered


def _severity_weight(label: object) -> int:
    if not isinstance(label, str):
        return 3
    return SEVERITY_WEIGHTS.get(label.lower(), 3)


def build_summary(scenario: Scenario, events: List[Dict[str, object]], iterations: int) -> Dict[str, object]:
    """Build an aggregate summary for analytics."""

    severity = Counter(evt.get("severity", "unknown") for evt in events)
    tactic = Counter(evt.get("tactic", "unknown") for evt in events)
    stage = Counter(evt.get("stage", "unknown") for evt in events)
    template_counts = Counter(evt.get("template", "unknown") for evt in events)
    phase_counts = Counter(evt.get("phase", "unknown") for evt in events)
    recommendations = Counter(evt.get("recommendation", "") for evt in events if evt.get("recommendation"))
    enrichment = Counter(evt.get("enrichment", "") for evt in events if evt.get("enrichment"))
    keywords: Counter[str] = Counter()
    for evt in events:
        raw_keywords = evt.get("keywords", "")
        if not raw_keywords:
            continue
        for keyword in str(raw_keywords).split(";"):
            keyword = keyword.strip().lower()
            if keyword:
                keywords[keyword] += 1

    weighted = sum(_severity_weight(evt.get("severity")) for evt in events)
    average_weight = (weighted / len(events)) if events else 0.0
    risk_level = next((label for threshold, label in RISK_LEVELS if average_weight >= threshold), "informational")

    timeline: Dict[str, object] = {}
    if events:
        start_dt = _parse_timestamp(events[0].get("timestamp"))
        end_dt = _parse_timestamp(events[-1].get("timestamp"))
        if start_dt and end_dt:
            timeline = {
                "start": start_dt.isoformat(),
                "end": end_dt.isoformat(),
                "duration_seconds": max(0.0, (end_dt - start_dt).total_seconds()),
            }

    template_details: Dict[str, Dict[str, object]] = {}
    for template_name, count in template_counts.items():
        detail: Dict[str, object] = {"count": count}
        try:
            template = get_template(template_name)
        except KeyError:
            detail["known_template"] = False
        else:
            detail.update(
                {
                    "known_template": True,
                    "reason": template.reason,
                    "tactic": template.tactic,
                    "stage": template.stage,
                    "severity": template.severity,
                    "recommendation": template.recommendation,
                    "keywords": list(template.keywords),
                }
            )
        template_details[template_name] = detail

    return {
        "scenario": scenario.name,
        "description": scenario.description,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "events": len(events),
        "iterations": iterations,
        "origin": scenario.origin,
        "objectives": list(scenario.objectives),
        "response": scenario.response,
        "severity": dict(severity),
        "tactic": dict(tactic),
        "stage": dict(stage),
        "templates": dict(template_counts),
        "phases": [
            {
                "name": phase.name,
                "count": phase_counts.get(phase.name, 0),
                "objective": phase.objective,
                "enrichment": list(phase.enrichment),
                "template": phase.template,
            }
            for phase in scenario.phases
        ],
        "recommendations": dict(recommendations),
        "enrichment": dict(enrichment),
        "keywords": dict(keywords),
        "risk": {
            "score": weighted,
            "average_severity": average_weight,
            "level": risk_level,
        },
        "timeline": timeline,
        "kill_chain": _ordered_unique(evt.get("stage", "unknown") for evt in events),
        "tactic_sequence": _ordered_unique(evt.get("tactic", "unknown") for evt in events),
        "template_details": template_details,
    }


def save_summary(summary: Dict[str, object], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        json.dump(summary, handle, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate adversarial engagements for the neural IDS")
    parser.add_argument("--scenario", default="multi_stage_intrusion", help="scenario to execute")
    parser.add_argument("--iterations", type=int, default=1, help="number of times to replay the scenario")
    parser.add_argument("--output-dir", type=Path, default=ENGAGEMENT_DIR, help="directory for generated artefacts")
    parser.add_argument("--seed", type=int, help="seed for reproducible simulations")
    parser.add_argument("--list", action="store_true", help="list available scenarios and exit")
    parser.add_argument("--format", choices=["plain", "tsv", "json"], default="plain", help="list format")
    parser.add_argument("--scenario-file", type=Path, help="optional JSON catalogue describing additional scenarios")
    args = parser.parse_args()

    scenarios = load_scenarios(args.scenario_file)
    if args.list:
        list_scenarios(scenarios, args.format)
        return

    if args.scenario not in scenarios:
        raise SystemExit(f"Unknown scenario '{args.scenario}'. Use --list to inspect available scenarios.")
    scenario = scenarios[args.scenario]
    if args.iterations < 1:
        raise SystemExit("Iterations must be at least 1")

    events = run_scenario(scenario, args.iterations, seed=args.seed)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.output_dir / f"{scenario.name}_{timestamp}.csv"
    json_path = args.output_dir / f"{scenario.name}_{timestamp}.json"

    write_csv(events, csv_path)
    summary = build_summary(scenario, events, args.iterations)
    summary.update({"csv": str(csv_path)})
    save_summary(summary, json_path)

    print(f"Simulated {len(events)} events for scenario '{scenario.name}' ({args.iterations} iteration(s))")
    print(f"CSV dataset: {csv_path}")
    print(f"Summary: {json_path}")
    if summary.get("severity"):
        top_severity = sorted(summary["severity"].items(), key=lambda item: item[1], reverse=True)
        preview = ", ".join(f"{label}: {count}" for label, count in top_severity[:3])
        print(f"Severity mix: {preview}")
    if summary.get("risk"):
        print(
            "Risk level: {level} (average severity {avg:.2f})".format(
                level=summary["risk"].get("level", "unknown"),
                avg=summary["risk"].get("average_severity", 0.0),
            )
        )


if __name__ == "__main__":
    main()
