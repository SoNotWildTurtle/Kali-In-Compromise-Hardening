#!/usr/bin/env python3
"""nn_ids_incident_response.py - Generate actionable IDS incident reports."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

ALERT_STATE = Path("/var/lib/nn_ids/alert_stats.json")
REPORT_DIR = Path("/var/log/nn_ids")
DEFAULT_REPORT = REPORT_DIR / "incident_response_report.md"


def load_state(path: Path) -> Dict:
    """Return the JSON analytics dictionary if available."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text() or "{}")
    except json.JSONDecodeError:
        return {}


def _sorted_items(mapping: Dict, limit: int = 10) -> List[Tuple[str, float]]:
    items: List[Tuple[str, float]] = []
    for key, value in mapping.items():
        try:
            items.append((str(key), float(value)))
        except (TypeError, ValueError):
            continue
    items.sort(key=lambda item: item[1], reverse=True)
    return items[:limit]


def _format_list(items: Iterable[str]) -> List[str]:
    return [f"- {item}" for item in items]


def _format_mapping(title: str, mapping: Dict, unit: str = "score") -> List[str]:
    entries = _sorted_items(mapping)
    if not entries:
        return []
    lines = [f"### {title}"]
    for key, value in entries:
        lines.append(f"- **{key}** ({unit}: {value:.2f})")
    lines.append("")
    return lines


def build_recommendations(state: Dict) -> List[str]:
    """Produce actionable recommendations based on analytics heuristics."""
    recs: List[str] = []
    if not state:
        return ["## Recommended Actions", "", "- No analytics available. Ensure the IDS service is running and has generated alerts.", ""]

    total_alerts = int(state.get("total_alerts", 0))
    if total_alerts == 0:
        recs.append("IDS has not recorded any alerts yet. Validate capture rules and traffic feeds.")

    campaign_watch = state.get("campaign_watchlist") or {}
    if campaign_watch:
        worst = _sorted_items(campaign_watch, limit=3)
        joined = ", ".join(f"{ip} ({score:.2f})" for ip, score in worst)
        recs.append(f"Investigate campaign sources: {joined}.")

    surge_sources = state.get("surge_sources") or {}
    if surge_sources:
        first = _sorted_items(surge_sources, limit=3)
        joined = ", ".join(f"{ip} (ratio {ratio:.2f})" for ip, ratio in first)
        recs.append(f"Apply rate limiting or blocking to surge traffic from: {joined}.")

    spike_sources = state.get("probability_spike_sources") or {}
    if spike_sources:
        first = _sorted_items(spike_sources, limit=3)
        joined = ", ".join(f"{ip} (spike {strength:.2f})" for ip, strength in first)
        recs.append(f"Capture full packets for spike sources: {joined} for forensic review.")

    intensity_watch = state.get("intensity_watchlist") or {}
    if intensity_watch:
        first = _sorted_items(intensity_watch, limit=3)
        joined = ", ".join(f"{ip} ({score:.2f})" for ip, score in first)
        recs.append(f"Consider isolating high-intensity actors: {joined}.")

    apt_suspects = state.get("apt_suspects") or {}
    if apt_suspects:
        suspects = ", ".join(f"{ip} (stages {count})" for ip, count in _sorted_items(apt_suspects, limit=5))
        recs.append(f"Treat APT-suspect sources with priority containment: {suspects}.")

    fanout_sources = state.get("fanout_sources") or {}
    if fanout_sources:
        first = _sorted_items(fanout_sources, limit=3)
        joined = ", ".join(f"{ip} ({targets:.0f} targets)" for ip, targets in first)
        recs.append(f"Review lateral movement attempts from: {joined}.")

    kill_chain_progress = state.get("kill_chain_progressions") or {}
    if kill_chain_progress:
        top = _sorted_items(kill_chain_progress, limit=3)
        joined = ", ".join(f"{ip} ({count:.0f} advancements)" for ip, count in top)
        recs.append(f"Kill-chain progression observed. Monitor containment for: {joined}.")

    model_info = state.get("model_info") or {}
    if isinstance(model_info, dict):
        if model_info.get("refresh_recommended"):
            recs.append("Retrain the neural IDS model (`ids_menu.sh` → Retrain IDS model) to refresh ageing weights.")
        health = model_info.get("health")
        if health:
            recs.append(f"Model health indicator: {health}. Adjust thresholds or retrain if health drifts lower.")

    threat_feed = state.get("threat_feed_hits") or {}
    if threat_feed:
        first = _sorted_items(threat_feed, limit=5)
        joined = ", ".join(f"{ip} ({count:.0f} hits)" for ip, count in first)
        recs.append(f"Threat-feed matches detected: {joined}. Verify blocks are effective.")

    if not recs:
        recs.append("No immediate actions detected. Continue monitoring and review IDS analytics periodically.")

    return ["## Recommended Actions", ""] + _format_list(recs) + [""]


def build_report(state: Dict) -> str:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines: List[str] = [
        "# IDS Incident Response Report",
        "",
        f"Generated: {timestamp}",
        "",
    ]

    if not state:
        lines.append("No alert analytics available. Ensure `/var/lib/nn_ids/alert_stats.json` exists and the IDS service is running.")
        lines.append("")
        return "\n".join(lines)

    total_alerts = int(state.get("total_alerts", 0))
    lines.extend(
        [
            "## Overview",
            "",
            f"- Total alerts recorded: **{total_alerts}**",
        ]
    )
    last_alert = state.get("last_alert")
    if last_alert:
        lines.append(f"- Last alert at: **{last_alert}**")
    last_reason = state.get("last_reason")
    if last_reason:
        lines.append(f"- Last alert reason: {last_reason}")
    last_prob = state.get("last_probability")
    if last_prob is not None:
        lines.append(f"- Last alert probability: {float(last_prob):.2f}")
    last_profile = state.get("last_adversarial_profile")
    if isinstance(last_profile, dict):
        stage = last_profile.get("stage")
        severity = last_profile.get("severity")
        rec = last_profile.get("recommendation")
        details = []
        if severity:
            details.append(f"severity **{severity}**")
        if stage:
            details.append(f"stage **{stage}**")
        if rec:
            details.append(f"recommended action: {rec}")
        if details:
            lines.append(f"- Adversarial catalog context: {', '.join(details)}")
    lines.append("")

    recent_alerts = state.get("recent_alerts")
    if isinstance(recent_alerts, list) and recent_alerts:
        lines.append("### Recent Alerts")
        for entry in recent_alerts[-5:]:
            if not isinstance(entry, dict):
                continue
            time = entry.get("time", "unknown time")
            src = entry.get("src", "?")
            dst = entry.get("dst", "?")
            prob = entry.get("probability")
            reason = entry.get("reason", "unknown reason")
            tactic = entry.get("tactic")
            severity = entry.get("severity")
            prob_display = f"{float(prob):.2f}" if prob is not None else "n/a"
            bullet = f"- {time}: {src} → {dst} (prob {prob_display}) - {reason}"
            if tactic:
                bullet += f" [{tactic}]"
            if severity:
                bullet += f" severity {severity}"
            lines.append(bullet)
        lines.append("")

    sections = [
        ("Campaign Watchlist", state.get("campaign_watchlist"), "risk"),
        ("Surge Sources", state.get("surge_sources"), "ratio"),
        ("Probability Spike Sources", state.get("probability_spike_sources"), "spike"),
        ("Intensity Watchlist", state.get("intensity_watchlist"), "intensity"),
        ("Fan-out Leaders", state.get("fanout_sources"), "targets"),
        ("Port Diversity Leaders", state.get("port_diversity_sources"), "ports"),
        ("APT Suspects", state.get("apt_suspects"), "stages"),
        ("Kill-chain Progressions", state.get("kill_chain_progressions"), "advancements"),
        ("Frequent Reasons", state.get("reason_counts"), "hits"),
        ("Dominant Tactics", state.get("tactic_counts"), "alerts"),
        ("Dominant Techniques", state.get("technique_counts"), "alerts"),
        ("Kill-chain Stage Totals", state.get("tactic_stage_totals"), "events"),
        ("Tactic Transitions", state.get("tactic_transitions"), "changes"),
        ("Threat Feed Hits", state.get("threat_feed_hits"), "matches"),
    ]
    for title, mapping, unit in sections:
        if isinstance(mapping, dict) and mapping:
            lines.extend(_format_mapping(title, mapping, unit))

    model_info = state.get("model_info")
    if isinstance(model_info, dict):
        lines.append("### Model Health")
        age = model_info.get("age_days")
        if age is not None:
            lines.append(f"- Model age: {float(age):.2f} days")
        last_trained = model_info.get("last_trained")
        if last_trained:
            lines.append(f"- Last trained: {last_trained}")
        health = model_info.get("health")
        if health:
            lines.append(f"- Health indicator: {health}")
        global_avg = model_info.get("global_average_probability")
        if global_avg is not None:
            lines.append(f"- Global probability EWMA: {float(global_avg):.3f}")
        recent_avg = model_info.get("recent_average_probability")
        if recent_avg is not None:
            lines.append(f"- Recent probability average: {float(recent_avg):.3f}")
        if model_info.get("refresh_recommended"):
            lines.append("- Refresh recommended: **Yes**")
        else:
            lines.append("- Refresh recommended: No")
        lines.append("")

    lines.extend(build_recommendations(state))
    return "\n".join(lines)


def write_report(content: str, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content)
    return destination


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate IDS incident response recommendations")
    parser.add_argument("--state", type=Path, default=ALERT_STATE, help="Path to alert_stats.json")
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT, help="Report destination (Markdown)")
    parser.add_argument("--stdout", action="store_true", help="Also print the report to stdout")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    state = load_state(args.state)
    report = build_report(state)
    output_path = write_report(report, args.output)
    if args.stdout:
        print(report)
    print(str(output_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
