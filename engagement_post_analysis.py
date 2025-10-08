#!/usr/bin/env python3
"""Produce post-engagement analysis reports from IDS alert logs."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_ALERT_LOG = Path("/var/log/nn_ids_alerts.log")
DEFAULT_ANALYSIS_DIR = Path("/opt/nnids/analysis")
DEFAULT_ENGAGEMENT_DIR = Path("/opt/nnids/engagements")

ALERT_PATTERN = re.compile(r"Threat \((?P<prob>[0-9]+\.?[0-9]*)\)")
TACTIC_PATTERN = re.compile(r"\[(?P<tactic>[^\]]+)\]")
IP_PATTERN = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3})")


def _load_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    with path.open() as handle:
        return [line.strip() for line in handle if line.strip()]


def _parse_meta(part: str) -> Dict[str, object]:
    if not part.startswith("meta="):
        return {}
    try:
        return json.loads(part[len("meta="):])
    except json.JSONDecodeError:
        return {}


def parse_alert_line(line: str) -> Optional[Dict[str, object]]:
    """Convert a raw log line into a structured record."""

    if not line:
        return None
    parts = [segment.strip() for segment in line.split("|")]
    timestamp = None
    confidence = None
    message = line
    meta: Dict[str, object] = {}
    if len(parts) >= 3:
        timestamp = parts[0]
        confidence = parts[1].split()[0].lower()
        message = parts[2]
        for extra in parts[3:]:
            meta.update(_parse_meta(extra))
    else:
        lowered = line.lower()
        if lowered.startswith("high confidence"):
            confidence = "high"
        elif lowered.startswith("low confidence"):
            confidence = "low"
    prob_match = ALERT_PATTERN.search(message)
    probability = float(prob_match.group("prob")) if prob_match else meta.get("probability")
    tactic_match = TACTIC_PATTERN.search(message)
    tactic = tactic_match.group("tactic") if tactic_match else meta.get("tactic")
    reason = None
    if "Reason:" in message:
        reason = message.split("Reason:", 1)[-1].strip()
    if not reason:
        reason = meta.get("explanation") or meta.get("reason")
    src = meta.get("src")
    dst = meta.get("dst")
    if not src:
        ips = IP_PATTERN.findall(message)
        if ips:
            src = ips[0]
        if len(ips) > 1 and not dst:
            dst = ips[1]
    if not dst:
        dst_match = re.search(r">\s*(\d+\.\d+\.\d+\.\d+)", message)
        if dst_match:
            dst = dst_match.group(1)
    stage = meta.get("stage")
    severity = meta.get("severity")
    template = meta.get("template")
    recommendation = meta.get("recommendation")
    return {
        "timestamp": timestamp,
        "confidence": confidence,
        "probability": float(probability) if probability is not None else None,
        "tactic": tactic,
        "reason": reason,
        "stage": stage,
        "severity": severity,
        "template": template,
        "recommendation": recommendation,
        "src": src,
        "dst": dst,
    }


def load_alerts(path: Path) -> List[Dict[str, object]]:
    lines = _load_lines(path)
    records: List[Dict[str, object]] = []
    for line in lines:
        parsed = parse_alert_line(line)
        if parsed:
            records.append(parsed)
    return records


def _counter_summary(counter: Counter, limit: int = 5) -> List[str]:
    if not counter:
        return ["  - None"]
    return [f"  - {key}: {value}" for key, value in counter.most_common(limit)]


def _find_latest(directory: Path, suffix: str) -> Optional[Path]:
    if not directory.exists():
        return None
    candidates = sorted(directory.glob(f"*{suffix}"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def load_latest_engagement_summary(directory: Path) -> Optional[Dict[str, object]]:
    summary_path = _find_latest(directory, ".json")
    if summary_path is None:
        return None
    try:
        with summary_path.open() as handle:
            data = json.load(handle)
            data["summary_path"] = str(summary_path)
            return data
    except Exception:
        return None


def load_summary_file(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists():
        return None
    try:
        with path.open() as handle:
            data = json.load(handle)
            data["summary_path"] = str(path)
            return data
    except Exception:
        return None


def compute_coverage(alerts: List[Dict[str, object]], engagement: Dict[str, object]) -> Dict[str, object]:
    template_targets = {
        str(name): int(count)
        for name, count in (engagement.get("templates") or {}).items()
        if name not in (None, "")
    }
    alert_templates: Counter[str] = Counter()
    for alert in alerts:
        template = alert.get("template")
        if template:
            alert_templates[str(template)] += 1
    expected = set(template_targets.keys())
    detected = set(alert_templates.keys()) & expected
    missing = sorted(expected - detected)
    phases: List[Dict[str, object]] = []
    for phase in engagement.get("phases", []):
        if not isinstance(phase, dict):
            continue
        template = str(phase.get("template", "")) if phase.get("template") else ""
        name = str(phase.get("name", "Unnamed Phase"))
        phase_entry = {
            "name": name,
            "template": template or None,
            "detected": bool(template and template in alert_templates),
            "events": int(phase.get("count", 0) or 0),
            "alerts": alert_templates.get(template, 0) if template else 0,
        }
        phases.append(phase_entry)
    coverage_percent = (len(detected) / len(expected) * 100.0) if expected else 0.0
    return {
        "expected_templates": sorted(expected),
        "detected_templates": sorted(detected),
        "missing_templates": missing,
        "coverage_percent": coverage_percent,
        "alerts_by_template": dict(alert_templates),
        "phase_coverage": phases,
    }


def _format_counter(counter: Counter, limit: int = 5) -> List[str]:
    formatted: List[str] = []
    for key, value in counter.most_common(limit):
        formatted.append(f"  - {key}: {value}")
    if not formatted:
        formatted.append("  - None")
    return formatted


def build_report(alerts: List[Dict[str, object]], engagement: Optional[Dict[str, object]]) -> str:
    now = datetime.now(timezone.utc).isoformat()
    total = len(alerts)
    confidences = Counter(alert.get("confidence", "unknown") for alert in alerts)
    probabilities = [alert["probability"] for alert in alerts if alert.get("probability") is not None]
    avg_prob = sum(probabilities) / len(probabilities) if probabilities else 0.0
    tactic_counts = Counter(alert.get("tactic", "unknown") for alert in alerts)
    stage_counts = Counter(alert.get("stage", "unknown") for alert in alerts)
    severity_counts = Counter(alert.get("severity", "unknown") for alert in alerts)
    template_counts = Counter(alert.get("template", "unknown") for alert in alerts)
    reason_counts = Counter(alert.get("reason", "unknown") for alert in alerts)
    recommendation_counts = Counter(alert.get("recommendation", "") for alert in alerts if alert.get("recommendation"))
    source_counts = Counter(alert.get("src", "unknown") for alert in alerts)
    dest_counts = Counter(alert.get("dst", "unknown") for alert in alerts)

    lines: List[str] = []
    lines.append("# Engagement Post-Analysis Report")
    lines.append(f"*Generated:* {now}")
    lines.append("")
    lines.append("## Alert Overview")
    lines.append(f"- Total alerts analysed: {total}")
    lines.append(f"- High confidence alerts: {confidences.get('high', 0)}")
    lines.append(f"- Low confidence alerts: {confidences.get('low', 0)}")
    if probabilities:
        lines.append(f"- Average alert probability: {avg_prob:.3f}")
    lines.append("")

    lines.append("## Tactic Distribution")
    lines.extend(_counter_summary(tactic_counts))
    lines.append("")

    lines.append("## Kill Chain Stage Distribution")
    lines.extend(_counter_summary(stage_counts))
    lines.append("")

    lines.append("## Severity Mix")
    lines.extend(_counter_summary(severity_counts))
    lines.append("")

    lines.append("## Leading Alert Reasons")
    lines.extend(_counter_summary(reason_counts))
    lines.append("")

    lines.append("## Template Coverage")
    lines.extend(_counter_summary(template_counts))
    lines.append("")

    lines.append("## Source Hotspots")
    lines.extend(_counter_summary(source_counts))
    lines.append("")

    lines.append("## Destination Hotspots")
    lines.extend(_counter_summary(dest_counts))
    lines.append("")

    lines.append("## Recommended Responses Observed")
    lines.extend(_counter_summary(recommendation_counts))
    lines.append("")

    if engagement:
        lines.append("## Latest Engagement Simulation")
        lines.append(f"- Scenario: {engagement.get('scenario')}")
        origin = engagement.get("origin")
        if origin:
            lines.append(f"- Source: {origin}")
        lines.append(f"- Events simulated: {engagement.get('events')}")
        iterations = engagement.get("iterations")
        if iterations:
            lines.append(f"- Iterations: {iterations}")
        timeline = engagement.get("timeline") or {}
        if timeline:
            start = timeline.get("start")
            end = timeline.get("end")
            duration = timeline.get("duration_seconds")
            details = []
            if start:
                details.append(f"start {start}")
            if end:
                details.append(f"end {end}")
            if duration is not None:
                details.append(f"duration {duration:.1f}s")
            if details:
                lines.append("- Timeline: " + ", ".join(details))
        lines.append(f"- Summary file: {engagement.get('summary_path')}")
        response = engagement.get('response')
        if response:
            lines.append(f"- Recommended containment: {response}")
        kill_chain = engagement.get("kill_chain") or []
        if kill_chain:
            lines.append("- Kill chain progression: " + " → ".join(str(stage) for stage in kill_chain))
        tactic_sequence = engagement.get("tactic_sequence") or []
        if tactic_sequence:
            lines.append("- Tactic sequence: " + " → ".join(str(tactic) for tactic in tactic_sequence))
        severity = engagement.get('severity') or {}
        if severity:
            lines.append("- Simulated severity mix:")
            for label, value in sorted(severity.items(), key=lambda item: item[1], reverse=True):
                lines.append(f"  - {label}: {value}")
        risk = engagement.get("risk") or {}
        if risk:
            lines.append("- Risk posture: {level} (avg weight {avg:.2f}, score {score})".format(
                level=risk.get("level", "unknown"),
                avg=risk.get("average_severity", 0.0),
                score=risk.get("score", 0),
            ))
        objectives = engagement.get('objectives') or []
        if objectives:
            lines.append("- Scenario objectives:")
            for objective in objectives:
                lines.append(f"  - {objective}")
        lines.append("")

        coverage = compute_coverage(alerts, engagement)
        lines.append("### Detection Coverage")
        lines.append(
            "- Templates detected: {det}/{exp} ({pct:.1f}%)".format(
                det=len(coverage["detected_templates"]),
                exp=len(coverage["expected_templates"]),
                pct=coverage["coverage_percent"],
            )
        )
        if coverage["missing_templates"]:
            lines.append("- Missing templates: " + ", ".join(coverage["missing_templates"]))
        if coverage["detected_templates"]:
            lines.append("- Detected templates: " + ", ".join(coverage["detected_templates"]))
        lines.append("")

        if coverage["phase_coverage"]:
            lines.append("### Phase Coverage")
            for phase in coverage["phase_coverage"]:
                icon = "✅" if phase["detected"] else "⚠️"
                template = phase.get("template") or "n/a"
                lines.append(
                    f"  - {icon} {phase['name']} (template {template}) – events: {phase['events']}, alerts: {phase['alerts']}"
                )
            lines.append("")

        keywords = engagement.get("keywords") or {}
        if keywords:
            keyword_counter = Counter(keywords)
            lines.append("### Simulation Keyword Highlights")
            lines.extend(_format_counter(keyword_counter, limit=10))
            lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate IDS engagement post-analysis reports")
    parser.add_argument("--alerts", type=Path, default=DEFAULT_ALERT_LOG, help="alert log to analyse")
    parser.add_argument("--output", type=Path, help="output report path (Markdown)")
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR, help="directory for generated reports")
    parser.add_argument("--engagement-dir", type=Path, default=DEFAULT_ENGAGEMENT_DIR, help="directory containing engagement summaries")
    parser.add_argument("--latest-simulation", action="store_true", help="include the most recent engagement simulation summary")
    parser.add_argument("--summary", type=Path, help="explicit engagement summary to analyse")
    parser.add_argument("--stdout", action="store_true", help="also print the report to STDOUT")
    args = parser.parse_args()

    alerts = load_alerts(args.alerts)
    engagement: Optional[Dict[str, object]] = None
    if args.summary:
        engagement = load_summary_file(args.summary)
    elif args.latest_simulation:
        engagement = load_latest_engagement_summary(args.engagement_dir)
    report = build_report(alerts, engagement)

    if args.output:
        output_path = args.output
    else:
        args.analysis_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_path = args.analysis_dir / f"engagement_report_{timestamp}.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report)

    print(f"Analysis report written to {output_path}")
    if args.stdout:
        print("\n" + report)


if __name__ == "__main__":
    main()
