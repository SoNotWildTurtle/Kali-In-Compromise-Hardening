#!/usr/bin/env python3
"""nn_ids_service.py - Monitor network traffic and alert based on NN model."""
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
import ipaddress
from pathlib import Path

import joblib
from scapy.all import sniff, IP, TCP, UDP

import os
import subprocess

MODEL_PATH = "/opt/nnids/ids_model.pkl"
ALERT_STATE = Path("/var/lib/nn_ids/alert_stats.json")
STATE_LIMIT = 50
ALERT_HISTORY_LIMIT = 20
HIGH_CONFIDENCE_FLOOR = 0.8
HOUR_RANGE = 24
MINUTE_RETENTION_MINUTES = 120
MINUTE_FORMAT = "%Y-%m-%dT%H:%MZ"

RECON_PORTS = {0, 1, 7, 19, 135, 137, 138, 139, 1433, 3306, 31337}
LATERAL_PORTS = {22, 23, 135, 139, 445, 3389}
DISCOVERY_PORTS = {53, 161, 162, 389}
C2_PORTS = {80, 443, 8080, 8443, 9001}
EXFIL_PORTS = {25, 2525, 465, 587}
BURST_WINDOW_SECONDS = 30
BEACON_MIN_SECONDS = 90
BEACON_MAX_SECONDS = 900

TACTIC_STAGE_ORDER = {
    "Reconnaissance": 1,
    "Resource Development": 2,
    "Initial Access": 3,
    "Execution": 4,
    "Persistence": 5,
    "Privilege Escalation": 6,
    "Defense Evasion": 7,
    "Credential Access": 8,
    "Discovery": 9,
    "Lateral Movement": 10,
    "Collection": 11,
    "Command and Control": 12,
    "Exfiltration": 13,
    "Impact": 14,
}

NOTIFY_ENABLED = os.getenv("NN_IDS_NOTIFY", "1") == "1"
DISCOVERY_MODE = os.getenv("NN_IDS_DISCOVERY_MODE", "auto")
THRESHOLD = float(os.getenv("NN_IDS_THRESHOLD", "0.5"))

try:
    clf = joblib.load(MODEL_PATH)
except Exception:
    clf = None

benign_counts = defaultdict(int)


def _trim_counts(counts):
    if not isinstance(counts, dict):
        return {}
    if len(counts) <= STATE_LIMIT:
        return {k: int(v) for k, v in counts.items()}
    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return {k: int(v) for k, v in sorted_counts[:STATE_LIMIT]}


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _is_float(value):
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def _trim_profiles(profiles):
    if not isinstance(profiles, dict):
        return {}
    ranked = []
    for key, profile in profiles.items():
        if not isinstance(profile, dict):
            continue
        ranked.append((key, profile, _as_int(profile.get("count", 0))))
    ranked.sort(key=lambda item: item[2], reverse=True)
    trimmed = {}
    for key, profile, _count in ranked[:STATE_LIMIT]:
        trimmed[key] = profile
    return trimmed


def classify_tactic(prob, port, proto_label, reason, pkt):
    results = []
    reason_lower = (reason or "").lower()
    ttl = None
    if IP in pkt:
        try:
            ttl = int(pkt[IP].ttl)
        except Exception:
            ttl = None
    flags = None
    if TCP in pkt:
        try:
            flags = int(pkt[TCP].flags)
        except Exception:
            flags = None
    port_val = None
    if port is not None:
        try:
            port_val = int(port)
        except (TypeError, ValueError):
            port_val = None

    if ttl is not None and ttl <= 1:
        results.append(("Defense Evasion", "TTL spoofing / hop-limit abuse"))
    if flags is not None and flags in {0x3F, 0x29, 0x27}:
        results.append(("Reconnaissance", "Stealth TCP scan"))
    if "xmas" in reason_lower or "scan" in reason_lower:
        results.append(("Reconnaissance", "Aggressive probing"))
    if port_val in RECON_PORTS:
        results.append(("Reconnaissance", "Unusual service probe"))
    if port_val in LATERAL_PORTS:
        results.append(("Lateral Movement", "Remote service targeting"))
    if port_val in DISCOVERY_PORTS or "dns" in reason_lower:
        results.append(("Discovery", "Service enumeration"))
    if proto_label not in {"tcp", "udp"}:
        results.append(("Command and Control", f"Protocol {proto_label}"))
    if port_val in C2_PORTS and prob >= 0.7:
        results.append(("Command and Control", "Web channel or tunnel"))
    if port_val in EXFIL_PORTS:
        results.append(("Exfiltration", "Mail or relay channel"))
    if "spoof" in reason_lower and prob >= 0.6:
        results.append(("Defense Evasion", "Identity spoofing attempt"))
    if not results and prob >= 0.8:
        results.append(("Execution", "High-confidence anomaly"))

    deduped = []
    seen = set()
    for tactic, technique in results:
        if not tactic:
            continue
        key = (tactic, technique)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((tactic, technique))
    return deduped


def _categorize_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None, None, None

    if ip_obj.is_unspecified:
        category = "unspecified"
    elif ip_obj.is_loopback:
        category = "loopback"
    elif ip_obj.is_private:
        category = "private"
    elif ip_obj.is_link_local:
        category = "link-local"
    elif ip_obj.is_multicast:
        category = "multicast"
    elif ip_obj.is_reserved:
        category = "reserved"
    elif getattr(ip_obj, "is_global", False):
        category = "public"
    else:
        category = "other"

    subnet = None
    if isinstance(ip_obj, ipaddress.IPv4Address):
        subnet = f"{ip_obj.exploded.rsplit('.', 1)[0]}.0/24"
    elif isinstance(ip_obj, ipaddress.IPv6Address):
        subnet = str(ipaddress.IPv6Network((ip_obj, 64), strict=False))

    version = f"ipv{ip_obj.version}"
    return category, subnet, version


def _load_alert_stats():
    if ALERT_STATE.exists():
        try:
            return json.loads(ALERT_STATE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def update_alert_stats(prob, pkt, reason, tactic_pairs=None):
    if IP not in pkt:
        return

    reason_lower = (reason or "").lower()

    existing = _load_alert_stats()
    if not isinstance(existing, dict):
        existing = {}

    data = existing
    data["total_alerts"] = int(data.get("total_alerts", 0)) + 1

    high_cutoff = max(THRESHOLD, HIGH_CONFIDENCE_FLOOR)
    if prob >= high_cutoff:
        data["high_confidence"] = int(data.get("high_confidence", 0)) + 1
        current_high = _as_int(data.get("current_high_streak", 0)) + 1
        data["current_high_streak"] = current_high
        longest_high = _as_int(data.get("longest_high_streak", 0))
        data["longest_high_streak"] = max(longest_high, current_high)
        data["current_low_streak"] = 0
    else:
        data["low_confidence"] = int(data.get("low_confidence", 0)) + 1
        current_low = _as_int(data.get("current_low_streak", 0)) + 1
        data["current_low_streak"] = current_low
        longest_low = _as_int(data.get("longest_low_streak", 0))
        data["longest_low_streak"] = max(longest_low, current_low)
        data["current_high_streak"] = 0

    src = pkt[IP].src
    dst = pkt[IP].dst

    sources = data.get("sources") or {}
    if not isinstance(sources, dict):
        sources = {}
    sources[src] = _as_int(sources.get(src)) + 1
    data["sources"] = _trim_counts(sources)

    destinations = data.get("destinations") or {}
    if not isinstance(destinations, dict):
        destinations = {}
    destinations[dst] = _as_int(destinations.get(dst)) + 1
    data["destinations"] = _trim_counts(destinations)

    src_category, src_subnet, src_version = _categorize_ip(src)
    if src_category:
        src_categories = data.get("source_categories") or {}
        if not isinstance(src_categories, dict):
            src_categories = {}
        src_categories[src_category] = _as_int(src_categories.get(src_category)) + 1
        data["source_categories"] = _trim_counts(src_categories)
    if src_version:
        src_versions = data.get("source_versions") or {}
        if not isinstance(src_versions, dict):
            src_versions = {}
        src_versions[src_version] = _as_int(src_versions.get(src_version)) + 1
        data["source_versions"] = _trim_counts(src_versions)
    if src_subnet:
        src_subnets = data.get("source_subnets") or {}
        if not isinstance(src_subnets, dict):
            src_subnets = {}
        src_subnets[src_subnet] = _as_int(src_subnets.get(src_subnet)) + 1
        data["source_subnets"] = _trim_counts(src_subnets)

    dst_category, dst_subnet, dst_version = _categorize_ip(dst)
    if dst_category:
        dst_categories = data.get("destination_categories") or {}
        if not isinstance(dst_categories, dict):
            dst_categories = {}
        dst_categories[dst_category] = _as_int(dst_categories.get(dst_category)) + 1
        data["destination_categories"] = _trim_counts(dst_categories)
    if dst_version:
        dst_versions = data.get("destination_versions") or {}
        if not isinstance(dst_versions, dict):
            dst_versions = {}
        dst_versions[dst_version] = _as_int(dst_versions.get(dst_version)) + 1
        data["destination_versions"] = _trim_counts(dst_versions)
    if dst_subnet:
        dst_subnets = data.get("destination_subnets") or {}
        if not isinstance(dst_subnets, dict):
            dst_subnets = {}
        dst_subnets[dst_subnet] = _as_int(dst_subnets.get(dst_subnet)) + 1
        data["destination_subnets"] = _trim_counts(dst_subnets)

    port = None
    proto_label = "other"
    if TCP in pkt:
        port = pkt[TCP].dport
        proto_label = "tcp"
    elif UDP in pkt:
        port = pkt[UDP].dport
        proto_label = "udp"
    else:
        try:
            proto_label = str(pkt[IP].proto)
        except Exception:
            proto_label = "unknown"

    if tactic_pairs is None:
        tactic_pairs = classify_tactic(prob, port, proto_label, reason, pkt)

    primary_tactic = tactic_pairs[0][0] if tactic_pairs else None
    primary_technique = (
        tactic_pairs[0][1] if tactic_pairs and len(tactic_pairs[0]) > 1 else None
    )

    if port is not None:
        ports = data.get("destination_ports") or {}
        if not isinstance(ports, dict):
            ports = {}
        port_key = str(port)
        ports[port_key] = int(ports.get(port_key, 0)) + 1
        data["destination_ports"] = _trim_counts(ports)

    protocols = data.get("protocols") or {}
    if not isinstance(protocols, dict):
        protocols = {}
    protocols[proto_label] = _as_int(protocols.get(proto_label)) + 1
    data["protocols"] = _trim_counts(protocols)

    if proto_label not in {"tcp", "udp"}:
        anomalies = data.get("protocol_anomalies") or {}
        if not isinstance(anomalies, dict):
            anomalies = {}
        anomalies[proto_label] = _as_int(anomalies.get(proto_label)) + 1
        data["protocol_anomalies"] = _trim_counts(anomalies)

    ttl_counts = data.get("ttl_distribution") or {}
    if not isinstance(ttl_counts, dict):
        ttl_counts = {}
    try:
        ttl_value = int(pkt[IP].ttl)
    except Exception:
        ttl_value = None
    if ttl_value is not None:
        ttl_key = f"{ttl_value:02d}"
        ttl_counts[ttl_key] = _as_int(ttl_counts.get(ttl_key)) + 1
        data["ttl_distribution"] = _trim_counts(ttl_counts)
        try:
            current_min_ttl = int(data.get("min_ttl", ttl_value))
        except (TypeError, ValueError):
            current_min_ttl = ttl_value
        data["min_ttl"] = int(min(current_min_ttl, ttl_value))

    try:
        pkt_length = int(getattr(pkt[IP], "len", None))
    except (TypeError, ValueError):
        pkt_length = None
    if pkt_length is not None and pkt_length >= 0:
        length_buckets = data.get("length_buckets") or {}
        if not isinstance(length_buckets, dict):
            length_buckets = {}
        bucket_start = (pkt_length // 100) * 100
        bucket_end = bucket_start + 99
        bucket_key = f"{bucket_start}-{bucket_end}"
        length_buckets[bucket_key] = _as_int(length_buckets.get(bucket_key)) + 1
        data["length_buckets"] = _trim_counts(length_buckets)
        length_sum = float(data.get("length_sum", 0.0)) + float(pkt_length)
        length_count = int(data.get("length_count", 0)) + 1
        data["length_sum"] = length_sum
        data["length_count"] = length_count
        data["average_length"] = round(length_sum / max(length_count, 1), 1)
        try:
            current_max_length = int(data.get("max_length", 0))
        except (TypeError, ValueError):
            current_max_length = 0
        data["max_length"] = int(max(current_max_length, pkt_length))

    if TCP in pkt:
        flags_data = data.get("tcp_flag_combinations") or {}
        if not isinstance(flags_data, dict):
            flags_data = {}
        try:
            raw_flags = pkt[TCP].flags
            flag_label = str(raw_flags)
            if not flag_label or flag_label.strip() == "0":
                flag_label = f"0x{int(raw_flags):02x}"
        except Exception:
            try:
                flag_label = f"0x{int(pkt[TCP].flags):02x}"
            except Exception:
                flag_label = "unknown"
        flags_data[flag_label] = _as_int(flags_data.get(flag_label)) + 1
        data["tcp_flag_combinations"] = _trim_counts(flags_data)

    reasons = data.get("reason_counts") or {}
    if not isinstance(reasons, dict):
        reasons = {}
    reason_key = reason or "unknown"
    reasons[reason_key] = _as_int(reasons.get(reason_key)) + 1
    data["reason_counts"] = _trim_counts(reasons)

    pairs = data.get("source_destination_pairs") or {}
    if not isinstance(pairs, dict):
        pairs = {}
    pair_key = f"{src}->{dst}"
    pairs[pair_key] = _as_int(pairs.get(pair_key)) + 1
    data["source_destination_pairs"] = _trim_counts(pairs)

    hourly = data.get("hourly_distribution") or {}
    if not isinstance(hourly, dict):
        hourly = {}
    hour_key = datetime.now(timezone.utc).strftime("%H")
    hourly[hour_key] = int(hourly.get(hour_key, 0)) + 1

    def _hour_sort(value):
        try:
            return int(str(value)) % HOUR_RANGE
        except (TypeError, ValueError):
            return 0

    pruned_hourly = {}
    for key in sorted(hourly.keys(), key=_hour_sort):
        if len(pruned_hourly) >= HOUR_RANGE:
            break
        try:
            hour_int = int(str(key)) % HOUR_RANGE
            label = f"{hour_int:02d}"
            pruned_hourly[label] = int(hourly[key])
        except Exception:
            continue
    data["hourly_distribution"] = pruned_hourly

    buckets = data.get("probability_buckets") or {}
    if not isinstance(buckets, dict):
        buckets = {}
    try:
        bucket_key = f"{round(float(prob), 1):.1f}"
    except Exception:
        bucket_key = "0.0"
    buckets[bucket_key] = _as_int(buckets.get(bucket_key)) + 1
    sorted_buckets = {}
    for key in sorted(buckets.keys(), key=lambda item: float(item) if _is_float(item) else 0.0):
        try:
            sorted_buckets[f"{float(key):.1f}"] = int(buckets[key])
        except Exception:
            continue
    data["probability_buckets"] = sorted_buckets

    prob_sum = float(data.get("prob_sum", 0.0)) + float(prob)
    prob_count = int(data.get("prob_count", 0)) + 1
    data["prob_sum"] = prob_sum
    data["prob_count"] = prob_count
    data["average_probability"] = round(prob_sum / max(prob_count, 1), 3)
    prob_sq_sum = float(data.get("prob_squared_sum", 0.0)) + float(prob) ** 2
    data["prob_squared_sum"] = prob_sq_sum
    if prob_count > 0:
        mean = prob_sum / prob_count
        variance = max(prob_sq_sum / prob_count - mean ** 2, 0.0)
        data["prob_stddev"] = round(variance ** 0.5, 3)

    now_utc = datetime.now(timezone.utc)
    minute_key = now_utc.strftime(MINUTE_FORMAT)
    minute_counts = data.get("minute_counts") or {}
    if not isinstance(minute_counts, dict):
        minute_counts = {}
    minute_counts[minute_key] = _as_int(minute_counts.get(minute_key)) + 1

    pruned_counts = {}
    cutoff = now_utc - timedelta(minutes=MINUTE_RETENTION_MINUTES)
    for key, value in minute_counts.items():
        try:
            stamp = datetime.strptime(str(key), MINUTE_FORMAT)
        except Exception:
            continue
        if stamp >= cutoff:
            pruned_counts[str(key)] = _as_int(value)
    data["minute_counts"] = pruned_counts

    last_hour_cutoff = now_utc - timedelta(hours=1)
    alerts_last_hour = 0
    for key, value in pruned_counts.items():
        try:
            stamp = datetime.strptime(str(key), MINUTE_FORMAT)
        except Exception:
            continue
        if stamp >= last_hour_cutoff:
            alerts_last_hour += _as_int(value)
    data["alerts_last_hour"] = alerts_last_hour
    data["alerts_current_minute"] = _as_int(pruned_counts.get(minute_key))

    if pruned_counts:
        peak_minute, peak_value = max(
            pruned_counts.items(), key=lambda item: _as_int(item[1])
        )
        data["peak_minute_label"] = peak_minute
        data["peak_minute_count"] = _as_int(peak_value)
    else:
        data.pop("peak_minute_label", None)
        data.pop("peak_minute_count", None)

    now_iso = now_utc.isoformat(timespec="seconds")

    zero_day_hit = False
    if prob >= 0.9 and (not reason or reason_lower == "unknown pattern"):
        zero_day_hit = True
    elif prob >= 0.95 and "anomaly" in reason_lower:
        zero_day_hit = True
    elif prob >= 0.85 and proto_label not in {"tcp", "udp"}:
        zero_day_hit = True

    if zero_day_hit:
        data["zero_day_alerts"] = _as_int(data.get("zero_day_alerts", 0)) + 1
        zero_sources = data.get("zero_day_sources") or {}
        if not isinstance(zero_sources, dict):
            zero_sources = {}
        zero_sources[src] = _as_int(zero_sources.get(src)) + 1
        data["zero_day_sources"] = _trim_counts(zero_sources)

    profiles = data.get("source_profiles") or {}
    if not isinstance(profiles, dict):
        profiles = {}
    profile = profiles.get(src)
    if not isinstance(profile, dict):
        profile = {}

    alert_count = _as_int(profile.get("count", 0)) + 1
    profile["count"] = alert_count

    previous_epoch = _as_float(profile.get("last_seen_epoch"), 0.0)
    now_ts = now_utc.timestamp()
    profile_burst = _as_int(profile.get("burst_count", 0))
    profile_beacon = _as_int(profile.get("beacon_count", 0))

    if previous_epoch > 0:
        gap = max(0.0, now_ts - previous_epoch)
        profile["last_gap_seconds"] = round(gap, 1)
        if 0 < gap <= BURST_WINDOW_SECONDS:
            profile_burst += 1
            burst_sources = data.get("burst_sources") or {}
            if not isinstance(burst_sources, dict):
                burst_sources = {}
            burst_sources[src] = _as_int(burst_sources.get(src)) + 1
            data["burst_sources"] = _trim_counts(burst_sources)
        elif BEACON_MIN_SECONDS <= gap <= BEACON_MAX_SECONDS and prob < max(0.85, THRESHOLD + 0.2):
            profile_beacon += 1
            beacon_sources = data.get("beacon_sources") or {}
            if not isinstance(beacon_sources, dict):
                beacon_sources = {}
            beacon_sources[src] = _as_int(beacon_sources.get(src)) + 1
            data["beacon_sources"] = _trim_counts(beacon_sources)
    else:
        profile["last_gap_seconds"] = None

    profile["burst_count"] = profile_burst
    profile["beacon_count"] = profile_beacon
    profile["last_seen_epoch"] = round(now_ts, 3)
    profile["last_seen"] = now_iso
    profile.setdefault("first_seen", now_iso)
    profile.setdefault("first_seen_epoch", round(now_ts, 3))

    dwell_seconds = max(0.0, now_ts - _as_float(profile.get("first_seen_epoch"), now_ts))
    profile["dwell_seconds"] = round(dwell_seconds, 1)
    profile["dwell_minutes"] = int(dwell_seconds // 60)

    dwell_map = data.get("long_dwell_sources") or {}
    if not isinstance(dwell_map, dict):
        dwell_map = {}
    if profile["dwell_minutes"] >= 5:
        dwell_map[src] = profile["dwell_minutes"]
    else:
        dwell_map.pop(src, None)
    data["long_dwell_sources"] = _trim_counts(dwell_map)

    profile_prob_sum = _as_float(profile.get("prob_sum"), 0.0) + float(prob)
    profile["prob_sum"] = round(profile_prob_sum, 6)
    profile["avg_probability"] = round(profile_prob_sum / max(alert_count, 1), 3)
    profile["last_probability"] = round(float(prob), 3)
    profile["max_probability"] = round(
        max(_as_float(profile.get("max_probability", 0.0)), float(prob)), 3
    )

    profile["last_protocol"] = proto_label
    if port is not None:
        try:
            profile["last_port"] = int(port)
        except (TypeError, ValueError):
            profile["last_port"] = str(port)

    recent_reasons = profile.get("recent_reasons")
    if not isinstance(recent_reasons, list):
        recent_reasons = []
    if reason:
        recent_reasons.append(reason)
    elif zero_day_hit:
        recent_reasons.append("high-confidence anomaly")
    profile["recent_reasons"] = recent_reasons[-5:]
    profile["last_reason"] = reason

    profile_tactics = profile.get("tactics")
    if not isinstance(profile_tactics, dict):
        profile_tactics = {}
    profile_techniques = profile.get("techniques")
    if not isinstance(profile_techniques, dict):
        profile_techniques = {}
    recent_tactics = profile.get("recent_tactics")
    if not isinstance(recent_tactics, list):
        recent_tactics = []

    if tactic_pairs:
        tactic_counts = data.get("tactic_counts") or {}
        if not isinstance(tactic_counts, dict):
            tactic_counts = {}
        technique_counts = data.get("technique_counts") or {}
        if not isinstance(technique_counts, dict):
            technique_counts = {}
        for tactic, technique in tactic_pairs:
            if tactic:
                profile_tactics[tactic] = _as_int(profile_tactics.get(tactic)) + 1
                tactic_counts[tactic] = _as_int(tactic_counts.get(tactic)) + 1
                recent_tactics.append(tactic)
            if technique:
                profile_techniques[technique] = _as_int(profile_techniques.get(technique)) + 1
                technique_counts[technique] = _as_int(technique_counts.get(technique)) + 1
        data["tactic_counts"] = _trim_counts(tactic_counts)
        data["technique_counts"] = _trim_counts(technique_counts)
        if primary_tactic:
            profile["last_tactic"] = primary_tactic
            data["last_tactic"] = primary_tactic
        if primary_technique:
            profile["last_technique"] = primary_technique

    profile["tactics"] = _trim_counts(profile_tactics)
    profile["techniques"] = _trim_counts(profile_techniques)
    profile["recent_tactics"] = recent_tactics[-5:]

    unique_tactic_count = len(profile["tactics"])
    profile["tactic_diversity"] = unique_tactic_count
    diversity_map = data.get("tactic_diversity_sources") or {}
    if not isinstance(diversity_map, dict):
        diversity_map = {}
    diversity_map[src] = unique_tactic_count
    data["tactic_diversity_sources"] = _trim_counts(diversity_map)

    stage_advancements = _as_int(profile.get("stage_advancements", 0))
    max_stage_order = _as_int(profile.get("max_stage_order", 0))
    stage_history = profile.get("stage_history")
    if not isinstance(stage_history, list):
        stage_history = []
    stage_order = None
    if primary_tactic:
        stage_order = TACTIC_STAGE_ORDER.get(primary_tactic)
        if stage_order is not None:
            stage_totals = data.get("tactic_stage_totals") or {}
            if not isinstance(stage_totals, dict):
                stage_totals = {}
            stage_key = f"{stage_order:02d}-{primary_tactic}"
            stage_totals[stage_key] = _as_int(stage_totals.get(stage_key)) + 1
            data["tactic_stage_totals"] = _trim_counts(stage_totals)
            if stage_order > max_stage_order:
                stage_advancements += 1
                max_stage_order = stage_order
                stage_history.append(
                    {"tactic": primary_tactic, "order": stage_order, "time": now_iso}
                )
                progressions = data.get("kill_chain_progressions") or {}
                if not isinstance(progressions, dict):
                    progressions = {}
                progressions[src] = _as_int(progressions.get(src)) + 1
                data["kill_chain_progressions"] = _trim_counts(progressions)
    profile["stage_advancements"] = stage_advancements
    profile["max_stage_order"] = max_stage_order
    profile["stage_history"] = stage_history[-10:]

    last_primary = profile.get("last_primary_tactic")
    if last_primary and primary_tactic and last_primary != primary_tactic:
        transitions = data.get("tactic_transitions") or {}
        if not isinstance(transitions, dict):
            transitions = {}
        key = f"{last_primary} -> {primary_tactic}"
        transitions[key] = _as_int(transitions.get(key)) + 1
        data["tactic_transitions"] = _trim_counts(transitions)
    if primary_tactic:
        profile["last_primary_tactic"] = primary_tactic

    zero_hits = _as_int(profile.get("zero_day_hits", 0))
    if zero_day_hit:
        zero_hits += 1
    profile["zero_day_hits"] = zero_hits

    avg_prob_profile = _as_float(profile.get("avg_probability"), 0.0)
    max_prob_profile = _as_float(profile.get("max_probability"), 0.0)
    normalized_count = min(1.0, alert_count / 10.0)
    zero_factor = min(1.0, zero_hits / 3.0)
    risk_score = min(
        1.0,
        round(
            0.5 * avg_prob_profile
            + 0.3 * max_prob_profile
            + 0.2 * max(normalized_count, zero_factor),
            3,
        ),
    )
    profile["risk_score"] = risk_score

    apt_map = data.get("apt_suspects") or {}
    if not isinstance(apt_map, dict):
        apt_map = {}
    if stage_advancements >= 3 and unique_tactic_count >= 3 and risk_score >= 0.6:
        apt_map[src] = stage_advancements
    else:
        apt_map.pop(src, None)
    data["apt_suspects"] = _trim_counts(apt_map)

    profiles[src] = profile
    data["source_profiles"] = _trim_profiles(profiles)

    data["last_alert"] = now_iso
    data["last_reason"] = reason
    data["last_probability"] = round(float(prob), 3)
    data["last_summary"] = pkt.summary()
    data["max_probability"] = float(max(float(data.get("max_probability", 0.0)), prob))

    history = data.get("recent_alerts")
    if not isinstance(history, list):
        history = []
    history.append(
        {
            "time": now_iso,
            "src": src,
            "dst": dst,
            "probability": round(float(prob), 3),
            "reason": reason,
            "tactic": primary_tactic,
            "technique": primary_technique,
            "zero_day": bool(zero_day_hit),
        }
    )
    data["recent_alerts"] = history[-ALERT_HISTORY_LIMIT:]

    ALERT_STATE.parent.mkdir(parents=True, exist_ok=True)
    ALERT_STATE.write_text(json.dumps(data))


def extract_features(pkt):
    if IP in pkt and TCP in pkt:
        return [pkt[IP].len, pkt[IP].ttl, pkt[TCP].dport, int(pkt[TCP].flags)]
    return None


def explain(feats):
    length, ttl, dport, flags = feats
    reasons = []
    if ttl <= 1:
        reasons.append("TTL indicates potential spoofing")
    if dport in {0, 31337}:
        reasons.append(f"target port {dport} is suspicious")
    if flags == 0x3F:
        reasons.append("all TCP flags set (Xmas scan)")
    if flags & 0x01 and dport == 443 and length < 100:
        reasons.append("small FIN packet on TLS port")
    return "; ".join(reasons) or "unknown pattern"


def analyze(pkt):
    if clf is None:
        return
    feats = extract_features(pkt)
    if feats:
        prob = clf.predict_proba([feats])[0][1]
        pred = int(prob >= THRESHOLD)
        key = tuple(feats)
        if pred == 1:
            reason = explain(feats)
            port = None
            proto_label = "other"
            if TCP in pkt:
                port = pkt[TCP].dport
                proto_label = "tcp"
            elif UDP in pkt:
                port = pkt[UDP].dport
                proto_label = "udp"
            else:
                try:
                    proto_label = str(pkt[IP].proto)
                except Exception:
                    proto_label = "unknown"
            tactic_pairs = classify_tactic(prob, port, proto_label, reason, pkt)
            if tactic_pairs:
                tactic_label = tactic_pairs[0][0]
            else:
                tactic_label = None
            if tactic_label:
                message = (
                    f"Threat ({prob:.2f}) [{tactic_label}]: {pkt.summary()} Reason: {reason}"
                )
            else:
                message = f"Threat ({prob:.2f}): {pkt.summary()} Reason: {reason}"
            update_alert_stats(prob, pkt, reason, tactic_pairs)
            with open('/var/log/nn_ids_alerts.log', 'a') as f:
                if prob >= 0.8:
                    f.write(f'High confidence {message}\n')
                else:
                    f.write(f'Low confidence {message}\n')
            if NOTIFY_ENABLED:
                subprocess.run(["wall", message], check=False)
            if DISCOVERY_MODE == "auto":
                subprocess.Popen(["/usr/local/bin/network_discovery.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif DISCOVERY_MODE == "manual" and NOTIFY_ENABLED:
                subprocess.run(["wall", "Run /usr/local/bin/network_discovery.sh for details"], check=False)
            elif DISCOVERY_MODE == "notify" and NOTIFY_ENABLED:
                subprocess.run(["wall", "Malicious traffic detected"], check=False)
            benign_counts.pop(key, None)
        else:
            benign_counts[key] += 1
            if benign_counts[key] > 10:
                with open('/var/log/nn_ids_alerts.log', 'a') as f:
                    f.write(f'Possible desensitization attempt: {pkt.summary()}\n')
                benign_counts[key] = 0
        if len(benign_counts) > 1000:
            benign_counts.clear()


def main():
    sniff(prn=analyze, store=0)


if __name__ == '__main__':
    main()
