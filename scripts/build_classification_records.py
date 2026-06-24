#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, load_json, write_json


FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}
AUTH_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 443: "http", 445: "smb", 3389: "rdp", 8080: "http", 8443: "http"}
COMMON_PORTS = {21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 587, 993, 995, 3389}
OBSERVABLE_FIELDS = [
    "payload_visibility", "observable_payload_available", "encrypted_protocol",
    "extraction_warnings", "evidence_limits", "evidence_mapping",
    "http_summary", "dns_summary", "tls_summary",
    "http_methods", "http_hosts", "http_uris_sample", "http_full_uri_sample",
    "http_status_codes", "http_user_agents", "http_referrers", "http_content_types",
    "http_request_body_len", "http_response_body_len", "http_cookie_present",
    "http_auth_header_present", "http_multipart_present", "http_upload_hints",
    "http_body_observed", "request_body_snippets_sanitized",
    "response_body_snippets_sanitized", "suspicious_payload_snippets",
    "suspicious_http_parameters", "suspicious_uri_patterns",
    "exploit_indicators", "vuln_scan_indicators", "auth_indicators",
    "implant_indicators", "backdoor_access_indicators", "c2_indicators",
    "transferred_files_summary", "pcap_summary",
]


def as_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(path)


def is_scan_candidate(card: dict[str, Any], min_failed_rate: float) -> bool:
    duration = as_float(card.get("duration"))
    total_bytes = (card.get("orig_bytes") or 0) + (card.get("resp_bytes") or 0)
    return (
        card.get("proto") in {"tcp", "udp"}
        and card.get("src_ip")
        and card.get("dst_ip")
        and card.get("same_src_unique_dst_ports", 0) >= 8
        and card.get("same_src_failed_conn_rate", 0) >= min_failed_rate
        and (duration is None or duration <= 5)
        and total_bytes <= 2000
    )


def group_scan_cards(cards: list[dict[str, Any]], window_seconds: float = 300.0, min_ports: int = 8, min_sessions: int = 8, min_failed_rate: float = 0.4) -> list[list[dict[str, Any]]]:
    by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for card in cards:
        if is_scan_candidate(card, min_failed_rate):
            by_key[(str(card.get("pcap_id")), str(card.get("src_ip")), str(card.get("dst_ip")), str(card.get("proto")))].append(card)

    groups: list[list[dict[str, Any]]] = []
    for key_cards in by_key.values():
        key_cards.sort(key=lambda c: (as_float(c.get("start_time")) is None, as_float(c.get("start_time")) or 0.0, c.get("session_id")))
        current: list[dict[str, Any]] = []
        group_start: float | None = None
        for card in key_cards:
            ts = as_float(card.get("start_time"))
            if current and group_start is not None and ts is not None and ts - group_start > window_seconds:
                if len({c.get("dst_port") for c in current}) >= min_ports and len(current) >= min_sessions:
                    groups.append(current)
                current = []
                group_start = None
            if not current:
                group_start = ts
            current.append(card)
        if current and len({c.get("dst_port") for c in current}) >= min_ports and len(current) >= min_sessions:
            groups.append(current)
    return groups


def make_scan_group(group: list[dict[str, Any]], idx: int) -> dict[str, Any]:
    ports = sorted({c.get("dst_port") for c in group if c.get("dst_port") not in (None, "")}, key=lambda x: int(x) if isinstance(x, int) or str(x).isdigit() else str(x))
    failed = [c for c in group if c.get("conn_state") in FAILED_STATES]
    start_times = [as_float(c.get("start_time")) for c in group if as_float(c.get("start_time")) is not None]
    end_times = [as_float(c.get("end_time")) for c in group if as_float(c.get("end_time")) is not None]
    first = group[0]
    record = {
        "record_type": "scan_group",
        "record_id": f"{first['pcap_id']}::scan_group::{idx:06d}",
        "session_id": f"{first['pcap_id']}::scan_group::{idx:06d}",
        "pcap_id": first["pcap_id"],
        "parser_source": first.get("parser_source"),
        "start_time": min(start_times) if start_times else None,
        "end_time": max(end_times) if end_times else None,
        "src_ip": first.get("src_ip"),
        "src_port": "multiple",
        "dst_ip": first.get("dst_ip"),
        "dst_port": "multiple",
        "proto": first.get("proto"),
        "session_count": len(group),
        "unique_dst_ports": len(ports),
        "dst_ports_sample": ports[:30],
        "failed_conn_rate": round(len(failed) / len(group), 4) if group else 0.0,
        "member_session_ids": [c["session_id"] for c in group],
        "candidate_hint": "TA43_01",
    }
    for field in OBSERVABLE_FIELDS:
        values = [card.get(field) for card in group if card.get(field) not in (None, "", [], {})]
        if values:
            record[field] = merge_observable_values(values, field)
    # A vulnerability-scanner probe must override the generic port-scan candidate hint.
    vuln = record.get("vuln_scan_indicators") or {}
    if any(value is True for value in vuln.values()) or vuln.get("matched_keywords"):
        record["candidate_hint"] = "TA43_02"
    return record


def merge_observable_values(values: list[Any], field: str = "") -> Any:
    if not values:
        return None
    if field == "pcap_summary":
        return values[0]
    if all(isinstance(value, bool) for value in values):
        return any(values)
    if all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
        return sum(values) if field.endswith("_body_len") or field == "total_files" else max(values)
    if all(isinstance(value, list) for value in values):
        merged: list[Any] = []
        seen: set[str] = set()
        for item in (item for value in values for item in value):
            key = json.dumps(item, ensure_ascii=False, sort_keys=True) if isinstance(item, (dict, list)) else str(item)
            if key not in seen:
                seen.add(key)
                merged.append(item)
            if len(merged) >= 12:
                break
        return merged
    if all(isinstance(value, dict) for value in values):
        keys = {key for value in values for key in value}
        return {key: merge_observable_values([value[key] for value in values if key in value], key) for key in sorted(keys)}
    if field == "payload_visibility":
        order = ["plaintext_http", "encrypted_tls", "metadata_only", "unknown"]
        return next((item for item in order if item in values), values[0])
    return values[0]


def time_bounds(cards: list[dict[str, Any]]) -> tuple[float | None, float | None]:
    starts = [as_float(card.get("start_time")) for card in cards]
    ends = [as_float(card.get("end_time")) for card in cards]
    starts = [value for value in starts if value is not None]
    ends = [value for value in ends if value is not None]
    return (min(starts) if starts else None, max(ends or starts) if starts else None)


def split_close_time(cards: list[dict[str, Any]], window_seconds: float) -> list[list[dict[str, Any]]]:
    ordered = sorted(cards, key=lambda card: (as_float(card.get("start_time")) is None, as_float(card.get("start_time")) or 0))
    groups: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    previous: float | None = None
    for card in ordered:
        ts = as_float(card.get("start_time"))
        if current and previous is not None and ts is not None and ts - previous > window_seconds:
            groups.append(current)
            current = []
        current.append(card)
        if ts is not None:
            previous = ts
    if current:
        groups.append(current)
    return groups


def inferred_auth_protocol(card: dict[str, Any]) -> str | None:
    indicator = card.get("auth_indicators") or {}
    protocol = str(indicator.get("auth_protocol") or "").lower()
    if protocol and protocol != "unknown":
        return protocol
    service = str(card.get("service") or "").lower()
    if service in {"ftp", "ssh", "http", "https", "rdp", "smb", "smb2", "telnet"}:
        return "http" if service == "https" else "smb" if service == "smb2" else service
    try:
        return AUTH_PORTS.get(int(card.get("dst_port")))
    except (TypeError, ValueError):
        return None


def group_auth_cards(cards: list[dict[str, Any]], window_seconds: float = 300.0, min_attempts: int = 3) -> list[list[dict[str, Any]]]:
    by_key: dict[tuple[str, str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for card in cards:
        protocol = inferred_auth_protocol(card)
        if not protocol or not card.get("src_ip") or not card.get("dst_ip"):
            continue
        key = (
            str(card.get("pcap_id")), str(card.get("src_ip")), str(card.get("dst_ip")),
            str(card.get("dst_port")), str(card.get("proto")), protocol,
        )
        by_key[key].append(card)
    return [group for cards_for_key in by_key.values() for group in split_close_time(cards_for_key, window_seconds) if len(group) >= min_attempts]


def make_auth_attempt_group(group: list[dict[str, Any]], idx: int) -> dict[str, Any]:
    first = group[0]
    protocol = inferred_auth_protocol(first) or "unknown"
    indicators = [card.get("auth_indicators") or {} for card in group]
    per_session_attempts = [max(1, int(item.get("same_src_same_dst_auth_attempts") or 0)) for item in indicators]
    attempt_count = sum(per_session_attempts)
    failed_login_count = sum(int(item.get("failed_login_count") or 0) for item in indicators)
    status_codes = [str(code) for item in indicators for code in item.get("auth_status_codes", [])]
    ftp_codes = [str(code) for item in indicators for code in item.get("ftp_response_codes", [])]
    start, end = time_bounds(group)
    span = max(0.0, (end or start or 0) - (start or 0)) if start is not None else None
    username_seen = any(bool(item.get("username_field_seen")) for item in indicators)
    password_seen = any(bool(item.get("password_field_seen")) for item in indicators)
    ssh_failure = any(bool(item.get("ssh_auth_failure_hint")) for item in indicators)
    repeated = attempt_count >= 5
    high = repeated and failed_login_count >= 2 and (username_seen or password_seen or ssh_failure)
    weak_reason = None if high else "Repeated connection metadata lacks enough credential fields or explicit authentication failures."
    auth_group_id = f"{first['pcap_id']}::auth_attempt_group::{idx:06d}"
    group_indicator = {
        "auth_protocol": protocol,
        "repeated_login_attempts": repeated,
        "failed_login_hint": failed_login_count > 0,
        "success_after_failures_hint": any(bool(item.get("success_after_failures_hint")) for item in indicators),
        "same_src_same_dst_auth_attempts": attempt_count,
        "username_field_seen": username_seen,
        "password_field_seen": password_seen,
        "unique_usernames_seen": max((int(item.get("unique_usernames_seen") or 0) for item in indicators), default=0),
        "failed_login_count": failed_login_count,
        "auth_status_codes": sorted(set(status_codes)),
        "ftp_response_codes": sorted(set(ftp_codes)),
        "ssh_auth_failure_hint": ssh_failure,
        "http_login_paths": merge_observable_values([item.get("http_login_paths", []) for item in indicators], "http_login_paths"),
        "weak_evidence": not high,
    }
    return {
        "record_type": "auth_attempt_group", "record_id": auth_group_id, "session_id": auth_group_id,
        "auth_group_id": auth_group_id, "pcap_id": first.get("pcap_id"), "parser_source": first.get("parser_source"),
        "start_time": start, "end_time": end, "src_ip": first.get("src_ip"), "src_port": "multiple",
        "dst_ip": first.get("dst_ip"), "dst_port": first.get("dst_port"), "proto": first.get("proto"),
        "service": first.get("service"), "auth_protocol": protocol, "attempt_count": attempt_count,
        "unique_usernames_seen": group_indicator["unique_usernames_seen"], "username_field_seen": username_seen,
        "password_field_seen": password_seen, "failed_login_count": failed_login_count,
        "success_after_failures_hint": group_indicator["success_after_failures_hint"],
        "repeated_login_attempts": repeated, "same_src_same_dst_auth_attempts": attempt_count,
        "time_span": round(span, 3) if span is not None else None,
        "attempt_rate": round(attempt_count / max(span, 1.0), 4) if span is not None else None,
        "status_code_summary": dict(Counter(status_codes)), "ftp_response_codes": sorted(set(ftp_codes)),
        "ssh_auth_failure_hint": ssh_failure, "http_login_paths": group_indicator["http_login_paths"],
        "weak_evidence_reason": weak_reason, "evidence_tier": "high_auth_behavioral" if high else "weak_auth_evidence",
        "auth_indicators": group_indicator, "member_session_count": len(group),
        "member_session_ids": [card["session_id"] for card in group],
    }


def group_c2_cards(cards: list[dict[str, Any]], min_connections: int = 4) -> list[list[dict[str, Any]]]:
    by_key: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for card in cards:
        if not card.get("src_ip") or not card.get("dst_ip"):
            continue
        key = (
            str(card.get("pcap_id")), str(card.get("src_ip")), str(card.get("dst_ip")),
            str(card.get("dst_port")), str(card.get("proto")),
        )
        by_key[key].append(card)
    return [group for group in by_key.values() if len(group) >= min_connections]


def numeric_pattern(values: list[float]) -> dict[str, Any]:
    ordered = sorted(values)
    mean = statistics.mean(ordered) if ordered else None
    cv = statistics.pstdev(ordered) / mean if len(ordered) >= 2 and mean else None
    return {
        "count": len(ordered), "min": round(ordered[0], 3) if ordered else None,
        "median": round(statistics.median(ordered), 3) if ordered else None,
        "p90": round(ordered[int(0.9 * (len(ordered) - 1))], 3) if ordered else None,
        "max": round(ordered[-1], 3) if ordered else None, "cv": round(cv, 3) if cv is not None else None,
    }


def make_c2_callback_group(group: list[dict[str, Any]], idx: int) -> dict[str, Any]:
    ordered = sorted(group, key=lambda card: as_float(card.get("start_time")) or 0)
    first = ordered[0]
    times = [as_float(card.get("start_time")) for card in ordered]
    times = [value for value in times if value is not None]
    intervals = [b - a for a, b in zip(times, times[1:]) if b >= a]
    interval_pattern = numeric_pattern(intervals)
    interval_cv = interval_pattern.get("cv")
    periodicity_score = round(1 / (1 + interval_cv), 3) if interval_cv is not None else 0.0
    bytes_pattern = numeric_pattern([float((card.get("orig_bytes") or 0) + (card.get("resp_bytes") or 0)) for card in ordered])
    duration_pattern = numeric_pattern([float(card.get("duration") or 0) for card in ordered])
    dns_queries = [query for card in ordered for query in (card.get("dns_summary") or {}).get("queries", [])]
    tls_sni = [name for card in ordered for name in (card.get("tls_summary") or {}).get("server_names", [])]
    repeated_dns = len(dns_queries) >= 3 and len(set(dns_queries)) < len(dns_queries)
    repeated_sni = len(tls_sni) >= 3 and len(set(tls_sni)) < len(tls_sni)
    try:
        unusual_port = int(first.get("dst_port")) not in COMMON_PORTS
    except (TypeError, ValueError):
        unusual_port = False
    small_repeated = len(ordered) >= 4 and (bytes_pattern.get("p90") or 0) <= 8192
    periodic = len(intervals) >= 3 and periodicity_score >= 0.6
    score = min(1.0, sum((
        0.2, 0.15 if len(ordered) >= 10 else 0.05, 0.2 if periodic else 0.0,
        0.15 if small_repeated else 0.0, 0.15 if unusual_port else 0.0,
        0.1 if repeated_dns or repeated_sni else 0.0, 0.05,
    )))
    start, end = time_bounds(ordered)
    c2_group_id = f"{first['pcap_id']}::c2_callback_group::{idx:06d}"
    evidence_tier = "high_callback_behavioral" if len(ordered) >= 5 and score >= 0.65 else "medium_callback_behavioral" if score >= 0.45 else "weak_callback_evidence"
    c2_indicators = {
        "periodic_connections": periodic, "fixed_remote_endpoint": True,
        "small_repeated_payload": small_repeated, "long_lived_connection": (end or 0) - (start or 0) >= 300 if start is not None else False,
        "dns_repeated_query": repeated_dns, "tls_sni_repeated": repeated_sni,
        "unusual_port": unusual_port, "client_initiated_external": True,
        "beacon_score": round(score, 3), "interval_summary": interval_pattern,
        "matched_keywords": [name for name, hit in (("periodic", periodic), ("fixed endpoint", True), ("small repeated payload", small_repeated), ("unusual port", unusual_port), ("repeated DNS", repeated_dns), ("repeated SNI", repeated_sni)) if hit],
    }
    return {
        "record_type": "c2_callback_group", "record_id": c2_group_id, "session_id": c2_group_id,
        "c2_group_id": c2_group_id, "pcap_id": first.get("pcap_id"), "parser_source": first.get("parser_source"),
        "start_time": start, "end_time": end, "src_ip": first.get("src_ip"), "src_port": "multiple",
        "dst_ip": first.get("dst_ip"), "dst_port": first.get("dst_port"), "proto": first.get("proto"),
        "service": first.get("service"), "connection_count": len(ordered), "interval_summary": interval_pattern,
        "periodicity_score": periodicity_score, "bytes_pattern": bytes_pattern, "duration_pattern": duration_pattern,
        "dns_query_repetition": {"repeated": repeated_dns, "query_count": len(dns_queries), "unique_count": len(set(dns_queries))},
        "tls_sni_repetition": {"repeated": repeated_sni, "sni_count": len(tls_sni), "unique_count": len(set(tls_sni))},
        "beacon_score": round(score, 3),
        "callback_direction_hint": "same source repeatedly initiates connections to one fixed remote endpoint",
        "evidence_tier": evidence_tier, "c2_indicators": c2_indicators,
        "http_hosts": merge_observable_values([card.get("http_hosts", []) for card in ordered], "http_hosts"),
        "http_uris_sample": merge_observable_values([card.get("http_uris_sample", []) for card in ordered], "http_uris_sample"),
        "dns_summary": merge_observable_values([card.get("dns_summary") for card in ordered if card.get("dns_summary")], "dns_summary"),
        "tls_summary": merge_observable_values([card.get("tls_summary") for card in ordered if card.get("tls_summary")], "tls_summary"),
        "member_session_count": len(ordered), "member_session_ids": [card["session_id"] for card in ordered],
    }


def make_session_record(card: dict[str, Any]) -> dict[str, Any]:
    keep = [
        "pcap_id",
        "parser_source",
        "start_time",
        "end_time",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "proto",
        "service",
        "duration",
        "orig_pkts",
        "resp_pkts",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
        "history",
        "zeek_uid",
        "tcp_stream",
        "http_summary",
        "dns_summary",
        "tls_summary",
        "same_src_conn_count",
        "same_src_unique_dst_ports",
        "same_src_unique_dst_ips",
        "same_src_failed_conn_rate",
        "same_dst_unique_src_count",
        "same_src_same_dst_port_count",
        *OBSERVABLE_FIELDS,
    ]
    record = {"record_type": "session", "record_id": card["session_id"], "session_id": card["session_id"]}
    for key in keep:
        record[key] = card.get(key)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Build scan groups and classification records from session cards.")
    parser.add_argument("--session-cards", type=Path, default=ROOT / "outputs/session_cards/session_cards_all.json")
    parser.add_argument("--scan-groups-output", type=Path, default=ROOT / "outputs/session_cards/scan_groups.json")
    parser.add_argument("--auth-groups-output", type=Path, default=ROOT / "outputs/session_cards/auth_attempt_groups.json")
    parser.add_argument("--c2-groups-output", type=Path, default=ROOT / "outputs/session_cards/c2_callback_groups.json")
    parser.add_argument("--records-output", type=Path, default=ROOT / "outputs/session_cards/classification_records_all.json")
    parser.add_argument("--report", type=Path, default=ROOT / "outputs/session_cards/classification_records_report.md")
    parser.add_argument("--scan-window-seconds", type=float, default=300.0)
    parser.add_argument("--min-scan-ports", type=int, default=8)
    parser.add_argument("--min-scan-sessions", type=int, default=8)
    parser.add_argument("--min-failed-rate", type=float, default=0.4)
    parser.add_argument("--emit-auth-groups", action="store_true")
    parser.add_argument("--emit-c2-groups", action="store_true")
    parser.add_argument("--auth-window-seconds", type=float, default=300.0)
    parser.add_argument("--min-auth-attempts", type=int, default=3)
    parser.add_argument("--min-c2-connections", type=int, default=4)
    parser.add_argument("--min-c2-group-score", type=float, default=0.45)
    args = parser.parse_args()

    cards = load_json(args.session_cards) if args.session_cards.exists() else []
    groups = group_scan_cards(cards, args.scan_window_seconds, args.min_scan_ports, args.min_scan_sessions, args.min_failed_rate)
    scan_groups = [make_scan_group(group, idx) for idx, group in enumerate(groups, start=1)]
    auth_source_groups = group_auth_cards(cards, args.auth_window_seconds, args.min_auth_attempts) if args.emit_auth_groups else []
    auth_groups = [make_auth_attempt_group(group, idx) for idx, group in enumerate(auth_source_groups, start=1)]
    auth_groups = [group for group in auth_groups if group["evidence_tier"] == "high_auth_behavioral"]
    c2_source_groups = group_c2_cards(cards, args.min_c2_connections) if args.emit_c2_groups else []
    c2_groups = [make_c2_callback_group(group, idx) for idx, group in enumerate(c2_source_groups, start=1)]
    c2_groups = [group for group in c2_groups if group["beacon_score"] >= args.min_c2_group_score]
    covered = {sid for group in [*scan_groups, *auth_groups, *c2_groups] for sid in group["member_session_ids"]}
    session_records = [make_session_record(card) for card in cards if card.get("session_id") not in covered]
    records = sorted([*scan_groups, *auth_groups, *c2_groups, *session_records], key=lambda r: (r.get("pcap_id") or "", r.get("start_time") is None, r.get("start_time") or 0, r.get("record_id") or ""))

    write_json(args.scan_groups_output, scan_groups)
    write_json(args.auth_groups_output, auth_groups)
    write_json(args.c2_groups_output, c2_groups)
    write_json(args.records_output, records)

    lines = [
        "# Classification records report",
        "",
        f"- Input session cards: `{display_path(args.session_cards)}`",
        f"- Session cards: {len(cards)}",
        f"- Scan groups: {len(scan_groups)}",
        f"- High-evidence auth attempt groups: {len(auth_groups)}",
        f"- C2 callback groups above score threshold: {len(c2_groups)}",
        f"- Scan thresholds: window_seconds={args.scan_window_seconds}, min_ports={args.min_scan_ports}, min_sessions={args.min_scan_sessions}, min_failed_rate={args.min_failed_rate}",
        f"- Covered scan member sessions: {len(covered)}",
        f"- Final classification records: {len(records)}",
        f"- Scan groups output: `{display_path(args.scan_groups_output)}`",
        f"- Classification records output: `{display_path(args.records_output)}`",
        "",
        "## Scan group policy",
        "",
        "- Multi-port port-scan sessions are grouped within the same PCAP by source IP, destination IP, protocol, time window, high unique destination ports, and high failed connection rate.",
        "- `dst_port` is written as `multiple`; `dst_ports_sample` records representative observed ports.",
        "- Clear scan-group member sessions are not emitted as separate final classification records, avoiding duplicated final output rows.",
        "- No cross-PCAP statistics, expected labels, or IP/domain reputation are used.",
    ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"built {len(records)} classification records with {len(scan_groups)} scan groups")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
