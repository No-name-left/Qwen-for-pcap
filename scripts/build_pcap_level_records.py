#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from qwen35_rag_utils import ROOT, load_json, write_json
from session_card_indicators import redact_sensitive_text


INDICATOR_FIELDS = [
    "vuln_scan_indicators",
    "exploit_indicators",
    "auth_indicators",
    "implant_indicators",
    "backdoor_access_indicators",
    "c2_indicators",
]
PAYLOAD_FIELDS = [
    "suspicious_payload_snippets",
    "request_body_snippets_sanitized",
    "response_body_snippets_sanitized",
    "suspicious_http_parameters",
    "suspicious_uri_patterns",
    "http_upload_hints",
]


def as_float(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def as_count(value: Any) -> float:
    number = as_float(value)
    return number if number is not None else 0.0


def non_empty(value: Any) -> bool:
    return value not in (None, "", [], {}, "-")


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(path)


def stable_key(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def dedupe(values: Iterable[Any], limit: int = 10) -> list[Any]:
    out: list[Any] = []
    seen: set[str] = set()
    for value in values:
        if not non_empty(value):
            continue
        clean = sanitize_value(value)
        key = stable_key(clean).lower()
        if key and key not in seen:
            seen.add(key)
            out.append(clean)
        if len(out) >= limit:
            break
    return out


def sanitize_value(value: Any, char_limit: int = 220) -> Any:
    if isinstance(value, str):
        return redact_sensitive_text(value, char_limit)
    if isinstance(value, list):
        return [sanitize_value(item, char_limit) for item in value[:12]]
    if isinstance(value, dict):
        return {str(key): sanitize_value(item, char_limit) for key, item in value.items()}
    return value


def indicator_positive(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, list):
        return bool(value)
    if isinstance(value, dict):
        return any(
            indicator_positive(item)
            for key, item in value.items()
            if key not in {"weak_evidence", "auth_protocol", "interval_summary", "beacon_score"}
        )
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value > 0
    return False


def merge_values(values: list[Any], field: str = "", limit: int = 12) -> Any:
    values = [value for value in values if non_empty(value)]
    if not values:
        return None
    if all(isinstance(value, bool) for value in values):
        return any(values)
    if all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
        return max(values)
    if all(isinstance(value, list) for value in values):
        return dedupe((item for value in values for item in value), limit)
    if all(isinstance(value, dict) for value in values):
        keys = sorted({key for value in values for key in value})
        merged = {
            key: merge_values([value[key] for value in values if key in value], key, limit)
            for key in keys
        }
        return {key: item for key, item in merged.items() if non_empty(item)}
    if field == "payload_visibility":
        order = ["plaintext_http", "encrypted_tls", "metadata_only", "unknown"]
        return next((item for item in order if item in values), values[0])
    return dedupe(values, limit)[0]


def top_counter(rows: Iterable[dict[str, Any]], field: str, limit: int = 10) -> list[dict[str, Any]]:
    counter = Counter(str(row.get(field)) for row in rows if non_empty(row.get(field)))
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def sorted_seen(rows: Iterable[dict[str, Any]], field: str, limit: int = 20) -> list[Any]:
    counter = Counter(str(row.get(field)) for row in rows if non_empty(row.get(field)))
    return [value for value, _ in counter.most_common(limit)]


def time_bounds(rows: Iterable[dict[str, Any]]) -> tuple[float | None, float | None]:
    starts = [value for row in rows if (value := as_float(row.get("start_time"))) is not None]
    ends = [value for row in rows if (value := as_float(row.get("end_time"))) is not None]
    return (min(starts) if starts else None, max(ends or starts) if starts else None)


def value_list(rows: Iterable[dict[str, Any]], field: str, limit: int = 12) -> list[Any]:
    values: list[Any] = []
    for row in rows:
        value = row.get(field)
        if not non_empty(value):
            continue
        if isinstance(value, list):
            values.extend(value)
        else:
            values.append(value)
    return dedupe(values, limit)


def value_count(rows: Iterable[dict[str, Any]], field: str) -> int:
    return sum(1 for row in rows if non_empty(row.get(field)))


def row_identity(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": row.get("record_id") or row.get("session_id"),
        "record_type": row.get("record_type", "session"),
        "start_time": row.get("start_time"),
        "end_time": row.get("end_time"),
        "src_ip": row.get("src_ip"),
        "src_port": row.get("src_port"),
        "dst_ip": row.get("dst_ip"),
        "dst_port": row.get("dst_port"),
        "service": row.get("service"),
    }


def row_score(row: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    record_type = str(row.get("record_type") or "session")

    fanout = max(
        as_count(row.get("same_src_unique_dst_ports")),
        as_count(row.get("unique_dst_ports")),
        as_count(row.get("same_src_unique_dst_ips")),
    )
    failed_rate = max(as_count(row.get("same_src_failed_conn_rate")), as_count(row.get("failed_conn_rate")))
    if record_type == "scan_group" or fanout >= 8:
        score += 55
        reasons.append("scan_high_fanout")
    if failed_rate >= 0.5:
        score += 15
        reasons.append("failed_connection_rate")

    auth_failures = max(as_count(row.get("failed_login_count")), as_count((row.get("auth_indicators") or {}).get("failed_login_count")))
    attempts = max(as_count(row.get("attempt_count")), as_count(row.get("same_src_same_dst_auth_attempts")))
    if record_type == "auth_attempt_group" or auth_failures > 0 or attempts >= 5 or indicator_positive(row.get("auth_indicators")):
        score += 50
        reasons.append("auth_failures")

    beacon_score = max(
        as_count(row.get("beacon_score")),
        as_count(row.get("regularity_score")),
        as_count(row.get("periodicity_score")),
        as_count((row.get("c2_indicators") or {}).get("beacon_score")),
    )
    if record_type == "c2_callback_group" or beacon_score >= 0.5 or indicator_positive(row.get("c2_indicators")):
        score += 50
        reasons.append("beacon_or_c2")

    if indicator_positive(row.get("exploit_indicators")):
        score += 48
        reasons.append("exploit_or_command_payload")
    if indicator_positive(row.get("vuln_scan_indicators")):
        score += 38
        reasons.append("vulnerability_scan")
    if indicator_positive(row.get("implant_indicators")) or row.get("http_multipart_present") or non_empty(row.get("http_upload_hints")):
        score += 42
        reasons.append("upload_or_multipart")
    if indicator_positive(row.get("backdoor_access_indicators")):
        score += 42
        reasons.append("backdoor_or_webshell")
    if any(non_empty(row.get(field)) for field in PAYLOAD_FIELDS):
        score += 22
        reasons.append("observable_payload")

    volume = as_count(row.get("orig_pkts")) + as_count(row.get("resp_pkts")) + (as_count(row.get("orig_bytes")) + as_count(row.get("resp_bytes"))) / 4096
    score += min(15, int(volume))
    if not reasons:
        reasons.append("benign_context")
    return score, dedupe(reasons, 12)


def ranked_rows(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    ordered = sorted(
        rows,
        key=lambda row: (
            -row_score(row)[0],
            as_float(row.get("start_time")) is None,
            as_float(row.get("start_time")) or 0,
            str(row.get("record_id") or row.get("session_id") or ""),
        ),
    )
    out: list[dict[str, Any]] = []
    for row in ordered[:limit]:
        score, reasons = row_score(row)
        identity = row_identity(row)
        identity["score"] = score
        identity["reasons"] = reasons
        active = [field for field in INDICATOR_FIELDS if indicator_positive(row.get(field))]
        if active:
            identity["active_indicators"] = active
        if non_empty(row.get("candidate_hint")):
            identity["candidate_hint"] = row.get("candidate_hint")
        out.append(identity)
    return out


def payload_evidence(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in sorted(rows, key=lambda item: (-row_score(item)[0], str(item.get("record_id") or ""))):
        for field in PAYLOAD_FIELDS:
            value = row.get(field)
            if not non_empty(value):
                continue
            items = value if isinstance(value, list) else [value]
            for item in items:
                text = redact_sensitive_text(item, 220)
                key = text.lower()
                if not text or key in seen:
                    continue
                seen.add(key)
                out.append({
                    "source_record_id": row.get("record_id") or row.get("session_id"),
                    "source_record_type": row.get("record_type", "session"),
                    "field": field,
                    "text": text,
                })
                if len(out) >= limit:
                    return out
    return out


def summarize_scan(records: list[dict[str, Any]]) -> dict[str, Any]:
    scan_rows = [
        row for row in records
        if row.get("record_type") == "scan_group"
        or max(as_count(row.get("same_src_unique_dst_ports")), as_count(row.get("unique_dst_ports"))) >= 8
    ]
    if not scan_rows:
        return {"scan_like_record_count": 0}
    return {
        "scan_like_record_count": len(scan_rows),
        "group_count": sum(1 for row in scan_rows if row.get("record_type") == "scan_group"),
        "max_unique_dst_ports": int(max(max(as_count(row.get("unique_dst_ports")), as_count(row.get("same_src_unique_dst_ports"))) for row in scan_rows)),
        "max_failed_conn_rate": round(max(max(as_count(row.get("failed_conn_rate")), as_count(row.get("same_src_failed_conn_rate"))) for row in scan_rows), 4),
        "top_records": ranked_rows(scan_rows, 5),
    }


def summarize_auth(records: list[dict[str, Any]]) -> dict[str, Any]:
    auth_rows = [
        row for row in records
        if row.get("record_type") == "auth_attempt_group"
        or indicator_positive(row.get("auth_indicators"))
        or as_count(row.get("failed_login_count")) > 0
    ]
    if not auth_rows:
        return {"auth_like_record_count": 0}
    return {
        "auth_like_record_count": len(auth_rows),
        "group_count": sum(1 for row in auth_rows if row.get("record_type") == "auth_attempt_group"),
        "max_attempt_count": int(max(as_count(row.get("attempt_count")) for row in auth_rows)),
        "failed_login_count": int(sum(as_count(row.get("failed_login_count")) for row in auth_rows)),
        "auth_protocols": value_list(auth_rows, "auth_protocol", 8),
        "ftp_response_codes": value_list(auth_rows, "ftp_response_codes", 12),
        "top_records": ranked_rows(auth_rows, 5),
    }


def summarize_beacon(records: list[dict[str, Any]]) -> dict[str, Any]:
    beacon_rows = [
        row for row in records
        if row.get("record_type") == "c2_callback_group"
        or indicator_positive(row.get("c2_indicators"))
        or max(as_count(row.get("beacon_score")), as_count(row.get("periodicity_score")), as_count(row.get("regularity_score"))) >= 0.5
    ]
    if not beacon_rows:
        return {"beacon_like_record_count": 0}
    return {
        "beacon_like_record_count": len(beacon_rows),
        "group_count": sum(1 for row in beacon_rows if row.get("record_type") == "c2_callback_group"),
        "max_beacon_score": round(max(max(as_count(row.get("beacon_score")), as_count((row.get("c2_indicators") or {}).get("beacon_score"))) for row in beacon_rows), 4),
        "max_connection_count": int(max(as_count(row.get("connection_count")) for row in beacon_rows)),
        "fixed_endpoint_record_count": sum(1 for row in beacon_rows if (row.get("c2_indicators") or {}).get("fixed_remote_endpoint") or (row.get("c2_indicators") or {}).get("source_initiated_fixed_endpoint")),
        "top_records": ranked_rows(beacon_rows, 5),
    }


def summarize_payload_visibility(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counter = Counter(str(row.get("payload_visibility")) for row in rows if non_empty(row.get("payload_visibility")))
    return {
        "by_visibility": dict(sorted(counter.items())),
        "observable_payload_records": sum(1 for row in rows if bool(row.get("observable_payload_available"))),
        "http_body_observed_records": sum(1 for row in rows if bool(row.get("http_body_observed"))),
        "encrypted_records": sum(1 for row in rows if row.get("payload_visibility") == "encrypted_tls" or bool(row.get("encrypted_protocol"))),
        "metadata_only_records": sum(1 for row in rows if row.get("payload_visibility") == "metadata_only"),
        "suspicious_payload_record_count": sum(1 for row in rows if non_empty(row.get("suspicious_payload_snippets"))),
    }


def context_summaries(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    http = {
        "methods": value_list(rows, "http_methods", 10),
        "hosts": value_list(rows, "http_hosts", 12),
        "uris": value_list(rows, "http_uris_sample", 12),
        "full_uris": value_list(rows, "http_full_uri_sample", 6),
        "status_codes": value_list(rows, "http_status_codes", 12),
        "user_agents": value_list(rows, "http_user_agents", 8),
        "content_types": value_list(rows, "http_content_types", 8),
        "multipart_observed": any(bool(row.get("http_multipart_present")) for row in rows),
        "body_observed": any(bool(row.get("http_body_observed")) for row in rows),
        "upload_hints": value_list(rows, "http_upload_hints", 8),
        "suspicious_parameters": value_list(rows, "suspicious_http_parameters", 8),
    }
    dns = {
        "summary_samples": value_list(rows, "dns_summary", 8),
        "query_repetition": value_list(rows, "dns_query_repetition", 8),
    }
    tls = {
        "summary_samples": value_list(rows, "tls_summary", 8),
        "sni_repetition": value_list(rows, "tls_sni_repetition", 8),
    }
    ftp = {
        "response_codes": value_list(rows, "ftp_response_codes", 12),
        "status_code_summary": value_list(rows, "status_code_summary", 8),
        "transferred_files_summary": value_list(rows, "transferred_files_summary", 8),
    }
    return (
        {key: value for key, value in http.items() if non_empty(value)},
        {key: value for key, value in dns.items() if non_empty(value)},
        {key: value for key, value in tls.items() if non_empty(value)},
        {key: value for key, value in ftp.items() if non_empty(value)},
    )


def parse_summary_map(parse_summary: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in parse_summary:
        case_id = str(item.get("case_id") or "")
        if not case_id:
            continue
        out[case_id] = item
    return out


def build_pcap_record(
    pcap_id: str,
    session_cards: list[dict[str, Any]],
    classification_records: list[dict[str, Any]],
    parse_summary: dict[str, Any] | None = None,
    *,
    top_suspicious_limit: int = 8,
    top_payload_limit: int = 5,
) -> dict[str, Any]:
    rows = classification_records or session_cards
    session_rows = session_cards or [row for row in classification_records if row.get("record_type") == "session"]
    all_rows = [*session_cards, *classification_records]
    start, end = time_bounds(all_rows or rows)
    parse_summary = parse_summary or {}
    pcap_name = Path(str(parse_summary.get("pcap_path") or parse_summary.get("pcap") or pcap_id)).name
    http, dns, tls, ftp = context_summaries(rows)
    suspicious_counts = {
        field: sum(1 for row in rows if indicator_positive(row.get(field)))
        for field in INDICATOR_FIELDS
    }
    merged_indicators = {
        field: merge_values([row.get(field) for row in rows if non_empty(row.get(field))], field)
        for field in INDICATOR_FIELDS
    }
    merged_indicators = {field: value for field, value in merged_indicators.items() if non_empty(value)}
    top_payload = payload_evidence(rows, top_payload_limit)
    top_suspicious = ranked_rows(rows, top_suspicious_limit)
    record: dict[str, Any] = {
        "record_id": f"{pcap_id}::pcap",
        "session_id": f"{pcap_id}::pcap",
        "pcap_id": pcap_id,
        "pcap": pcap_name,
        "pcap_name": pcap_name,
        "record_type": "pcap",
        "start_time": start,
        "end_time": end,
        "time_range": {"start_time": start, "end_time": end, "duration": round(end - start, 6) if start is not None and end is not None else None},
        "src_ip": "multiple",
        "src_port": "multiple",
        "dst_ip": "multiple",
        "dst_port": "multiple",
        "proto": "multiple",
        "service": "multiple",
        "source_session_count": len(session_rows),
        "source_record_count": len(classification_records),
        "protocols_seen": sorted_seen(all_rows, "proto", 20),
        "top_src_ips": top_counter(session_rows or rows, "src_ip", 10),
        "top_dst_ips": top_counter(session_rows or rows, "dst_ip", 10),
        "top_dst_ports": top_counter(session_rows or rows, "dst_port", 15),
        "services_seen": sorted_seen(all_rows, "service", 20),
        "parser_sources_seen": sorted_seen(all_rows, "parser_source", 10),
        "payload_visibility_summary": summarize_payload_visibility(rows),
        "http_context_summary": http,
        "dns_context_summary": dns,
        "tls_context_summary": tls,
        "ftp_context_summary": ftp,
        "scan_group_summary": summarize_scan(rows),
        "auth_attempt_summary": summarize_auth(rows),
        "beacon_like_summary": summarize_beacon(rows),
        "suspicious_indicator_counts": suspicious_counts,
        "top_suspicious_sessions": top_suspicious,
        "top_payload_evidence": top_payload,
        "representative_benign_context": ranked_rows(rows, min(5, len(rows))),
        "evidence_limits": {
            "top_suspicious_sessions": top_suspicious_limit,
            "top_payload_evidence": top_payload_limit,
            "payload_policy": "bounded redacted snippets only; no complete payload, raw body, extracted files, or FTP command arguments",
        },
        "pcap_summary": {
            "pcap_name": pcap_name,
            "source_session_count": len(session_rows),
            "source_record_count": len(classification_records),
            "time_range": {"start_time": start, "end_time": end},
        },
    }
    if non_empty(parse_summary.get("parser_source")):
        record["parser_source"] = parse_summary.get("parser_source")
    if non_empty(parse_summary.get("payload_supplement_source")):
        record["payload_supplement_source"] = parse_summary.get("payload_supplement_source")
    if top_suspicious and non_empty(top_suspicious[0].get("candidate_hint")):
        record["candidate_hint"] = top_suspicious[0]["candidate_hint"]
    for field, value in merged_indicators.items():
        record[field] = value
    for field in (
        "payload_visibility",
        "observable_payload_available",
        "encrypted_protocol",
        "http_body_observed",
        "http_multipart_present",
        "suspicious_payload_snippets",
        "suspicious_http_parameters",
        "suspicious_uri_patterns",
        "http_upload_hints",
        "benign_periodic_hints",
    ):
        merged = merge_values([row.get(field) for row in rows if non_empty(row.get(field))], field)
        if non_empty(merged):
            record[field] = merged
    if http.get("uris"):
        record["http_uris_sample"] = http["uris"]
    if http.get("hosts"):
        record["http_hosts"] = http["hosts"]
    if dns:
        record["dns_summary"] = dns
    if tls:
        record["tls_summary"] = tls
    return record


def build_pcap_records(
    session_cards: list[dict[str, Any]],
    classification_records: list[dict[str, Any]],
    parse_summary: list[dict[str, Any]] | None = None,
    *,
    top_suspicious_limit: int = 8,
    top_payload_limit: int = 5,
) -> list[dict[str, Any]]:
    cards_by_pcap: dict[str, list[dict[str, Any]]] = defaultdict(list)
    records_by_pcap: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for card in session_cards:
        pcap_id = str(card.get("pcap_id") or "")
        if pcap_id:
            cards_by_pcap[pcap_id].append(card)
    for record in classification_records:
        pcap_id = str(record.get("pcap_id") or "")
        if pcap_id:
            records_by_pcap[pcap_id].append(record)
    summary_by_case = parse_summary_map(parse_summary or [])
    pcap_ids = sorted(set(cards_by_pcap) | set(records_by_pcap) | set(summary_by_case))
    return [
        build_pcap_record(
            pcap_id,
            cards_by_pcap.get(pcap_id, []),
            records_by_pcap.get(pcap_id, []),
            summary_by_case.get(pcap_id),
            top_suspicious_limit=top_suspicious_limit,
            top_payload_limit=top_payload_limit,
        )
        for pcap_id in pcap_ids
    ]


def write_report(path: Path, output: Path, records: list[dict[str, Any]], args: argparse.Namespace) -> None:
    lines = [
        "# PCAP-level record build report",
        "",
        f"- Records: {len(records)}",
        f"- Output: `{display_path(output)}`",
        f"- Top suspicious session limit: {args.top_suspicious_limit}",
        f"- Top payload evidence limit: {args.top_payload_limit}",
        "",
        "## Safety",
        "",
        "- Aggregates preserve bounded, redacted observable summaries only.",
        "- Full payloads, raw HTTP bodies, extracted files, and FTP command arguments are not emitted.",
        "",
    ]
    for record in records[:20]:
        lines.append(f"## {record['record_id']}")
        lines.append(f"- pcap: `{record.get('pcap_name') or record.get('pcap_id')}`")
        lines.append(f"- source sessions: {record.get('source_session_count', 0)}")
        lines.append(f"- source classification records: {record.get('source_record_count', 0)}")
        lines.append(f"- top suspicious sessions: {len(record.get('top_suspicious_sessions') or [])}")
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate session/group classification records into one bounded record per PCAP.")
    parser.add_argument("--session-cards", type=Path, required=True)
    parser.add_argument("--classification-records", type=Path, required=True)
    parser.add_argument("--parse-summary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--top-suspicious-limit", type=int, default=8)
    parser.add_argument("--top-payload-limit", type=int, default=5)
    args = parser.parse_args()

    session_cards = load_json(args.session_cards) if args.session_cards.exists() else []
    classification_records = load_json(args.classification_records) if args.classification_records.exists() else []
    parse_summary = load_json(args.parse_summary) if args.parse_summary and args.parse_summary.exists() else []
    records = build_pcap_records(
        session_cards,
        classification_records,
        parse_summary,
        top_suspicious_limit=args.top_suspicious_limit,
        top_payload_limit=args.top_payload_limit,
    )
    write_json(args.output, records)
    write_report(args.report, args.output, records, args)
    print(f"built {len(records)} pcap-level records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
