#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, load_json, write_json


FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}


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
    return {
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
    ]
    record = {"record_type": "session", "record_id": card["session_id"], "session_id": card["session_id"]}
    for key in keep:
        record[key] = card.get(key)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Build scan groups and classification records from session cards.")
    parser.add_argument("--session-cards", type=Path, default=ROOT / "outputs/session_cards/session_cards_all.json")
    parser.add_argument("--scan-groups-output", type=Path, default=ROOT / "outputs/session_cards/scan_groups.json")
    parser.add_argument("--records-output", type=Path, default=ROOT / "outputs/session_cards/classification_records_all.json")
    parser.add_argument("--report", type=Path, default=ROOT / "outputs/session_cards/classification_records_report.md")
    parser.add_argument("--scan-window-seconds", type=float, default=300.0)
    parser.add_argument("--min-scan-ports", type=int, default=8)
    parser.add_argument("--min-scan-sessions", type=int, default=8)
    parser.add_argument("--min-failed-rate", type=float, default=0.4)
    args = parser.parse_args()

    cards = load_json(args.session_cards) if args.session_cards.exists() else []
    groups = group_scan_cards(cards, args.scan_window_seconds, args.min_scan_ports, args.min_scan_sessions, args.min_failed_rate)
    scan_groups = [make_scan_group(group, idx) for idx, group in enumerate(groups, start=1)]
    covered = {sid for group in scan_groups for sid in group["member_session_ids"]}
    session_records = [make_session_record(card) for card in cards if card.get("session_id") not in covered]
    records = sorted([*scan_groups, *session_records], key=lambda r: (r.get("pcap_id") or "", r.get("start_time") is None, r.get("start_time") or 0, r.get("record_id") or ""))

    write_json(args.scan_groups_output, scan_groups)
    write_json(args.records_output, records)

    lines = [
        "# Classification records report",
        "",
        f"- Input session cards: `{display_path(args.session_cards)}`",
        f"- Session cards: {len(cards)}",
        f"- Scan groups: {len(scan_groups)}",
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
