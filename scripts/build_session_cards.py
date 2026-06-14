#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, sanitize_for_prompt, write_json


FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}


def parse_float(value: Any) -> float | None:
    if value in (None, "", "-"):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(parsed):
        return None
    return parsed


def parse_int(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def sample(values: list[Any], limit: int = 10) -> list[Any]:
    out: list[Any] = []
    seen = set()
    for value in values:
        if value in (None, "", "-"):
            continue
        key = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def read_zeek_log(path: Path | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if path is None or not path.exists() or not path.is_file():
        return rows
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return rows
    if path.suffix in {".json", ".jsonl"}:
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
        return rows

    fields: list[str] | None = None
    for line in text.splitlines():
        if not line or line.startswith("#separator") or line.startswith("#set_separator") or line.startswith("#empty_field") or line.startswith("#unset_field") or line.startswith("#path") or line.startswith("#open") or line.startswith("#close"):
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#types"):
            continue
        if not fields:
            continue
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts.extend([""] * (len(fields) - len(parts)))
        rows.append(dict(zip(fields, parts)))
    return rows


def read_csv_rows(path: Path | None) -> list[dict[str, str]]:
    if path is None or not path.exists() or not path.is_file():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def read_suricata_eve(path: Path | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if path is None or not path.exists() or not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def pcap_dirs(parsed_dir: Path) -> list[Path]:
    if not parsed_dir.exists():
        return []
    summary_path = parsed_dir / "parse_all_summary.json"
    if summary_path.exists():
        try:
            rows = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            rows = []
        case_dirs = []
        for row in rows:
            case_id = row.get("case_id") if isinstance(row, dict) else None
            if case_id and (parsed_dir / case_id).is_dir():
                case_dirs.append(parsed_dir / case_id)
        if case_dirs:
            return sorted(case_dirs)
    direct_logs = [parsed_dir / "zeek" / "conn.log", parsed_dir / "conn.log"]
    if any(path.exists() for path in direct_logs):
        return [parsed_dir]
    return sorted(path for path in parsed_dir.iterdir() if path.is_dir())


def log_path(case_dir: Path, name: str) -> Path | None:
    candidates = [
        case_dir / "zeek" / name,
        case_dir / name,
        case_dir / "logs" / name,
    ]
    if name == "ssl.log":
        candidates.extend([case_dir / "zeek" / "tls.log", case_dir / "tls.log"])
    for path in candidates:
        if path.exists():
            return path
    return None


def suricata_path(case_dir: Path) -> Path | None:
    for path in [case_dir / "suricata" / "eve.json", case_dir / "eve.json"]:
        if path.exists():
            return path
    return None


def packets_path(case_dir: Path) -> Path | None:
    for path in [case_dir / "tshark" / "packets.csv", case_dir / "packets.csv"]:
        if path.exists():
            return path
    return None


def key_for_conn(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(row.get("id.orig_h") or row.get("src_ip") or row.get("src") or ""),
        str(row.get("id.orig_p") or row.get("src_port") or row.get("sport") or ""),
        str(row.get("id.resp_h") or row.get("dst_ip") or row.get("dest_ip") or row.get("dst") or ""),
        str(row.get("id.resp_p") or row.get("dst_port") or row.get("dport") or ""),
        str(row.get("proto") or "").lower(),
    )


def conn_time(row: dict[str, Any]) -> float | None:
    return parse_float(row.get("ts") or row.get("start_time") or row.get("timestamp"))


def build_side_indexes(rows: list[dict[str, Any]], key_func) -> dict[tuple[str, str, str, str, str], list[dict[str, Any]]]:
    out: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        out[key_func(row)].append(row)
    return out


def packet_key(row: dict[str, str]) -> tuple[str, str, str, str, str]:
    proto = (row.get("_ws.col.Protocol") or row.get("protocol") or "").lower()
    src = row.get("ip.src") or row.get("src_ip") or ""
    dst = row.get("ip.dst") or row.get("dst_ip") or ""
    sport = row.get("tcp.srcport") or row.get("udp.srcport") or row.get("src_port") or ""
    dport = row.get("tcp.dstport") or row.get("udp.dstport") or row.get("dst_port") or ""
    if row.get("tcp.srcport") or row.get("tcp.dstport") or "tcp" in proto or proto in {"ssh", "http", "tls", "ssl"}:
        proto = "tcp"
    elif "udp" in proto or "dns" in proto:
        proto = "udp"
    return (src, sport, dst, dport, proto)


def packet_time(row: dict[str, str]) -> float | None:
    return parse_float(row.get("frame.time_epoch") or row.get("timestamp") or row.get("ts"))


def packet_len(row: dict[str, str]) -> int:
    return parse_int(row.get("frame.len") or row.get("length") or row.get("len")) or 0


def alert_key(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    proto = str(row.get("proto") or row.get("app_proto") or "").lower()
    if proto not in {"tcp", "udp", "icmp"}:
        proto = "tcp" if row.get("src_port") or row.get("dest_port") else proto
    return (
        str(row.get("src_ip") or ""),
        str(row.get("src_port") or ""),
        str(row.get("dest_ip") or row.get("dst_ip") or ""),
        str(row.get("dest_port") or row.get("dst_port") or ""),
        proto,
    )


def rows_by_uid(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        uid = row.get("uid")
        if uid:
            out[str(uid)].append(row)
    return out


def make_http_summary(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    return {
        "count": len(rows),
        "hosts": sample([r.get("host") for r in rows]),
        "uris": sample([r.get("uri") for r in rows]),
        "methods": sample([r.get("method") for r in rows]),
        "status_codes": sample([r.get("status_code") for r in rows]),
        "user_agents": sample([r.get("user_agent") for r in rows], 5),
    }


def make_dns_summary(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    return {
        "count": len(rows),
        "queries": sample([r.get("query") for r in rows]),
        "rcode_names": sample([r.get("rcode_name") for r in rows]),
        "answers": sample([r.get("answers") for r in rows], 5),
    }


def make_tls_summary(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    return {
        "count": len(rows),
        "server_names": sample([r.get("server_name") for r in rows]),
        "versions": sample([r.get("version") for r in rows]),
        "ciphers": sample([r.get("cipher") for r in rows], 5),
    }


def make_alert_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts = []
    for row in rows:
        if row.get("event_type") != "alert" and "alert" not in row:
            continue
        alert = row.get("alert") if isinstance(row.get("alert"), dict) else {}
        alerts.append(
            {
                "timestamp": row.get("timestamp"),
                "signature": alert.get("signature") or row.get("signature"),
                "category": alert.get("category") or row.get("category"),
                "severity": alert.get("severity") or row.get("severity"),
            }
        )
    return alerts[:20]


def build_cards_from_packets(
    packet_rows: list[dict[str, str]],
    alert_index: dict[tuple[str, str, str, str, str], list[dict[str, Any]]],
    pcap_id: str,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in packet_rows:
        key = packet_key(row)
        if not key[0] or not key[2] or not key[4]:
            continue
        grouped[key].append(row)

    cards: list[dict[str, Any]] = []
    for idx, (key, rows) in enumerate(sorted(grouped.items(), key=lambda item: (packet_time(item[1][0]) or 0.0, item[0])), start=1):
        src_ip, src_port, dst_ip, dst_port, proto = key
        times = [t for t in (packet_time(row) for row in rows) if t is not None]
        start = min(times) if times else None
        end = max(times) if times else None
        tcp_stream = sample([row.get("tcp.stream") for row in rows], 1)
        syn_count = sum(1 for row in rows if str(row.get("tcp.flags.syn", "")).lower() in {"1", "true"})
        ack_count = sum(1 for row in rows if str(row.get("tcp.flags.ack", "")).lower() in {"1", "true"})
        orig_bytes = sum(packet_len(row) for row in rows if row.get("ip.src") == src_ip)
        resp_bytes = sum(packet_len(row) for row in rows if row.get("ip.src") == dst_ip)
        conn_state = None
        if proto == "tcp" and syn_count > 0 and ack_count == 0:
            conn_state = "S0"
        card = {
            "record_type": "session",
            "session_id": f"{pcap_id}::session::{idx:06d}",
            "pcap_id": pcap_id,
            "start_time": start,
            "end_time": end,
            "src_ip": src_ip or None,
            "src_port": parse_int(src_port) if str(src_port).isdigit() else (src_port or None),
            "dst_ip": dst_ip or None,
            "dst_port": parse_int(dst_port) if str(dst_port).isdigit() else (dst_port or None),
            "proto": proto or None,
            "service": None,
            "duration": round(end - start, 6) if start is not None and end is not None else None,
            "orig_pkts": sum(1 for row in rows if row.get("ip.src") == src_ip),
            "resp_pkts": sum(1 for row in rows if row.get("ip.src") == dst_ip),
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "conn_state": conn_state,
            "history": "tshark_fallback",
            "zeek_uid": None,
            "tcp_stream": tcp_stream[0] if tcp_stream else None,
            "related_suricata_alerts": make_alert_summary(alert_index.get(key, [])),
            "http_summary": make_http_summary(rows) if any(row.get("http.host") or row.get("http.request.uri") for row in rows) else None,
            "dns_summary": make_dns_summary([{"query": row.get("dns.qry.name")} for row in rows if row.get("dns.qry.name")]),
            "tls_summary": make_tls_summary([{"server_name": row.get("tls.handshake.extensions_server_name")} for row in rows if row.get("tls.handshake.extensions_server_name")]),
        }
        cards.append(card)
    return cards


def build_cards_for_pcap(case_dir: Path, pcap_id: str) -> list[dict[str, Any]]:
    conn_rows = read_zeek_log(log_path(case_dir, "conn.log"))
    http_by_uid = rows_by_uid(read_zeek_log(log_path(case_dir, "http.log")))
    dns_by_uid = rows_by_uid(read_zeek_log(log_path(case_dir, "dns.log")))
    tls_by_uid = rows_by_uid(read_zeek_log(log_path(case_dir, "ssl.log")))
    packet_rows = read_csv_rows(packets_path(case_dir))
    packet_index = build_side_indexes(packet_rows, packet_key)
    alert_rows = read_suricata_eve(suricata_path(case_dir))
    alert_index = build_side_indexes(alert_rows, alert_key)

    if not conn_rows and packet_rows:
        return build_cards_from_packets(packet_rows, alert_index, pcap_id)

    cards: list[dict[str, Any]] = []
    for idx, row in enumerate(conn_rows, start=1):
        src_ip, src_port, dst_ip, dst_port, proto = key_for_conn(row)
        ts = conn_time(row)
        duration = parse_float(row.get("duration"))
        end_ts = ts + duration if ts is not None and duration is not None else None
        uid = row.get("uid")
        key = (src_ip, src_port, dst_ip, dst_port, proto)
        packets = packet_index.get(key, [])
        related_alerts = make_alert_summary(alert_index.get(key, []))
        tcp_stream = sample([p.get("tcp.stream") for p in packets], 1)
        card = {
            "record_type": "session",
            "session_id": f"{pcap_id}::session::{idx:06d}",
            "pcap_id": pcap_id,
            "start_time": ts,
            "end_time": end_ts,
            "src_ip": src_ip or None,
            "src_port": parse_int(src_port) if str(src_port).isdigit() else (src_port or None),
            "dst_ip": dst_ip or None,
            "dst_port": parse_int(dst_port) if str(dst_port).isdigit() else (dst_port or None),
            "proto": proto or None,
            "service": row.get("service") if row.get("service") != "-" else None,
            "duration": duration,
            "orig_pkts": parse_int(row.get("orig_pkts")),
            "resp_pkts": parse_int(row.get("resp_pkts")),
            "orig_bytes": parse_int(row.get("orig_bytes")),
            "resp_bytes": parse_int(row.get("resp_bytes")),
            "conn_state": row.get("conn_state") if row.get("conn_state") != "-" else None,
            "history": row.get("history") if row.get("history") != "-" else None,
            "zeek_uid": uid,
            "tcp_stream": tcp_stream[0] if tcp_stream else None,
            "related_suricata_alerts": related_alerts,
            "http_summary": make_http_summary(http_by_uid.get(str(uid), [])) if uid else None,
            "dns_summary": make_dns_summary(dns_by_uid.get(str(uid), [])) if uid else None,
            "tls_summary": make_tls_summary(tls_by_uid.get(str(uid), [])) if uid else None,
        }
        cards.append(card)
    return cards


def add_context_features(cards: list[dict[str, Any]]) -> None:
    by_pcap: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for card in cards:
        by_pcap[card["pcap_id"]].append(card)

    for pcap_cards in by_pcap.values():
        by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
        by_dst: dict[str, list[dict[str, Any]]] = defaultdict(list)
        by_src_dst_port: dict[tuple[str, str, Any], list[dict[str, Any]]] = defaultdict(list)
        for card in pcap_cards:
            by_src[str(card.get("src_ip"))].append(card)
            by_dst[str(card.get("dst_ip"))].append(card)
            by_src_dst_port[(str(card.get("src_ip")), str(card.get("dst_ip")), card.get("dst_port"))].append(card)

        alert_times = [
            card.get("start_time")
            for card in pcap_cards
            if card.get("related_suricata_alerts") and isinstance(card.get("start_time"), (int, float))
        ]
        for card in pcap_cards:
            src_cards = by_src[str(card.get("src_ip"))]
            dst_cards = by_dst[str(card.get("dst_ip"))]
            failed = [c for c in src_cards if c.get("conn_state") in FAILED_STATES]
            same_src_same_dst_port = by_src_dst_port[(str(card.get("src_ip")), str(card.get("dst_ip")), card.get("dst_port"))]
            start = card.get("start_time")
            neighbor_alert_count = 0
            if isinstance(start, (int, float)):
                neighbor_alert_count = sum(1 for t in alert_times if isinstance(t, (int, float)) and abs(t - start) <= 60)
            card["same_src_conn_count"] = len(src_cards)
            card["same_src_unique_dst_ports"] = len({c.get("dst_port") for c in src_cards if c.get("dst_port") not in (None, "")})
            card["same_src_unique_dst_ips"] = len({c.get("dst_ip") for c in src_cards if c.get("dst_ip") not in (None, "")})
            card["same_src_failed_conn_rate"] = round(len(failed) / len(src_cards), 4) if src_cards else 0.0
            card["same_dst_unique_src_count"] = len({c.get("src_ip") for c in dst_cards if c.get("src_ip") not in (None, "")})
            card["same_src_same_dst_port_count"] = len(same_src_same_dst_port)
            card["time_window_neighbor_alert_count"] = neighbor_alert_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Build session cards from parsed PCAP outputs.")
    parser.add_argument("--parsed-dir", type=Path, default=ROOT / "outputs/parsed")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/session_cards/session_cards_all.json")
    parser.add_argument("--llm-output", type=Path, default=ROOT / "outputs/session_cards/llm_session_cards_all.json")
    parser.add_argument("--report", type=Path, default=ROOT / "outputs/session_cards/session_cards_report.md")
    parser.add_argument("--max-cards", type=int, default=0, help="Optional cap for small feasibility runs; 0 means no cap.")
    args = parser.parse_args()

    all_cards: list[dict[str, Any]] = []
    per_pcap: dict[str, int] = {}
    warnings: list[str] = []
    for case_dir in pcap_dirs(args.parsed_dir):
        pcap_id = case_dir.name if case_dir != args.parsed_dir else "parsed"
        cards = build_cards_for_pcap(case_dir, pcap_id)
        if not cards:
            warnings.append(f"No Zeek conn sessions found for `{pcap_id}`.")
        per_pcap[pcap_id] = len(cards)
        all_cards.extend(cards)

    if not args.parsed_dir.exists():
        warnings.append(f"Parsed input directory does not exist: `{args.parsed_dir.relative_to(ROOT)}`.")

    add_context_features(all_cards)
    original_count = len(all_cards)
    if args.max_cards and args.max_cards > 0:
        all_cards = sorted(all_cards, key=lambda c: (c.get("pcap_id") or "", c.get("start_time") is None, c.get("start_time") or 0, c.get("session_id") or ""))[: args.max_cards]
    write_json(args.output, all_cards)
    write_json(args.llm_output, sanitize_for_prompt(all_cards))

    lines = [
        "# Session cards report",
        "",
        f"- Parsed input: `{args.parsed_dir.relative_to(ROOT) if args.parsed_dir.is_absolute() and ROOT in args.parsed_dir.parents else args.parsed_dir}`",
        f"- Session cards: {len(all_cards)}",
        f"- Original uncapped session cards: {original_count}",
        f"- Max cards cap: {args.max_cards if args.max_cards else 'none'}",
        f"- Output: `{args.output.relative_to(ROOT)}`",
        f"- LLM-safe output: `{args.llm_output.relative_to(ROOT)}`",
        "",
        "## Per PCAP counts",
        "",
    ]
    if per_pcap:
        lines.extend(f"- {pcap_id}: {count}" for pcap_id, count in sorted(per_pcap.items()))
    else:
        lines.append("- none")
    lines.extend([
        "",
        "## Safety notes",
        "",
        "- Expected labels and answer files are not read.",
        "- Context features are computed within each PCAP only.",
        "- IP/domain reputation is not used.",
        "- LLM-safe output removes known leakage-prone keys through shared sanitizer.",
        "",
        "## Warnings",
        "",
    ])
    lines.extend(f"- {warning}" for warning in warnings) if warnings else lines.append("- none")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"built {len(all_cards)} session cards")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
