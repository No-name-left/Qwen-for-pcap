#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, sanitize_for_prompt, write_json
from session_card_indicators import (
    EVIDENCE_LIMITS,
    build_file_summary,
    build_http_fields,
    build_indicators,
    has_positive_indicator,
)


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


def safe_rate(total: int | float, duration: float | None) -> float | None:
    if duration is None or duration <= 0:
        return None
    return round(float(total) / duration, 4)


def uri_path(value: Any) -> str:
    return str(value or "").split("?", 1)[0].split("#", 1)[0]


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
    case_dirs: set[Path] = set()
    for conn_path in parsed_dir.rglob("conn.log"):
        if conn_path.parent.name in {"zeek", "logs"}:
            case_dirs.add(conn_path.parent.parent)
        else:
            case_dirs.add(conn_path.parent)
    for packet_path in parsed_dir.rglob("packets.csv"):
        if packet_path.parent.name == "tshark":
            case_dirs.add(packet_path.parent.parent)
        else:
            case_dirs.add(packet_path.parent)
    return sorted(case_dirs)


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


def packets_path(case_dir: Path) -> Path | None:
    for path in [case_dir / "tshark" / "packets.csv", case_dir / "packets.csv"]:
        if path.exists():
            return path
    return None


def observable_http_path(case_dir: Path) -> Path | None:
    for path in [case_dir / "tshark" / "observable_http.jsonl", case_dir / "observable_http.jsonl"]:
        if path.exists():
            return path
    return None


def parse_summary_by_case(parsed_dir: Path) -> dict[str, dict[str, Any]]:
    summary_path = parsed_dir / "parse_all_summary.json"
    if not summary_path.exists():
        return {}
    try:
        rows = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("case_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("case_id")
    }


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(path)


def key_for_conn(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(row.get("id.orig_h") or row.get("src_ip") or row.get("src") or ""),
        str(row.get("id.orig_p") or row.get("src_port") or row.get("sport") or ""),
        str(row.get("id.resp_h") or row.get("dst_ip") or row.get("dest_ip") or row.get("dst") or ""),
        str(row.get("id.resp_p") or row.get("dst_port") or row.get("dport") or ""),
        str(row.get("proto") or "").lower(),
    )


def canonical_key(key: tuple[str, str, str, str, str]) -> tuple[tuple[str, str], tuple[str, str], str]:
    left = (str(key[0]), str(key[1]))
    right = (str(key[2]), str(key[3]))
    return (*sorted((left, right)), str(key[4]).lower())


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


def ftp_rows_from_packets(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    return [
        {
            "command": row.get("ftp.request.command") or None,
            "reply_code": row.get("ftp.response.code") or None,
        }
        for row in rows
        if row.get("ftp.request.command") or row.get("ftp.response.code")
    ]


def observation_key(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(row.get("src_ip") or ""), str(row.get("src_port") or ""),
        str(row.get("dst_ip") or ""), str(row.get("dst_port") or ""), "tcp",
    )


def rows_by_uid(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        uid = row.get("uid")
        if uid:
            out[str(uid)].append(row)
    return out


def files_by_conn_uid(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        raw = str(row.get("conn_uids") or row.get("uid") or "")
        for uid in re_split_set(raw):
            out[uid].append(row)
    return out


def re_split_set(value: str) -> list[str]:
    return [item.strip() for item in value.strip("[]{}()").replace(";", ",").split(",") if item.strip() and item.strip() != "-"]


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
        "referrers": sample([r.get("referrer") for r in rows], 5),
        "content_types": sample([r.get("mime_type") or r.get("content_type") for r in rows], 5),
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


def make_session_evidence(
    service: str | None,
    dst_port: Any,
    http_rows: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    tls_rows: list[dict[str, Any]],
    file_rows: list[dict[str, Any]],
    ssh_rows: list[dict[str, Any]],
    ftp_rows: list[dict[str, Any]],
    observation_source_available: bool,
    mapping_method: str,
) -> dict[str, Any]:
    http = build_http_fields(http_rows, observations)
    files = build_file_summary(file_rows)
    indicators = build_indicators(http, files, ssh_rows, ftp_rows)
    normalized_service = str(service or "").lower()
    is_http = bool(http_rows or observations or normalized_service in {"http", "http-alt"})
    is_tls = bool(tls_rows or normalized_service in {"ssl", "tls", "https"})
    is_ssh = bool(ssh_rows or normalized_service == "ssh")
    is_quic = normalized_service in {"quic", "quic-ietf"} or (str(dst_port) == "443" and normalized_service == "udp")
    warnings: list[str] = []
    if is_http and not observation_source_available:
        warnings.append("tshark_observable_http_unavailable; HTTP body/header-presence evidence may be incomplete")
    if is_http and observation_source_available and not observations:
        warnings.append("no_mapped_tshark_http_observation; Zeek HTTP metadata retained")
    if is_tls:
        payload_visibility = "encrypted_tls"
        encrypted_protocol = "tls"
    elif is_ssh:
        payload_visibility = "metadata_only"
        encrypted_protocol = "ssh"
    elif is_quic:
        payload_visibility = "metadata_only"
        encrypted_protocol = "quic"
    elif is_http:
        payload_visibility = "plaintext_http"
        encrypted_protocol = "none"
    elif service or dst_port:
        payload_visibility = "metadata_only"
        encrypted_protocol = "none"
    else:
        payload_visibility = "unknown"
        encrypted_protocol = "unknown"
    http_summary = None
    if is_http:
        http_summary = {
            "count": max(len(http_rows), len(observations)),
            "hosts": http["http_hosts"],
            "uris": http["http_uris_sample"],
            "methods": http["http_methods"],
            "status_codes": http["http_status_codes"],
            "user_agents": http["http_user_agents"],
            "content_types": http["http_content_types"],
        }
    evidence: dict[str, Any] = {
        "payload_visibility": payload_visibility,
        "observable_payload_available": bool(is_http and (http["http_uris_sample"] or http["http_body_observed"])),
        "encrypted_protocol": encrypted_protocol,
        "extraction_warnings": warnings,
        "evidence_limits": dict(EVIDENCE_LIMITS),
        "evidence_mapping": {
            "method": mapping_method,
            "confidence": "high" if mapping_method in {"zeek_uid", "tcp_stream"} else "medium" if mapping_method == "bidirectional_five_tuple" else "not_applicable",
        },
        "http_summary": http_summary,
        **http,
        "transferred_files_summary": files,
        **indicators,
    }
    return evidence


def build_cards_from_packets(
    packet_rows: list[dict[str, str]],
    pcap_id: str,
    observations: list[dict[str, Any]] | None = None,
    observation_source_available: bool = False,
) -> list[dict[str, Any]]:
    grouped: dict[Any, list[dict[str, str]]] = defaultdict(list)
    for row in packet_rows:
        key = packet_key(row)
        if not key[0] or not key[2] or not key[4]:
            continue
        stream = row.get("tcp.stream")
        group_key: Any = ("stream", stream) if stream not in (None, "") else ("flow", canonical_key(key))
        grouped[group_key].append(row)

    observations = observations or []
    obs_by_stream: dict[str, list[dict[str, Any]]] = defaultdict(list)
    obs_by_key: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for row in observations:
        if row.get("tcp_stream") not in (None, ""):
            obs_by_stream[str(row["tcp_stream"])].append(row)
        obs_by_key[canonical_key(observation_key(row))].append(row)

    cards: list[dict[str, Any]] = []
    for idx, (_group_key, rows) in enumerate(sorted(grouped.items(), key=lambda item: (packet_time(item[1][0]) or 0.0, str(item[0]))), start=1):
        first = rows[0]
        src_ip, src_port, dst_ip, dst_port, proto = packet_key(first)
        times = [t for t in (packet_time(row) for row in rows) if t is not None]
        start = min(times) if times else None
        end = max(times) if times else None
        tcp_stream = sample([row.get("tcp.stream") for row in rows], 1)
        mapped_observations = obs_by_stream.get(str(tcp_stream[0]), []) if tcp_stream else obs_by_key.get(canonical_key(packet_key(first)), [])
        mapping_method = "tcp_stream" if tcp_stream and mapped_observations else "bidirectional_five_tuple" if mapped_observations else "none"
        syn_count = sum(1 for row in rows if str(row.get("tcp.flags.syn", "")).lower() in {"1", "true"})
        ack_count = sum(1 for row in rows if str(row.get("tcp.flags.ack", "")).lower() in {"1", "true"})
        orig_bytes = sum(packet_len(row) for row in rows if row.get("ip.src") == src_ip)
        resp_bytes = sum(packet_len(row) for row in rows if row.get("ip.src") == dst_ip)
        conn_state = None
        if proto == "tcp" and syn_count > 0 and ack_count == 0:
            conn_state = "S0"
        service = next((str(row.get("_ws.col.Protocol") or "").lower() for row in rows if row.get("_ws.col.Protocol") and str(row.get("_ws.col.Protocol")).lower() not in {"tcp", "udp"}), None)
        evidence = make_session_evidence(
            service, dst_port, [], mapped_observations, [], [], [], ftp_rows_from_packets(rows),
            observation_source_available, mapping_method,
        )
        evidence["extraction_warnings"] = [
            *evidence.get("extraction_warnings", []),
            "zeek_unavailable; session and application metadata use tshark fallback",
        ]
        card = {
            "record_type": "session",
            "session_id": f"{pcap_id}::session::{idx:06d}",
            "pcap_id": pcap_id,
            "parser_source": "tshark_fallback",
            "start_time": start,
            "end_time": end,
            "src_ip": src_ip or None,
            "src_port": parse_int(src_port) if str(src_port).isdigit() else (src_port or None),
            "dst_ip": dst_ip or None,
            "dst_port": parse_int(dst_port) if str(dst_port).isdigit() else (dst_port or None),
            "proto": proto or None,
            "service": service,
            "duration": round(end - start, 6) if start is not None and end is not None else None,
            "orig_pkts": sum(1 for row in rows if row.get("ip.src") == src_ip),
            "resp_pkts": sum(1 for row in rows if row.get("ip.src") == dst_ip),
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "conn_state": conn_state,
            "history": "tshark_fallback",
            "zeek_uid": None,
            "tcp_stream": tcp_stream[0] if tcp_stream else None,
            **evidence,
            "dns_summary": make_dns_summary([{"query": row.get("dns.qry.name")} for row in rows if row.get("dns.qry.name")]),
            "tls_summary": make_tls_summary([{"server_name": row.get("tls.handshake.extensions_server_name")} for row in rows if row.get("tls.handshake.extensions_server_name")]),
        }
        card["packet_rate"] = safe_rate((card["orig_pkts"] or 0) + (card["resp_pkts"] or 0), card["duration"])
        card["byte_rate"] = safe_rate((card["orig_bytes"] or 0) + (card["resp_bytes"] or 0), card["duration"])
        cards.append(card)
    return cards


def build_cards_for_pcap(case_dir: Path, pcap_id: str, zeek_parser_source: str = "zeek_conn") -> list[dict[str, Any]]:
    conn_rows = read_zeek_log(log_path(case_dir, "conn.log"))
    http_by_uid = rows_by_uid(read_zeek_log(log_path(case_dir, "http.log")))
    dns_by_uid = rows_by_uid(read_zeek_log(log_path(case_dir, "dns.log")))
    tls_by_uid = rows_by_uid(read_zeek_log(log_path(case_dir, "ssl.log")))
    files_by_uid = files_by_conn_uid(read_zeek_log(log_path(case_dir, "files.log")))
    ssh_by_uid = rows_by_uid(read_zeek_log(log_path(case_dir, "ssh.log")))
    ftp_by_uid = rows_by_uid(read_zeek_log(log_path(case_dir, "ftp.log")))
    packet_rows = read_csv_rows(packets_path(case_dir))
    obs_path = observable_http_path(case_dir)
    observations = read_zeek_log(obs_path)
    observation_source_available = obs_path is not None
    packet_index: dict[Any, list[dict[str, str]]] = defaultdict(list)
    for packet in packet_rows:
        packet_index[canonical_key(packet_key(packet))].append(packet)
    obs_by_stream: dict[str, list[dict[str, Any]]] = defaultdict(list)
    obs_by_key: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        if observation.get("tcp_stream") not in (None, ""):
            obs_by_stream[str(observation["tcp_stream"])].append(observation)
        obs_by_key[canonical_key(observation_key(observation))].append(observation)
    if not conn_rows and packet_rows:
        return build_cards_from_packets(packet_rows, pcap_id, observations, observation_source_available)

    cards: list[dict[str, Any]] = []
    for idx, row in enumerate(conn_rows, start=1):
        src_ip, src_port, dst_ip, dst_port, proto = key_for_conn(row)
        ts = conn_time(row)
        duration = parse_float(row.get("duration"))
        end_ts = ts + duration if ts is not None and duration is not None else None
        uid = row.get("uid")
        key = (src_ip, src_port, dst_ip, dst_port, proto)
        packets = packet_index.get(canonical_key(key), [])
        tcp_stream = sample([p.get("tcp.stream") for p in packets], 1)
        mapped_observations = obs_by_stream.get(str(tcp_stream[0]), []) if tcp_stream else []
        mapping_method = "tcp_stream" if mapped_observations else "none"
        if not mapped_observations:
            mapped_observations = obs_by_key.get(canonical_key(key), [])
            if mapped_observations:
                mapping_method = "bidirectional_five_tuple"
        service = row.get("service") if row.get("service") != "-" else None
        uid_text = str(uid) if uid else ""
        evidence = make_session_evidence(
            service,
            dst_port,
            http_by_uid.get(uid_text, []),
            mapped_observations,
            tls_by_uid.get(uid_text, []),
            files_by_uid.get(uid_text, []),
            ssh_by_uid.get(uid_text, []),
            ftp_by_uid.get(uid_text, []) or ftp_rows_from_packets(packets),
            observation_source_available,
            "zeek_uid" if http_by_uid.get(uid_text) else mapping_method,
        )
        card = {
            "record_type": "session",
            "session_id": f"{pcap_id}::session::{idx:06d}",
            "pcap_id": pcap_id,
            "parser_source": zeek_parser_source,
            "start_time": ts,
            "end_time": end_ts,
            "src_ip": src_ip or None,
            "src_port": parse_int(src_port) if str(src_port).isdigit() else (src_port or None),
            "dst_ip": dst_ip or None,
            "dst_port": parse_int(dst_port) if str(dst_port).isdigit() else (dst_port or None),
            "proto": proto or None,
            "service": service,
            "duration": duration,
            "orig_pkts": parse_int(row.get("orig_pkts")),
            "resp_pkts": parse_int(row.get("resp_pkts")),
            "orig_bytes": parse_int(row.get("orig_bytes")),
            "resp_bytes": parse_int(row.get("resp_bytes")),
            "conn_state": row.get("conn_state") if row.get("conn_state") != "-" else None,
            "history": row.get("history") if row.get("history") != "-" else None,
            "zeek_uid": uid,
            "tcp_stream": tcp_stream[0] if tcp_stream else None,
            **evidence,
            "dns_summary": make_dns_summary(dns_by_uid.get(str(uid), [])) if uid else None,
            "tls_summary": make_tls_summary(tls_by_uid.get(str(uid), [])) if uid else None,
        }
        card["packet_rate"] = safe_rate((card["orig_pkts"] or 0) + (card["resp_pkts"] or 0), duration)
        card["byte_rate"] = safe_rate((card["orig_bytes"] or 0) + (card["resp_bytes"] or 0), duration)
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
        by_endpoint: dict[tuple[str, str, Any, str], list[dict[str, Any]]] = defaultdict(list)
        by_src_dst: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for card in pcap_cards:
            by_src[str(card.get("src_ip"))].append(card)
            by_dst[str(card.get("dst_ip"))].append(card)
            by_src_dst_port[(str(card.get("src_ip")), str(card.get("dst_ip")), card.get("dst_port"))].append(card)
            by_endpoint[(str(card.get("src_ip")), str(card.get("dst_ip")), card.get("dst_port"), str(card.get("proto")))].append(card)
            by_src_dst[(str(card.get("src_ip")), str(card.get("dst_ip")))].append(card)

        src_stats = {}
        for src, src_cards in by_src.items():
            failed_count = sum(1 for c in src_cards if c.get("conn_state") in FAILED_STATES)
            src_stats[src] = {
                "conn_count": len(src_cards),
                "unique_dst_ports": len({c.get("dst_port") for c in src_cards if c.get("dst_port") not in (None, "")}),
                "unique_dst_ips": len({c.get("dst_ip") for c in src_cards if c.get("dst_ip") not in (None, "")}),
                "failed_rate": round(failed_count / len(src_cards), 4) if src_cards else 0.0,
            }
        dst_unique_src_count = {
            dst: len({c.get("src_ip") for c in dst_cards if c.get("src_ip") not in (None, "")})
            for dst, dst_cards in by_dst.items()
        }
        src_dst_port_count = {key: len(value) for key, value in by_src_dst_port.items()}

        for card in pcap_cards:
            src = str(card.get("src_ip"))
            dst = str(card.get("dst_ip"))
            stats = src_stats.get(src, {})
            card["same_src_conn_count"] = stats.get("conn_count", 0)
            card["same_src_unique_dst_ports"] = stats.get("unique_dst_ports", 0)
            card["same_src_unique_dst_ips"] = stats.get("unique_dst_ips", 0)
            card["same_src_failed_conn_rate"] = stats.get("failed_rate", 0.0)
            card["same_dst_unique_src_count"] = dst_unique_src_count.get(dst, 0)
            card["same_src_same_dst_port_count"] = src_dst_port_count.get((src, dst, card.get("dst_port")), 0)

        # Cross-session indicators are computed only inside the current PCAP.
        for endpoint_cards in by_endpoint.values():
            endpoint_cards.sort(key=lambda c: (c.get("start_time") is None, c.get("start_time") or 0.0))
            times = [parse_float(c.get("start_time")) for c in endpoint_cards]
            times = [value for value in times if value is not None]
            intervals = [b - a for a, b in zip(times, times[1:]) if b >= a]
            mean_interval = statistics.mean(intervals) if intervals else None
            interval_std = statistics.pstdev(intervals) if len(intervals) >= 2 else None
            interval_cv = interval_std / mean_interval if interval_std is not None and mean_interval and mean_interval > 0 else None
            median_interval = statistics.median(intervals) if intervals else None
            regularity_score = 1 / (1 + interval_cv) if interval_cv is not None else 0.0
            periodic = len(intervals) >= 3 and mean_interval is not None and mean_interval >= 1.0 and interval_cv is not None and interval_cv <= 0.35
            byte_totals = [int(c.get("orig_bytes") or 0) + int(c.get("resp_bytes") or 0) for c in endpoint_cards]
            small_repeated = len(byte_totals) >= 4 and max(byte_totals, default=0) <= 4096
            dns_queries = [q for c in endpoint_cards for q in (c.get("dns_summary") or {}).get("queries", [])]
            tls_sni = [q for c in endpoint_cards for q in (c.get("tls_summary") or {}).get("server_names", [])]
            repeated_dns = len(dns_queries) >= 3 and len(set(dns_queries)) < len(dns_queries)
            repeated_sni = len(tls_sni) >= 3 and len(set(tls_sni)) < len(tls_sni)
            first = endpoint_cards[0]
            try:
                src_private = ipaddress.ip_address(str(first.get("src_ip"))).is_private
                dst_private = ipaddress.ip_address(str(first.get("dst_ip"))).is_private
                client_external = src_private and not dst_private
            except ValueError:
                client_external = False
            unusual_port = bool(first.get("dst_port") and int(first.get("dst_port")) not in {21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 993, 995, 3389}) if str(first.get("dst_port") or "").isdigit() else False
            long_lived = any((parse_float(c.get("duration")) or 0) >= 300 for c in endpoint_cards)
            fixed_endpoint_duration = max(0.0, (times[-1] - times[0])) if len(times) >= 2 else 0.0
            app_blob = " ".join(
                str(value) for card in endpoint_cards
                for value in [*card.get("http_hosts", []), *card.get("http_uris_sample", [])]
            ).lower()
            update_like = any(word in app_blob for word in ("update", "telemetry", "health", "wpad", "sync", "ntp"))
            ntp_like = str(first.get("proto")) == "udp" and str(first.get("dst_port")) == "123"
            dns_refresh_like = str(first.get("dst_port")) == "53" and repeated_dns
            explicit_callback_text = any(word in app_blob for word in ("callback", "beacon", "heartbeat", "checkin", "dummy-c2"))
            score = sum([
                0.35 if periodic else 0.0,
                0.15 if len(endpoint_cards) >= 4 else 0.0,
                0.15 if small_repeated else 0.0,
                0.1 if repeated_dns or repeated_sni else 0.0,
                0.1 if unusual_port else 0.0,
                0.1 if client_external else 0.0,
                0.05 if long_lived else 0.0,
                0.2 if explicit_callback_text else 0.0,
            ])
            interval_summary = {
                "count": len(intervals),
                "mean_seconds": round(mean_interval, 3) if mean_interval is not None else None,
                "median_seconds": round(median_interval, 3) if median_interval is not None else None,
                "std_seconds": round(interval_std, 3) if interval_std is not None else None,
                "cv": round(interval_cv, 3) if interval_cv is not None else None,
                "min_seconds": round(min(intervals), 3) if intervals else None,
                "max_seconds": round(max(intervals), 3) if intervals else None,
            }
            for card in endpoint_cards:
                card["c2_indicators"] = {
                    "periodic_connections": periodic,
                    "fixed_remote_endpoint": len(endpoint_cards) >= 4,
                    "small_repeated_payload": small_repeated,
                    "long_lived_connection": long_lived,
                    "dns_repeated_query": repeated_dns,
                    "tls_sni_repeated": repeated_sni,
                    "unusual_port": unusual_port,
                    "client_initiated_external": client_external,
                    "callback_text_hint": explicit_callback_text,
                    "beacon_score": round(min(score, 1.0), 3),
                    "regularity_score": round(regularity_score, 3),
                    "fixed_endpoint_duration": round(fixed_endpoint_duration, 3),
                    "interval_summary": interval_summary,
                    "matched_keywords": [name for name, hit in (("periodic", periodic), ("fixed endpoint", len(endpoint_cards) >= 4), ("repeated DNS", repeated_dns), ("repeated SNI", repeated_sni), ("callback context", explicit_callback_text)) if hit],
                }
                card["benign_periodic_hints"] = {
                    "common_service_port": str(first.get("dst_port")) in {"53", "80", "123", "443"},
                    "update_or_telemetry_text": update_like,
                    "dns_refresh_like": dns_refresh_like,
                    "ntp_like": ntp_like,
                    "short_burst_not_beacon": bool(median_interval is not None and median_interval < 1.0),
                    "periodicity_alone": bool(periodic and not any((unusual_port, repeated_dns, repeated_sni, explicit_callback_text))),
                }

        for pair_cards in by_src_dst.values():
            all_uris = [uri for c in pair_cards for uri in c.get("http_uris_sample", [])]
            all_uri_paths = [uri_path(uri) for uri in all_uris]
            statuses = [code for c in pair_cards for code in c.get("http_status_codes", [])]
            backdoor_uris = [uri for c in pair_cards for uri in c.get("http_uris_sample", []) if any(word in str(uri).lower() for word in ("webshell", "shell.php", "cmd.php", "cmd.jsp", "c99", "r57"))]
            for card in pair_cards:
                vuln = card.get("vuln_scan_indicators") or {}
                vuln["high_uri_fanout"] = bool(vuln.get("high_uri_fanout") or len(set(all_uri_paths)) >= 8)
                vuln["high_404_rate"] = bool(vuln.get("high_404_rate") or (len(statuses) >= 5 and sum(str(code) == "404" for code in statuses) / len(statuses) >= 0.6))
                card["vuln_scan_indicators"] = vuln
                backdoor = card.get("backdoor_access_indicators") or {}
                backdoor["repeated_backdoor_endpoint_access"] = bool(backdoor.get("repeated_backdoor_endpoint_access") or len(backdoor_uris) >= 2)
                card["backdoor_access_indicators"] = backdoor
                auth = card.get("auth_indicators") or {}
                if auth.get("auth_protocol") != "unknown" and card.get("same_src_same_dst_port_count", 0) >= 5:
                    auth["repeated_login_attempts"] = True
                    auth["same_src_same_dst_auth_attempts"] = card.get("same_src_same_dst_port_count")
                    if not auth.get("failed_login_hint"):
                        auth["weak_evidence"] = True
                card["auth_indicators"] = auth

        starts = [parse_float(c.get("start_time")) for c in pcap_cards if parse_float(c.get("start_time")) is not None]
        ends = [parse_float(c.get("end_time")) for c in pcap_cards if parse_float(c.get("end_time")) is not None]
        top = lambda values, limit=5: [{"value": value, "count": count} for value, count in Counter(v for v in values if v not in (None, "")).most_common(limit)]
        indicator_names = ("exploit_indicators", "vuln_scan_indicators", "auth_indicators", "implant_indicators", "backdoor_access_indicators", "c2_indicators")
        suspicious_counts = {name: sum(has_positive_indicator(c.get(name, {})) for c in pcap_cards) for name in indicator_names}
        scan_sources = {
            c.get("src_ip") for c in pcap_cards
            if c.get("same_src_unique_dst_ports", 0) >= 8 and c.get("same_src_failed_conn_rate", 0) >= 0.4
        }
        auth_cards = [c for c in pcap_cards if has_positive_indicator(c.get("auth_indicators", {}))]
        beacon_cards = [c for c in pcap_cards if (c.get("c2_indicators") or {}).get("beacon_score", 0) >= 0.5]
        summary = {
            "pcap_id": pcap_cards[0].get("pcap_id"),
            "time_range": {"start": min(starts) if starts else None, "end": max(ends) if ends else None},
            "total_sessions": len(pcap_cards),
            "protocols_seen": sample([c.get("service") or c.get("proto") for c in pcap_cards]),
            "top_src_ips": top([c.get("src_ip") for c in pcap_cards]),
            "top_dst_ips": top([c.get("dst_ip") for c in pcap_cards]),
            "top_dst_ports": top([c.get("dst_port") for c in pcap_cards]),
            "http_hosts_sample": sample([host for c in pcap_cards for host in c.get("http_hosts", [])], 5),
            "dns_queries_sample": sample([query for c in pcap_cards for query in (c.get("dns_summary") or {}).get("queries", [])], 5),
            "tls_sni_sample": sample([sni for c in pcap_cards for sni in (c.get("tls_summary") or {}).get("server_names", [])], 5),
            "suspicious_indicator_counts": suspicious_counts,
            "scan_group_count": len(scan_sources),
            "auth_attempt_summary": {"sessions_with_auth_hints": len(auth_cards), "failed_login_hint_sessions": sum(bool((c.get("auth_indicators") or {}).get("failed_login_hint")) for c in auth_cards)},
            "beacon_like_summary": {"sessions_with_score_ge_0_5": len(beacon_cards), "max_beacon_score": max(((c.get("c2_indicators") or {}).get("beacon_score", 0) for c in pcap_cards), default=0)},
        }
        for card in pcap_cards:
            card["pcap_summary"] = summary


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
    discovered_case_dirs = pcap_dirs(args.parsed_dir)
    summary_by_case = parse_summary_by_case(args.parsed_dir)
    for case_dir in discovered_case_dirs:
        if case_dir == args.parsed_dir:
            pcap_id = "parsed"
        else:
            relative = case_dir.relative_to(args.parsed_dir)
            pcap_id = "__".join(relative.parts)
        parse_meta = summary_by_case.get(pcap_id, {})
        parser_source = str(parse_meta.get("parser_source") or "zeek_conn")
        zeek_parser_source = parser_source if parser_source in {"zeek_conn", "zeek_docker"} else "zeek_conn"
        cards = build_cards_for_pcap(case_dir, pcap_id, zeek_parser_source)
        if not cards:
            warnings.append(f"No Zeek conn sessions found for `{pcap_id}`.")
        per_pcap[pcap_id] = len(cards)
        all_cards.extend(cards)

    if not args.parsed_dir.exists():
        warnings.append(f"Parsed input directory does not exist: `{display_path(args.parsed_dir)}`.")
    elif not discovered_case_dirs:
        warnings.append(f"No case directory containing Zeek conn.log or tshark packets.csv was found under `{display_path(args.parsed_dir)}`.")

    add_context_features(all_cards)
    original_count = len(all_cards)
    if original_count == 0:
        raise RuntimeError(
            f"no session cards were built from {args.parsed_dir}; expected Zeek conn.log or tshark packets.csv in a case directory"
        )
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
        f"- Output: `{display_path(args.output)}`",
        f"- LLM-safe output: `{display_path(args.llm_output)}`",
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
