#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, load_json


def add_term(terms: list[str], value: Any) -> None:
    if value is None:
        return
    if isinstance(value, (int, float)):
        terms.append(str(value))
    elif isinstance(value, str) and value.strip():
        terms.append(value.strip())
    elif isinstance(value, list):
        for item in value:
            add_term(terms, item)
    elif isinstance(value, dict):
        for item in value.values():
            add_term(terms, item)


def dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen = set()
    for value in values:
        value = str(value).strip()
        if not value:
            continue
        key = value.lower()
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def record_terms(record: dict[str, Any]) -> tuple[list[str], list[str], bool]:
    terms: list[str] = ["official competition code", "session-level classification", str(record.get("record_type", ""))]
    rules: list[str] = []
    low_signal = False

    add_term(terms, record.get("proto"))
    add_term(terms, record.get("service"))
    add_term(terms, record.get("conn_state"))
    add_term(terms, record.get("history"))
    add_term(terms, record.get("candidate_hint"))
    add_term(terms, record.get("http_summary"))
    add_term(terms, record.get("dns_summary"))
    add_term(terms, record.get("tls_summary"))
    add_term(terms, record.get("related_suricata_alerts"))

    if record.get("record_type") == "scan_group":
        terms.extend(["scan_group", "many destination ports", "failed connections", "port scan", "TA43_01"])
        rules.append("scan_group:TA43_01")
    if record.get("same_src_unique_dst_ports", 0) >= 8 or record.get("unique_dst_ports", 0) >= 8:
        terms.extend(["many ports", "port scan", "TA43_01"])
        rules.append("many_ports:TA43_01")
    if record.get("same_src_failed_conn_rate", 0) >= 0.5 or record.get("failed_conn_rate", 0) >= 0.5:
        terms.extend(["failed connection rate", "reconnaissance", "TA43_01"])
        rules.append("failed_rate")

    blob = json.dumps(record, ensure_ascii=False).lower()
    blob_tokens = set(re.findall(r"[a-z0-9_+-]+", blob))
    if any(s in blob for s in ["vulnerability scan", "scanner", "nikto", "nessus", "openvas", "version probe"]):
        terms.extend(["vulnerability scan signs", "TA43_02"])
        rules.append("vulnerability_scan:TA43_02")
    if any(s in blob for s in ["login", "authentication", "bruteforce", "brute force", "ssh", "ftp", "rdp"]):
        terms.extend(["login failures", "password bruteforce", "TA01_01"])
        rules.append("login_failures:TA01_01")
    if any(s in blob for s in ["exploit", "cve", "command injection", "sql injection", "xss", "ms17-010", "payload"]):
        terms.extend(["exploit alert", "payload", "vulnerability exploitation", "TA01_02"])
        rules.append("exploit_payload:TA01_02")
    if any(s in blob for s in ["implant", "persistence", "webshell", "backdoor placement"]):
        terms.extend(["implant", "persistence", "TA03_01"])
        rules.append("implant:TA03_01")
    if any(s in blob for s in ["backdoor access", "reverse shell", "webshell command", "shell"]):
        terms.extend(["backdoor access", "TA11_01"])
        rules.append("backdoor_access:TA11_01")
    if any(s in blob for s in ["callback", "c2", "cnc", "beacon", "checkin"]) or "rat" in blob_tokens:
        terms.extend(["callback", "C2", "periodic beacon", "TA11_02"])
        rules.append("callback_c2:TA11_02")

    alert_count = len(record.get("related_suricata_alerts") or [])
    packets = (record.get("orig_pkts") or 0) + (record.get("resp_pkts") or 0)
    if record.get("record_type") == "session" and alert_count == 0 and packets <= 3 and not rules:
        terms.extend(["normal business", "weak-only signal", "TN01_01"])
        rules.append("low_signal:TN01_01")
        low_signal = True
    if not rules:
        terms.extend(["normal business", "weak-only signal", "TN01_01"])
        rules.append("default_boundary:TN01_01")

    return dedupe(terms), rules, low_signal


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic RAG queries from classification records.")
    parser.add_argument("--input", type=Path, default=ROOT / "outputs/session_cards/classification_records_all.json")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/rag_queries/qwen35_session_records_rag_queries.jsonl")
    parser.add_argument("--report", type=Path, default=ROOT / "outputs/rag_queries/qwen35_session_records_rag_query_report.md")
    args = parser.parse_args()

    records = load_json(args.input) if args.input.exists() else []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    with args.output.open("w", encoding="utf-8") as f:
        for record in records:
            record_id = record.get("record_id") or record.get("event_id")
            terms, rules, low_signal = record_terms(record)
            row = {
                "record_id": record_id,
                "query_id": record_id,
                "pcap_id": record.get("pcap_id"),
                "record_type": record.get("record_type", "session"),
                "query": " ".join(terms[:100]),
                "query_terms": terms,
                "matched_rules": rules,
                "low_signal": low_signal,
            }
            rows.append(row)
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    low_count = sum(1 for row in rows if row["low_signal"])
    lines = [
        "# Qwen3.5-27B session-record RAG query report",
        "",
        f"- Input: `{args.input.relative_to(ROOT) if args.input.exists() and ROOT in args.input.resolve().parents else args.input}`",
        f"- Records: {len(rows)}",
        f"- Low-signal records: {low_count}",
        f"- Output: `{args.output.relative_to(ROOT)}`",
        "",
        "## Rule notes",
        "",
        "- Query IDs use `record_id`.",
        "- `session` and `scan_group` records are handled separately.",
        "- Query expansion includes official code candidates.",
        "- Expected labels are not read and no LLM is used.",
    ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"built {len(rows)} rag queries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
