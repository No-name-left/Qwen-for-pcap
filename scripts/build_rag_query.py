#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, flatten_strings, load_json, micro_path, tokenize


EXPANSIONS = [
    (["strrat"], ["remote access trojan", "c2", "command and control", "malware checkin"]),
    (["cnc checkin", "checkin"], ["c2", "command_and_control", "malware callback"]),
    (["ms17-010", "eternalblue"], ["SMB exploit", "SMBv1", "port 445", "initial_access"]),
    (["doublepulsar", "beacon response"], ["implant", "backdoor", "beacon", "post-exploitation", "trojan_callback", "command_and_control"]),
    (["invalid checksum", "unknown code", "icmpv6", "udpv6"], ["protocol anomaly", "low confidence", "possible false positive"]),
]


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


def event_terms(card: dict) -> tuple[list[str], list[str], bool]:
    terms: list[str] = []
    rules: list[str] = []
    add_term(terms, card.get("candidate_labels", []))
    add_term(terms, card.get("protocols", []))
    tshark = card.get("tshark_features", {})
    zeek = card.get("zeek_features", {})
    suri = card.get("suricata_features", {})
    alerts = card.get("suricata_alerts", [])

    for key in ["http_uri_samples", "dns_query_samples", "tls_sni_samples"]:
        add_term(terms, tshark.get(key))
    for key in ["dns_queries", "http_uris", "tls_sni", "services", "weird_names", "notice_types"]:
        add_term(terms, zeek.get(key))
    for key in ["top_alert_signatures", "top_alert_categories"]:
        add_term(terms, suri.get(key))
    for alert in alerts:
        if isinstance(alert, dict):
            for key in ["signature", "category", "severity"]:
                add_term(terms, alert.get(key))

    unique_dst_ports = tshark.get("unique_dst_ports", 0) or 0
    tcp_syn_count = tshark.get("tcp_syn_count", 0) or 0
    failed_rate = zeek.get("failed_conn_rate", 0) or 0
    packet_count = tshark.get("packet_count", 0) or 0
    conn_count = zeek.get("conn_count", 0) or 0
    alert_count = suri.get("suricata_alert_count", len(alerts) if isinstance(alerts, list) else 0) or 0

    if unique_dst_ports >= 20 or tcp_syn_count >= 100 or failed_rate >= 0.7:
        terms.extend(["port scan", "reconnaissance", "many destination ports", "failed connections", "TCP SYN scan"])
        rules.append("scan_shape")
    if packet_count <= 6 and conn_count <= 1 and alert_count == 0:
        terms.extend(["low signal event", "weak evidence", "normal none"])
        rules.append("low_signal")

    joined = " ".join(terms).lower()
    for needles, adds in EXPANSIONS:
        if any(needle in joined for needle in needles):
            terms.extend(adds)
            rules.append("expand:" + "/".join(needles))

    deduped: list[str] = []
    seen = set()
    for term in terms:
        term = str(term).strip()
        if not term:
            continue
        key = term.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(term)
    low_signal = "low_signal" in rules
    return deduped, rules, low_signal


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic RAG queries from event cards.")
    parser.add_argument("--input", type=Path, default=micro_path("outputs/event_cards/qwen_test_event_cards.json"))
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/rag_queries/qwen35_27b_test_rag_queries.jsonl")
    parser.add_argument("--report", type=Path, default=ROOT / "outputs/rag_queries/qwen35_27b_test_rag_query_report.md")
    args = parser.parse_args()
    cards = load_json(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    with args.output.open("w", encoding="utf-8") as f:
        for card in cards:
            terms, rules, low_signal = event_terms(card)
            query = " ".join(terms[:80])
            row = {"event_id": card["event_id"], "query": query, "query_terms": terms, "matched_rules": rules, "low_signal": low_signal}
            rows.append(row)
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    low_count = sum(1 for r in rows if r["low_signal"])
    lines = [
        "# Qwen3.5-27B deterministic RAG query report",
        "",
        f"- Input: `{args.input.relative_to(ROOT)}`",
        f"- Events: {len(rows)}",
        f"- Low-signal events: {low_count}",
        f"- Output: `{args.output.relative_to(ROOT)}`",
        "",
        "## Rule notes",
        "",
        "- Query terms were built deterministically from event card fields.",
        "- Evaluation labels were not read.",
        "- No LLM was used.",
    ]
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"built {len(rows)} rag queries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
