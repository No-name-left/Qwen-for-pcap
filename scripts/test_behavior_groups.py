#!/usr/bin/env python3
"""Regression checks for auth-attempt and C2 callback group evidence."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from build_classification_records import make_auth_attempt_group, make_c2_callback_group, make_scan_group
from build_qwen35_session_prompts import build_prompt
from build_rag_query import record_terms, targeted_rag_metadata, detect_confusion_groups
from qwen35_rag_utils import DEFAULT_RUNTIME_PROFILES, ROOT, load_runtime_profile


def auth_card(index: int, strong: bool = True) -> dict:
    return {
        "session_id": f"auth::{index}", "pcap_id": "auth_fixture", "parser_source": "zeek_conn",
        "start_time": index * 10.0, "end_time": index * 10.0 + 1, "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2", "dst_port": 21, "proto": "tcp", "service": "ftp",
        "payload_visibility": "plaintext_http", "encrypted_protocol": "none",
        "auth_indicators": {
            "auth_protocol": "ftp", "session_auth_attempt_count": 1,
            "same_src_same_dst_auth_attempts": 5,
            "username_field_seen": strong, "password_field_seen": strong,
            "unique_usernames_seen": 1 if strong else 0, "failed_login_count": 1 if strong else 0,
            "failed_login_hint": strong, "ftp_response_codes": ["530"] if strong else [],
            "auth_status_codes": [], "ssh_auth_failure_hint": False,
        },
    }


def c2_card(index: int) -> dict:
    return {
        "session_id": f"c2::{index}", "pcap_id": "c2_fixture", "parser_source": "zeek_conn",
        "start_time": index * 30.0, "end_time": index * 30.0 + 1, "src_ip": "10.0.0.3",
        "src_port": 40000 + index, "dst_ip": "198.51.100.8", "dst_port": 5678,
        "proto": "tcp", "service": None, "orig_bytes": 180, "resp_bytes": 4000, "duration": 1.0,
        "payload_visibility": "encrypted_tls", "encrypted_protocol": "tls",
        "dns_summary": None, "tls_summary": None, "http_hosts": [], "http_uris_sample": [],
    }


def scan_card(index: int) -> dict:
    return {
        "session_id": f"scan::{index}", "pcap_id": "scan_fixture", "parser_source": "zeek_conn",
        "start_time": index * 0.1, "end_time": index * 0.1 + 0.01, "src_ip": "10.0.0.4",
        "src_port": 41000 + index, "dst_ip": "10.0.0.5", "dst_port": 1000 + index,
        "proto": "tcp", "conn_state": "S0", "same_src_unique_dst_ports": 10,
        "same_src_failed_conn_rate": 1.0, "duration": 0.01, "orig_bytes": 60, "resp_bytes": 0,
    }


def main() -> int:
    auth = make_auth_attempt_group([auth_card(index) for index in range(5)], 1)
    assert auth["record_type"] == "auth_attempt_group"
    assert auth["evidence_tier"] == "high_auth_behavioral"
    assert auth["attempt_count"] == 5 and auth["failed_login_count"] == 5
    assert auth["payload_visibility"] == "plaintext_http"
    assert auth["inter_attempt_intervals"]["median"] == 10.0
    assert auth["failure_burst"]["failure_rate"] == 1.0
    auth_groups = detect_confusion_groups(auth)
    auth_triggers, auth_docs, auth_fields = targeted_rag_metadata(auth, auth_groups)
    assert "auth_indicators" in auth_fields and "auth_indicators=positive" in auth_triggers
    assert "observable_auth_bruteforce_indicators" in auth_docs
    auth_terms, auth_rules, _ = record_terms(auth)
    assert "authentication attempt group" in auth_terms and "auth_attempt_group:TA01_01_boundary" in auth_rules
    weak = make_auth_attempt_group([auth_card(index, strong=False) for index in range(5)], 2)
    assert weak["evidence_tier"] == "weak_auth_evidence" and weak["weak_evidence_reason"]

    scan = make_scan_group([scan_card(index) for index in range(10)], 1)
    assert scan["scan_duration"] and scan["probe_rate"]
    assert scan["port_probe_count"] == 10 and scan["inter_arrival_summary"]["count"] == 9
    scan_groups = detect_confusion_groups(scan)
    scan_triggers, scan_docs, _ = targeted_rag_metadata(scan, scan_groups)
    assert "scan_timing=positive" in scan_triggers and "observable_scan_probe_timing" in scan_docs

    c2 = make_c2_callback_group([c2_card(index) for index in range(10)], 1)
    assert c2["record_type"] == "c2_callback_group"
    assert c2["connection_count"] == 10 and c2["periodicity_score"] == 1.0
    assert c2["interval_summary"]["mean"] == 30.0 and c2["interval_summary"]["std"] == 0.0
    assert c2["fixed_endpoint_duration"] == 271.0
    assert c2["evidence_tier"] == "high_callback_behavioral"
    assert c2["payload_visibility"] == "encrypted_tls" and c2["encrypted_protocol"] == "tls"
    groups = detect_confusion_groups(c2)
    triggers, docs, fields = targeted_rag_metadata(c2, groups)
    assert "c2_indicators" in fields and "c2_indicators=positive" in triggers
    assert "observable_backdoor_access_vs_callback" in docs
    assert "callback_timing=positive" in triggers and "observable_beacon_timing_boundary" in docs
    terms, rules, _ = record_terms(c2)
    assert "callback group" in terms and "c2_callback_group:TA11_02_boundary" in rules
    profile = load_runtime_profile("nvidia_ubuntu_online_api", DEFAULT_RUNTIME_PROFILES)
    auth_prompt, auth_meta = build_prompt(auth, "technique", [], profile, {
        "targeted_rag_triggers": auth_triggers, "targeted_boundary_cards": auth_docs,
        "indicator_fields_used": auth_fields,
    })
    assert "auth_attempt_group" in auth_prompt and "failed_login_count" in auth_prompt
    assert auth_meta["estimated_prompt_tokens"] <= profile["max_prompt_tokens"]
    prompt, meta = build_prompt(c2, "technique", [], profile, {
        "targeted_rag_triggers": triggers, "targeted_boundary_cards": docs, "indicator_fields_used": fields,
    })
    assert "c2_callback_group" in prompt and "periodicity_score" in prompt
    assert "regularity_score" in prompt and "fixed_endpoint_duration" in prompt
    assert "interval_summary" in meta["timing_fields_included"]
    assert meta["estimated_prompt_tokens"] <= profile["max_prompt_tokens"]

    fast_probe = [
        {**c2_card(index), "start_time": index * 0.001, "end_time": index * 0.001 + 0.0005,
         "vuln_scan_indicators": {"scanner_user_agents": ["Nikto"]}}
        for index in range(10)
    ]
    fast_group = make_c2_callback_group(fast_probe, 2)
    assert fast_group["evidence_tier"] != "high_callback_behavioral"
    assert fast_group["benign_periodic_hints"]["short_burst_not_beacon"]
    assert "vuln_scan_indicators" in fast_group["competing_behavior_fields"]

    strict_path = ROOT / "datasets/public_eval/strict_observable_v3_records.jsonl"
    strict = [json.loads(line) for line in strict_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert Counter(row["technique_code"] for row in strict) == Counter({"TA43_01": 3, "TA11_02": 3, "TN01_01": 3})
    assert not any(row["technique_code"] == "TA01_01" for row in strict)
    assert all(row.get("evidence_tier") and "strict_subset" in row.get("subset_membership", []) for row in strict)
    for row in strict:
        visible = json.dumps(row["classification_record"], ensure_ascii=False).lower()
        assert "from-botnet" not in visible and "expected_technique" not in visible
    print("auth grouping, C2 grouping, targeted RAG, strict tiering, and label isolation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
