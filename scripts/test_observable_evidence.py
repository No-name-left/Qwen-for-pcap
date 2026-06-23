#!/usr/bin/env python3
"""Regression checks for bounded HTTP evidence, redaction, and targeted RAG."""

from __future__ import annotations

from build_qwen35_session_prompts import PROMPT_VERSION, build_prompt
from build_rag_query import detect_confusion_groups, targeted_rag_metadata
from qwen35_rag_utils import load_runtime_profile
from session_card_indicators import build_file_summary, build_http_fields, build_indicators, make_safe_http_observation


def main() -> int:
    raw = {
        "frame.time_epoch": "1.0", "ip.src": "10.0.0.1", "tcp.srcport": "41000",
        "ip.dst": "10.0.0.2", "tcp.dstport": "80", "tcp.stream": "7",
        "http.request.method": "POST", "http.host": "fixture.invalid",
        "http.request.uri": "/api/query", "http.request.full_uri": "http://fixture.invalid/api/query",
        "http.content_type": "application/x-www-form-urlencoded", "http.content_length": "73",
        "http.file_data": "statement=;exec master..xp_cmdshell 'whoami';&password=do-not-retain&token=secret",
        "http.cookie": "sessionid=must-not-retain", "http.authorization": "Bearer must-not-retain",
    }
    observation = make_safe_http_observation(raw)
    assert observation is not None
    serialized = str(observation)
    assert "xp_cmdshell" in serialized and "exec" in serialized
    assert "do-not-retain" not in serialized and "must-not-retain" not in serialized and "token=secret" not in serialized
    assert "[REDACTED]" in serialized
    assert observation["cookie_present"] and observation["auth_header_present"]

    http = build_http_fields([], [observation])
    indicators = build_indicators(http, build_file_summary([]), [], [])
    assert indicators["exploit_indicators"]["xp_cmdshell"]
    record = {
        "record_id": "observable::session::1", "session_id": "observable::session::1",
        "pcap_id": "observable", "record_type": "session", "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2", "dst_port": 80, "proto": "tcp", "service": "http",
        "payload_visibility": "plaintext_http", **http, **indicators,
    }
    groups = detect_confusion_groups(record)
    triggers, docs, fields = targeted_rag_metadata(record, groups)
    assert "ta01_02_vs_tn01_01" in groups
    assert "exploit_indicators=positive" in triggers
    assert "observable_exploit_indicator_mapping" in docs
    assert "exploit_indicators" in fields

    all_trigger_record = {
        **record,
        "payload_visibility": "encrypted_tls",
        "vuln_scan_indicators": {"nikto_user_agent": True},
        "auth_indicators": {"auth_protocol": "http", "repeated_login_attempts": True},
        "implant_indicators": {"multipart_upload": True},
        "backdoor_access_indicators": {"webshell_path_hint": True},
        "c2_indicators": {"periodic_connections": True, "beacon_score": 0.8},
    }
    all_groups = detect_confusion_groups(all_trigger_record)
    all_triggers, all_docs, all_fields = targeted_rag_metadata(all_trigger_record, all_groups)
    assert set(all_fields) == {
        "vuln_scan_indicators", "exploit_indicators", "auth_indicators",
        "implant_indicators", "backdoor_access_indicators", "c2_indicators",
        "payload_visibility",
    }
    assert "payload_visibility=encrypted_tls" in all_triggers
    assert {
        "observable_vulnerability_scan_indicators", "observable_exploit_indicator_mapping",
        "observable_auth_bruteforce_indicators", "observable_file_upload_and_implant_hints",
        "observable_backdoor_access_vs_callback", "observable_encrypted_visibility_limits",
    }.issubset(set(all_docs))

    prompt, meta = build_prompt(record, "technique", None, load_runtime_profile("dry_run_mock"))
    assert PROMPT_VERSION == "observable_boundary_rag_v3"
    assert "OBSERVABLE_EVIDENCE_FROM_PCAP:" in prompt and "xp_cmdshell" in prompt
    assert meta["estimated_prompt_tokens"] <= 3400
    print("observable evidence redaction, indicators, RAG triggers, and prompt budget passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
