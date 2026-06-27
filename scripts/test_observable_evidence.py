#!/usr/bin/env python3
"""Regression checks for bounded HTTP evidence, redaction, and targeted RAG."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from build_classification_records import make_session_record
from build_qwen35_session_prompts import PROMPT_VERSION, build_prompt
from build_rag_query import detect_confusion_groups, targeted_rag_metadata
from build_session_cards import build_cards_for_pcap, build_cards_from_packets
from parse_public_pcaps import TSHARK_FIELDS
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
    ftp_rows = [
        {"command": "USER", "arg": "audit-user"},
        {"command": "PASS", "arg": "[REDACTED]", "reply_code": "530"},
        {"command": "PASS", "arg": "[REDACTED]", "reply_code": "530"},
        {"command": "PASS", "arg": "[REDACTED]", "reply_code": "530"},
        {"command": "PASS", "arg": "[REDACTED]", "reply_code": "530"},
        {"command": "PASS", "arg": "[REDACTED]", "reply_code": "530"},
    ]
    ftp_auth = build_indicators(build_http_fields([], []), build_file_summary([]), [], ftp_rows)["auth_indicators"]
    assert ftp_auth["session_auth_attempt_count"] == 5 and ftp_auth["failed_login_count"] == 5
    assert ftp_auth["failed_login_hint"] and ftp_auth["ftp_response_codes"] == ["530"]
    assert "audit-user" not in str(ftp_auth) and "[REDACTED]" not in str(ftp_auth)
    assert "ftp.request.command" in TSHARK_FIELDS and "ftp.response.code" in TSHARK_FIELDS
    assert "ftp.request.arg" not in TSHARK_FIELDS
    ftp_packets = []
    for index in range(5):
        ftp_packets.extend([
            {
                "frame.time_epoch": str(index * 2.0), "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2",
                "tcp.srcport": "41000", "tcp.dstport": "21", "tcp.stream": "9",
                "_ws.col.Protocol": "FTP", "frame.len": "80", "ftp.request.command": "PASS",
            },
            {
                "frame.time_epoch": str(index * 2.0 + 0.1), "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1",
                "tcp.srcport": "21", "tcp.dstport": "41000", "tcp.stream": "9",
                "_ws.col.Protocol": "FTP", "frame.len": "80", "ftp.response.code": "530",
            },
        ])
    ftp_card = build_cards_from_packets(ftp_packets, "ftp_tshark_fixture")[0]
    assert ftp_card["parser_source"] == "tshark_fallback"
    assert ftp_card["auth_indicators"]["failed_login_count"] == 5
    assert ftp_card["auth_indicators"]["password_field_seen"]
    assert any("zeek_unavailable" in warning for warning in ftp_card["extraction_warnings"])

    with tempfile.TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        zeek_dir = case_dir / "zeek"
        tshark_dir = case_dir / "tshark"
        zeek_dir.mkdir()
        tshark_dir.mkdir()
        (zeek_dir / "conn.log").write_text(
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_pkts\tresp_pkts\torig_bytes\tresp_bytes\tconn_state\thistory\n"
            "1.0\tC1\t10.0.0.1\t41000\t10.0.0.2\t80\ttcp\thttp\t1.0\t1\t1\t120\t200\tSF\tDd\n",
            encoding="utf-8",
        )
        (zeek_dir / "http.log").write_text(
            "#fields\tts\tuid\tmethod\thost\turi\tstatus_code\tuser_agent\treferrer\tmime_type\trequest_body_len\tresponse_body_len\n"
            "1.0\tC1\tPOST\tfixture.invalid\t/api/query\t200\tFixture-Agent\t-\ttext/plain\t73\t12\n",
            encoding="utf-8",
        )
        (zeek_dir / "ftp.log").write_text(
            "#fields\tts\tuid\tcommand\targ\treply_code\n"
            "1.1\tC1\tUSER\t[REDACTED]\t-\n"
            "1.2\tC1\tPASS\t[REDACTED]\t530\n",
            encoding="utf-8",
        )
        (tshark_dir / "observable_http.jsonl").write_text(json.dumps(observation) + "\n", encoding="utf-8")
        supplement_card = build_cards_for_pcap(case_dir, "supplement_fixture", "zeek_conn")[0]
        supplement_record = make_session_record(supplement_card)
        assert supplement_card["parser_source"] == "zeek_conn"
        assert supplement_card["http_body_observed"]
        assert supplement_card["evidence_mapping"]["method"] == "zeek_uid+bidirectional_five_tuple"
        assert supplement_record["suspicious_payload_snippets"]
        assert "xp_cmdshell" in str(supplement_record["suspicious_payload_snippets"])
        assert "do-not-retain" not in json.dumps(supplement_record)
        assert "audit-user" not in json.dumps(supplement_record)
        assert supplement_record["auth_indicators"]["password_field_seen"]
        assert supplement_record["auth_indicators"]["ftp_response_codes"] == ["530"]
    record = {
        "record_id": "observable::session::1", "session_id": "observable::session::1",
        "pcap_id": "observable", "record_type": "session", "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2", "dst_port": 80, "proto": "tcp", "service": "http",
        "payload_visibility": "plaintext_http", "duration": 1.25, "packet_rate": 8.0, **http, **indicators,
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
        "interval_summary": {"count": 5, "median": 30.0, "mean": 30.0, "std": 0.5, "cv": 0.017},
        "regularity_score": 0.983,
        "benign_periodic_hints": {"periodicity_alone": True},
    }
    all_groups = detect_confusion_groups(all_trigger_record)
    all_triggers, all_docs, all_fields = targeted_rag_metadata(all_trigger_record, all_groups)
    assert set(all_fields) == {
        "vuln_scan_indicators", "exploit_indicators", "auth_indicators",
        "implant_indicators", "backdoor_access_indicators", "c2_indicators",
        "payload_visibility",
    }
    assert "payload_visibility=encrypted_tls" in all_triggers
    assert "encrypted_timing_metadata=positive" in all_triggers
    assert "callback_timing=positive" in all_triggers
    assert "benign_periodic_hints=positive" in all_triggers
    assert {
        "observable_vulnerability_scan_indicators", "observable_exploit_indicator_mapping",
        "observable_auth_bruteforce_indicators", "observable_file_upload_and_implant_hints",
        "observable_backdoor_access_vs_callback", "observable_encrypted_visibility_limits",
        "observable_beacon_timing_boundary", "normal_periodic_connection_vs_c2",
    }.issubset(set(all_docs))

    prompt, meta = build_prompt(record, "technique", None, load_runtime_profile("dry_run_mock"))
    assert PROMPT_VERSION == "observable_timing_boundary_rag_v4"
    assert "OBSERVABLE_EVIDENCE_FROM_PCAP:" in prompt and "xp_cmdshell" in prompt
    assert "packet_rate" in prompt and "duration" in meta["timing_fields_included"]
    assert meta["estimated_prompt_tokens"] <= 3400
    supplement_prompt, _ = build_prompt(supplement_record, "technique", None, load_runtime_profile("dry_run_mock"))
    assert "http_body_observed" in supplement_prompt and "suspicious_payload_snippets" in supplement_prompt
    assert "do-not-retain" not in supplement_prompt and "audit-user" not in supplement_prompt
    upload_prompt_record = {
        **record,
        "record_id": "observable::session::upload",
        "http_upload_hints": ["/admin/plugin/upload?filename=safe-marker.txt"],
        "suspicious_payload_snippets": ["/admin/plugin/upload?filename=safe-marker.txt NON_EXECUTABLE_TRAINING_MARKER"],
        "implant_indicators": {"upload_to_server_hint": True, "file_write_like_request": True},
    }
    upload_prompt, _ = build_prompt(upload_prompt_record, "technique", None, load_runtime_profile("dry_run_mock"))
    assert "http_upload_hints" in upload_prompt and "safe-marker.txt" in upload_prompt
    print("observable evidence redaction, indicators, RAG triggers, and prompt budget passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
