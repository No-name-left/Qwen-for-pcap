#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import run_phase1_pipeline as pipeline
from build_pcap_level_records import build_pcap_records
from build_qwen35_session_prompts import STAGE_CODES, TECHNIQUE_TO_STAGE, build_phase1_prompt
from build_rag_query import detect_confusion_groups, record_terms, targeted_rag_metadata
from evaluate_phase1_predictions import evaluate
from export_official_submission import OFFICIAL_COLUMNS, build_official_rows, export_official_submission
from parse_public_pcaps import discover_pcaps, parse_case
from run_phase1_pipeline import official_rows, qwen_extra_body, run_api, safe_config_report, validate_prediction, write_candidate_diagnostics
from technique_profiles import TECHNIQUE_PROFILES, technique_codes, validate_profiles


def one_pcap_record(records: list[dict], cards: list[dict] | None = None) -> dict:
    return build_pcap_records(
        cards or [],
        records,
        [{"case_id": "phase1_001", "pcap_path": "/inputs/sample.pcap"}],
    )[0]


class Phase1PromptTests(unittest.TestCase):
    def test_technique_profiles_cover_all_techniques(self) -> None:
        validate_profiles()
        self.assertEqual(set(TECHNIQUE_PROFILES), set(technique_codes()))
        self.assertEqual(len(technique_codes()), 8)
        for code, profile in TECHNIQUE_PROFILES.items():
            self.assertTrue(profile["positive_evidence"], code)
            self.assertTrue(profile["negative_evidence"], code)
            self.assertTrue(profile["weak_evidence"], code)

    def test_neutral_case_ids_hide_label_bearing_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "known_TA43_01_sample.pcap").touch()
            cases = discover_pcaps(root, "phase1", neutral_case_ids=True)
            self.assertEqual(cases[0][0], "phase1_001")
            self.assertNotIn("TA43", cases[0][0])

    def test_stage_first_prompt_is_bounded_and_complete(self) -> None:
        record = {
            "record_id": "case::session::000001", "pcap_id": "case", "record_type": "session",
            "start_time": 1.0, "end_time": 2.0, "src_ip": "10.0.0.1", "src_port": 44000,
            "dst_ip": "10.0.0.2", "dst_port": 443, "proto": "tcp", "payload_visibility": "encrypted_tls",
            "interval_summary": {"count": 10, "mean": 30.0, "cv": 0.03}, "c2_indicators": {"beacon_score": 0.7},
        }
        profile = {
            "name": "test", "max_prompt_tokens": 2200, "max_prompt_chars": 6600,
            "max_session_context_chars": 2200, "max_rag_chunks": 2, "max_rag_chars_per_chunk": 300,
        }
        snippets = [{"doc_id": "boundary", "targeted_boundary": True, "score": 10, "text": "periodicity is not sufficient for C2"}]
        prompt, meta = build_phase1_prompt(record, snippets, profile, {"targeted_rag_triggers": ["c2_vs_normal"]})
        self.assertEqual(meta["task"], "phase1_stage_first")
        self.assertLessEqual(meta["estimated_prompt_tokens"], profile["max_prompt_tokens"])
        self.assertEqual(meta["rag_chunks_included"], 1)
        self.assertIn("stage_code first", prompt)
        for stage in STAGE_CODES:
            self.assertIn(stage, prompt)
        for technique, stage in TECHNIQUE_TO_STAGE.items():
            self.assertIn(technique, prompt)
            self.assertIn(stage, STAGE_CODES)
        self.assertNotIn("answer_key", prompt.lower())

    def test_pcap_level_prompt_judges_whole_pcap_under_budget(self) -> None:
        record = {
            "record_id": "phase1_001::pcap", "pcap_id": "phase1_001", "pcap_name": "sample.pcap", "record_type": "pcap",
            "source_session_count": 17, "source_record_count": 5,
            "time_range": {"start_time": 1.0, "end_time": 9.5, "duration": 8.5},
            "protocols_seen": ["tcp"], "top_dst_ports": [{"value": "80", "count": 12}],
            "scan_group_summary": {"scan_like_record_count": 1, "max_unique_dst_ports": 12, "max_failed_conn_rate": 0.75},
            "candidate_technique_scores": {"TA43_01": 4.3, "TN01_01": 0.0},
            "primary_rule_candidate": "TA43_01",
            "rule_evidence": ["scan_group_summary shows port/target fanout"],
            "top_suspicious_sessions": [{"record_id": "phase1_001::scan_group::000001", "reasons": ["scan_high_fanout"], "score": 70}],
            "top_payload_evidence": [{"source_record_id": "phase1_001::session::000002", "field": "suspicious_payload_snippets", "text": "cmd=whoami"}],
        }
        profile = {
            "name": "test", "max_prompt_tokens": 2200, "max_prompt_chars": 6600,
            "max_session_context_chars": 2200, "max_rag_chunks": 1, "max_rag_chars_per_chunk": 300,
        }
        prompt, meta = build_phase1_prompt(record, [], profile)
        self.assertLessEqual(meta["estimated_prompt_tokens"], profile["max_prompt_tokens"])
        self.assertIn("judging the whole PCAP", prompt)
        self.assertIn("one stage_code for the entire PCAP", prompt)
        self.assertIn("candidate_technique_scores are deterministic evidence priors", prompt)
        self.assertIn("Do not classify as TN01_01", prompt)
        self.assertIn("source_session_count", prompt)
        self.assertIn("candidate_technique_scores", prompt)
        self.assertIn("top_suspicious_sessions", prompt)
        self.assertEqual(meta["task"], "phase1_stage_first")

    def test_prediction_validation_keeps_stage_primary(self) -> None:
        record = {"record_id": "r1", "pcap_id": "p1", "record_type": "session"}
        item = {"record_id": "r1", "stage_code": "TA11", "technique_guess": "TA01_01", "confidence": "high", "reason": "Repeated callback timing."}
        parsed = validate_prediction(item, record)
        self.assertEqual(parsed["stage_code"], "TA11")
        self.assertFalse(parsed["technique_stage_consistent"])
        self.assertEqual(parsed["confidence"], 0.85)

    def test_prediction_validation_fills_stage_from_technique_guess(self) -> None:
        record = {"record_id": "r1", "pcap_id": "p1", "record_type": "pcap"}
        item = {"record_id": "r1", "stage_code": "", "technique_guess": "TA11_01", "confidence": 0.7, "reason": "Backdoor endpoint access."}
        parsed = validate_prediction(item, record)
        self.assertEqual(parsed["stage_code"], "TA11")
        self.assertEqual(parsed["technique_guess"], "TA11_01")

    def test_safe_config_never_contains_api_key(self) -> None:
        config = {
            "input_dir": Path("/input"), "output_dir": Path("/output"), "base_url": "http://127.0.0.1:8000/v1",
            "model": "qwen", "api_key": "very-secret", "answer": None, "dry_run": True, "resume": True,
            "limit": 5, "rag_top_k": 4, "max_prompt_tokens": 6000, "request_timeout": 180,
            "max_retries": 2, "enable_thinking": False, "save_prompt_samples": True, "prompt_sample_limit": 5,
            "prefer_zeek": True, "allow_tshark_fallback": True, "zeek_docker_image": "zeek:test",
            "enable_tshark_observable_supplement": True,
        }
        report = safe_config_report(config)
        self.assertNotIn("api_key", report)
        self.assertNotIn("very-secret", json.dumps(report))
        self.assertEqual(report["thinking_control"], "chat_template_kwargs.enable_thinking")
        self.assertFalse(report["enable_thinking"])
        self.assertTrue(report["enable_tshark_observable_supplement"])
        self.assertEqual(report["granularity"], "pcap")

    def test_qwen_extra_body_uses_chat_template_kwargs(self) -> None:
        payload = qwen_extra_body(False)
        self.assertEqual(payload, {"chat_template_kwargs": {"enable_thinking": False}})
        self.assertNotIn("enable_thinking", payload)

    def test_run_api_sends_qwen_thinking_control_payload(self) -> None:
        captured: list[dict] = []

        class FakeOpenAI:
            def __init__(self, **kwargs) -> None:
                self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

            def create(self, **kwargs):
                captured.append(kwargs)
                content = json.dumps({
                    "record_id": "r1", "pcap_id": "p1", "record_type": "session",
                    "start_time": None, "end_time": None, "src_ip": "10.0.0.1", "src_port": 12345,
                    "dst_ip": "10.0.0.2", "dst_port": 443, "stage_code": "TN01",
                    "technique_guess": None, "confidence": 0.8, "reason": "No attack behavior is visible.",
                })
                return SimpleNamespace(
                    id="fake-response",
                    choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
                    usage=SimpleNamespace(model_dump=lambda: {"total_tokens": 12}),
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prompts = root / "prompts"
            prompts.mkdir()
            (prompts / "p.txt").write_text("Return exactly one JSON object.", encoding="utf-8")
            paths = {"prompts": prompts, "api_parsed": root / "api" / "parsed"}
            config = {
                "dry_run": False, "base_url": "http://127.0.0.1:8000/v1", "api_key": "EMPTY",
                "request_timeout": 10, "model": "qwen3.5", "resume": False, "max_retries": 0,
                "enable_thinking": False,
            }
            records = [{"record_id": "r1", "pcap_id": "p1", "record_type": "session"}]
            manifest = [{"record_id": "r1", "prompt_file": "p.txt"}]
            fake_openai_module = SimpleNamespace(OpenAI=FakeOpenAI)
            with patch.dict(sys.modules, {"openai": fake_openai_module}):
                results, failures, api_calls = run_api(config, paths, records, manifest)

        self.assertEqual(api_calls, 1)
        self.assertEqual(len(results), 1)
        self.assertEqual(failures, [])
        self.assertEqual(captured[0]["extra_body"], {"chat_template_kwargs": {"enable_thinking": False}})
        self.assertNotIn("enable_thinking", captured[0]["extra_body"])

    def test_pcap_level_records_aggregate_one_record_per_pcap(self) -> None:
        cards = [
            {"pcap_id": "phase1_001", "session_id": "s1", "record_type": "session", "start_time": 1.0, "end_time": 1.2, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80, "proto": "tcp", "service": "http", "parser_source": "zeek_conn"},
            {"pcap_id": "phase1_001", "session_id": "s2", "record_type": "session", "start_time": 2.0, "end_time": 2.2, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "dst_port": 8080, "proto": "tcp", "service": "http", "parser_source": "zeek_conn"},
            {"pcap_id": "phase1_002", "session_id": "s3", "record_type": "session", "start_time": 3.0, "end_time": 3.2, "src_ip": "10.0.0.4", "dst_ip": "10.0.0.5", "dst_port": 443, "proto": "tcp", "service": "ssl", "parser_source": "tshark_fallback"},
        ]
        records = [
            {
                "pcap_id": "phase1_001", "record_id": "phase1_001::scan_group::000001", "record_type": "scan_group",
                "start_time": 1.0, "end_time": 2.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "unique_dst_ports": 12, "failed_conn_rate": 0.8, "candidate_hint": "TA43_01",
            },
            {
                "pcap_id": "phase1_001", "record_id": "phase1_001::session::000002", "record_type": "session",
                "start_time": 2.0, "end_time": 2.2, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "dst_port": 80,
                "payload_visibility": "plaintext_http", "http_body_observed": True,
                "suspicious_payload_snippets": ["cmd=whoami&password=secret"],
                "exploit_indicators": {"command_injection": True, "matched_keywords": ["cmd_exe"]},
            },
            {"pcap_id": "phase1_002", "record_id": "phase1_002::session::000001", "record_type": "session", "start_time": 3.0, "end_time": 3.2, "src_ip": "10.0.0.4", "dst_ip": "10.0.0.5"},
        ]
        parse_summary = [{"case_id": "phase1_001", "pcap_path": "/inputs/a.pcap"}, {"case_id": "phase1_002", "pcap_path": "/inputs/b.pcap"}]
        pcap_records = build_pcap_records(cards, records, parse_summary)
        self.assertEqual([item["record_id"] for item in pcap_records], ["phase1_001::pcap", "phase1_002::pcap"])
        first = pcap_records[0]
        self.assertEqual(first["record_type"], "pcap")
        self.assertEqual(first["pcap_name"], "a.pcap")
        self.assertEqual(first["source_session_count"], 2)
        self.assertEqual(first["source_record_count"], 2)
        self.assertEqual(first["scan_group_summary"]["max_unique_dst_ports"], 12)
        self.assertIn("candidate_technique_scores", first)
        self.assertEqual(first["primary_rule_candidate"], "TA01_02")
        self.assertGreater(first["candidate_technique_scores"]["TA01_02"], first["candidate_technique_scores"]["TN01_01"])
        self.assertGreaterEqual(len(first["top_suspicious_sessions"]), 1)
        self.assertIn("cmd=whoami", json.dumps(first["top_payload_evidence"], ensure_ascii=False))
        self.assertNotIn("secret", json.dumps(first, ensure_ascii=False))

    def test_pcap_record_rag_query_uses_aggregate_summaries(self) -> None:
        record = {
            "record_id": "phase1_001::pcap", "pcap_id": "phase1_001", "record_type": "pcap",
            "scan_group_summary": {"scan_like_record_count": 1, "max_unique_dst_ports": 20},
            "auth_attempt_summary": {"failed_login_count": 6, "max_attempt_count": 6},
            "top_payload_evidence": [{"text": "cmd=whoami"}],
            "exploit_indicators": {"command_injection": True},
        }
        terms, rules, low_signal = record_terms(record)
        groups = detect_confusion_groups(record)
        triggers, docs, _ = targeted_rag_metadata(record, groups)
        self.assertFalse(low_signal)
        self.assertIn("pcap-level classification", terms)
        self.assertIn("pcap_scan_summary:TA43", rules)
        self.assertIn("pcap_auth_summary:TA01_01", rules)
        self.assertIn("pcap_payload_evidence", rules)
        self.assertIn("pcap_scan_summary=positive", triggers)
        self.assertTrue(docs)

    def test_official_rows_preserve_core_columns_and_pcap_metadata(self) -> None:
        rows = official_rows(
            [{
                "record_id": "phase1_001::pcap", "pcap_id": "phase1_001", "record_type": "pcap",
                "stage_code": "", "technique_guess": "TA43_01", "confidence": 0.9, "reason": "Port fanout across the PCAP.",
            }],
            {"phase1_001::pcap": "a.pcap"},
        )
        self.assertEqual(rows[0]["pcap"], "a.pcap")
        self.assertEqual(rows[0]["编号"], "phase1_001::pcap")
        self.assertEqual(rows[0]["record_id"], "phase1_001::pcap")
        self.assertEqual(rows[0]["pcap_id"], "phase1_001")
        self.assertEqual(rows[0]["record_type"], "pcap")
        self.assertEqual(rows[0]["stage_code"], "TA43")
        self.assertEqual(rows[0]["攻击阶段编号或正常流量编号"], "TA43")
        self.assertEqual(rows[0]["technique_guess"], "TA43_01")
        self.assertEqual(rows[0]["reason"], "Port fanout across the PCAP.")
        self.assertEqual(rows[0]["研判理由（不计入评分）"], "Port fanout across the PCAP.")

        session_row = official_rows(
            [{
                "record_id": "phase1_001::session::000001", "pcap_id": "phase1_001", "record_type": "session",
                "stage_code": "TN01", "technique_guess": "TN01_01", "confidence": 0.8, "reason": "Ordinary short flow.",
            }],
            {"phase1_001::session::000001": "a.pcap"},
        )[0]
        self.assertEqual(session_row["record_type"], "session")
        self.assertEqual(session_row["stage_code"], "TN01")

    def test_official_submission_csv_is_strict_stage_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = root / "selected_records.json"
            records.write_text(json.dumps([{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "pcap_name": "sample01.pcap",
                "start_time": 1312967328.170871,
                "end_time": 1312967330.0,
                "src_ip": "multiple",
                "src_port": "multiple",
                "dst_ip": "multiple",
                "dst_port": "multiple",
            }], ensure_ascii=False), encoding="utf-8")
            predictions = [{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "record_type": "pcap",
                "stage_code": "",
                "technique_guess": "TA11_02",
                "confidence": 0.86,
                "reason": "Beacon timing and fixed remote endpoint are visible.",
            }]
            csv_path = root / "official_submission.csv"
            stats = export_official_submission(
                predictions=predictions,
                records_json=records,
                output_csv=csv_path,
                output_xlsx=root / "official_submission.xlsx",
            )

            self.assertEqual(stats["rows"], 1)
            with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                self.assertEqual(reader.fieldnames, OFFICIAL_COLUMNS)
                row = next(reader)
            self.assertEqual(row["pcap编号"], "phase1_001")
            self.assertEqual(row["攻击阶段编号或正常流量编号"], "TA11")
            self.assertEqual(row["研判理由（不计分）"], "Beacon timing and fixed remote endpoint are visible.")
            self.assertEqual(row["开始时间"], "2011-08-10 17:08:48.170871")
            self.assertNotIn("2026", row["开始时间"])
            self.assertNotIn("technique_guess", row)
            self.assertNotIn("confidence", row)
            self.assertNotIn("record_id", row)

    def test_official_submission_timezone_can_switch_to_utc(self) -> None:
        rows = build_official_rows(
            [{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "stage_code": "TA11",
                "technique_guess": "TA11_02",
                "start_time": 1312967328.170871,
                "end_time": 1312967329.0,
                "reason": "Callback behavior.",
            }],
            submission_timezone="UTC",
            official_metadata_source="aggregate",
        )
        self.assertEqual(rows[0]["开始时间"], "2011-08-10 09:08:48.170871")
        self.assertEqual(rows[0]["结束时间"], "2011-08-10 09:08:49")
        shanghai = build_official_rows(
            [{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "stage_code": "TA11",
                "technique_guess": "TA11_02",
                "start_time": 1312967328.170871,
                "end_time": 1312967329.0,
                "reason": "Callback behavior.",
            }],
            submission_timezone="Asia/Shanghai",
            official_metadata_source="aggregate",
        )
        self.assertEqual(shanghai[0]["开始时间"], "2011-08-10 17:08:48.170871")

    def test_official_submission_representative_prefers_attack_session(self) -> None:
        record = {
            "record_id": "phase1_001::pcap",
            "pcap_id": "phase1_001",
            "record_type": "pcap",
            "start_time": 1312967000.0,
            "end_time": 1312968000.0,
            "src_ip": "multiple",
            "src_port": "multiple",
            "dst_ip": "multiple",
            "dst_port": "multiple",
            "top_suspicious_sessions": [{
                "record_id": "phase1_001::session::000007",
                "start_time": 1312967328.170871,
                "end_time": 1312967328.381522,
                "src_ip": "147.32.84.165",
                "src_port": 1274,
                "dst_ip": "94.63.150.20",
                "dst_port": 80,
            }],
        }
        rows = build_official_rows(
            [{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "stage_code": "TA11",
                "technique_guess": "TA11_02",
                "reason": "Suspicious callback.",
            }],
            records={record["record_id"]: record},
        )
        self.assertEqual(rows[0]["开始时间"], "2011-08-10 17:08:48.170871")
        self.assertEqual(rows[0]["源IP"], "147.32.84.165")
        self.assertEqual(rows[0]["源端口"], "1274")
        self.assertEqual(rows[0]["目的IP"], "94.63.150.20")
        self.assertEqual(rows[0]["目的端口"], "80")

    def test_official_submission_aggregate_mode_keeps_multiple(self) -> None:
        record = {
            "record_id": "phase1_001::pcap",
            "pcap_id": "phase1_001",
            "record_type": "pcap",
            "start_time": 1312967000.0,
            "end_time": 1312968000.0,
            "src_ip": "multiple",
            "src_port": "multiple",
            "dst_ip": "multiple",
            "dst_port": "multiple",
            "top_suspicious_sessions": [{
                "start_time": 1312967328.170871,
                "src_ip": "147.32.84.165",
                "src_port": 1274,
                "dst_ip": "94.63.150.20",
                "dst_port": 80,
            }],
        }
        rows = build_official_rows(
            [{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "stage_code": "TA11",
                "technique_guess": "TA11_02",
                "reason": "Suspicious callback.",
            }],
            records={record["record_id"]: record},
            official_metadata_source="aggregate",
        )
        self.assertEqual(rows[0]["开始时间"], "2011-08-10 17:03:20")
        self.assertEqual(rows[0]["源IP"], "multiple")
        self.assertEqual(rows[0]["源端口"], "multiple")
        self.assertEqual(rows[0]["目的IP"], "multiple")
        self.assertEqual(rows[0]["目的端口"], "multiple")

    def test_official_submission_scan_uses_scan_representative_and_ports(self) -> None:
        record = {
            "record_id": "phase1_001::pcap",
            "pcap_id": "phase1_001",
            "record_type": "pcap",
            "start_time": 1312967000.0,
            "end_time": 1312968000.0,
            "src_ip": "multiple",
            "src_port": "multiple",
            "dst_ip": "multiple",
            "dst_port": "multiple",
            "primary_rule_candidate": "TA43_01",
            "top_dst_ports": [{"value": 22, "count": 3}, {"value": 80, "count": 2}, {"value": 443, "count": 1}],
            "scan_group_summary": {
                "scan_like_record_count": 1,
                "top_records": [{
                    "record_id": "phase1_001::scan_group::000001",
                    "start_time": 1312967100.0,
                    "end_time": 1312967110.0,
                    "src_ip": "10.0.0.5",
                    "src_port": "multiple",
                    "dst_ip": "10.0.0.9",
                    "dst_port": "multiple",
                }],
            },
        }
        rows = build_official_rows(
            [{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "stage_code": "TA43",
                "technique_guess": "TA43_01",
                "reason": "Port fanout.",
            }],
            records={record["record_id"]: record},
        )
        self.assertEqual(rows[0]["源IP"], "10.0.0.5")
        self.assertEqual(rows[0]["目的IP"], "10.0.0.9")
        self.assertEqual(rows[0]["目的端口"], "22,80,443")

    def test_official_submission_normal_prefers_benign_context(self) -> None:
        record = {
            "record_id": "phase1_001::pcap",
            "pcap_id": "phase1_001",
            "record_type": "pcap",
            "start_time": 1312967000.0,
            "end_time": 1312968000.0,
            "src_ip": "multiple",
            "src_port": "multiple",
            "dst_ip": "multiple",
            "dst_port": "multiple",
            "representative_benign_context": [{
                "record_id": "phase1_001::session::000001",
                "start_time": 1312967200.0,
                "end_time": 1312967201.0,
                "src_ip": "192.0.2.10",
                "src_port": 53000,
                "dst_ip": "198.51.100.20",
                "dst_port": 443,
            }],
            "top_suspicious_sessions": [{
                "src_ip": "203.0.113.1",
                "dst_ip": "203.0.113.2",
                "dst_port": 4444,
            }],
        }
        rows = build_official_rows(
            [{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "stage_code": "TN01",
                "technique_guess": "TN01_01",
                "reason": "No attack indicators.",
            }],
            records={record["record_id"]: record},
        )
        self.assertEqual(rows[0]["源IP"], "192.0.2.10")
        self.assertEqual(rows[0]["源端口"], "53000")
        self.assertEqual(rows[0]["目的IP"], "198.51.100.20")
        self.assertEqual(rows[0]["目的端口"], "443")

    def test_official_submission_can_export_technique_level(self) -> None:
        rows = build_official_rows(
            [{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "pcap_name": "sample01.pcap",
                "stage_code": "TA11",
                "technique_guess": "TA11_02",
                "reason": "Callback behavior.",
            }],
            submission_label_level="technique",
            pcap_id_source="filename_stem",
        )
        self.assertEqual(rows[0]["pcap编号"], "sample01")
        self.assertEqual(rows[0]["攻击阶段编号或正常流量编号"], "TA11_02")
        self.assertEqual(rows[0]["研判理由（不计分）"], "Callback behavior.")

    def test_phase1_predictions_remains_debug_output(self) -> None:
        rows = official_rows(
            [{
                "record_id": "phase1_001::pcap", "pcap_id": "phase1_001", "record_type": "pcap",
                "stage_code": "TA43", "technique_guess": "TA43_01", "confidence": 0.9,
                "reason": "Port fanout.",
            }],
            {"phase1_001::pcap": "sample01.pcap"},
        )
        self.assertIn("technique_guess", rows[0])
        self.assertIn("confidence", rows[0])
        self.assertIn("record_id", rows[0])
        self.assertIn("研判理由（不计入评分）", rows[0])
        official = build_official_rows(rows)
        self.assertEqual(set(official[0]), set(OFFICIAL_COLUMNS))

    def test_output_dir_export_uses_pipeline_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "session_cards").mkdir()
            (root / "predictions.jsonl").write_text(json.dumps({
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "record_type": "pcap",
                "stage_code": "TN01",
                "technique_guess": "TN01_01",
                "reason": "No attack indicators are visible.",
            }, ensure_ascii=False) + "\n", encoding="utf-8")
            (root / "session_cards" / "selected_records.json").write_text(json.dumps([{
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "pcap_name": "normal.pcap",
                "src_ip": "multiple",
                "src_port": "multiple",
                "dst_ip": "multiple",
                "dst_port": "multiple",
            }], ensure_ascii=False), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parent / "export_official_submission.py"), "--output-dir", str(root)],
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn("official_submission.csv", result.stdout)
            self.assertTrue((root / "official_submission.csv").exists())

    def test_pipeline_without_answer_exports_official_submission_and_skips_evaluator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "out"
            record = {
                "record_id": "phase1_001::pcap",
                "pcap_id": "phase1_001",
                "pcap_name": "sample01.pcap",
                "record_type": "pcap",
                "start_time": 1312967000.0,
                "end_time": 1312968000.0,
                "src_ip": "multiple",
                "src_port": "multiple",
                "dst_ip": "multiple",
                "dst_port": "multiple",
                "top_suspicious_sessions": [{
                    "start_time": 1312967328.170871,
                    "end_time": 1312967328.381522,
                    "src_ip": "147.32.84.165",
                    "src_port": 1274,
                    "dst_ip": "94.63.150.20",
                    "dst_port": 80,
                }],
            }
            result = {
                "record_id": record["record_id"],
                "pcap_id": record["pcap_id"],
                "record_type": "pcap",
                "stage_code": "TA11",
                "technique_guess": "TA11_02",
                "confidence": 0.85,
                "reason": "Suspicious callback.",
            }
            config = {
                "input_dir": root / "input",
                "output_dir": output,
                "base_url": "http://127.0.0.1:8000/v1",
                "model": "qwen3.5",
                "api_key": "EMPTY",
                "answer": None,
                "granularity": "pcap",
                "submission_label_level": "stage",
                "pcap_id_source": "pcap_id",
                "submission_timezone": "Asia/Shanghai",
                "official_metadata_source": "representative",
                "dry_run": False,
                "resume": False,
                "limit": 0,
                "rag_top_k": 4,
                "max_prompt_tokens": 6000,
                "request_timeout": 120,
                "max_retries": 0,
                "enable_thinking": False,
                "prefer_zeek": True,
                "allow_tshark_fallback": True,
                "enable_tshark_observable_supplement": True,
                "zeek_docker_image": "",
                "save_prompt_samples": False,
                "prompt_sample_limit": 0,
                "enable_critic": False,
                "critic_only_on_conflict": True,
                "allow_remote_base_url": False,
                "config_path": root / "config.yaml",
            }

            def fake_prepare_evidence(_config, paths, _pcaps):
                paths["selected"].parent.mkdir(parents=True, exist_ok=True)
                paths["selected"].write_text(json.dumps([record], ensure_ascii=False), encoding="utf-8")
                paths["parse_summary"].parent.mkdir(parents=True, exist_ok=True)
                paths["parse_summary"].write_text(json.dumps([{
                    "case_id": "phase1_001",
                    "pcap_path": "/inputs/sample01.pcap",
                }], ensure_ascii=False), encoding="utf-8")
                return [record], {"phase1_001": "sample01.pcap"}, {record["record_id"]: "sample01.pcap"}, {
                    "source_session_cards": 1,
                    "source_classification_records": 1,
                    "pcap_level_records": 1,
                    "selected_records": 1,
                }

            def fake_write_xlsx(path, rows):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
                return True

            run_labels: list[str] = []

            def fake_run_command(label, command):
                run_labels.append(label)
                if label.startswith("evaluate"):
                    raise AssertionError("evaluator should not run without --answer")

            with (
                patch.object(pipeline, "parse_args", return_value=SimpleNamespace()),
                patch.object(pipeline, "effective_config", return_value=config),
                patch.object(pipeline, "validate_config", return_value=[root / "input" / "sample01.pcap"]),
                patch.object(pipeline, "prepare_evidence", side_effect=fake_prepare_evidence),
                patch.object(pipeline, "prepare_rag", return_value=[]),
                patch.object(pipeline, "prepare_prompts", return_value=[{"record_id": record["record_id"], "estimated_prompt_tokens": 1000, "rag_chunks_included": 0}]),
                patch.object(pipeline, "run_api", return_value=([result], [], 1)),
                patch.object(pipeline, "run_command", side_effect=fake_run_command),
                patch("export_official_submission.write_xlsx", side_effect=fake_write_xlsx),
            ):
                status = pipeline.main()

            self.assertEqual(status, 0)
            self.assertTrue((output / "official_submission.csv").exists())
            self.assertTrue((output / "official_submission.xlsx").exists())
            self.assertFalse(any(label.startswith("evaluate") for label in run_labels))
            with (output / "official_submission.csv").open("r", encoding="utf-8-sig", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["源IP"], "147.32.84.165")
            self.assertEqual(row["攻击阶段编号或正常流量编号"], "TA11")

    def test_official_xlsx_generation_when_openpyxl_available(self) -> None:
        try:
            import openpyxl  # noqa: F401
        except ImportError:
            self.skipTest("openpyxl is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stats = export_official_submission(
                predictions=[{
                    "record_id": "phase1_001::pcap",
                    "pcap_id": "phase1_001",
                    "stage_code": "TA43",
                    "technique_guess": "TA43_01",
                    "reason": "Scan fanout.",
                }],
                output_csv=root / "official_submission.csv",
                output_xlsx=root / "official_submission.xlsx",
            )
            self.assertTrue(stats["xlsx_written"])
            self.assertTrue((root / "official_submission.xlsx").exists())

    def test_offline_readiness_script_runs_without_network(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parent / "check_offline_readiness.py"),
                "--soft",
                "--no-check-api",
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("Offline readiness", result.stdout)
        self.assertNotIn("api-key", result.stdout.lower())

    def test_unstable_safe_calibration_default_is_not_present(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for relative in (
            "configs/phase1_vm.yaml",
            "scripts/run_phase1_pipeline.py",
            "scripts/build_pcap_level_records.py",
            "scripts/build_qwen35_session_prompts.py",
            "scripts/build_rag_query.py",
        ):
            text = (root / relative).read_text(encoding="utf-8")
            self.assertNotIn("safe_calibration", text)

    def test_pcap_candidate_scores_capture_attack_priors(self) -> None:
        exploit = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::1", "record_type": "session",
            "suspicious_payload_snippets": ["cmd=whoami"],
            "exploit_indicators": {"command_injection": True},
        }])
        self.assertEqual(set(exploit["candidate_technique_scores"]), set(technique_codes()))
        self.assertIn("top_rule_candidates", exploit)
        self.assertIn("candidate_evidence", exploit)
        self.assertIn("candidate_counter_evidence", exploit)
        self.assertIn("evidence_strength", exploit)
        self.assertGreater(exploit["candidate_technique_scores"]["TA01_02"], exploit["candidate_technique_scores"]["TN01_01"])

        beacon = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::c2_callback_group::1", "record_type": "c2_callback_group",
            "payload_visibility": "encrypted_tls", "dst_port": 4430,
            "c2_indicators": {"periodic_connections": True, "fixed_remote_endpoint": True},
        }])
        self.assertGreater(beacon["candidate_technique_scores"]["TA11_02"], beacon["candidate_technique_scores"]["TN01_01"])

        miner = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::miner", "record_type": "session",
            "http_uris_sample": ["/miner/ping?id=abcd1234&hashrate=600000"],
            "http_user_agents": ["ethminer/0.19.0"],
            "http_content_types": ["application/json"],
        }])
        self.assertGreater(miner["candidate_technique_scores"]["TA11_02"], miner["candidate_technique_scores"]["TN01_01"])

        auth_rows = [
            {
                "pcap_id": "phase1_001", "record_id": f"phase1_001::session::{index:06d}", "record_type": "session",
                "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "dst_port": 3306,
                "resp_pkts": 0, "resp_bytes": 0, "same_src_same_dst_port_count": 24,
                "c2_indicators": {"periodic_connections": True},
            }
            for index in range(24)
        ]
        auth = one_pcap_record(auth_rows)
        self.assertGreater(auth["candidate_technique_scores"]["TA01_01"], auth["candidate_technique_scores"]["TA11_02"])

        sensitive = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::probe", "record_type": "session",
            "http_methods": ["HEAD"], "http_uris_sample": ["/App_Data/db.mdb"], "http_status_codes": [502],
        }])
        self.assertGreater(sensitive["candidate_technique_scores"]["TA43_02"], sensitive["candidate_technique_scores"]["TN01_01"])

        generic_post = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::post", "record_type": "session",
            "http_methods": ["POST"], "suspicious_payload_snippets": ["POST /search?q=;id"],
            "exploit_indicators": {"command_injection": True},
            "implant_indicators": {"payload_delivery_hint": True},
        }])
        self.assertGreater(generic_post["candidate_technique_scores"]["TA01_02"], generic_post["candidate_technique_scores"]["TA03_01"])

    def test_pcap_candidate_scores_counter_false_positive_families(self) -> None:
        encoded_only = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::encoded", "record_type": "session",
            "suspicious_payload_snippets": ["base64 AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"],
        }])
        self.assertGreaterEqual(encoded_only["candidate_technique_scores"]["TN01_01"], encoded_only["candidate_technique_scores"]["TA01_02"])

        steam = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::steam", "record_type": "session",
            "http_hosts": ["cdn.steamcontent.com"], "http_uris_sample": ["/depot/123/chunk/abcdef"],
            "http_user_agents": ["Valve/Steam HTTP Client"], "http_content_types": ["application/x-steam-chunk"],
            "suspicious_payload_snippets": ["binary chunk data"],
        }])
        self.assertGreater(steam["candidate_technique_scores"]["TN01_01"], steam["candidate_technique_scores"]["TA01_02"])
        self.assertTrue(any("download/chunk" in item for item in steam["candidate_counter_evidence"]["TA01_02"]))

        webshell = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::shell", "record_type": "session",
            "http_uris_sample": ["/shell.php?cmd=whoami"], "suspicious_http_parameters": ["cmd=whoami"],
            "exploit_indicators": {"command_injection": True},
        }])
        self.assertGreater(webshell["candidate_technique_scores"]["TA11_01"], webshell["candidate_technique_scores"]["TA01_02"])

        placement = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::upload", "record_type": "session",
            "http_multipart_present": True, "http_upload_hints": ["/admin/upload filename=shell.php"],
            "implant_indicators": {"webshell_filename": True},
        }])
        self.assertGreater(placement["candidate_technique_scores"]["TA03_01"], placement["candidate_technique_scores"]["TA01_02"])

        weak_php = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::weak", "record_type": "session",
            "http_methods": ["POST"], "http_uris_sample": ["/chuli.php"],
        }])
        self.assertIn("generic_php_post_weak_implant_evidence", weak_php["rule_conflict_flags"])
        self.assertLess(weak_php["candidate_technique_scores"]["TA03_01"], 1.0)

    def test_candidate_scores_csv_is_generated(self) -> None:
        record = one_pcap_record([{
            "pcap_id": "phase1_001", "record_id": "phase1_001::session::1", "record_type": "session",
            "suspicious_payload_snippets": ["cmd=whoami"],
            "exploit_indicators": {"command_injection": True},
        }])
        result = {
            "record_id": record["record_id"], "pcap_id": record["pcap_id"], "record_type": "pcap",
            "stage_code": "TA01", "technique_guess": "TA01_02", "confidence": 0.7,
            "reason": "Exploit payload is visible.",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {
                "candidate_scores": root / "candidate_scores.csv",
                "candidate_score_report": root / "candidate_score_report.md",
                "conflict_cases": root / "conflict_cases.jsonl",
                "critic_prompts": root / "critic_review_prompts",
            }
            stats = write_candidate_diagnostics(
                {"enable_critic": True, "critic_only_on_conflict": True},
                paths,
                [record],
                [result],
                {record["record_id"]: "sample.pcap"},
            )
            self.assertEqual(stats["candidate_rows"], 1)
            self.assertTrue(paths["candidate_scores"].exists())
            self.assertTrue(paths["candidate_score_report"].exists())
            text = paths["candidate_scores"].read_text(encoding="utf-8-sig")
            self.assertIn("primary_rule_candidate", text)
            self.assertIn("TA01_02", text)


class Phase1ParserSelectionTests(unittest.TestCase):
    def test_system_zeek_missing_uses_configured_docker_zeek(self) -> None:
        def fake_command_exists(name: str, env: dict | None = None) -> bool:
            return name == "docker"

        def fake_run(cmd: list[str], cwd=None, env=None, stdout_path=None):
            if cmd[:3] == ["docker", "image", "inspect"]:
                return 0, "", ""
            if cmd[:3] == ["docker", "run", "--rm"]:
                zeek_mount = next(item for item in cmd if item.endswith(":/zeek"))
                Path(zeek_mount.split(":", 1)[0]).joinpath("conn.log").write_text("#fields\tts\tuid\n", encoding="utf-8")
                return 0, "", ""
            raise AssertionError(f"unexpected command: {cmd}")

        def fake_extract(_pcap: Path, output: Path):
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("", encoding="utf-8")
            return 0, 0, ""

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "sample.pcap"
            pcap.touch()
            with (
                patch("parse_public_pcaps.command_exists", fake_command_exists),
                patch("parse_public_pcaps.run", fake_run),
                patch("parse_public_pcaps.extract_safe_http_observations", fake_extract),
            ):
                summary = parse_case("case1", pcap, root / "parsed", zeek_docker_image="zeek:test")

        self.assertTrue(summary["zeek_success"])
        self.assertFalse(summary["tshark_attempted"])
        self.assertTrue(summary["tshark_supplement_attempted"])
        self.assertTrue(summary["tshark_supplement_success"])
        self.assertEqual(summary["parser_source"], "zeek_docker")
        self.assertEqual(summary["zeek_error"], "")
        self.assertEqual(summary["warnings"], [])
        self.assertEqual(summary["payload_supplement_source"], "tshark_observable")

    def test_docker_zeek_failure_falls_back_to_tshark_when_allowed(self) -> None:
        def fake_command_exists(name: str, env: dict | None = None) -> bool:
            return name in {"docker", "tshark"}

        def fake_run(cmd: list[str], cwd=None, env=None, stdout_path=None):
            if cmd[:3] == ["docker", "image", "inspect"]:
                return 0, "", ""
            if cmd[:3] == ["docker", "run", "--rm"]:
                return 1, "", "<Error> docker zeek failed"
            if cmd and cmd[0] == "tshark" and stdout_path:
                Path(stdout_path).write_text("frame.time_epoch,ip.src,ip.dst\n1.0,10.0.0.1,10.0.0.2\n", encoding="utf-8")
                return 0, "", ""
            raise AssertionError(f"unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "sample.pcap"
            pcap.touch()
            with (
                patch("parse_public_pcaps.command_exists", fake_command_exists),
                patch("parse_public_pcaps.run", fake_run),
                patch("parse_public_pcaps.extract_safe_http_observations", return_value=(0, 0, "")),
            ):
                summary = parse_case("case1", pcap, root / "parsed", zeek_docker_image="zeek:test")

        self.assertFalse(summary["zeek_success"])
        self.assertTrue(summary["tshark_success"])
        self.assertTrue(summary["tshark_fallback_success"])
        self.assertTrue(summary["tshark_attempted"])
        self.assertFalse(summary["tshark_supplement_attempted"])
        self.assertEqual(summary["parser_source"], "tshark_fallback")
        self.assertIn("docker zeek failed", summary["zeek_error"])
        self.assertTrue(any("using tshark packet aggregation fallback" in warning for warning in summary["warnings"]))

    def test_system_zeek_success_runs_observable_supplement(self) -> None:
        def fake_command_exists(name: str, env: dict | None = None) -> bool:
            return name == "zeek"

        def fake_run(cmd: list[str], cwd=None, env=None, stdout_path=None):
            if cmd and cmd[0] == "zeek":
                Path(cwd).joinpath("conn.log").write_text("#fields\tts\tuid\n", encoding="utf-8")
                return 0, "", ""
            raise AssertionError(f"unexpected command: {cmd}")

        def fake_extract(_pcap: Path, output: Path):
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text('{"body_observed": true}\n', encoding="utf-8")
            return 0, 1, ""

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "sample.pcap"
            pcap.touch()
            with (
                patch("parse_public_pcaps.command_exists", fake_command_exists),
                patch("parse_public_pcaps.run", fake_run),
                patch("parse_public_pcaps.extract_safe_http_observations", fake_extract),
            ):
                summary = parse_case("case1", pcap, root / "parsed", zeek_docker_image="zeek:test")

        self.assertTrue(summary["zeek_success"])
        self.assertFalse(summary["tshark_success"])
        self.assertFalse(summary["tshark_attempted"])
        self.assertTrue(summary["tshark_supplement_attempted"])
        self.assertTrue(summary["tshark_supplement_success"])
        self.assertEqual(summary["tshark_supplement_rows"], 1)
        self.assertEqual(summary["payload_supplement_source"], "tshark_observable")
        self.assertEqual(summary["parser_source"], "zeek_conn")
        self.assertEqual(summary["zeek_mode"], "system")

    def test_system_zeek_success_continues_when_supplement_fails(self) -> None:
        def fake_command_exists(name: str, env: dict | None = None) -> bool:
            return name == "zeek"

        def fake_run(cmd: list[str], cwd=None, env=None, stdout_path=None):
            if cmd and cmd[0] == "zeek":
                Path(cwd).joinpath("conn.log").write_text("#fields\tts\tuid\n", encoding="utf-8")
                return 0, "", ""
            raise AssertionError(f"unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "sample.pcap"
            pcap.touch()
            with (
                patch("parse_public_pcaps.command_exists", fake_command_exists),
                patch("parse_public_pcaps.run", fake_run),
                patch("parse_public_pcaps.extract_safe_http_observations", return_value=(1, 0, "<Error> tshark failed")),
            ):
                summary = parse_case("case1", pcap, root / "parsed", zeek_docker_image="zeek:test")

        self.assertTrue(summary["zeek_success"])
        self.assertEqual(summary["parser_source"], "zeek_conn")
        self.assertTrue(summary["tshark_supplement_attempted"])
        self.assertFalse(summary["tshark_supplement_success"])
        self.assertEqual(summary["payload_supplement_source"], "none")
        self.assertTrue(any("observable supplement failed" in warning for warning in summary["warnings"]))

    def test_system_zeek_success_skips_disabled_supplement(self) -> None:
        def fake_command_exists(name: str, env: dict | None = None) -> bool:
            return name == "zeek"

        def fake_run(cmd: list[str], cwd=None, env=None, stdout_path=None):
            if cmd and cmd[0] == "zeek":
                Path(cwd).joinpath("conn.log").write_text("#fields\tts\tuid\n", encoding="utf-8")
                return 0, "", ""
            raise AssertionError(f"unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "sample.pcap"
            pcap.touch()
            with (
                patch("parse_public_pcaps.command_exists", fake_command_exists),
                patch("parse_public_pcaps.run", fake_run),
                patch("parse_public_pcaps.extract_safe_http_observations") as extract_mock,
            ):
                summary = parse_case(
                    "case1",
                    pcap,
                    root / "parsed",
                    zeek_docker_image="zeek:test",
                    enable_tshark_observable_supplement=False,
                )

        self.assertTrue(summary["zeek_success"])
        self.assertFalse(summary["tshark_supplement_attempted"])
        self.assertFalse(summary["tshark_supplement_success"])
        self.assertEqual(summary["payload_supplement_source"], "none")
        extract_mock.assert_not_called()


class Phase1EvaluationTests(unittest.TestCase):
    def test_csv_evaluation_and_flexible_headers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            predictions = root / "predictions.csv"
            answer = root / "answer.csv"
            with predictions.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["pcap", "编号", "攻击阶段编号或正常流量编号"])
                writer.writeheader()
                writer.writerows([
                    {"pcap": "a.pcap", "编号": "r1", "攻击阶段编号或正常流量编号": "TA43"},
                    {"pcap": "a.pcap", "编号": "r2", "攻击阶段编号或正常流量编号": "TN01"},
                    {"pcap": "b.pcap", "编号": "r3", "攻击阶段编号或正常流量编号": "TA11"},
                ])
            with answer.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["PCAP filename", "record_id", "technique_code"])
                writer.writeheader()
                writer.writerows([
                    {"PCAP filename": "a.pcap", "record_id": "r1", "technique_code": "TA43_01"},
                    {"PCAP filename": "a.pcap", "record_id": "r2", "technique_code": "TN01_01"},
                    {"PCAP filename": "b.pcap", "record_id": "r3", "technique_code": "TA11_02"},
                ])
            result = evaluate(predictions, answer, root / "evaluation")
            self.assertEqual(result["matched"], 3)
            self.assertEqual(result["accuracy"], 1.0)
            self.assertTrue((root / "evaluation/eval_report.md").exists())
            self.assertTrue((root / "evaluation/confusion_matrix.csv").exists())

    def test_pcap_level_answer_table_matches_by_unique_pcap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            predictions = root / "predictions.csv"
            answer = root / "answer.csv"
            with predictions.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["pcap", "编号", "攻击阶段编号或正常流量编号", "technique_guess"])
                writer.writeheader()
                writer.writerows([
                    {"pcap": "a.pcap", "编号": "phase1_001::pcap", "攻击阶段编号或正常流量编号": "TA43", "technique_guess": "TA43_01"},
                    {"pcap": "b.pcap", "编号": "phase1_002::pcap", "攻击阶段编号或正常流量编号": "TN01", "technique_guess": "TN01_01"},
                ])
            with answer.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["filename", "研判结果"])
                writer.writeheader()
                writer.writerows([
                    {"filename": "a.pcap", "研判结果": "TA43"},
                    {"filename": "b.pcap", "研判结果": "TN01"},
                ])
            result = evaluate(predictions, answer, root / "evaluation")
            report = (root / "evaluation/eval_report.md").read_text(encoding="utf-8")
            self.assertEqual(result["matched"], 2)
            self.assertEqual(result["accuracy"], 1.0)
            self.assertIn("'pcap': 2", report)

    def test_official_like_chinese_answer_table_matches_12_pcap_rows(self) -> None:
        labels = [
            ("sample01.pcap", "端口扫描", "TA43_01"),
            ("sample02.pcap", "漏洞扫描", "TA43_02"),
            ("sample03.pcap", "密码爆破", "TA01_01"),
            ("sample04.pcap", "漏洞利用", "TA01_02"),
            ("sample05.pcap", "植入后门", "TA03_01"),
            ("sample06.pcap", "访问后门", "TA11_01"),
            ("sample07.pcap", "木马回连", "TA11_02"),
            ("sample08.pcap", "正常流量", "TN01_01"),
            ("sample09.pcap", "漏洞利用", "TA01_02"),
            ("sample10.pcap", "木马回连", "TA11_02"),
            ("sample11.pcap", "漏洞扫描", "TA43_02"),
            ("sample12.pcap", "密码爆破", "TA01_01"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            predictions = root / "predictions.csv"
            answer = root / "answer.csv"
            with predictions.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["pcap_name", "record_id", "stage_code", "technique_guess", "reason"])
                writer.writeheader()
                writer.writerows([
                    {
                        "pcap_name": pcap,
                        "record_id": f"phase1_{index:03d}::pcap",
                        "stage_code": "",
                        "technique_guess": technique,
                        "reason": "Rule candidate matched observable evidence.",
                    }
                    for index, (pcap, _label, technique) in enumerate(labels, start=1)
                ])
            with answer.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["文件名", "开始时间", "结束时间", "源IP", "源端口", "目的IP", "目的端口", "攻击技术名称或正常流量", "是否为加密流量"])
                writer.writeheader()
                writer.writerows([
                    {"文件名": pcap, "攻击技术名称或正常流量": label, "是否为加密流量": "否"}
                    for pcap, label, _technique in labels
                ])
            result = evaluate(predictions, answer, root / "evaluation")
            self.assertEqual(result["matched"], 12)
            self.assertEqual(result["stage_accuracy"], 1.0)
            self.assertEqual(result["technique_accuracy"], 1.0)
            self.assertEqual(result["normal_vs_attack_accuracy"], 1.0)


if __name__ == "__main__":
    unittest.main()
