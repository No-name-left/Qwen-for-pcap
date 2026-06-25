#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from build_qwen35_session_prompts import STAGE_CODES, TECHNIQUE_TO_STAGE, build_phase1_prompt
from evaluate_phase1_predictions import evaluate
from parse_public_pcaps import discover_pcaps, parse_case
from run_phase1_pipeline import qwen_extra_body, run_api, safe_config_report, validate_prediction


class Phase1PromptTests(unittest.TestCase):
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
            "name": "test", "max_prompt_tokens": 1600, "max_prompt_chars": 4800,
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

    def test_prediction_validation_keeps_stage_primary(self) -> None:
        record = {"record_id": "r1", "pcap_id": "p1", "record_type": "session"}
        item = {"record_id": "r1", "stage_code": "TA11", "technique_guess": "TA01_01", "confidence": "high", "reason": "Repeated callback timing."}
        parsed = validate_prediction(item, record)
        self.assertEqual(parsed["stage_code"], "TA11")
        self.assertFalse(parsed["technique_stage_consistent"])
        self.assertEqual(parsed["confidence"], 0.85)

    def test_safe_config_never_contains_api_key(self) -> None:
        config = {
            "input_dir": Path("/input"), "output_dir": Path("/output"), "base_url": "http://127.0.0.1:8000/v1",
            "model": "qwen", "api_key": "very-secret", "answer": None, "dry_run": True, "resume": True,
            "limit": 5, "rag_top_k": 4, "max_prompt_tokens": 6000, "request_timeout": 180,
            "max_retries": 2, "enable_thinking": False, "save_prompt_samples": True, "prompt_sample_limit": 5,
            "prefer_zeek": True, "allow_tshark_fallback": True, "zeek_docker_image": "zeek:test",
        }
        report = safe_config_report(config)
        self.assertNotIn("api_key", report)
        self.assertNotIn("very-secret", json.dumps(report))
        self.assertEqual(report["thinking_control"], "chat_template_kwargs.enable_thinking")
        self.assertFalse(report["enable_thinking"])

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

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "sample.pcap"
            pcap.touch()
            with patch("parse_public_pcaps.command_exists", fake_command_exists), patch("parse_public_pcaps.run", fake_run):
                summary = parse_case("case1", pcap, root / "parsed", zeek_docker_image="zeek:test")

        self.assertTrue(summary["zeek_success"])
        self.assertFalse(summary["tshark_attempted"])
        self.assertEqual(summary["parser_source"], "zeek_docker")
        self.assertEqual(summary["zeek_error"], "")
        self.assertEqual(summary["warnings"], [])

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
        self.assertTrue(summary["tshark_attempted"])
        self.assertEqual(summary["parser_source"], "tshark_fallback")
        self.assertIn("docker zeek failed", summary["zeek_error"])
        self.assertTrue(any("using tshark packet aggregation fallback" in warning for warning in summary["warnings"]))

    def test_system_zeek_success_sets_zeek_parser_source(self) -> None:
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
            with patch("parse_public_pcaps.command_exists", fake_command_exists), patch("parse_public_pcaps.run", fake_run):
                summary = parse_case("case1", pcap, root / "parsed", zeek_docker_image="zeek:test")

        self.assertTrue(summary["zeek_success"])
        self.assertFalse(summary["tshark_success"])
        self.assertFalse(summary["tshark_attempted"])
        self.assertEqual(summary["parser_source"], "zeek_conn")
        self.assertEqual(summary["zeek_mode"], "system")


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


if __name__ == "__main__":
    unittest.main()
