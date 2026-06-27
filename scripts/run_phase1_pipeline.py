#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import yaml

from build_qwen35_session_prompts import (
    PROMPT_VERSION,
    STAGE_CODES,
    TECHNIQUE_CODES,
    TECHNIQUE_TO_STAGE,
    build_phase1_prompt,
)
from export_official_submission import export_official_submission


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs/phase1_vm.yaml"
STAGE_FIELD = "攻击阶段编号或正常流量编号"
REASON_FIELD = "研判理由（不计入评分）"
CSV_FIELDS = [
    "pcap", "pcap_id", "pcap_name", "record_id", "record_type", "编号",
    "开始时间", "结束时间", "源IP", "源端口", "目的IP", "目的端口",
    STAGE_FIELD, "stage_code", "technique_guess", "confidence", REASON_FIELD, "reason",
]
CANDIDATE_SCORE_FIELDS = [
    "pcap_name", "pcap_id", "record_id", "record_type",
    "primary_rule_candidate", "top_rule_candidates", "score_margin", "evidence_strength",
    "predicted_technique", "predicted_stage", "confidence",
    "conflict_review_needed", "conflict_flags", "rule_evidence", "counter_evidence",
]
ROUTING_FIELDS = [
    "record_id", "pcap_id", "record_type", "route", "status", "inference_source",
    "primary_rule_candidate", "primary_rule_score", "score_margin", "evidence_strength",
    "conflict_count", "conflict_flags", "reason", "latency_seconds",
]
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
EVIDENCE_STRENGTH_ORDER = {"weak": 1, "medium": 2, "strong": 3}
BLOCK_RULE_DIRECT_FLAGS = {
    "weak_attack_uncertainty",
    "payload_observability_gap",
    "model_prediction_differs_from_primary_rule_candidate",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def qwen_extra_body(enable_thinking: bool) -> dict[str, Any]:
    """Build the vLLM/Qwen chat-template extension used to control thinking."""
    return {"chat_template_kwargs": {"enable_thinking": bool(enable_thinking)}}


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                item = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run_command(label: str, command: list[str]) -> None:
    print(f"[RUN] {label}", flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def path_has_json_list(path: Path) -> bool:
    try:
        return isinstance(load_json(path), list)
    except (OSError, json.JSONDecodeError):
        return False


def read_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def config_value(config: dict[str, Any], args: argparse.Namespace, name: str, env_names: list[str], cast: Any = str) -> Any:
    cli_value = getattr(args, name)
    if cli_value is not None:
        return cli_value
    for env_name in env_names:
        if env_name in os.environ and os.environ[env_name] != "":
            return cast(os.environ[env_name])
    value = config.get(name)
    return cast(value) if value is not None else None


def effective_config(args: argparse.Namespace) -> dict[str, Any]:
    read_env_file(ROOT / ".env")
    config_path = args.config.resolve()
    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"config must be a YAML mapping: {config_path}")
    values = {
        "input_dir": config_value(data, args, "input_dir", ["PHASE1_INPUT_DIR"], Path),
        "output_dir": config_value(data, args, "output_dir", ["PHASE1_OUTPUT_DIR"], Path),
        "base_url": config_value(data, args, "base_url", ["LLM_BASE_URL", "BASE_URL", "OPENAI_BASE_URL"]),
        "model": config_value(data, args, "model", ["LLM_MODEL_NAME", "MODEL", "OPENAI_MODEL"]),
        "api_key": config_value(data, args, "api_key", ["LLM_API_KEY", "API_KEY", "OPENAI_API_KEY"]),
        "answer": config_value(data, args, "answer", ["PHASE1_ANSWER"], Path),
        "granularity": config_value(data, args, "granularity", ["PHASE1_GRANULARITY"]),
        "submission_label_level": config_value(data, args, "submission_label_level", ["PHASE1_SUBMISSION_LABEL_LEVEL"]),
        "pcap_id_source": config_value(data, args, "pcap_id_source", ["PHASE1_PCAP_ID_SOURCE"]),
        "submission_timezone": config_value(data, args, "submission_timezone", ["PHASE1_SUBMISSION_TIMEZONE"]),
        "official_metadata_source": config_value(data, args, "official_metadata_source", ["PHASE1_OFFICIAL_METADATA_SOURCE"]),
        "submission_template": config_value(data, args, "submission_template", ["PHASE1_SUBMISSION_TEMPLATE"], Path),
        "dry_run": config_value(data, args, "dry_run", ["PHASE1_DRY_RUN"], as_bool),
        "resume": config_value(data, args, "resume", ["PHASE1_RESUME"], as_bool),
        "limit": config_value(data, args, "limit", ["PHASE1_LIMIT"], int),
        "rag_top_k": config_value(data, args, "rag_top_k", ["PHASE1_RAG_TOP_K"], int),
        "max_prompt_tokens": config_value(data, args, "max_prompt_tokens", ["PHASE1_MAX_PROMPT_TOKENS", "LLM_MAX_PROMPT_TOKENS"], int),
        "request_timeout": config_value(data, args, "request_timeout", ["PHASE1_REQUEST_TIMEOUT", "LLM_REQUEST_TIMEOUT"], float),
        "max_retries": config_value(data, args, "max_retries", ["PHASE1_MAX_RETRIES"], int),
        "api_retries": config_value(data, args, "api_retries", ["PHASE1_API_RETRIES"], int),
        "api_retry_sleep": config_value(data, args, "api_retry_sleep", ["PHASE1_API_RETRY_SLEEP"], float),
        "max_api_workers": config_value(data, args, "max_api_workers", ["PHASE1_MAX_API_WORKERS"], int),
        "num_shards": config_value(data, args, "num_shards", ["PHASE1_NUM_SHARDS"], int),
        "shard_index": config_value(data, args, "shard_index", ["PHASE1_SHARD_INDEX"], int),
        "llm_routing": config_value(data, args, "llm_routing", ["PHASE1_LLM_ROUTING"]),
        "rule_direct_min_score": config_value(data, args, "rule_direct_min_score", ["PHASE1_RULE_DIRECT_MIN_SCORE"], float),
        "rule_direct_min_margin": config_value(data, args, "rule_direct_min_margin", ["PHASE1_RULE_DIRECT_MIN_MARGIN"], float),
        "rule_direct_min_strength": config_value(data, args, "rule_direct_min_strength", ["PHASE1_RULE_DIRECT_MIN_STRENGTH"]),
        "rule_direct_allow_normal": config_value(data, args, "rule_direct_allow_normal", ["PHASE1_RULE_DIRECT_ALLOW_NORMAL"], as_bool),
        "rule_direct_max_conflicts": config_value(data, args, "rule_direct_max_conflicts", ["PHASE1_RULE_DIRECT_MAX_CONFLICTS"], int),
        "max_completion_tokens": config_value(data, args, "max_completion_tokens", ["PHASE1_MAX_COMPLETION_TOKENS", "LLM_MAX_COMPLETION_TOKENS"], int),
        "compact_reason": config_value(data, args, "compact_reason", ["PHASE1_COMPACT_REASON"], as_bool),
        "estimated_llm_latency": config_value(data, args, "estimated_llm_latency", ["PHASE1_ESTIMATED_LLM_LATENCY"], float),
        "enable_thinking": config_value(data, args, "enable_thinking", ["PHASE1_ENABLE_THINKING", "LLM_ENABLE_THINKING", "ENABLE_THINKING"], as_bool),
        "prefer_zeek": config_value(data, args, "prefer_zeek", ["PHASE1_PREFER_ZEEK"], as_bool),
        "allow_tshark_fallback": config_value(data, args, "allow_tshark_fallback", ["PHASE1_ALLOW_TSHARK_FALLBACK"], as_bool),
        "enable_tshark_observable_supplement": config_value(data, args, "enable_tshark_observable_supplement", ["PHASE1_ENABLE_TSHARK_OBSERVABLE_SUPPLEMENT"], as_bool),
        "zeek_docker_image": config_value(data, args, "zeek_docker_image", ["PHASE1_ZEEK_DOCKER_IMAGE", "ZEEK_DOCKER_IMAGE"]),
        "save_prompt_samples": config_value(data, args, "save_prompt_samples", ["PHASE1_SAVE_PROMPT_SAMPLES"], as_bool),
        "prompt_sample_limit": config_value(data, args, "prompt_sample_limit", ["PHASE1_PROMPT_SAMPLE_LIMIT"], int),
        "enable_critic": config_value(data, args, "enable_critic", ["PHASE1_ENABLE_CRITIC"], as_bool),
        "critic_only_on_conflict": config_value(data, args, "critic_only_on_conflict", ["PHASE1_CRITIC_ONLY_ON_CONFLICT"], as_bool),
    }
    if values["enable_thinking"] is None:
        values["enable_thinking"] = False
    if values["prefer_zeek"] is None:
        values["prefer_zeek"] = True
    if values["allow_tshark_fallback"] is None:
        values["allow_tshark_fallback"] = True
    if values["enable_tshark_observable_supplement"] is None:
        values["enable_tshark_observable_supplement"] = True
    if values["granularity"] is None:
        values["granularity"] = "pcap"
    values["granularity"] = str(values["granularity"]).strip().lower()
    if values["submission_label_level"] is None:
        values["submission_label_level"] = "stage"
    values["submission_label_level"] = str(values["submission_label_level"]).strip().lower()
    if values["pcap_id_source"] is None:
        values["pcap_id_source"] = "pcap_id"
    values["pcap_id_source"] = str(values["pcap_id_source"]).strip().lower()
    if values["submission_timezone"] is None:
        values["submission_timezone"] = "Asia/Shanghai"
    values["submission_timezone"] = str(values["submission_timezone"]).strip()
    if values["official_metadata_source"] is None:
        values["official_metadata_source"] = "representative"
    values["official_metadata_source"] = str(values["official_metadata_source"]).strip().lower()
    if values["resume"] is None:
        values["resume"] = False
    if values["api_retries"] is None:
        values["api_retries"] = values["max_retries"] if values["max_retries"] is not None else 2
    if values["api_retry_sleep"] is None:
        values["api_retry_sleep"] = 3.0
    if values["max_api_workers"] is None:
        values["max_api_workers"] = 1
    if values["num_shards"] is None:
        values["num_shards"] = 1
    if values["shard_index"] is None:
        values["shard_index"] = 0
    if values["llm_routing"] is None:
        values["llm_routing"] = "all"
    values["llm_routing"] = str(values["llm_routing"]).strip().lower()
    if values["rule_direct_min_score"] is None:
        values["rule_direct_min_score"] = 7.0
    if values["rule_direct_min_margin"] is None:
        values["rule_direct_min_margin"] = 2.5
    if values["rule_direct_min_strength"] is None:
        values["rule_direct_min_strength"] = "strong"
    values["rule_direct_min_strength"] = str(values["rule_direct_min_strength"]).strip().lower()
    if values["rule_direct_allow_normal"] is None:
        values["rule_direct_allow_normal"] = False
    if values["rule_direct_max_conflicts"] is None:
        values["rule_direct_max_conflicts"] = 0
    if values["max_completion_tokens"] is None:
        values["max_completion_tokens"] = 384
    if values["compact_reason"] is None:
        values["compact_reason"] = False
    if values["estimated_llm_latency"] is None:
        values["estimated_llm_latency"] = 32.8
    if values["enable_critic"] is None:
        values["enable_critic"] = False
    if values["critic_only_on_conflict"] is None:
        values["critic_only_on_conflict"] = True
    values["input_dir"] = Path(values["input_dir"]).expanduser().resolve()
    values["output_dir"] = Path(values["output_dir"]).expanduser().resolve()
    values["answer"] = Path(values["answer"]).expanduser().resolve() if values.get("answer") else None
    values["submission_template"] = Path(values["submission_template"]).expanduser().resolve() if values.get("submission_template") else None
    values["allow_remote_base_url"] = bool(args.allow_remote_base_url)
    values["config_path"] = config_path
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Phase-1 PCAP-to-local-Qwen VM pipeline.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--input", "--input-dir", dest="input_dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--base-url")
    parser.add_argument("--model")
    parser.add_argument("--api-key")
    parser.add_argument("--answer", type=Path)
    parser.add_argument("--granularity", choices=["pcap", "session"], help="Final output granularity. pcap builds one prompt/prediction per PCAP; session preserves existing per-record behavior.")
    parser.add_argument("--submission-label-level", choices=["stage", "technique"], help="Official submission label granularity. Defaults to stage for Phase-1.")
    parser.add_argument("--pcap-id-source", choices=["pcap_id", "pcap_name", "filename_stem"], help="Official submission pcap编号 source. Defaults to pcap_id.")
    parser.add_argument("--submission-timezone", choices=["UTC", "Asia/Shanghai"], help="Official submission display timezone. Defaults to Asia/Shanghai.")
    parser.add_argument("--official-metadata-source", choices=["representative", "aggregate"], help="Official submission time/IP/port source. Defaults to representative sessions.")
    parser.add_argument("--submission-template", type=Path, help="Optional official empty CSV/XLSX template whose metadata columns should be copied into the submission.")
    parser.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--rag-top-k", type=int)
    parser.add_argument("--max-prompt-tokens", type=int)
    parser.add_argument("--request-timeout", type=float)
    parser.add_argument("--max-retries", type=int)
    parser.add_argument("--api-retries", type=int, help="Per-record OpenAI-compatible API retries. Defaults to 2.")
    parser.add_argument("--api-retry-sleep", type=float, help="Seconds to wait between API retry attempts. Defaults to 3.")
    parser.add_argument("--max-api-workers", type=int, help="Concurrent API workers. Defaults to 1 for legacy serial behavior.")
    parser.add_argument("--num-shards", type=int, help="Total stable shards to split selected records into.")
    parser.add_argument("--shard-index", type=int, help="Zero-based shard index to run when --num-shards is set.")
    parser.add_argument("--llm-routing", choices=["all", "high-confidence-skip", "none"], help="LLM routing mode. Defaults to all.")
    parser.add_argument("--rule-direct-min-score", type=float)
    parser.add_argument("--rule-direct-min-margin", type=float)
    parser.add_argument("--rule-direct-min-strength", choices=["strong", "medium", "weak"])
    parser.add_argument("--rule-direct-allow-normal", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--rule-direct-max-conflicts", type=int)
    parser.add_argument("--max-completion-tokens", type=int, help="Maximum completion tokens for live LLM calls.")
    parser.add_argument("--compact-reason", action=argparse.BooleanOptionalAction, default=None, help="Shorten validated reasons in prediction outputs.")
    parser.add_argument("--estimated-llm-latency", type=float, help="Seconds/record used for serial runtime estimates when no live latency is available.")
    parser.add_argument("--enable-thinking", dest="enable_thinking", action="store_true", default=None, help="Enable Qwen chat-template thinking mode.")
    parser.add_argument("--disable-thinking", dest="enable_thinking", action="store_false", default=None, help="Disable Qwen chat-template thinking mode for strict JSON output.")
    parser.add_argument("--prefer-zeek", action=argparse.BooleanOptionalAction, default=None, help="Prefer system/Docker Zeek before TShark fallback.")
    parser.add_argument("--allow-tshark-fallback", action=argparse.BooleanOptionalAction, default=None, help="Use TShark packet aggregation if Zeek is unavailable or fails.")
    parser.add_argument("--enable-tshark-observable-supplement", action=argparse.BooleanOptionalAction, default=None, help="When Zeek succeeds, run safe TShark HTTP observable supplement extraction.")
    parser.add_argument("--zeek-docker-image", help="Local Docker Zeek image used when system Zeek is unavailable or fails.")
    parser.add_argument("--save-prompt-samples", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--prompt-sample-limit", type=int)
    parser.add_argument("--enable-critic", dest="enable_critic", action="store_true", default=None, help="Generate lightweight conflict-review prompts for PCAP-level predictions.")
    parser.add_argument("--disable-critic", dest="enable_critic", action="store_false", default=None, help="Disable conflict-review prompt generation.")
    parser.add_argument("--critic-only-on-conflict", action=argparse.BooleanOptionalAction, default=None, help="Only generate critic review prompts for conflict cases.")
    parser.add_argument("--allow-remote-base-url", action="store_true", help="Explicitly allow a non-loopback OpenAI-compatible endpoint.")
    return parser.parse_args()


def validate_config(config: dict[str, Any]) -> list[Path]:
    if config["limit"] < 0 or config["rag_top_k"] < 1 or config["max_prompt_tokens"] < 1000:
        raise ValueError("limit must be >=0, rag_top_k >=1, and max_prompt_tokens >=1000")
    if config["granularity"] not in {"pcap", "session"}:
        raise ValueError("granularity must be either 'pcap' or 'session'")
    if config["submission_label_level"] not in {"stage", "technique"}:
        raise ValueError("submission_label_level must be either 'stage' or 'technique'")
    if config["pcap_id_source"] not in {"pcap_id", "pcap_name", "filename_stem"}:
        raise ValueError("pcap_id_source must be one of 'pcap_id', 'pcap_name', or 'filename_stem'")
    if config["submission_timezone"] not in {"UTC", "Asia/Shanghai"}:
        raise ValueError("submission_timezone must be either 'UTC' or 'Asia/Shanghai'")
    if config["official_metadata_source"] not in {"representative", "aggregate"}:
        raise ValueError("official_metadata_source must be either 'representative' or 'aggregate'")
    if config["llm_routing"] not in {"all", "high-confidence-skip", "none"}:
        raise ValueError("llm_routing must be one of 'all', 'high-confidence-skip', or 'none'")
    if config["rule_direct_min_strength"] not in EVIDENCE_STRENGTH_ORDER:
        raise ValueError("rule_direct_min_strength must be one of 'weak', 'medium', or 'strong'")
    if config["max_api_workers"] < 1 or config["api_retries"] < 0 or config["api_retry_sleep"] < 0:
        raise ValueError("max_api_workers must be >=1, api_retries >=0, and api_retry_sleep >=0")
    if config["num_shards"] < 1 or not 0 <= config["shard_index"] < config["num_shards"]:
        raise ValueError("num_shards must be >=1 and shard_index must be zero-based within the shard count")
    if config["rule_direct_max_conflicts"] < 0:
        raise ValueError("rule_direct_max_conflicts must be >=0")
    if config["max_completion_tokens"] < 1:
        raise ValueError("max_completion_tokens must be >=1")
    if config["estimated_llm_latency"] < 0:
        raise ValueError("estimated_llm_latency must be >=0")
    if config.get("submission_template") and not config["submission_template"].is_file():
        raise FileNotFoundError(f"submission template does not exist: {config['submission_template']}")
    input_dir = config["input_dir"]
    if not input_dir.is_dir():
        raise FileNotFoundError(f"input directory does not exist: {input_dir}")
    pcaps = sorted(path for path in input_dir.iterdir() if path.is_file() and path.suffix.lower() in PCAP_SUFFIXES)
    if not pcaps:
        raise FileNotFoundError(f"no direct .pcap/.pcapng/.cap files found in {input_dir}")
    parsed = urlparse(config["base_url"])
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("base_url must be an HTTP(S) OpenAI-compatible endpoint")
    local_hosts = {"127.0.0.1", "localhost", "::1"}
    if not config["dry_run"] and parsed.hostname not in local_hosts and not config["allow_remote_base_url"]:
        raise ValueError("live mode rejects non-loopback base_url; add --allow-remote-base-url only when intentional")
    if not config["dry_run"] and not config["model"]:
        raise ValueError("model is required in live mode")
    return pcaps


def step_paths(output: Path) -> dict[str, Path]:
    cards = output / "session_cards"
    rag = output / "rag"
    return {
        "parsed": output / "parsed",
        "parse_summary": output / "parsed/parse_all_summary.json",
        "input_manifest": output / "input_manifest.json",
        "cards": cards / "session_cards.json",
        "llm_cards": cards / "llm_session_cards.json",
        "cards_report": cards / "session_cards_report.md",
        "scan_groups": cards / "scan_groups.json",
        "auth_groups": cards / "auth_attempt_groups.json",
        "c2_groups": cards / "c2_callback_groups.json",
        "records": cards / "classification_records.json",
        "pcap_records": cards / "pcap_level_records.json",
        "selected": cards / "selected_records.json",
        "records_report": cards / "classification_records_report.md",
        "pcap_records_report": cards / "pcap_level_records_report.md",
        "queries": rag / "queries.jsonl",
        "query_report": rag / "query_report.md",
        "retrieval": rag / "retrieval.json",
        "rag_config": rag / "run_config.json",
        "retrieval_report": rag / "retrieval_report.md",
        "prompts": output / "prompts",
        "prompt_manifest": output / "prompts/prompt_manifest.json",
        "prompt_samples": output / "prompt_samples",
        "api_parsed": output / "api/parsed",
        "candidate_scores": output / "candidate_scores.csv",
        "candidate_score_report": output / "candidate_score_report.md",
        "conflict_cases": output / "conflict_cases.jsonl",
        "critic_prompts": output / "critic_review_prompts",
        "routing_summary": output / "routing_summary.csv",
        "inference_plan_report": output / "inference_plan_report.md",
        "official_submission_csv": output / "official_submission.csv",
        "official_submission_xlsx": output / "official_submission.xlsx",
    }


def create_parse_errors(summary: list[dict[str, Any]]) -> list[dict[str, Any]]:
    errors = []
    for item in summary:
        warnings = item.get("warnings") or []
        if warnings or not (item.get("zeek_success") or item.get("tshark_success")):
            errors.append({
                "case_id": item.get("case_id"), "pcap": Path(str(item.get("pcap_path") or "")).name,
                "parser_source": item.get("parser_source"),
                "zeek_success": bool(item.get("zeek_success")), "tshark_success": bool(item.get("tshark_success")),
                "tshark_fallback_success": bool(item.get("tshark_fallback_success")),
                "tshark_supplement_enabled": bool(item.get("tshark_supplement_enabled")),
                "tshark_supplement_success": bool(item.get("tshark_supplement_success")),
                "payload_supplement_source": item.get("payload_supplement_source"),
                "zeek_error": item.get("zeek_error"), "tshark_error": item.get("tshark_error"),
                "tshark_supplement_error": item.get("tshark_supplement_error"),
                "warnings": warnings,
            })
    return errors


def prepare_evidence(config: dict[str, Any], paths: dict[str, Path], pcaps: list[Path]) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str], dict[str, int]]:
    python = sys.executable
    parse_summary = load_json(paths["parse_summary"], []) if config["resume"] else []
    current_manifest = [{"name": path.name, "size": path.stat().st_size, "mtime_ns": path.stat().st_mtime_ns} for path in pcaps]
    previous_manifest = load_json(paths["input_manifest"], []) if config["resume"] else []
    parsed_names = {Path(str(item.get("pcap_path") or "")).name for item in parse_summary}
    current_names = {path.name for path in pcaps}
    neutral_ids = all(re.fullmatch(r"phase1_\d{3}", str(item.get("case_id") or "")) for item in parse_summary)
    parse_config_matches = all(
        item.get("tshark_supplement_enabled") == config["enable_tshark_observable_supplement"]
        for item in parse_summary
    )
    parse_reused = bool(len(parse_summary) == len(pcaps) and parsed_names == current_names and neutral_ids and previous_manifest == current_manifest and parse_config_matches)
    if parse_reused:
        print(f"[SKIP] parse: resume found {len(pcaps)} matching cases", flush=True)
    else:
        parse_cmd = [
            python, str(ROOT / "scripts/parse_public_pcaps.py"),
            "--input-dir", str(config["input_dir"]),
            "--output-dir", str(paths["parsed"]),
            "--dataset-id", "phase1",
            "--neutral-case-ids",
            "--prefer-zeek" if config["prefer_zeek"] else "--no-prefer-zeek",
            "--allow-tshark-fallback" if config["allow_tshark_fallback"] else "--no-allow-tshark-fallback",
            "--enable-tshark-observable-supplement" if config["enable_tshark_observable_supplement"] else "--no-enable-tshark-observable-supplement",
        ]
        if config.get("zeek_docker_image"):
            parse_cmd.extend(["--zeek-docker-image", str(config["zeek_docker_image"])])
        run_command("parse PCAPs with Zeek/Docker Zeek/TShark", parse_cmd)
        parse_summary = load_json(paths["parse_summary"], [])
        write_json(paths["input_manifest"], current_manifest)
    if not parse_summary:
        raise RuntimeError("parser produced no cases")
    write_jsonl(config["output_dir"] / "parse_errors.jsonl", create_parse_errors(parse_summary))
    case_to_pcap = {str(item.get("case_id")): Path(str(item.get("pcap_path") or item.get("case_id"))).name for item in parse_summary}

    cards_reused = bool(config["resume"] and parse_reused and path_has_json_list(paths["cards"]))
    if cards_reused:
        print("[SKIP] session cards: resume artifact is valid", flush=True)
    else:
        run_command("build session cards", [python, str(ROOT / "scripts/build_session_cards.py"), "--parsed-dir", str(paths["parsed"]), "--output", str(paths["cards"]), "--llm-output", str(paths["llm_cards"]), "--report", str(paths["cards_report"])])
    records_reused = bool(config["resume"] and cards_reused and path_has_json_list(paths["records"]))
    if records_reused:
        print("[SKIP] classification records: resume artifact is valid", flush=True)
    else:
        run_command("build behavioral classification records", [
            python, str(ROOT / "scripts/build_classification_records.py"), "--session-cards", str(paths["cards"]),
            "--scan-groups-output", str(paths["scan_groups"]), "--auth-groups-output", str(paths["auth_groups"]),
            "--c2-groups-output", str(paths["c2_groups"]), "--records-output", str(paths["records"]),
            "--report", str(paths["records_report"]), "--emit-auth-groups", "--emit-c2-groups",
        ])
    session_cards = load_json(paths["cards"], [])
    records = load_json(paths["records"], [])
    if not records:
        raise RuntimeError("no classification records were built from the input PCAPs")
    pcap_records: list[dict[str, Any]] = []
    if config["granularity"] == "pcap":
        pcap_reused = bool(config["resume"] and parse_reused and records_reused and path_has_json_list(paths["pcap_records"]))
        if pcap_reused:
            print("[SKIP] PCAP-level records: resume artifact is valid", flush=True)
        else:
            run_command("build PCAP-level classification records", [
                python, str(ROOT / "scripts/build_pcap_level_records.py"),
                "--session-cards", str(paths["cards"]),
                "--classification-records", str(paths["records"]),
                "--parse-summary", str(paths["parse_summary"]),
                "--output", str(paths["pcap_records"]),
                "--report", str(paths["pcap_records_report"]),
            ])
        pcap_records = load_json(paths["pcap_records"], [])
        if not pcap_records:
            raise RuntimeError("no PCAP-level records were built from the input PCAPs")
        final_records = pcap_records
    else:
        final_records = records
    selected = final_records[: config["limit"]] if config["limit"] else final_records
    write_json(paths["selected"], selected)
    record_to_pcap = {str(record.get("record_id")): case_to_pcap.get(str(record.get("pcap_id")), str(record.get("pcap_id") or "")) for record in selected}
    evidence_stats = {
        "source_session_cards": len(session_cards),
        "source_classification_records": len(records),
        "pcap_level_records": len(pcap_records),
        "selected_records": len(selected),
    }
    return selected, case_to_pcap, record_to_pcap, evidence_stats


def record_identity(record: dict[str, Any]) -> str:
    return str(record.get("record_id") or record.get("session_id") or "")


def apply_shard_to_records(
    records: list[dict[str, Any]],
    *,
    num_shards: int = 1,
    shard_index: int = 0,
) -> list[dict[str, Any]]:
    if num_shards <= 1:
        return list(records)
    return [record for index, record in enumerate(records) if index % num_shards == shard_index]


def apply_configured_shard(
    config: dict[str, Any],
    paths: dict[str, Path],
    records: list[dict[str, Any]],
    record_to_pcap: dict[str, str],
) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, int]]:
    num_shards = int(config.get("num_shards") or 1)
    shard_index = int(config.get("shard_index") or 0)
    if num_shards <= 1:
        return records, record_to_pcap, {
            "pre_shard_records": len(records),
            "num_shards": 1,
            "shard_index": 0,
            "shard_records": len(records),
        }
    full_selected = paths["selected"].with_name("selected_records_all.json")
    write_json(full_selected, records)
    shard_records = apply_shard_to_records(records, num_shards=num_shards, shard_index=shard_index)
    write_json(paths["selected"], shard_records)
    shard_ids = {record_identity(record) for record in shard_records}
    shard_record_to_pcap = {record_id: pcap for record_id, pcap in record_to_pcap.items() if record_id in shard_ids}
    return shard_records, shard_record_to_pcap, {
        "pre_shard_records": len(records),
        "num_shards": num_shards,
        "shard_index": shard_index,
        "shard_records": len(shard_records),
        "selected_records_all": str(full_selected),
    }


def prepare_rag(config: dict[str, Any], paths: dict[str, Path], expected_count: int) -> list[dict[str, Any]]:
    python = sys.executable
    cached = load_json(paths["retrieval"], []) if config["resume"] else []
    expected_ids = [str(item.get("record_id")) for item in load_json(paths["selected"], [])]
    expected_config = {"rag_top_k": config["rag_top_k"], "granularity": config["granularity"], "record_ids": expected_ids}
    cached_config = load_json(paths["rag_config"], {}) if config["resume"] else {}
    if len(cached) == expected_count and [str(item.get("record_id")) for item in cached] == expected_ids and paths["queries"].exists() and cached_config == expected_config:
        print(f"[SKIP] RAG: resume found {expected_count} retrieval records", flush=True)
        return cached
    run_command("build observable-only RAG queries", [python, str(ROOT / "scripts/build_rag_query.py"), "--input", str(paths["selected"]), "--output", str(paths["queries"]), "--report", str(paths["query_report"])])
    run_command("retrieve boundary-first RAG evidence", [
        python, str(ROOT / "scripts/retrieve_rag.py"), "--queries", str(paths["queries"]),
        "--chunks", str(ROOT / "rag/chunks/rag_chunks.jsonl"), "--index", str(ROOT / "rag/index/keyword_index.json"),
        "--output", str(paths["retrieval"]), "--report", str(paths["retrieval_report"]),
        "--top-k", str(config["rag_top_k"]), "--max-boundary-chunks", str(config["rag_top_k"]),
    ])
    retrieved = load_json(paths["retrieval"], [])
    write_json(paths["rag_config"], expected_config)
    return retrieved


def safe_prompt_name(index: int, record_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", record_id)[-80:].strip("_") or "record"
    digest = hashlib.sha256(record_id.encode("utf-8")).hexdigest()[:10]
    return f"{index:06d}_{slug}_{digest}.txt"


def prepare_prompts(config: dict[str, Any], paths: dict[str, Path], records: list[dict[str, Any]], retrieval: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cached = load_json(paths["prompt_manifest"], []) if config["resume"] else []
    expected_ids = [str(record.get("record_id") or record.get("session_id")) for record in records]
    if (
        len(cached) == len(records)
        and [str(item.get("record_id")) for item in cached] == expected_ids
        and all((paths["prompts"] / str(item.get("prompt_file"))).exists() for item in cached)
        and all(int(item.get("estimated_prompt_tokens") or 10**9) <= config["max_prompt_tokens"] for item in cached)
        and all(int(item.get("max_prompt_chars") or 0) == config["max_prompt_tokens"] * 3 for item in cached)
        and all(item.get("prompt_version") == PROMPT_VERSION for item in cached)
        and all(
            item.get("prompt_sha256") == hashlib.sha256((paths["prompts"] / str(item.get("prompt_file"))).read_bytes()).hexdigest()
            for item in cached
        )
    ):
        print(f"[SKIP] prompts: resume found {len(cached)} budget-valid prompts", flush=True)
        return cached
    retrieval_map = {str(item.get("record_id")): item for item in retrieval}
    profile = {
        "name": "phase1_vm_inline", "max_prompt_tokens": config["max_prompt_tokens"],
        "max_prompt_chars": config["max_prompt_tokens"] * 3,
        "max_session_context_chars": min(7500, max(4500, config["max_prompt_tokens"])),
        "max_rag_chunks": config["rag_top_k"], "max_rag_chars_per_chunk": 600,
    }
    paths["prompts"].mkdir(parents=True, exist_ok=True)
    for old in paths["prompts"].glob("*.txt"):
        old.unlink()
    if config["save_prompt_samples"]:
        paths["prompt_samples"].mkdir(parents=True, exist_ok=True)
        for old in paths["prompt_samples"].glob("*.txt"):
            old.unlink()
    manifest = []
    for index, record in enumerate(records, start=1):
        record_id = str(record.get("record_id") or record.get("session_id"))
        retrieval_item = retrieval_map.get(record_id, {})
        prompt, meta = build_phase1_prompt(record, retrieval_item.get("snippets", []), profile, retrieval_item)
        if meta["estimated_prompt_tokens"] > config["max_prompt_tokens"]:
            raise RuntimeError(f"prompt token estimate exceeded budget for {record_id}")
        filename = safe_prompt_name(index, record_id)
        prompt_path = paths["prompts"] / filename
        prompt_path.write_text(prompt, encoding="utf-8")
        if config["save_prompt_samples"] and index <= config["prompt_sample_limit"]:
            (paths["prompt_samples"] / filename).write_text(prompt, encoding="utf-8")
        manifest.append({
            "record_id": record_id, "pcap_id": record.get("pcap_id"), "record_type": record.get("record_type"),
            "prompt_file": filename, "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(), **meta,
        })
    write_json(paths["prompt_manifest"], manifest)
    return manifest


def extract_json_object(text: str) -> dict[str, Any]:
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()
    decoder = json.JSONDecoder()
    objects = []
    for match in re.finditer(r"\{", cleaned):
        try:
            obj, _ = decoder.raw_decode(cleaned[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            objects.append(obj)
    if len(objects) != 1:
        raise ValueError(f"expected exactly one JSON object, found {len(objects)}")
    return objects[0]


def confidence_value(value: Any) -> float:
    if isinstance(value, str):
        named = {"high": 0.85, "medium": 0.6, "low": 0.35}
        if value.strip().lower() in named:
            return named[value.strip().lower()]
    number = float(value)
    if not 0 <= number <= 1:
        raise ValueError("confidence must be between 0 and 1")
    return round(number, 4)


def stage_from_technique(value: Any) -> str:
    technique = str(value or "").strip().upper()
    if technique in TECHNIQUE_TO_STAGE:
        return TECHNIQUE_TO_STAGE[technique]
    prefix = technique.split("_", 1)[0]
    return prefix if prefix in STAGE_CODES else ""


def safe_exception(exc: Exception) -> str:
    if isinstance(exc, (ValueError, TypeError, json.JSONDecodeError)):
        return f"{type(exc).__name__}: {exc}"
    status = getattr(exc, "status_code", None)
    suffix = f" (HTTP {status})" if status else ""
    return f"{type(exc).__name__}: model request failed{suffix}"


def validate_prediction(item: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    expected_id = str(record.get("record_id") or record.get("session_id"))
    record_id = str(item.get("record_id") or "")
    if record_id != expected_id:
        raise ValueError(f"record_id mismatch: expected {expected_id}, received {record_id or '<empty>'}")
    legacy_technique = str(item.get("technique_code") or item.get("predicted_code") or "").upper()
    raw_technique = item.get("technique_guess") or legacy_technique or None
    technique = None if raw_technique in (None, "", "null") else str(raw_technique).upper()
    stage = str(item.get("stage_code") or stage_from_technique(technique or legacy_technique)).upper()
    if stage not in STAGE_CODES:
        raise ValueError(f"invalid stage_code: {stage or '<empty>'}")
    if technique is not None and technique not in TECHNIQUE_CODES:
        raise ValueError(f"invalid technique_guess: {technique}")
    reason = " ".join(str(item.get("reason") or "").split())
    if not reason:
        raise ValueError("reason is required")
    return {
        "record_id": expected_id, "pcap_id": record.get("pcap_id"), "record_type": record.get("record_type"),
        "start_time": record.get("start_time"), "end_time": record.get("end_time"),
        "src_ip": record.get("src_ip"), "src_port": record.get("src_port"),
        "dst_ip": record.get("dst_ip"), "dst_port": record.get("dst_port"),
        "stage_code": stage, "technique_guess": technique,
        "technique_stage_consistent": technique is None or TECHNIQUE_TO_STAGE[technique] == stage,
        "confidence": confidence_value(item.get("confidence")), "reason": reason[:500],
    }


def number_value(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalized_technique(value: Any) -> str:
    technique = str(value or "").strip().upper()
    return technique if technique in TECHNIQUE_CODES else ""


def primary_rule_candidate(record: dict[str, Any]) -> str:
    return normalized_technique(record.get("primary_rule_candidate"))


def technique_score(record: dict[str, Any], technique: str) -> float:
    scores = record.get("candidate_technique_scores") or {}
    if isinstance(scores, dict) and technique in scores:
        return number_value(scores.get(technique))
    candidates = record.get("top_rule_candidates") or []
    if isinstance(candidates, list):
        for item in candidates:
            if not isinstance(item, dict):
                continue
            code = normalized_technique(item.get("technique") or item.get("code") or item.get("technique_code"))
            if code == technique:
                return number_value(item.get("score") or item.get("value"))
    return 0.0


def best_score_candidate(record: dict[str, Any]) -> str:
    primary = primary_rule_candidate(record)
    if primary:
        return primary
    scores = record.get("candidate_technique_scores") or {}
    if isinstance(scores, dict):
        valid = [(normalized_technique(code), number_value(score)) for code, score in scores.items()]
        valid = [(code, score) for code, score in valid if code]
        if valid:
            return max(valid, key=lambda item: (item[1], item[0] != "TN01_01"))[0]
    return "TN01_01"


def score_margin(record: dict[str, Any], technique: str) -> float:
    if record.get("score_margin") not in (None, ""):
        return number_value(record.get("score_margin"))
    scores = record.get("candidate_technique_scores") or {}
    if not isinstance(scores, dict):
        return 0.0
    values = sorted((number_value(score) for code, score in scores.items() if normalized_technique(code)), reverse=True)
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    return max(0.0, technique_score(record, technique) - values[1])


def evidence_strength_rank(value: Any) -> int:
    return EVIDENCE_STRENGTH_ORDER.get(str(value or "").strip().lower(), 0)


def list_values(value: Any) -> list[str]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, dict):
        return [str(key) for key, enabled in value.items() if enabled]
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, (list, dict)):
            return list_values(parsed)
        return [part.strip() for part in re.split(r"[,;]", text) if part.strip()]
    return [str(value)]


def routing_conflict_flags(record: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    for key in ("rule_conflict_flags", "conflict_flags"):
        flags.extend(list_values(record.get(key)))
    if as_bool(record.get("conflict_review_needed")):
        flags.append("conflict_review_needed")
    return sorted(set(flags))


def rule_direct_decision(record: dict[str, Any], config: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
    technique = primary_rule_candidate(record)
    if not technique:
        return False, "missing_primary_rule_candidate", {}
    score = technique_score(record, technique)
    margin = score_margin(record, technique)
    strength = str(record.get("evidence_strength") or "").strip().lower()
    flags = routing_conflict_flags(record)
    detail = {
        "technique": technique,
        "stage": stage_from_technique(technique),
        "score": score,
        "margin": margin,
        "evidence_strength": strength,
        "conflict_flags": flags,
    }
    if technique == "TN01_01" and not config.get("rule_direct_allow_normal", False):
        return False, "normal_rule_direct_disabled", detail
    if score < float(config.get("rule_direct_min_score", 7.0)):
        return False, "score_below_threshold", detail
    if margin < float(config.get("rule_direct_min_margin", 2.5)):
        return False, "margin_below_threshold", detail
    if evidence_strength_rank(strength) < evidence_strength_rank(config.get("rule_direct_min_strength", "strong")):
        return False, "evidence_strength_below_threshold", detail
    if len(flags) > int(config.get("rule_direct_max_conflicts", 0)):
        return False, "too_many_conflicts", detail
    if any(flag in BLOCK_RULE_DIRECT_FLAGS for flag in flags):
        return False, "blocking_conflict_flag", detail
    return True, "high_confidence_rule_candidate", detail


def rule_direct_allowed(record: dict[str, Any], config: dict[str, Any]) -> bool:
    allowed, _, _ = rule_direct_decision(record, config)
    return allowed


def rule_evidence_text(record: dict[str, Any], technique: str) -> list[str]:
    evidence: list[str] = []
    for key in ("rule_evidence", "rule_reasons"):
        evidence.extend(list_values(record.get(key)))
    candidate_evidence = record.get("candidate_evidence") or {}
    if isinstance(candidate_evidence, dict):
        evidence.extend(list_values(candidate_evidence.get(technique)))
    return list(dict.fromkeys(" ".join(str(item).split()) for item in evidence if str(item).strip()))


def compact_text(text: str, max_chars: int = 220) -> str:
    clean = " ".join(str(text or "").split())
    if len(clean) <= max_chars:
        return clean
    return clean[: max_chars - 1].rstrip(" ,.;") + "."


def build_rule_direct_prediction(record: dict[str, Any], config: dict[str, Any], *, forced: bool = False) -> dict[str, Any]:
    technique = best_score_candidate(record)
    score = technique_score(record, technique)
    margin = score_margin(record, technique)
    strength = str(record.get("evidence_strength") or "").strip().lower()
    stage = stage_from_technique(technique) or "TN01"
    flags = routing_conflict_flags(record)
    evidence = rule_evidence_text(record, technique)
    if evidence:
        reason = "; ".join(evidence[:2])
    else:
        reason = f"Deterministic evidence priors select {technique}."
    reason = compact_text(reason, 180 if config.get("compact_reason") else 300)
    confidence = 0.72 if forced else 0.78
    confidence += min(max(score - 7.0, 0.0) * 0.015, 0.07)
    confidence += min(max(margin - 2.5, 0.0) * 0.015, 0.05)
    if strength == "strong":
        confidence += 0.04
    elif strength == "weak":
        confidence -= 0.08
    if technique == "TN01_01":
        confidence -= 0.06
    confidence = max(0.55, min(confidence, 0.9))
    return {
        "record_id": record_identity(record),
        "pcap_id": record.get("pcap_id"),
        "record_type": record.get("record_type"),
        "start_time": record.get("start_time"),
        "end_time": record.get("end_time"),
        "src_ip": record.get("src_ip"),
        "src_port": record.get("src_port"),
        "dst_ip": record.get("dst_ip"),
        "dst_port": record.get("dst_port"),
        "stage_code": stage,
        "technique_guess": technique,
        "technique_stage_consistent": technique in TECHNIQUE_TO_STAGE and TECHNIQUE_TO_STAGE[technique] == stage,
        "confidence": round(confidence, 4),
        "reason": reason,
        "response_meta": {
            "inference_source": "rule_direct",
            "routing_mode": config.get("llm_routing", "all"),
            "forced": bool(forced),
            "primary_rule_candidate": primary_rule_candidate(record),
            "primary_rule_score": score,
            "score_margin": margin,
            "evidence_strength": strength,
            "conflict_flags": flags,
        },
    }


def apply_compact_reason(result: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    if config.get("compact_reason"):
        result = dict(result)
        result["reason"] = compact_text(str(result.get("reason") or ""), 220)
    return result


def load_existing_predictions(path: Path, records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    records_by_id = {record_identity(record): record for record in records}
    existing: dict[str, dict[str, Any]] = {}
    for item in read_jsonl(path):
        record_id = str(item.get("record_id") or "")
        if record_id not in records_by_id:
            continue
        try:
            validated = validate_prediction(item, records_by_id[record_id])
        except (ValueError, TypeError):
            continue
        if item.get("response_meta"):
            validated["response_meta"] = item.get("response_meta")
        existing[record_id] = validated
    return existing


def usage_dict(response: Any) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    if hasattr(usage, "model_dump"):
        data = usage.model_dump()
        return data if isinstance(data, dict) else {}
    if isinstance(usage, dict):
        return usage
    return {key: getattr(usage, key) for key in ("prompt_tokens", "completion_tokens", "total_tokens") if hasattr(usage, key)}


def run_api(config: dict[str, Any], paths: dict[str, Path], records: list[dict[str, Any]], manifest: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    if config["dry_run"] or not records or not manifest:
        return [], [], 0
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("live mode requires the openai package from requirements.txt") from exc
    paths["api_parsed"].mkdir(parents=True, exist_ok=True)
    records_by_id = {str(record.get("record_id") or record.get("session_id")): record for record in records}
    manifest = [entry for entry in manifest if str(entry.get("record_id")) in records_by_id]
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    api_calls = 0
    api_call_lock = threading.Lock()
    thread_local = threading.local()
    retries = int(config.get("api_retries", config.get("max_retries", 2)))
    retry_sleep = float(config.get("api_retry_sleep", 3.0))
    max_tokens = int(config.get("max_completion_tokens", 384))

    def client_for_thread() -> Any:
        client = getattr(thread_local, "client", None)
        if client is None:
            client = OpenAI(base_url=config["base_url"], api_key=config["api_key"] or "EMPTY", timeout=config["request_timeout"])
            thread_local.client = client
        return client

    def infer_one(index: int, entry: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None, int]:
        nonlocal api_calls
        record_id = entry["record_id"]
        parsed_path = paths["api_parsed"] / f"{hashlib.sha256(record_id.encode()).hexdigest()}.json"
        prompt = (paths["prompts"] / entry["prompt_file"]).read_text(encoding="utf-8")
        prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        if config["resume"] and parsed_path.exists():
            try:
                raw_cached = load_json(parsed_path)
                if (raw_cached.get("response_meta") or {}).get("prompt_sha256") != prompt_sha256:
                    raise ValueError("cached response prompt hash mismatch")
                cached = validate_prediction(raw_cached, records_by_id[record_id])
                cached["response_meta"] = raw_cached.get("response_meta") or {}
                cached["response_meta"].setdefault("inference_source", "llm")
                print(f"[SKIP] API {index}/{len(manifest)}: cached {record_id}", flush=True)
                return apply_compact_reason(cached, config), None, 0
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pass
        error = ""
        attempts = retries + 1
        for attempt in range(attempts):
            started = time.monotonic()
            try:
                with api_call_lock:
                    api_calls += 1
                response = client_for_thread().chat.completions.create(
                    model=config["model"], messages=[{"role": "user", "content": prompt}],
                    temperature=0, top_p=0.8, max_tokens=max_tokens, stream=False,
                    extra_body=qwen_extra_body(config["enable_thinking"]),
                )
                content = response.choices[0].message.content or ""
                parsed = validate_prediction(extract_json_object(content), records_by_id[record_id])
                usage = usage_dict(response)
                parsed["response_meta"] = {
                    "request_id": getattr(response, "id", None), "latency_seconds": round(time.monotonic() - started, 3),
                    "prompt_sha256": prompt_sha256,
                    "prompt_tokens": usage.get("prompt_tokens"),
                    "completion_tokens": usage.get("completion_tokens"),
                    "total_tokens": usage.get("total_tokens"),
                    "usage": usage,
                    "inference_source": "llm",
                }
                write_json(parsed_path, parsed)
                print(f"[OK] API {index}/{len(manifest)}: {record_id}", flush=True)
                return apply_compact_reason(parsed, config), None, 1
            except Exception as exc:  # Network/client exceptions vary by OpenAI SDK version.
                error = safe_exception(exc)
                if attempt < retries:
                    time.sleep(retry_sleep)
        failure = {"record_id": record_id, "pcap_id": records_by_id[record_id].get("pcap_id"), "error": error[:1000], "attempts": attempts}
        print(f"[FAIL] API {index}/{len(manifest)}: {record_id}: {error}", flush=True)
        return None, failure, 0

    indexed_manifest = list(enumerate(manifest, start=1))
    workers = int(config.get("max_api_workers") or 1)
    if workers <= 1:
        for index, entry in indexed_manifest:
            result, failure, _ = infer_one(index, entry)
            if result is not None:
                results.append(result)
            if failure is not None:
                failures.append(failure)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(infer_one, index, entry): entry for index, entry in indexed_manifest}
            for future in as_completed(futures):
                result, failure, _ = future.result()
                if result is not None:
                    results.append(result)
                if failure is not None:
                    failures.append(failure)
    order = {entry["record_id"]: index for index, entry in enumerate(manifest)}
    results.sort(key=lambda item: order[item["record_id"]])
    failures.sort(key=lambda item: order.get(item["record_id"], 10**9))
    return results, failures, api_calls


def routing_row(record: dict[str, Any], route: str, status: str, result: dict[str, Any] | None = None, reason: str = "") -> dict[str, Any]:
    technique = primary_rule_candidate(record)
    flags = routing_conflict_flags(record)
    meta = (result or {}).get("response_meta") or {}
    return {
        "record_id": record_identity(record),
        "pcap_id": record.get("pcap_id") or "",
        "record_type": record.get("record_type") or "",
        "route": route,
        "status": status,
        "inference_source": meta.get("inference_source") or route,
        "primary_rule_candidate": technique,
        "primary_rule_score": technique_score(record, technique) if technique else "",
        "score_margin": score_margin(record, technique) if technique else "",
        "evidence_strength": record.get("evidence_strength") or "",
        "conflict_count": len(flags),
        "conflict_flags": json_cell(flags),
        "reason": reason or (result or {}).get("reason") or "",
        "latency_seconds": meta.get("latency_seconds", ""),
    }


def write_routing_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ROUTING_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_inference_plan_report(config: dict[str, Any], paths: dict[str, Path], stats: dict[str, Any]) -> None:
    lines = [
        "# Inference Plan Report",
        "",
        f"- Total records in this run: {stats.get('total_records', 0)}",
        f"- Rule-direct records: {stats.get('rule_direct_count', 0)}",
        f"- LLM-routed records: {stats.get('llm_count', 0)}",
        f"- Failed records: {stats.get('failed_count', 0)}",
        f"- API workers: {config.get('max_api_workers', 1)}",
        f"- LLM routing mode: `{config.get('llm_routing', 'all')}`",
        f"- Estimated serial LLM days: {stats.get('estimated_llm_days_serial', 0)}",
        f"- Average live LLM latency seconds: {stats.get('average_latency', 0)}",
        f"- Actual throughput records/second: {stats.get('actual_throughput_records_per_second', 0)}",
        f"- Inference elapsed seconds: {stats.get('inference_elapsed_seconds', 0)}",
        "",
        "## Resume",
        "",
        f"- resumed_from_existing_predictions: `{str(stats.get('resumed_from_existing_predictions', False)).lower()}`",
        f"- skipped_completed: {stats.get('skipped_completed', 0)}",
        f"- remaining_to_infer: {stats.get('remaining_to_infer', 0)}",
        "",
        "## Shard",
        "",
        f"- num_shards: {config.get('num_shards', 1)}",
        f"- shard_index: {config.get('shard_index', 0)}",
        f"- pre_shard_records: {stats.get('pre_shard_records', stats.get('total_records', 0))}",
        f"- shard_records: {stats.get('shard_records', stats.get('total_records', 0))}",
        "",
        "## Routing Outputs",
        "",
        f"- routing_summary.csv: `{paths['routing_summary']}`",
        f"- failed_records.jsonl: `{config['output_dir'] / 'failed_records.jsonl'}`",
        "",
    ]
    paths["inference_plan_report"].write_text("\n".join(lines), encoding="utf-8")


def average_llm_latency(results: list[dict[str, Any]]) -> float:
    latencies = [
        number_value((item.get("response_meta") or {}).get("latency_seconds"), -1.0)
        for item in results
        if (item.get("response_meta") or {}).get("inference_source") == "llm"
    ]
    latencies = [value for value in latencies if value >= 0]
    return round(sum(latencies) / len(latencies), 3) if latencies else 0.0


def run_inference(
    config: dict[str, Any],
    paths: dict[str, Path],
    records: list[dict[str, Any]],
    manifest: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, dict[str, Any], list[dict[str, Any]]]:
    if config["dry_run"]:
        return [], [], 0, {
            "total_records": len(records),
            "rule_direct_count": 0,
            "llm_count": 0,
            "skipped_completed": 0,
            "remaining_to_infer": 0,
            "resumed_from_existing_predictions": False,
            "inference_elapsed_seconds": 0.0,
            "average_latency": 0.0,
            "actual_throughput_records_per_second": 0.0,
            "estimated_llm_days_serial": 0.0,
        }, []
    started = time.monotonic()
    record_order = {record_identity(record): index for index, record in enumerate(records)}
    record_by_id = {record_identity(record): record for record in records}
    manifest_by_id = {str(entry.get("record_id")): entry for entry in manifest}
    existing_by_id = load_existing_predictions(config["output_dir"] / "predictions.jsonl", records) if config.get("resume") else {}
    results_by_id: dict[str, dict[str, Any]] = {}
    routing_rows: list[dict[str, Any]] = []
    llm_records: list[dict[str, Any]] = []
    llm_manifest: list[dict[str, Any]] = []
    llm_route_reasons: dict[str, str] = {}
    pre_api_failures: list[dict[str, Any]] = []
    skipped_completed = 0
    rule_direct_count = 0
    routing_mode = config.get("llm_routing", "all")
    for record in records:
        record_id = record_identity(record)
        if record_id in existing_by_id:
            result = apply_compact_reason(existing_by_id[record_id], config)
            results_by_id[record_id] = result
            skipped_completed += 1
            routing_rows.append(routing_row(record, "resume", "skipped_completed", result))
            continue
        if routing_mode == "none":
            result = build_rule_direct_prediction(record, config, forced=True)
            results_by_id[record_id] = result
            rule_direct_count += 1
            routing_rows.append(routing_row(record, "rule_direct", "success", result, "llm_routing=none"))
            continue
        if routing_mode == "high-confidence-skip":
            allowed, decision_reason, _ = rule_direct_decision(record, config)
            if allowed:
                result = build_rule_direct_prediction(record, config)
                results_by_id[record_id] = result
                rule_direct_count += 1
                routing_rows.append(routing_row(record, "rule_direct", "success", result, decision_reason))
                continue
            llm_route_reasons[record_id] = decision_reason
        entry = manifest_by_id.get(record_id)
        if entry:
            llm_records.append(record)
            llm_manifest.append(entry)
        else:
            failure = {
                "record_id": record_id,
                "pcap_id": record.get("pcap_id"),
                "error": "missing prompt manifest entry",
                "attempts": 0,
            }
            pre_api_failures.append(failure)
            routing_rows.append(routing_row(record, "llm", "failed", None, failure["error"]))
    if llm_records:
        llm_results, api_failures, api_calls = run_api(config, paths, llm_records, llm_manifest)
    else:
        llm_results, api_failures, api_calls = [], [], 0
    failures = pre_api_failures + api_failures
    for result in llm_results:
        record_id = str(result.get("record_id") or "")
        results_by_id[record_id] = result
        record = record_by_id.get(record_id, {})
        routing_rows.append(routing_row(record, "llm", "success", result, llm_route_reasons.get(record_id, "")))
    for failure in api_failures:
        record_id = str(failure.get("record_id") or "")
        record = record_by_id.get(record_id, {})
        routing_rows.append(routing_row(record, "llm", "failed", None, llm_route_reasons.get(record_id) or str(failure.get("error") or "")))
    results = sorted(results_by_id.values(), key=lambda item: record_order.get(str(item.get("record_id")), 10**9))
    elapsed = round(time.monotonic() - started, 3)
    avg_latency = average_llm_latency(llm_results)
    estimate_latency = avg_latency or float(config.get("estimated_llm_latency") or 0.0)
    completed_or_failed = len(results) + len(failures)
    routing_rows.sort(key=lambda item: (record_order.get(str(item.get("record_id")), 10**9), str(item.get("status"))))
    stats = {
        "total_records": len(records),
        "rule_direct_count": rule_direct_count,
        "llm_count": len(llm_records),
        "llm_success_count": len(llm_results),
        "skipped_completed": skipped_completed,
        "remaining_to_infer": len(records) - skipped_completed,
        "resumed_from_existing_predictions": bool(existing_by_id),
        "failed_count": len(failures),
        "inference_elapsed_seconds": elapsed,
        "average_latency": avg_latency,
        "actual_throughput_records_per_second": round(completed_or_failed / elapsed, 4) if elapsed > 0 else 0.0,
        "estimated_llm_days_serial": round(len(llm_records) * estimate_latency / 86400, 4),
    }
    return results, failures, api_calls, stats, routing_rows


def official_rows(results: list[dict[str, Any]], record_to_pcap: dict[str, str]) -> list[dict[str, Any]]:
    rows = []
    for item in results:
        technique = item.get("technique_guess") or ""
        stage = item.get("stage_code") or stage_from_technique(technique)
        reason = item.get("reason") or ""
        pcap_name = record_to_pcap.get(item["record_id"], item.get("pcap_id") or "")
        rows.append({
            "pcap": pcap_name,
            "pcap_id": item.get("pcap_id") or "",
            "pcap_name": pcap_name,
            "record_id": item["record_id"],
            "record_type": item.get("record_type") or "",
            "编号": item["record_id"],
            "开始时间": item.get("start_time"), "结束时间": item.get("end_time"),
            "源IP": item.get("src_ip"), "源端口": item.get("src_port"),
            "目的IP": item.get("dst_ip"), "目的端口": item.get("dst_port"),
            STAGE_FIELD: stage, "stage_code": stage,
            "technique_guess": technique,
            "confidence": item.get("confidence"),
            REASON_FIELD: reason, "reason": reason,
        })
    return rows


def json_cell(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def write_candidate_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CANDIDATE_SCORE_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def prediction_technique(result: dict[str, Any] | None) -> str:
    if not result:
        return ""
    return str(result.get("technique_guess") or "").upper()


def candidate_conflict_flags(record: dict[str, Any], result: dict[str, Any] | None) -> list[str]:
    flags = list(record.get("rule_conflict_flags") or [])
    predicted = prediction_technique(result)
    predicted_stage = str((result or {}).get("stage_code") or stage_from_technique(predicted)).upper()
    primary = str(record.get("primary_rule_candidate") or "")
    scores = record.get("candidate_technique_scores") or {}
    attack_scores = [float(score or 0) for code, score in scores.items() if code != "TN01_01"]
    max_attack = max(attack_scores or [0.0])
    if result:
        if predicted and primary and predicted != primary:
            flags.append("model_prediction_differs_from_primary_rule_candidate")
        if predicted == "TN01_01" or predicted_stage == "TN01":
            if max_attack >= 3.0 and str(record.get("evidence_strength")) != "weak":
                flags.append("predicted_normal_with_attack_candidate")
        elif any("benign" in str(item).lower() or "download/chunk" in str(item).lower() for item in (record.get("candidate_counter_evidence") or {}).get(predicted, [])):
            flags.append("predicted_attack_with_benign_counter_evidence")
    return sorted(set(flags))


def build_critic_prompt(record: dict[str, Any], result: dict[str, Any] | None, flags: list[str]) -> str:
    payload = {
        "record_id": record.get("record_id"),
        "pcap_id": record.get("pcap_id"),
        "pcap_name": record.get("pcap_name") or record.get("pcap"),
        "primary_model_output": result or {},
        "top_rule_candidates": record.get("top_rule_candidates"),
        "candidate_evidence": record.get("candidate_evidence"),
        "candidate_counter_evidence": record.get("candidate_counter_evidence"),
        "candidate_weak_evidence": record.get("candidate_weak_evidence"),
        "rule_conflict_flags": flags,
    }
    return (
        "Review this Phase-1 PCAP-level classification conflict. Keep the model output unless the rule evidence and boundary logic clearly justify a revision.\n"
        "Return exactly one JSON object with keep_or_revise, final_technique_guess, final_stage_code, confidence, reason.\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
        + "\n"
    )


def write_candidate_diagnostics(
    config: dict[str, Any],
    paths: dict[str, Path],
    records: list[dict[str, Any]],
    results: list[dict[str, Any]],
    record_to_pcap: dict[str, str],
) -> dict[str, int]:
    result_by_id = {str(item.get("record_id")): item for item in results}
    rows: list[dict[str, Any]] = []
    conflict_rows: list[dict[str, Any]] = []
    if config.get("enable_critic"):
        paths["critic_prompts"].mkdir(parents=True, exist_ok=True)
        for old in paths["critic_prompts"].glob("*.txt"):
            old.unlink()
    for index, record in enumerate(records, start=1):
        record_id = str(record.get("record_id") or record.get("session_id") or "")
        result = result_by_id.get(record_id)
        predicted = prediction_technique(result)
        predicted_stage = str((result or {}).get("stage_code") or stage_from_technique(predicted)).upper()
        flags = candidate_conflict_flags(record, result)
        review_needed = bool(flags) and (bool(result) or config.get("enable_critic"))
        row = {
            "pcap_name": record_to_pcap.get(record_id, record.get("pcap_name") or record.get("pcap") or ""),
            "pcap_id": record.get("pcap_id") or "",
            "record_id": record_id,
            "record_type": record.get("record_type") or "",
            "primary_rule_candidate": record.get("primary_rule_candidate") or "",
            "top_rule_candidates": json_cell(record.get("top_rule_candidates")),
            "score_margin": record.get("score_margin"),
            "evidence_strength": record.get("evidence_strength") or "",
            "predicted_technique": predicted,
            "predicted_stage": predicted_stage,
            "confidence": (result or {}).get("confidence"),
            "conflict_review_needed": str(review_needed).lower(),
            "conflict_flags": json_cell(flags),
            "rule_evidence": json_cell(record.get("rule_evidence") or record.get("candidate_evidence")),
            "counter_evidence": json_cell(record.get("candidate_counter_evidence")),
        }
        rows.append(row)
        if review_needed:
            conflict = {**row, "primary_model_output": result or {}}
            conflict_rows.append(conflict)
            if config.get("enable_critic") and (not config.get("critic_only_on_conflict") or flags):
                prompt_path = paths["critic_prompts"] / f"{index:06d}_{hashlib.sha256(record_id.encode()).hexdigest()[:10]}.txt"
                prompt_path.write_text(build_critic_prompt(record, result, flags), encoding="utf-8")
    write_candidate_csv(paths["candidate_scores"], rows)
    write_jsonl(paths["conflict_cases"], conflict_rows)
    lines = [
        "# Candidate Score Report", "",
        f"- Records: {len(records)}",
        f"- Candidate rows: {len(rows)}",
        f"- Conflict review needed: {len(conflict_rows)}",
        f"- Critic prompt generation enabled: `{str(config.get('enable_critic')).lower()}`",
        "",
        "## Notes", "",
        "- Scores are deterministic evidence priors, not final labels.",
        "- Counter-evidence is preserved to support boundary review and reduce false positives.",
        "- `conflict_cases.jsonl` contains rows where score margin, weak evidence, benign counters, or model/rule disagreement deserve review.",
        "",
    ]
    paths["candidate_score_report"].write_text("\n".join(lines), encoding="utf-8")
    return {"candidate_rows": len(rows), "conflict_cases": len(conflict_rows)}


def safe_config_report(config: dict[str, Any]) -> dict[str, Any]:
    parsed_url = urlparse(config["base_url"])
    safe_netloc = parsed_url.hostname or ""
    if parsed_url.port:
        safe_netloc += f":{parsed_url.port}"
    safe_url = urlunparse((parsed_url.scheme, safe_netloc, parsed_url.path, "", "", ""))
    return {
        "input_dir": str(config["input_dir"]), "output_dir": str(config["output_dir"]),
        "base_url": safe_url, "model": config["model"], "api_key_configured": bool(config.get("api_key")),
        "answer_configured": bool(config.get("answer")), "granularity": config.get("granularity", "pcap"),
        "submission_label_level": config.get("submission_label_level", "stage"),
        "pcap_id_source": config.get("pcap_id_source", "pcap_id"),
        "submission_timezone": config.get("submission_timezone", "Asia/Shanghai"),
        "official_metadata_source": config.get("official_metadata_source", "representative"),
        "submission_template_configured": bool(config.get("submission_template")),
        "submission_template": str(config["submission_template"]) if config.get("submission_template") else "",
        "dry_run": config["dry_run"], "resume": config["resume"],
        "limit": config["limit"], "rag_top_k": config["rag_top_k"], "max_prompt_tokens": config["max_prompt_tokens"],
        "request_timeout": config["request_timeout"], "max_retries": config["max_retries"],
        "api_retries": config.get("api_retries", config.get("max_retries")),
        "api_retry_sleep": config.get("api_retry_sleep", 3.0),
        "max_api_workers": config.get("max_api_workers", 1),
        "num_shards": config.get("num_shards", 1),
        "shard_index": config.get("shard_index", 0),
        "llm_routing": config.get("llm_routing", "all"),
        "rule_direct_min_score": config.get("rule_direct_min_score", 7.0),
        "rule_direct_min_margin": config.get("rule_direct_min_margin", 2.5),
        "rule_direct_min_strength": config.get("rule_direct_min_strength", "strong"),
        "rule_direct_allow_normal": config.get("rule_direct_allow_normal", False),
        "rule_direct_max_conflicts": config.get("rule_direct_max_conflicts", 0),
        "max_completion_tokens": config.get("max_completion_tokens", 384),
        "compact_reason": config.get("compact_reason", False),
        "estimated_llm_latency": config.get("estimated_llm_latency", 32.8),
        "enable_thinking": config["enable_thinking"], "thinking_control": "chat_template_kwargs.enable_thinking",
        "prefer_zeek": config["prefer_zeek"], "allow_tshark_fallback": config["allow_tshark_fallback"],
        "enable_tshark_observable_supplement": config["enable_tshark_observable_supplement"],
        "zeek_docker_image": config.get("zeek_docker_image"),
        "save_prompt_samples": config["save_prompt_samples"], "prompt_sample_limit": config["prompt_sample_limit"],
        "enable_critic": config.get("enable_critic", False), "critic_only_on_conflict": config.get("critic_only_on_conflict", True),
        "prompt_version": PROMPT_VERSION,
    }


def write_summary(config: dict[str, Any], paths: dict[str, Path], stats: dict[str, Any]) -> None:
    lines = [
        "# Phase-1 VM Run Summary", "",
        f"- Status: `{stats['status']}`", f"- Finished at: `{utc_now()}`",
        f"- Dry-run: `{str(config['dry_run']).lower()}`", f"- Resume: `{str(config['resume']).lower()}`",
        f"- Granularity: `{config.get('granularity', 'pcap')}`",
        f"- Input PCAPs: {stats.get('pcaps', 0)}",
        f"- Source session cards: {stats.get('source_session_cards', 0)}",
        f"- Source classification records: {stats.get('source_classification_records', 0)}",
        f"- PCAP-level records: {stats.get('pcap_level_records', 0)}",
        f"- Classification records selected for prompting: {stats.get('records', 0)}",
        f"- Prompts built: {stats.get('prompts', 0)}", f"- Predictions: {stats.get('predictions', 0)}",
        f"- Official submission rows: {stats.get('official_submission_rows', 0)}",
        f"- Official submission XLSX written: `{str(stats.get('official_xlsx_written', False)).lower()}`",
        f"- Candidate score rows: {stats.get('candidate_rows', 0)}", f"- Conflict cases: {stats.get('conflict_cases', 0)}",
        f"- Failed records: {stats.get('failures', 0)}", f"- API requests attempted: {stats.get('api_calls', 0)}",
        f"- API workers: {config.get('max_api_workers', 1)}",
        f"- LLM routing mode: `{config.get('llm_routing', 'all')}`",
        f"- Rule-direct predictions: {stats.get('rule_direct_count', 0)}",
        f"- LLM-routed records: {stats.get('llm_count', 0)}",
        f"- Resumed from existing predictions: `{str(stats.get('resumed_from_existing_predictions', False)).lower()}`",
        f"- Skipped completed predictions: {stats.get('skipped_completed', 0)}",
        f"- Remaining to infer after resume: {stats.get('remaining_to_infer', 0)}",
        f"- Shard: {stats.get('shard_index', config.get('shard_index', 0))}/{stats.get('num_shards', config.get('num_shards', 1))}",
        f"- Prompt profile: `{PROMPT_VERSION}`", f"- Maximum estimated prompt tokens: {stats.get('max_prompt_tokens', 0)} / {config['max_prompt_tokens']}",
        f"- Prompts with RAG context: {stats.get('prompts_with_rag', 0)}", "",
        "## Model request controls", "",
        f"- enable_thinking: `{str(config['enable_thinking']).lower()}`",
        "- thinking_control: `chat_template_kwargs.enable_thinking`", "",
        "## Inference routing controls", "",
        f"- max_api_workers: {config.get('max_api_workers', 1)}",
        f"- api_retries: {config.get('api_retries', config.get('max_retries'))}",
        f"- api_retry_sleep: {config.get('api_retry_sleep', 3.0)}",
        f"- llm_routing: `{config.get('llm_routing', 'all')}`",
        f"- rule_direct_min_score: {config.get('rule_direct_min_score', 7.0)}",
        f"- rule_direct_min_margin: {config.get('rule_direct_min_margin', 2.5)}",
        f"- rule_direct_min_strength: `{config.get('rule_direct_min_strength', 'strong')}`",
        f"- rule_direct_allow_normal: `{str(config.get('rule_direct_allow_normal', False)).lower()}`",
        f"- rule_direct_max_conflicts: {config.get('rule_direct_max_conflicts', 0)}",
        f"- max_completion_tokens: {config.get('max_completion_tokens', 384)}",
        f"- compact_reason: `{str(config.get('compact_reason', False)).lower()}`",
        f"- num_shards: {config.get('num_shards', 1)}",
        f"- shard_index: {config.get('shard_index', 0)}",
        f"- inference_plan_report: `{paths['inference_plan_report']}`",
        f"- routing_summary_csv: `{paths['routing_summary']}`", "",
        "## Critic controls", "",
        f"- enable_critic: `{str(config.get('enable_critic', False)).lower()}`",
        f"- critic_only_on_conflict: `{str(config.get('critic_only_on_conflict', True)).lower()}`", "",
        "## Submission export controls", "",
        f"- submission_label_level: `{config.get('submission_label_level', 'stage')}`",
        f"- pcap_id_source: `{config.get('pcap_id_source', 'pcap_id')}`",
        f"- submission_timezone: `{config.get('submission_timezone', 'Asia/Shanghai')}`",
        f"- official_metadata_source: `{config.get('official_metadata_source', 'representative')}`",
        f"- submission_template_used: `{str(bool(config.get('submission_template'))).lower()}`",
        f"- submission_template: `{config.get('submission_template') or ''}`",
        f"- official_submission_csv: `{paths['official_submission_csv']}`",
        f"- official_submission_xlsx: `{paths['official_submission_xlsx']}`", "",
        "## Parser controls", "",
        f"- prefer_zeek: `{str(config['prefer_zeek']).lower()}`",
        f"- allow_tshark_fallback: `{str(config['allow_tshark_fallback']).lower()}`",
        f"- enable_tshark_observable_supplement: `{str(config['enable_tshark_observable_supplement']).lower()}`",
        f"- zeek_docker_image: `{config.get('zeek_docker_image') or ''}`", "",
        "## Safety boundaries", "",
        "- Answer data was not loaded before prompt generation or inference.",
        "- No raw model response body is persisted; only validated JSON and response metadata are stored.",
        "- API credentials are omitted from logs and generated configuration reports.", "",
        "## Primary outputs", "",
        "- `official_submission.csv`", "- `official_submission.xlsx`",
        "- `phase1_predictions.csv`", "- `predictions.jsonl`", "- `failed_records.jsonl`",
        "- `routing_summary.csv`", "- `inference_plan_report.md`",
        "- `parse_errors.jsonl`", "- `candidate_scores.csv`", "- `candidate_score_report.md`",
        "- `conflict_cases.jsonl`", "- `prompt_samples/`", "- `prompts/prompt_manifest.json`", "",
    ]
    if config["dry_run"]:
        lines.extend(["Dry-run stopped before API initialization. Prediction files contain no fabricated rows.", ""])
    (config["output_dir"] / "run_summary.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    config = effective_config(args)
    pcaps = validate_config(config)
    output = config["output_dir"]
    output.mkdir(parents=True, exist_ok=True)
    paths = step_paths(output)
    write_json(output / "config_effective.json", safe_config_report(config))
    state = {"started_at": utc_now(), "status": "running", "dry_run": config["dry_run"], "granularity": config["granularity"], "steps": {}}
    write_json(output / "run_state.json", state)
    stats: dict[str, Any] = {
        "pcaps": len(pcaps), "records": 0, "source_session_cards": 0,
        "source_classification_records": 0, "pcap_level_records": 0,
        "prompts": 0, "predictions": 0, "failures": 0, "api_calls": 0,
        "rule_direct_count": 0, "llm_count": 0, "skipped_completed": 0, "remaining_to_infer": 0,
        "resumed_from_existing_predictions": False,
        "pre_shard_records": 0, "num_shards": config.get("num_shards", 1), "shard_index": config.get("shard_index", 0), "shard_records": 0,
        "candidate_rows": 0, "conflict_cases": 0,
        "official_submission_rows": 0, "official_xlsx_written": False,
    }
    try:
        records, _, record_to_pcap, evidence_stats = prepare_evidence(config, paths, pcaps)
        stats.update(evidence_stats)
        records, record_to_pcap, shard_stats = apply_configured_shard(config, paths, records, record_to_pcap)
        stats.update(shard_stats)
        stats["records"] = len(records)
        state["steps"]["evidence"] = "complete"
        write_json(output / "run_state.json", state)
        retrieval = prepare_rag(config, paths, len(records))
        state["steps"]["rag"] = "complete"
        manifest = prepare_prompts(config, paths, records, retrieval)
        stats["prompts"] = len(manifest)
        stats["max_prompt_tokens"] = max((item["estimated_prompt_tokens"] for item in manifest), default=0)
        stats["prompts_with_rag"] = sum(item["rag_chunks_included"] > 0 for item in manifest)
        state["steps"]["prompts"] = "complete"
        write_json(output / "run_state.json", state)
        results, failures, api_calls, inference_stats, routing_rows = run_inference(config, paths, records, manifest)
        stats.update(inference_stats)
        stats.update({"predictions": len(results), "failures": len(failures), "api_calls": api_calls})
        write_jsonl(output / "predictions.jsonl", results)
        write_jsonl(output / "failed_records.jsonl", failures)
        write_routing_csv(paths["routing_summary"], routing_rows)
        write_inference_plan_report(config, paths, stats)
        write_csv(output / "phase1_predictions.csv", official_rows(results, record_to_pcap))
        export_stats = export_official_submission(
            predictions=results,
            records_json=paths["selected"],
            parse_summary=paths["parse_summary"],
            submission_template=config.get("submission_template"),
            output_csv=paths["official_submission_csv"],
            output_xlsx=paths["official_submission_xlsx"],
            submission_label_level=config["submission_label_level"],
            pcap_id_source=config["pcap_id_source"],
            submission_timezone=config["submission_timezone"],
            official_metadata_source=config["official_metadata_source"],
        )
        stats["official_submission_rows"] = export_stats["rows"]
        stats["official_xlsx_written"] = export_stats["xlsx_written"]
        stats.update(write_candidate_diagnostics(config, paths, records, results, record_to_pcap))
        state["steps"]["api"] = "skipped_dry_run" if config["dry_run"] else "complete"
        state["steps"]["candidate_diagnostics"] = "complete"
        state["steps"]["export"] = "complete"
        if config.get("answer") and not config["dry_run"]:
            run_command("evaluate predictions after inference", [
                sys.executable, str(ROOT / "scripts/evaluate_phase1_predictions.py"),
                "--predictions", str(output / "phase1_predictions.csv"), "--answer", str(config["answer"]),
                "--output-dir", str(output), "--predictions-jsonl", str(output / "predictions.jsonl"),
            ])
            state["steps"]["evaluation"] = "complete"
        elif config.get("answer"):
            state["steps"]["evaluation"] = "skipped_dry_run"
        stats["status"] = "prompts_ready_no_api" if config["dry_run"] else ("partial_failure" if failures else "complete")
        state.update({"finished_at": utc_now(), "status": stats["status"]})
        write_json(output / "run_state.json", state)
        write_summary(config, paths, stats)
        print(f"[DONE] status={stats['status']} output={output}", flush=True)
        return 2 if failures else 0
    except Exception as exc:
        state.update({"finished_at": utc_now(), "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        write_json(output / "run_state.json", state)
        stats["status"] = "failed"
        write_summary(config, paths, stats)
        print(f"[ERROR] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
