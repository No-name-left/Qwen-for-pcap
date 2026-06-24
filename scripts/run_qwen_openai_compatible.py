#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from openai import OpenAI

from qwen35_rag_utils import DEFAULT_RUNTIME_PROFILES, ROOT, load_env_file, load_runtime_profile, strip_markdown_fence


TECHNIQUE_CODES = {"TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"}


class ModelOutputParseError(ValueError):
    pass


class ModelResultValidationError(ValueError):
    pass


class ThinkingModeError(RuntimeError):
    pass


def load_config(path: Path) -> dict:
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {}


def cfg_value(cfg: dict, key: str):
    value = cfg.get(key)
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        return os.environ.get(value[2:-1])
    return value


def nested_cfg_value(cfg: dict, section: str, key: str):
    value = cfg.get(section, {})
    if isinstance(value, dict):
        return value.get(key)
    return None


def env_from_config(cfg: dict, section: str, key: str):
    env_name = nested_cfg_value(cfg, section, key) or cfg.get(key)
    if env_name:
        return os.environ.get(env_name)
    return None


def api_key_from_env(cfg: dict):
    return (
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("API_KEY")
        or os.environ.get("LLM_API_KEY")
        or env_from_config(cfg, "provider", "api_key_env")
        or os.environ.get("HF_TOKEN")
        or os.environ.get("HUGGINGFACEHUB_API_TOKEN")
    )


def parse_json_objects(text: str) -> list[dict[str, Any]]:
    cleaned = text.strip()
    if "</think>" in cleaned:
        cleaned = cleaned.rsplit("</think>", 1)[1].strip()
    cleaned = strip_markdown_fence(cleaned)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        parsed = None
        decoder = json.JSONDecoder()
        for idx, char in enumerate(cleaned):
            if char not in "[{":
                continue
            try:
                candidate, _ = decoder.raw_decode(cleaned[idx:])
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict) or (
                isinstance(candidate, list) and all(isinstance(item, dict) for item in candidate)
            ):
                parsed = candidate
                break
        if parsed is None:
            raise ModelOutputParseError("no JSON object or object array found in model output")
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and all(isinstance(item, dict) for item in parsed):
        return parsed
    raise ModelOutputParseError("model output is JSON but not an object or object array")


def validate_technique_results(results: list[dict[str, Any]], expected_record_id: str) -> list[dict[str, Any]]:
    if len(results) != 1:
        raise ModelResultValidationError(f"expected exactly one result object, got {len(results)}")
    item = dict(results[0])
    record_id = item.get("record_id")
    if not isinstance(record_id, str) or not record_id.strip():
        raise ModelResultValidationError("record_id is required and must be a non-empty string")
    if record_id != expected_record_id:
        raise ModelResultValidationError(f"record_id mismatch: expected `{expected_record_id}`, got `{record_id}`")
    code = item.get("predicted_code") or item.get("technique_code")
    if code not in TECHNIQUE_CODES:
        raise ModelResultValidationError(f"invalid technique code `{code}`")
    confidence = item.get("confidence")
    if confidence is not None and (
        not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1
    ):
        raise ModelResultValidationError(f"invalid confidence `{confidence}`")
    reason = item.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise ModelResultValidationError("reason must be a string when present")
    item["predicted_code"] = code
    item.pop("technique_code", None)
    return [item]


def extract_record_id_from_prompt(prompt_text: str, fallback: str) -> str:
    marker = "CLASSIFICATION_RECORD:"
    if marker not in prompt_text:
        return fallback
    payload = prompt_text.split(marker, 1)[1].strip()
    try:
        record, _ = json.JSONDecoder().raw_decode(payload)
    except json.JSONDecodeError:
        return fallback
    if isinstance(record, dict):
        return str(record.get("record_id") or record.get("session_id") or fallback)
    return fallback


def extract_prompt_version(prompt_text: str) -> str:
    prefix = "PROMPT_VERSION:"
    for line in prompt_text.splitlines()[:5]:
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip()
    return "unknown"


def usage_dict(response: Any) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    if hasattr(usage, "model_dump"):
        return usage.model_dump()
    return {
        key: getattr(usage, key)
        for key in ("prompt_tokens", "completion_tokens", "total_tokens")
        if getattr(usage, key, None) is not None
    }


def extract_record_from_prompt(prompt_text: str) -> dict[str, Any]:
    marker = "CLASSIFICATION_RECORD:"
    if marker not in prompt_text:
        return {}
    try:
        value, _ = json.JSONDecoder().raw_decode(prompt_text.split(marker, 1)[1].strip())
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def mock_result(prompt_text: str, record_id: str) -> dict[str, Any]:
    """Deterministic smoke output; intentionally not a model-quality baseline."""
    record = extract_record_from_prompt(prompt_text)
    blob = json.dumps(record, ensure_ascii=False).lower()
    if record.get("record_type") == "scan_group" or float(record.get("unique_dst_ports") or 0) >= 8:
        code = "TA43_01"
    elif any(word in blob for word in ("bruteforce", "brute force", "ftp-bruteforce", "ssh-bruteforce")):
        code = "TA01_01"
    elif any(word in blob for word in ("sql injection", "command injection", "cve-", "../")):
        code = "TA01_02"
    elif any(word in blob for word in ("callback", "botnet", "beacon", "c2", "cnc")):
        code = "TA11_02"
    else:
        code = "TN01_01"
    return {
        "record_id": record_id,
        "pcap_id": record.get("pcap_id"),
        "record_type": record.get("record_type", "session"),
        "start_time": record.get("start_time"), "end_time": record.get("end_time"),
        "src_ip": record.get("src_ip"), "src_port": record.get("src_port"),
        "dst_ip": record.get("dst_ip"), "dst_port": record.get("dst_port"),
        "predicted_code": code, "confidence": 0.5,
        "reason": "Deterministic dry-run mock for pipeline validation.",
    }


def load_record_id_filter(value: str | None) -> set[str] | None:
    if not value:
        return None
    path = Path(value)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for key in ("record_ids", "failed_records", "records"):
                if key in data:
                    data = data[key]
                    break
        if not isinstance(data, list):
            raise ValueError(f"--only-record-ids file must contain a list or known list field: {path}")
        out: set[str] = set()
        for item in data:
            if isinstance(item, dict):
                rid = item.get("record_id") or item.get("session_id")
            else:
                rid = item
            if rid:
                out.add(str(rid))
        return out
    return {item.strip() for item in value.split(",") if item.strip()}


def load_existing_parsed_results(parsed_dir: Path, result_path: Path) -> dict[str, dict[str, Any]]:
    existing: dict[str, dict[str, Any]] = {}
    candidates = sorted(parsed_dir.glob("*.json"))
    if result_path.exists():
        candidates.append(result_path)
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            rid = item.get("record_id") or item.get("session_id")
            if rid:
                existing[str(rid)] = item
    return existing


def error_code(error: str) -> str | None:
    for code in ("401", "402", "403", "408", "429", "500", "502", "503", "504"):
        if code in error:
            return code
    return None


def classify_error(error: str, exc_type: str = "") -> str:
    low = f"{exc_type} {error}".lower()
    if "401" in low or "unauthorized" in low:
        return "401 unauthorized"
    if "402" in low or "quota" in low or "payment required" in low:
        return "402 quota depleted"
    if "429" in low or "rate limit" in low or "too many requests" in low:
        return "429 rate limit"
    if "timed out" in low or "timeout" in low:
        return "timeout"
    if "modeloutputparseerror" in low or "jsondecodeerror" in low or "no json object" in low:
        return "JSON parse failure"
    if "modelresultvalidationerror" in low or "invalid technique code" in low or "record_id mismatch" in low:
        return "result validation failure"
    if "thinkingmodeerror" in low or "thinking disabled but provider reported" in low:
        return "thinking mode policy failure"
    if "empty" in low:
        return "empty response"
    if any(code in low for code in ("500", "502", "503", "504")):
        return "provider error"
    return "unknown"


def safe_host(base_url: str) -> str:
    parsed = urlparse(base_url)
    return parsed.netloc or base_url.split("/")[0]


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def parse_bool(value: str | bool | None, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Qwen/OpenAI-compatible batch prompts.")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/llm_qwen35_27b.yaml")
    parser.add_argument("--runtime-profiles", type=Path, default=DEFAULT_RUNTIME_PROFILES)
    parser.add_argument("--runtime-profile", default=os.environ.get("RUNTIME_PROFILE", "ascend_openeuler_qwen35_27b"))
    parser.add_argument("--prompt-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--result-name", required=True)
    parser.add_argument("--summary-name", required=True)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--max-files", type=int)
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--max-tokens", type=int)
    parser.add_argument("--timeout-seconds", type=float)
    parser.add_argument("--sleep-seconds", type=float, default=0.0)
    parser.add_argument("--enable-thinking", choices=["true", "false"], help="Qwen chat-template thinking mode; default false.")
    parser.add_argument("--disable-extra-body", action="store_true", help="Do not send chat_template_kwargs (for providers that reject extra_body).")
    parser.add_argument("--require-run-api-flag", action="store_true")
    parser.add_argument("--retry-failed-once", action="store_true")
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--failed-records-out", type=Path)
    parser.add_argument("--only-record-ids")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    load_env_file(ROOT / ".env")
    load_env_file(ROOT / ".env.local")
    cfg = load_config(args.config)
    profile = load_runtime_profile(args.runtime_profile, args.runtime_profiles)
    mock_mode = bool(profile.get("mock", False))
    generation = cfg.get("generation", {}) if isinstance(cfg.get("generation"), dict) else {}
    base_url = profile.get("base_url") if mock_mode else (
        os.environ.get("OPENAI_BASE_URL")
        or os.environ.get("BASE_URL")
        or os.environ.get("LLM_BASE_URL")
        or env_from_config(cfg, "provider", "base_url_env")
        or profile.get("base_url")
        or cfg_value(cfg, "base_url")
    )
    api_key = api_key_from_env(cfg)
    model = profile.get("model") if mock_mode else (
        os.environ.get("OPENAI_MODEL")
        or os.environ.get("MODEL")
        or os.environ.get("LLM_MODEL_NAME")
        or env_from_config(cfg, "provider", "model_name_env")
        or profile.get("model")
        or cfg_value(cfg, "model_name")
    )
    temperature = args.temperature if args.temperature is not None else float(os.environ.get("LLM_TEMPERATURE", generation.get("temperature", cfg.get("temperature", 0.1))))
    max_tokens = args.max_tokens if args.max_tokens is not None else int(os.environ.get("LLM_MAX_TOKENS", profile.get("max_output_tokens", generation.get("max_tokens", cfg.get("max_tokens", 512)))))
    top_p = float(os.environ.get("LLM_TOP_P", generation.get("top_p", cfg.get("top_p", 0.8))))
    enable_thinking = parse_bool(
        args.enable_thinking
        if args.enable_thinking is not None
        else os.environ.get("ENABLE_THINKING", os.environ.get("LLM_ENABLE_THINKING")),
        default=parse_bool(profile.get("enable_thinking", generation.get("enable_thinking")), default=False),
    )
    send_extra_body = not args.disable_extra_body and parse_bool(
        os.environ.get("LLM_SEND_EXTRA_BODY"), default=bool(profile.get("send_extra_body", generation.get("send_extra_body", True)))
    )
    if args.require_run_api_flag and os.environ.get("RUN_API") != "1":
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / args.summary_name).write_text(
            "# Qwen3.5-27B run summary\n\nStatus: not_started\n\n- Missing required `RUN_API=1`; no model call was made.\n",
            encoding="utf-8",
        )
        print("missing RUN_API=1; no call made")
        return 2
    if not base_url or not model or (not api_key and not mock_mode):
        args.output_dir.mkdir(parents=True, exist_ok=True)
        summary = args.output_dir / args.summary_name
        summary.write_text(
            "# Qwen3.5-27B run summary\n\n"
            "Status: not_started\n\n"
            "Missing API configuration. Set:\n\n"
            "- `OPENAI_API_KEY`, `API_KEY`, or `LLM_API_KEY`\n"
            "- `OPENAI_BASE_URL`, `BASE_URL`, or `LLM_BASE_URL`\n"
            "- `OPENAI_MODEL`, `MODEL`, or `LLM_MODEL_NAME`\n\n"
            "No model call was made and no result was fabricated.\n",
            encoding="utf-8",
        )
        print("missing API configuration; set BASE_URL/MODEL/API_KEY (or LLM_* aliases); no call made")
        return 2
    if args.retry_failed_once:
        args.retries = max(args.retries, 1)
    record_id_filter = load_record_id_filter(args.only_record_ids)
    prompt_items = []
    for prompt_path in sorted(args.prompt_dir.glob("*.txt")):
        prompt_text = prompt_path.read_text(encoding="utf-8")
        record_id = extract_record_id_from_prompt(prompt_text, prompt_path.stem)
        if record_id_filter is None or record_id in record_id_filter:
            prompt_items.append((prompt_path, record_id, prompt_text))
    prompts = prompt_items
    if args.max_files is not None:
        prompts = prompts[: args.max_files]
    if not prompts:
        raise FileNotFoundError(f"no prompt files in {args.prompt_dir}")
    request_timeout = args.timeout_seconds if args.timeout_seconds is not None else float(
        os.environ.get("LLM_REQUEST_TIMEOUT", generation.get("request_timeout_seconds", cfg.get("request_timeout", 180)))
    )
    client = None if mock_mode else OpenAI(base_url=base_url, api_key=api_key, timeout=request_timeout)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = args.output_dir / "raw"
    parsed_dir = args.output_dir / "parsed"
    raw_dir.mkdir(parents=True, exist_ok=True)
    parsed_dir.mkdir(parents=True, exist_ok=True)
    result_path = args.output_dir / args.result_name
    existing_results: dict[str, dict[str, Any]] = {}
    existing_status: dict[str, dict[str, Any]] = {}
    if args.resume:
        loaded_existing = load_existing_parsed_results(parsed_dir, result_path)
        stats_path = args.output_dir / "run_stats.json"
        if stats_path.exists():
            try:
                prior_stats = json.loads(stats_path.read_text(encoding="utf-8"))
                existing_status = {row["record_id"]: row for row in prior_stats.get("rows", []) if row.get("record_id")}
            except (json.JSONDecodeError, OSError):
                existing_status = {}
        prompt_record_ids = {record_id for _, record_id, _ in prompts}
        for record_id, item in loaded_existing.items():
            if record_id not in prompt_record_ids:
                continue
            try:
                existing_results[record_id] = validate_technique_results([item], record_id)[0]
            except ModelResultValidationError:
                continue
    all_results = list(existing_results.values())
    rows = []
    json_parse_failures = 0
    invalid_code_count = 0
    validation_failure_count = 0
    error_counts: dict[str, int] = {}
    failed_records: list[dict[str, Any]] = []
    stop_after_batch = False
    api_calls_attempted = 0
    for idx, (prompt_path, record_id, prompt_text) in enumerate(prompts, start=1):
        raw_path = raw_dir / f"raw_batch_{idx:03d}.txt"
        error_path = raw_dir / f"error_batch_{idx:03d}.txt"
        parsed_path = parsed_dir / f"parsed_batch_{idx:03d}.json"
        if args.resume and record_id in existing_results:
            prior = existing_status.get(record_id, {})
            rows.append({
                "batch": idx,
                "record_id": record_id,
                "prompt": display_path(prompt_path),
                "prompt_version": extract_prompt_version(prompt_text),
                "status": "skipped_existing",
                "error": "",
                "error_category": "",
                "records": 1,
                "invalid_codes": 0,
                "parse_success": True,
                "valid_label": True,
                "attempts_made": prior.get("attempts_made", 0),
                "latency_seconds": prior.get("latency_seconds"),
                "request_id": prior.get("request_id"),
                "response_id": prior.get("response_id"),
                "usage": prior.get("usage", {}),
            })
            continue
        status = "failed"
        error = ""
        content = ""
        records = 0
        invalid_codes_for_batch = 0
        parse_success = False
        valid_label = False
        attempts_made = 0
        latency_seconds = 0.0
        request_id = None
        response_id = None
        usage: dict[str, Any] = {}
        for attempt in range(args.retries + 1):
            attempts_made += 1
            attempt_started = time.perf_counter()
            try:
                if mock_mode:
                    content = json.dumps(mock_result(prompt_text, record_id), ensure_ascii=False)
                else:
                    api_calls_attempted += 1
                    request_kwargs: dict[str, Any] = {
                        "model": model,
                        "messages": [{"role": "user", "content": prompt_text}],
                        "temperature": temperature,
                        "top_p": top_p,
                        "max_tokens": max_tokens,
                        "stream": False,
                    }
                    if send_extra_body:
                        request_kwargs["extra_body"] = {
                            "chat_template_kwargs": {"enable_thinking": enable_thinking}
                        }
                    response = client.chat.completions.create(**request_kwargs)
                    content = response.choices[0].message.content or ""
                    request_id = getattr(response, "_request_id", None) or getattr(response, "id", None)
                    response_id = getattr(response, "id", None)
                    usage = usage_dict(response)
                    reasoning_tokens = int((usage.get("completion_tokens_details") or {}).get("reasoning_tokens") or 0)
                    if not enable_thinking and reasoning_tokens:
                        raise ThinkingModeError(
                            f"thinking disabled but provider reported {reasoning_tokens} reasoning tokens"
                        )
                raw_path.write_text(content, encoding="utf-8")
                (raw_dir / f"raw_batch_{idx:03d}_attempt_{attempt + 1:02d}.txt").write_text(content, encoding="utf-8")
                parsed = parse_json_objects(content)
                parse_success = True
                parsed = validate_technique_results(parsed, record_id)
                valid_label = True
                parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                all_results.extend(parsed)
                records = len(parsed)
                status = "success"
                latency_seconds += time.perf_counter() - attempt_started
                break
            except Exception as exc:
                latency_seconds += time.perf_counter() - attempt_started
                request_id = request_id or getattr(exc, "request_id", None)
                error = str(exc)
                category = classify_error(error, type(exc).__name__)
                error_path.write_text(f"ERROR: {type(exc).__name__}: {error}\n", encoding="utf-8")
                final_attempt = attempt == args.retries or isinstance(exc, ThinkingModeError)
                if final_attempt:
                    if isinstance(exc, (json.JSONDecodeError, ModelOutputParseError)):
                        json_parse_failures += 1
                    if isinstance(exc, ModelResultValidationError) and "invalid technique code" in error:
                        invalid_codes_for_batch = 1
                        invalid_code_count += 1
                    if isinstance(exc, ModelResultValidationError):
                        validation_failure_count += 1
                    code = error_code(error)
                    if code:
                        error_counts[code] = error_counts.get(code, 0) + 1
                    failed_records.append({
                        "record_id": record_id,
                        "prompt": display_path(prompt_path),
                        "batch": idx,
                        "error_category": category,
                        "error": error,
                    })
                    if category in {"401 unauthorized", "402 quota depleted"}:
                        stop_after_batch = True
                    if isinstance(exc, ThinkingModeError):
                        stop_after_batch = True
                    break
                time.sleep(2 * (attempt + 1))
        rows.append({
            "batch": idx,
            "record_id": record_id,
            "prompt": display_path(prompt_path),
            "prompt_version": extract_prompt_version(prompt_text),
            "status": status,
            "error": error,
            "error_category": classify_error(error) if error else "",
            "records": records,
            "invalid_codes": invalid_codes_for_batch,
            "parse_success": parse_success,
            "valid_label": valid_label,
            "attempts_made": attempts_made,
            "latency_seconds": round(latency_seconds, 6),
            "request_id": request_id,
            "response_id": response_id,
            "usage": usage,
        })
        summary_path = args.output_dir / args.summary_name
        lines = [
            "# Qwen3.5-27B run summary",
            "",
            f"- Model: `{model}`",
            f"- Runtime profile: `{args.runtime_profile}`",
            f"- Mock mode: {str(mock_mode).lower()}",
            f"- Base URL host: `{safe_host(base_url)}`",
            f"- Request timeout seconds: {request_timeout}",
            f"- Enable thinking: {str(enable_thinking).lower()}",
            f"- Extra body sent: {str(send_extra_body).lower()}",
            f"- Max files: {args.max_files if args.max_files is not None else 'all'}",
            f"- Batches observed so far: {len(rows)}",
            f"- Successful batches so far: {sum(1 for r in rows if r['status']=='success')}",
            f"- Skipped existing batches so far: {sum(1 for r in rows if r['status']=='skipped_existing')}",
            f"- Failed batches so far: {sum(1 for r in rows if r['status'] not in {'success', 'skipped_existing'})}",
            f"- JSON parse failures so far: {json_parse_failures}",
            f"- Invalid code count so far: {invalid_code_count}",
            f"- Result validation failures so far: {validation_failure_count}",
            f"- HTTP/API error counts so far: `{json.dumps(error_counts, sort_keys=True)}`",
            "",
        ]
        for row in rows:
            lines.append(f"- batch_{row['batch']:03d}: {row['status']}; record_id=`{row['record_id']}`; prompt=`{row['prompt']}`; records={row['records']}; invalid_codes={row['invalid_codes']}")
            if row["error"] and row["status"] != "success":
                lines.append(f"  error_category: {row['error_category']}")
                lines.append(f"  error: {row['error']}")
        summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        if stop_after_batch or (status != "success" and not args.continue_on_error):
            break
        if args.sleep_seconds > 0 and idx < len(prompts):
            time.sleep(args.sleep_seconds)
    if all_results:
        result_path.write_text(json.dumps(all_results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary_path = args.output_dir / args.summary_name
    stats = {
        "batches": len(rows),
        "success": sum(1 for r in rows if r["status"] == "success"),
        "failed": sum(1 for r in rows if r["status"] not in {"success", "skipped_existing"}),
        "skipped_existing": sum(1 for r in rows if r["status"] == "skipped_existing"),
        "api_calls_attempted": api_calls_attempted,
        "runtime_profile": args.runtime_profile,
        "mock_mode": mock_mode,
        "json_parse_failures": json_parse_failures,
        "invalid_code_count": invalid_code_count,
        "validation_failure_count": validation_failure_count,
        "error_counts": error_counts,
        "records": len(all_results),
        "rows": rows,
        "failed_records": failed_records,
    }
    (args.output_dir / "run_stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.failed_records_out:
        args.failed_records_out.parent.mkdir(parents=True, exist_ok=True)
        args.failed_records_out.write_text(json.dumps(failed_records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Qwen3.5-27B run summary",
        "",
        f"- Model: `{model}`",
        f"- Runtime profile: `{args.runtime_profile}`",
        f"- Mock mode: {str(mock_mode).lower()}",
        f"- Base URL host: `{safe_host(base_url)}`",
        f"- Enable thinking: {str(enable_thinking).lower()}",
        f"- Extra body sent: {str(send_extra_body).lower()}",
        f"- Batches: {len(rows)}",
        f"- Successful batches: {stats['success']}",
        f"- Skipped existing batches: {stats['skipped_existing']}",
        f"- Failed batches: {stats['failed']}",
        f"- API calls attempted: {api_calls_attempted}",
        f"- JSON parse failures: {json_parse_failures}",
        f"- Invalid code count: {invalid_code_count}",
        f"- Result validation failures: {validation_failure_count}",
        f"- HTTP/API error counts: `{json.dumps(error_counts, sort_keys=True)}`",
        "",
    ]
    for row in rows:
        lines.append(f"- batch_{row['batch']:03d}: {row['status']}; record_id=`{row['record_id']}`; prompt=`{row['prompt']}`; records={row['records']}; invalid_codes={row['invalid_codes']}")
        if row["error"] and row["status"] != "success":
            lines.append(f"  error_category: {row['error_category']}")
            lines.append(f"  error: {row['error']}")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(all_results)} parsed records")
    return 0 if all(r["status"] in {"success", "skipped_existing"} for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
