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

from qwen35_rag_utils import ROOT, parse_json_array, strip_markdown_fence, validate_llm_results


STAGE_CODES = {"TA43", "TA01", "TA03", "TA11", "TN01"}
TECHNIQUE_CODES = {"TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"}


def load_config(path: Path) -> dict:
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {}


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


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
        os.environ.get("LLM_API_KEY")
        or env_from_config(cfg, "provider", "api_key_env")
        or os.environ.get("HF_TOKEN")
        or os.environ.get("HUGGINGFACEHUB_API_TOKEN")
    )


def parse_json_objects(text: str) -> list[dict[str, Any]]:
    cleaned = strip_markdown_fence(text)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        try:
            parsed = parse_json_array(cleaned)
        except Exception:
            start_obj = cleaned.find("{")
            end_obj = cleaned.rfind("}")
            if start_obj >= 0 and end_obj > start_obj:
                parsed = json.loads(cleaned[start_obj : end_obj + 1])
            else:
                raise
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and all(isinstance(item, dict) for item in parsed):
        return parsed
    raise ValueError("model output is JSON but not an object or object array")


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


def code_set_for_name(name: str) -> set[str] | None:
    low = name.lower()
    if "technique" in low:
        return TECHNIQUE_CODES
    if "stage" in low:
        return STAGE_CODES
    return None


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
    if "jsondecodeerror" in low or "model output is json but not" in low:
        return "JSON parse failure"
    if "empty" in low:
        return "empty response"
    if any(code in low for code in ("500", "502", "503", "504")):
        return "provider error"
    return "unknown"


def safe_host(base_url: str) -> str:
    parsed = urlparse(base_url)
    return parsed.netloc or base_url.split("/")[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Qwen/OpenAI-compatible batch prompts.")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/llm_qwen35_27b.yaml")
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
    parser.add_argument("--require-run-api-flag", action="store_true")
    parser.add_argument("--retry-failed-once", action="store_true")
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--failed-records-out", type=Path)
    parser.add_argument("--only-record-ids")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    load_env_file(ROOT / ".env")
    cfg = load_config(args.config)
    generation = cfg.get("generation", {}) if isinstance(cfg.get("generation"), dict) else {}
    recommended = cfg.get("recommended_environment", {}) if isinstance(cfg.get("recommended_environment"), dict) else {}
    base_url = (
        os.environ.get("LLM_BASE_URL")
        or env_from_config(cfg, "provider", "base_url_env")
        or cfg_value(cfg, "base_url")
        or recommended.get("huggingface_router_base_url")
    )
    api_key = api_key_from_env(cfg)
    model = (
        os.environ.get("LLM_MODEL_NAME")
        or env_from_config(cfg, "provider", "model_name_env")
        or cfg_value(cfg, "model_name")
        or recommended.get("huggingface_router_model_name")
        or recommended.get("fallback_model_name")
    )
    temperature = args.temperature if args.temperature is not None else float(os.environ.get("LLM_TEMPERATURE", generation.get("temperature", cfg.get("temperature", 0.1))))
    max_tokens = args.max_tokens if args.max_tokens is not None else int(os.environ.get("LLM_MAX_TOKENS", generation.get("max_tokens", cfg.get("max_tokens", 8192))))
    top_p = float(os.environ.get("LLM_TOP_P", generation.get("top_p", cfg.get("top_p", 0.8))))
    if args.require_run_api_flag and os.environ.get("RUN_API") != "1":
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / args.summary_name).write_text(
            "# Qwen3.5-27B run summary\n\nStatus: not_started\n\n- Missing required `RUN_API=1`; no model call was made.\n",
            encoding="utf-8",
        )
        print("missing RUN_API=1; no call made")
        return 2
    if not base_url or not api_key or not model:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        summary = args.output_dir / args.summary_name
        summary.write_text(
            "# Qwen3.5-27B run summary\n\n"
            "Status: not_started\n\n"
            "Missing API configuration. Set:\n\n"
            "- `LLM_API_KEY` or `HF_TOKEN`\n"
            "- optional: `LLM_BASE_URL`\n"
            "- optional: `LLM_MODEL_NAME`\n\n"
            "No model call was made and no result was fabricated.\n",
            encoding="utf-8",
        )
        print("missing API key; set LLM_API_KEY or HF_TOKEN; no call made")
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
    client = OpenAI(base_url=base_url, api_key=api_key, timeout=request_timeout)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = args.output_dir / "raw"
    parsed_dir = args.output_dir / "parsed"
    raw_dir.mkdir(parents=True, exist_ok=True)
    parsed_dir.mkdir(parents=True, exist_ok=True)
    allowed_codes = code_set_for_name(args.prompt_dir.name) or code_set_for_name(args.output_dir.name)
    result_path = args.output_dir / args.result_name
    existing_results = load_existing_parsed_results(parsed_dir, result_path) if args.resume else {}
    all_results = list(existing_results.values())
    rows = []
    json_parse_failures = 0
    invalid_code_count = 0
    error_counts: dict[str, int] = {}
    failed_records: list[dict[str, Any]] = []
    stop_after_batch = False
    api_calls_attempted = 0
    for idx, (prompt_path, record_id, prompt_text) in enumerate(prompts, start=1):
        raw_path = raw_dir / f"raw_batch_{idx:03d}.txt"
        parsed_path = parsed_dir / f"parsed_batch_{idx:03d}.json"
        if args.resume and record_id in existing_results:
            rows.append({
                "batch": idx,
                "record_id": record_id,
                "prompt": str(prompt_path.resolve().relative_to(ROOT)),
                "status": "skipped_existing",
                "error": "",
                "error_category": "",
                "records": 1,
                "invalid_codes": 0,
            })
            continue
        status = "failed"
        error = ""
        content = ""
        records = 0
        invalid_codes_for_batch = 0
        for attempt in range(args.retries + 1):
            try:
                api_calls_attempted += 1
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt_text}],
                    temperature=temperature,
                    top_p=top_p,
                    max_tokens=max_tokens,
                    stream=False,
                )
                content = response.choices[0].message.content or ""
                raw_path.write_text(content, encoding="utf-8")
                parsed = parse_json_objects(content)
                parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                if allowed_codes:
                    invalid_codes_for_batch = sum(1 for item in parsed if item.get("predicted_code") not in allowed_codes)
                    invalid_code_count += invalid_codes_for_batch
                all_results.extend(parsed)
                records = len(parsed)
                status = "success"
                break
            except Exception as exc:
                error = str(exc)
                category = classify_error(error, type(exc).__name__)
                raw_path.write_text(f"ERROR: {type(exc).__name__}: {error}\n", encoding="utf-8")
                if attempt == args.retries:
                    if type(exc).__name__ in {"JSONDecodeError", "ValueError"}:
                        json_parse_failures += 1
                    code = error_code(error)
                    if code:
                        error_counts[code] = error_counts.get(code, 0) + 1
                    failed_records.append({
                        "record_id": record_id,
                        "prompt": str(prompt_path.resolve().relative_to(ROOT)),
                        "batch": idx,
                        "error_category": category,
                        "error": error,
                    })
                    if category in {"401 unauthorized", "402 quota depleted"}:
                        stop_after_batch = True
                time.sleep(2 * (attempt + 1))
        rows.append({
            "batch": idx,
            "record_id": record_id,
            "prompt": str(prompt_path.resolve().relative_to(ROOT)),
            "status": status,
            "error": error,
            "error_category": classify_error(error) if error else "",
            "records": records,
            "invalid_codes": invalid_codes_for_batch,
        })
        summary_path = args.output_dir / args.summary_name
        lines = [
            "# Qwen3.5-27B run summary",
            "",
            f"- Model: `{model}`",
            f"- Base URL host: `{safe_host(base_url)}`",
            f"- Request timeout seconds: {request_timeout}",
            f"- Max files: {args.max_files if args.max_files is not None else 'all'}",
            f"- Batches observed so far: {len(rows)}",
            f"- Successful batches so far: {sum(1 for r in rows if r['status']=='success')}",
            f"- Skipped existing batches so far: {sum(1 for r in rows if r['status']=='skipped_existing')}",
            f"- Failed batches so far: {sum(1 for r in rows if r['status'] not in {'success', 'skipped_existing'})}",
            f"- JSON parse failures so far: {json_parse_failures}",
            f"- Invalid code count so far: {invalid_code_count}",
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
        "json_parse_failures": json_parse_failures,
        "invalid_code_count": invalid_code_count,
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
        f"- Base URL host: `{safe_host(base_url)}`",
        f"- Batches: {len(rows)}",
        f"- Successful batches: {stats['success']}",
        f"- Skipped existing batches: {stats['skipped_existing']}",
        f"- Failed batches: {stats['failed']}",
        f"- API calls attempted: {api_calls_attempted}",
        f"- JSON parse failures: {json_parse_failures}",
        f"- Invalid code count: {invalid_code_count}",
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
