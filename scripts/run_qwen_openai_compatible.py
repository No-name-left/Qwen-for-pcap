#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

import yaml
from openai import OpenAI

from qwen35_rag_utils import ROOT, parse_json_array, validate_llm_results


def load_config(path: Path) -> dict:
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {}


def cfg_value(cfg: dict, key: str):
    value = cfg.get(key)
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        return os.environ.get(value[2:-1])
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Qwen/OpenAI-compatible batch prompts.")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/llm_qwen35_27b.yaml")
    parser.add_argument("--prompt-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--result-name", required=True)
    parser.add_argument("--summary-name", required=True)
    parser.add_argument("--retries", type=int, default=2)
    args = parser.parse_args()
    cfg = load_config(args.config)
    base_url = os.environ.get("LLM_BASE_URL") or cfg_value(cfg, "base_url")
    api_key = os.environ.get("LLM_API_KEY") or cfg.get("api_key_env") and os.environ.get(cfg.get("api_key_env"))
    model = os.environ.get("LLM_MODEL_NAME") or cfg_value(cfg, "model_name")
    temperature = float(os.environ.get("LLM_TEMPERATURE", cfg.get("temperature", 0.1)))
    max_tokens = int(os.environ.get("LLM_MAX_TOKENS", cfg.get("max_tokens", 8192)))
    top_p = float(os.environ.get("LLM_TOP_P", cfg.get("top_p", 0.8)))
    if not base_url or not api_key or not model:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        summary = args.output_dir / args.summary_name
        summary.write_text(
            "# Qwen3.5-27B run summary\n\n"
            "Status: not_started\n\n"
            "Missing API configuration. Set:\n\n"
            "- `LLM_BASE_URL`\n"
            "- `LLM_API_KEY`\n"
            "- `LLM_MODEL_NAME`\n\n"
            "No model call was made and no result was fabricated.\n",
            encoding="utf-8",
        )
        print("missing LLM_BASE_URL / LLM_API_KEY / LLM_MODEL_NAME; no call made")
        return 2
    prompts = sorted(args.prompt_dir.glob("*.txt"))
    if not prompts:
        raise FileNotFoundError(f"no prompt files in {args.prompt_dir}")
    request_timeout = float(os.environ.get("LLM_REQUEST_TIMEOUT", cfg.get("request_timeout", 180)))
    client = OpenAI(base_url=base_url, api_key=api_key, timeout=request_timeout)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    all_results = []
    rows = []
    for idx, prompt_path in enumerate(prompts, start=1):
        raw_path = args.output_dir / f"raw_batch_{idx:03d}.txt"
        parsed_path = args.output_dir / f"parsed_batch_{idx:03d}.json"
        status = "failed"
        error = ""
        content = ""
        for attempt in range(args.retries + 1):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt_path.read_text(encoding="utf-8")}],
                    temperature=temperature,
                    top_p=top_p,
                    max_tokens=max_tokens,
                    stream=False,
                )
                content = response.choices[0].message.content or ""
                raw_path.write_text(content, encoding="utf-8")
                parsed = parse_json_array(content)
                parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                all_results.extend(parsed)
                status = "success"
                break
            except Exception as exc:
                error = str(exc)
                raw_path.write_text(f"ERROR: {type(exc).__name__}: {error}\n", encoding="utf-8")
                time.sleep(2 * (attempt + 1))
        rows.append({"batch": idx, "prompt": str(prompt_path.resolve().relative_to(ROOT)), "status": status, "error": error})
        summary_path = args.output_dir / args.summary_name
        lines = [
            "# Qwen3.5-27B run summary",
            "",
            f"- Model: `{model}`",
            f"- Base URL: `{base_url}`",
            f"- Request timeout seconds: {request_timeout}",
            f"- Batches observed so far: {len(rows)}",
            f"- Successful batches so far: {sum(1 for r in rows if r['status']=='success')}",
            "",
        ]
        for row in rows:
            lines.append(f"- batch_{row['batch']:03d}: {row['status']}; prompt=`{row['prompt']}`")
            if row["error"] and row["status"] != "success":
                lines.append(f"  error: {row['error']}")
        summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result_path = args.output_dir / args.result_name
    if all_results:
        result_path.write_text(json.dumps(all_results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary_path = args.output_dir / args.summary_name
    lines = ["# Qwen3.5-27B run summary", "", f"- Model: `{model}`", f"- Base URL: `{base_url}`", f"- Batches: {len(rows)}", f"- Successful batches: {sum(1 for r in rows if r['status']=='success')}", ""]
    for row in rows:
        lines.append(f"- batch_{row['batch']:03d}: {row['status']}; prompt=`{row['prompt']}`")
        if row["error"] and row["status"] != "success":
            lines.append(f"  error: {row['error']}")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(all_results)} parsed records")
    return 0 if all(r["status"] == "success" for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
