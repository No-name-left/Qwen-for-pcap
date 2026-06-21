#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
from pathlib import Path

import yaml
from openai import OpenAI

from qwen35_rag_utils import ROOT
from run_qwen_openai_compatible import (
    extract_record_id_from_prompt,
    parse_bool,
    parse_json_objects,
    validate_technique_results,
)


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
        os.environ.get("API_KEY")
        or os.environ.get("LLM_API_KEY")
        or env_from_config(cfg, "provider", "api_key_env")
        or os.environ.get("HF_TOKEN")
        or os.environ.get("HUGGINGFACEHUB_API_TOKEN")
    )


def call_model(prompt: str, cfg: dict, queue: mp.Queue) -> None:
    try:
        client = OpenAI(base_url=cfg["base_url"], api_key=cfg["api_key"], timeout=cfg["request_timeout"])
        request_kwargs = dict(
            model=cfg["model"],
            messages=[{"role": "user", "content": prompt}],
            temperature=cfg["temperature"],
            top_p=cfg["top_p"],
            max_tokens=cfg["max_tokens"],
            stream=False,
        )
        if cfg["send_extra_body"]:
            request_kwargs["extra_body"] = {
                "chat_template_kwargs": {"enable_thinking": cfg["enable_thinking"]}
            }
        resp = client.chat.completions.create(**request_kwargs)
        queue.put({"ok": True, "content": resp.choices[0].message.content or ""})
    except Exception as exc:
        queue.put({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def main() -> int:
    parser = argparse.ArgumentParser(description="Run OpenAI-compatible prompts with hard per-batch isolation timeout.")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/llm_qwen35_27b.yaml")
    parser.add_argument("--prompt-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--result-name", required=True)
    parser.add_argument("--summary-name", required=True)
    parser.add_argument("--hard-timeout", type=int, default=180)
    parser.add_argument("--enable-thinking", choices=["true", "false"])
    parser.add_argument("--disable-extra-body", action="store_true")
    args = parser.parse_args()
    load_env_file(ROOT / ".env")
    cfg_raw = yaml.safe_load(args.config.read_text(encoding="utf-8")) if args.config.exists() else {}
    generation = cfg_raw.get("generation", {}) if isinstance(cfg_raw.get("generation"), dict) else {}
    cfg = {
        "base_url": (
            os.environ.get("BASE_URL")
            or os.environ.get("LLM_BASE_URL")
            or env_from_config(cfg_raw, "provider", "base_url_env")
            or cfg_value(cfg_raw, "base_url")
        ),
        "api_key": api_key_from_env(cfg_raw),
        "model": (
            os.environ.get("MODEL")
            or os.environ.get("LLM_MODEL_NAME")
            or env_from_config(cfg_raw, "provider", "model_name_env")
            or cfg_value(cfg_raw, "model_name")
        ),
        "temperature": float(os.environ.get("LLM_TEMPERATURE", generation.get("temperature", cfg_raw.get("temperature", 0.1)))),
        "top_p": float(os.environ.get("LLM_TOP_P", generation.get("top_p", cfg_raw.get("top_p", 0.8)))),
        "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", generation.get("max_tokens", cfg_raw.get("max_tokens", 2048)))),
        "request_timeout": float(os.environ.get("LLM_REQUEST_TIMEOUT", generation.get("request_timeout_seconds", cfg_raw.get("request_timeout", 90)))),
        "enable_thinking": parse_bool(
            args.enable_thinking if args.enable_thinking is not None else os.environ.get("ENABLE_THINKING", os.environ.get("LLM_ENABLE_THINKING")),
            default=parse_bool(generation.get("enable_thinking"), default=False),
        ),
        "send_extra_body": not args.disable_extra_body and parse_bool(
            os.environ.get("LLM_SEND_EXTRA_BODY"), default=bool(generation.get("send_extra_body", True))
        ),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.output_dir / args.summary_name
    if not cfg["base_url"] or not cfg["api_key"] or not cfg["model"]:
        summary_path.write_text(
            "# Qwen3.5-27B isolated run summary\n\n"
            "Status: not_started\n\n"
            "- Missing API configuration. Set BASE_URL/MODEL/API_KEY or their LLM_* aliases.\n",
            encoding="utf-8",
        )
        print("missing API configuration; set BASE_URL/MODEL/API_KEY or their LLM_* aliases")
        return 2

    prompts = sorted(args.prompt_dir.glob("*.txt"))
    all_results = []
    rows = []
    for idx, prompt_path in enumerate(prompts, start=1):
        raw_path = args.output_dir / f"raw_batch_{idx:03d}.txt"
        parsed_path = args.output_dir / f"parsed_batch_{idx:03d}.json"
        queue: mp.Queue = mp.Queue()
        prompt_text = prompt_path.read_text(encoding="utf-8")
        record_id = extract_record_id_from_prompt(prompt_text, prompt_path.stem)
        proc = mp.Process(target=call_model, args=(prompt_text, cfg, queue))
        proc.start()
        proc.join(args.hard_timeout)
        if proc.is_alive():
            proc.terminate()
            proc.join(5)
            row = {"batch": idx, "status": "failed", "error": f"hard timeout after {args.hard_timeout}s", "prompt": str(prompt_path.resolve().relative_to(ROOT))}
            raw_path.write_text(row["error"] + "\n", encoding="utf-8")
        else:
            result = queue.get() if not queue.empty() else {"ok": False, "error": "empty child result"}
            if not result.get("ok"):
                row = {"batch": idx, "status": "failed", "error": result.get("error", "unknown error"), "prompt": str(prompt_path.resolve().relative_to(ROOT))}
                raw_path.write_text(row["error"] + "\n", encoding="utf-8")
            else:
                content = result["content"]
                raw_path.write_text(content, encoding="utf-8")
                try:
                    parsed = validate_technique_results(parse_json_objects(content), record_id)
                    parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                    all_results.extend(parsed)
                    row = {"batch": idx, "status": "success", "error": "", "prompt": str(prompt_path.resolve().relative_to(ROOT)), "records": len(parsed)}
                except Exception as exc:
                    row = {"batch": idx, "status": "failed", "error": f"parse error: {type(exc).__name__}: {exc}", "prompt": str(prompt_path.resolve().relative_to(ROOT))}
        rows.append(row)
        lines = [
            "# Qwen3.5-27B isolated run summary",
            "",
            f"- Model: `{cfg['model']}`",
            f"- Base URL: `{cfg['base_url']}`",
            f"- API key exists: true",
            f"- Prompt files: {len(prompts)}",
            f"- Completed batches: {len(rows)}",
            f"- Successful batches: {sum(1 for r in rows if r['status'] == 'success')}",
            "",
        ]
        for r in rows:
            lines.append(f"- batch_{r['batch']:03d}: {r['status']}; prompt=`{r['prompt']}`; records={r.get('records', 0)}")
            if r["error"]:
                lines.append(f"  error: {r['error'][:500]}")
        summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if all_results:
        (args.output_dir / args.result_name).write_text(json.dumps(all_results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"successful_batches={sum(1 for r in rows if r['status']=='success')}/{len(rows)} records={len(all_results)}")
    return 0 if all(r["status"] == "success" for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
