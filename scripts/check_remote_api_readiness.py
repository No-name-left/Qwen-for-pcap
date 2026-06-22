#!/usr/bin/env python3
"""Check a remote OpenAI-compatible endpoint with at most two tiny requests."""

from __future__ import annotations

import argparse
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, load_env_file


def classify_error(exc: Exception) -> tuple[str, int | None, str]:
    if isinstance(exc, urllib.error.HTTPError):
        code = exc.code
        category = {
            401: "unauthorized", 402: "credits_or_billing", 403: "forbidden",
            404: "endpoint_or_model_not_found", 429: "rate_limited",
        }.get(code, "provider_http_error")
        body = exc.read(1000).decode("utf-8", "replace")
        return category, code, body[:500]
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout", None, str(exc)
    if isinstance(exc, urllib.error.URLError):
        return "connection_or_dns", None, str(exc.reason)
    return "unknown", None, str(exc)


def request_json(url: str, api_key: str, method: str = "GET", payload: dict[str, Any] | None = None, timeout: float = 20) -> tuple[int, Any, dict[str, str]]:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json", "User-Agent": "Qwen-for-pcap-readiness/1.0"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(2_000_000)
        try:
            body: Any = json.loads(raw)
        except json.JSONDecodeError:
            body = {"non_json_preview": raw[:300].decode("utf-8", "replace")}
        return response.status, body, dict(response.headers.items())


def base_url_info(base_url: str | None) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(base_url or "")
    compatible_shape = parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    host = (parsed.hostname or "").lower()
    local = host in {"127.0.0.1", "localhost", "::1"}
    return {
        "configured": bool(base_url), "compatible_shape": compatible_shape,
        "scheme": parsed.scheme or None, "host": parsed.netloc or None,
        "path": parsed.path or None, "endpoint_scope": "local" if local else "remote" if host else "unknown",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check OpenAI-compatible API readiness without exposing secrets.")
    parser.add_argument("--dry-run", action="store_true", help="Inspect configuration only; make zero network/API requests.")
    parser.add_argument("--timeout-seconds", type=float, default=20)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/api_readiness")
    args = parser.parse_args()
    load_env_file(ROOT / ".env")
    load_env_file(ROOT / ".env.local")
    base_url = os.environ.get("BASE_URL") or os.environ.get("LLM_BASE_URL")
    model = os.environ.get("MODEL") or os.environ.get("LLM_MODEL_NAME")
    api_key = os.environ.get("API_KEY") or os.environ.get("LLM_API_KEY") or os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACEHUB_API_TOKEN")
    key_length = len(api_key) if api_key else 0
    base = base_url_info(base_url)
    missing = [name for name, value in (("BASE_URL/LLM_BASE_URL", base_url), ("MODEL/LLM_MODEL_NAME", model), ("API_KEY/LLM_API_KEY/HF_TOKEN", api_key)) if not value]
    report: dict[str, Any] = {
        "dry_run": args.dry_run, "configuration": {
            "base_url": base, "model_configured": bool(model), "model_name": model if model else None,
            "api_key_present": bool(api_key), "api_key_length": key_length, "api_key_value_printed": False,
            "missing": missing,
        },
        "request_limits": {"models": 1, "chat_completions": 1},
        "models_check": {"attempted": False}, "chat_check": {"attempted": False},
        "requests_made": 0, "ready_for_tiny_real_eval": False,
    }
    can_call = not args.dry_run and not missing and base["compatible_shape"]
    if can_call:
        root = str(base_url).rstrip("/")
        try:
            status, body, _headers = request_json(root + "/models", api_key, timeout=args.timeout_seconds)
            models = body.get("data", []) if isinstance(body, dict) else []
            ids = [item.get("id") for item in models if isinstance(item, dict) and item.get("id")]
            report["models_check"] = {"attempted": True, "success": 200 <= status < 300, "status": status, "model_count": len(ids), "configured_model_listed": model in ids if ids else None}
        except Exception as exc:
            category, status, detail = classify_error(exc)
            report["models_check"] = {"attempted": True, "success": False, "status": status, "error_category": category, "detail": detail}
        report["requests_made"] += 1
        payload = {
            "model": model, "messages": [{"role": "user", "content": "Reply with exactly OK."}],
            "temperature": 0, "max_tokens": 4, "stream": False,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        try:
            status, body, _headers = request_json(root + "/chat/completions", api_key, method="POST", payload=payload, timeout=args.timeout_seconds)
            usage = body.get("usage") if isinstance(body, dict) else None
            choices = body.get("choices", []) if isinstance(body, dict) else []
            content_present = bool(choices and isinstance(choices[0], dict) and choices[0].get("message", {}).get("content") is not None)
            report["chat_check"] = {
                "attempted": True, "success": 200 <= status < 300 and content_present, "status": status,
                "content_present": content_present, "thinking_off_extra_body_supported": True,
                "usage_present": isinstance(usage, dict), "usage": usage if isinstance(usage, dict) else None,
                "fallback_plain_request_tested": False,
            }
        except Exception as exc:
            category, status, detail = classify_error(exc)
            report["chat_check"] = {
                "attempted": True, "success": False, "status": status, "error_category": category, "detail": detail,
                "thinking_off_extra_body_supported": False if status in {400, 404, 422} else None,
                "fallback_plain_request_tested": False,
                "fallback_note": "Not retried: readiness policy permits only one minimal chat request. Use --disable-extra-body for the next explicitly approved test.",
            }
        report["requests_made"] += 1
        report["ready_for_tiny_real_eval"] = bool(report["chat_check"].get("success"))

    if args.dry_run:
        status_text = "configuration_only"
    elif missing:
        status_text = "missing_configuration"
    elif not base["compatible_shape"]:
        status_text = "invalid_base_url_shape"
    elif report["ready_for_tiny_real_eval"]:
        status_text = "ready"
    else:
        status_text = "not_ready"
    report["status"] = status_text
    needs = []
    if missing:
        needs.append("Set " + ", ".join(missing) + ".")
    if report["models_check"].get("error_category") == "credits_or_billing" or report["chat_check"].get("error_category") == "credits_or_billing":
        needs.append("Provider credits/billing appear insufficient (HTTP 402).")
    if report["chat_check"].get("error_category") == "endpoint_or_model_not_found":
        needs.append("Confirm provider base URL and exact model name.")
    if report["chat_check"].get("error_category") == "connection_or_dns":
        needs.append("Confirm network/DNS access and whether HTTP(S)_PROXY is required.")
    report["requirements_before_eval"] = needs

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "api_readiness_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Remote API readiness", "", f"- Status: `{status_text}`", f"- Dry run: {str(args.dry_run).lower()}",
        f"- Endpoint scope: `{base['endpoint_scope']}`", f"- BASE_URL configured/shape valid: {base['configured']} / {base['compatible_shape']}",
        f"- MODEL configured: {bool(model)}", f"- API credential present: {bool(api_key)}; length: {key_length}; value printed: no",
        f"- Requests made: {report['requests_made']}", f"- `/models` success: {report['models_check'].get('success', 'not_attempted')}",
        f"- minimal chat success: {report['chat_check'].get('success', 'not_attempted')}",
        f"- thinking off extra body supported: {report['chat_check'].get('thinking_off_extra_body_supported', 'not_tested')}",
        f"- usage tokens returned: {report['chat_check'].get('usage_present', 'not_tested')}",
        f"- Ready for tiny real paired eval: {report['ready_for_tiny_real_eval']}", "", "## Required before evaluation", "",
    ]
    lines.extend(f"- {item}" for item in needs) if needs else lines.append("- None detected by this check.")
    lines.extend(["", "Set variables only in the shell or untracked `.env.local`: `LLM_BASE_URL`, `LLM_MODEL_NAME`, `LLM_API_KEY`. Confirm provider pricing/credits separately; this script never exposes the key."])
    (args.output_dir / "api_readiness_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"status": status_text, "missing": missing, "requests_made": report["requests_made"], "ready_for_tiny_real_eval": report["ready_for_tiny_real_eval"], "api_key_present": bool(api_key), "api_key_length": key_length}))
    return 0 if args.dry_run or report["ready_for_tiny_real_eval"] or bool(missing) else 1


if __name__ == "__main__":
    raise SystemExit(main())
