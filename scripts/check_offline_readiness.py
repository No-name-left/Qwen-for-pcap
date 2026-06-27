#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]


def safe_base_url(value: str) -> str:
    parsed = urlparse(value)
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def docker_image_exists(image: str) -> bool:
    if not image or not command_exists("docker"):
        return False
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def check_vllm_endpoint(base_url: str, model: str, timeout: float) -> tuple[bool, str]:
    parsed = urlparse(base_url)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        return False, "refused non-loopback endpoint for offline readiness"
    endpoint = base_url.rstrip("/") + "/models"
    request = Request(endpoint, headers={"Authorization": "Bearer EMPTY"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(2_000)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if not model:
        return True, "/v1/models reachable"
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return True, "/v1/models reachable; response was not JSON"
    names = {str(item.get("id") or "") for item in payload.get("data", []) if isinstance(item, dict)}
    if model in names:
        return True, f"model {model} listed"
    return False, f"/v1/models reachable but {model} was not listed"


def writable_dir(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".offline_readiness_", dir=path, delete=True) as handle:
            handle.write(b"ok")
        return True, "writable"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def check_exporter() -> tuple[bool, str]:
    script = ROOT / "scripts" / "export_official_submission.py"
    if not script.exists():
        return False, "missing"
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0, "help command ok" if result.returncode == 0 else "help command failed"


def add_result(results: list[dict[str, Any]], name: str, ok: bool, detail: str, *, required: bool = True) -> None:
    results.append({"name": name, "ok": ok, "required": required, "detail": detail})


def collect_checks(args: argparse.Namespace) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    add_result(results, "Python", True, sys.version.split()[0])

    try:
        import openpyxl  # noqa: F401
        add_result(results, "openpyxl", True, "available", required=False)
    except ImportError:
        add_result(results, "openpyxl", False, "not installed; CSV export still works", required=False)

    zeek_ok = command_exists("zeek")
    docker_zeek_ok = docker_image_exists(args.zeek_docker_image)
    zeek_detail = "system zeek available" if zeek_ok else (
        f"Docker Zeek image available: {args.zeek_docker_image}" if docker_zeek_ok else "neither system zeek nor configured Docker Zeek image is available"
    )
    add_result(results, "Zeek or Docker Zeek", zeek_ok or docker_zeek_ok, zeek_detail)

    add_result(results, "TShark", command_exists("tshark"), "available" if command_exists("tshark") else "missing")

    model_path = args.model_path.expanduser()
    add_result(results, "Qwen model path", model_path.exists(), str(model_path))

    if args.check_api:
        ok, detail = check_vllm_endpoint(args.base_url, args.model, args.timeout)
        add_result(results, "vLLM endpoint", ok, f"{safe_base_url(args.base_url)} - {detail}")
    else:
        add_result(results, "vLLM endpoint", True, "skipped by --no-check-api", required=False)

    rag_chunks = ROOT / "rag" / "chunks" / "rag_chunks.jsonl"
    rag_index = ROOT / "rag" / "index" / "keyword_index.json"
    rag_docs = ROOT / "rag" / "knowledge"
    rag_ok = rag_chunks.exists() and rag_index.exists() and rag_docs.exists()
    add_result(results, "RAG docs/chunks", rag_ok, f"{rag_chunks.relative_to(ROOT)}, {rag_index.relative_to(ROOT)}, {rag_docs.relative_to(ROOT)}")

    runner = ROOT / "run_phase1_vm.sh"
    add_result(results, "run_phase1_vm.sh", runner.exists(), str(runner.relative_to(ROOT)) if runner.exists() else "missing")

    exporter_ok, exporter_detail = check_exporter()
    add_result(results, "export_official_submission.py", exporter_ok, exporter_detail)

    output_ok, output_detail = writable_dir(args.outputs_dir.expanduser())
    add_result(results, "outputs writable", output_ok, f"{args.outputs_dir}: {output_detail}")
    return results


def print_report(results: list[dict[str, Any]]) -> None:
    print("# Offline readiness")
    for result in results:
        status = "PASS" if result["ok"] else ("WARN" if not result["required"] else "FAIL")
        required = "required" if result["required"] else "optional"
        print(f"[{status}] {result['name']} ({required}): {result['detail']}")
    required_failures = [item for item in results if item["required"] and not item["ok"]]
    optional_warnings = [item for item in results if not item["required"] and not item["ok"]]
    print("")
    print(f"Required failures: {len(required_failures)}")
    print(f"Optional warnings: {len(optional_warnings)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check offline Phase-1 VM readiness without internet access.")
    parser.add_argument("--model-path", type=Path, default=Path("/data/models/Qwen3.5-27B"))
    parser.add_argument("--outputs-dir", type=Path, default=Path("/data/outputs"))
    parser.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or "http://127.0.0.1:8000/v1")
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL_NAME") or os.environ.get("MODEL") or "qwen3.5")
    parser.add_argument("--zeek-docker-image", default=os.environ.get("PHASE1_ZEEK_DOCKER_IMAGE") or "public.ecr.aws/zeek/zeek:8.0.6-arm64")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--check-api", dest="check_api", action="store_true", default=True)
    parser.add_argument("--no-check-api", dest="check_api", action="store_false", help="Skip local /v1/models probe.")
    parser.add_argument("--soft", action="store_true", help="Always return 0 after printing the readiness report.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = collect_checks(args)
    print_report(results)
    failed = any(item["required"] and not item["ok"] for item in results)
    return 0 if args.soft or not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
