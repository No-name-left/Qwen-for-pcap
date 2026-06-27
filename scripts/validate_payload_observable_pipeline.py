#!/usr/bin/env python3
"""Validate that bounded payload/application observables survive the pipeline.

The script is intentionally read-only.  Raw PCAP inspection uses TShark counts,
while pipeline inspection only reads generated cards, records, and prompt text.
Examples are redacted and truncated before display.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from qwen35_rag_utils import ROOT
from session_card_indicators import redact_sensitive_text


PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
BODY_KEYS = (
    "body_snippets_sanitized",
    "request_body_snippets_sanitized",
    "response_body_snippets_sanitized",
)
HTTP_KEYS = ("http_hosts", "http_uris_sample", "http_full_uri_sample", "http_methods", "http_status_codes", "http_user_agents")
DNS_KEYS = ("dns_queries_sample",)
TLS_KEYS = ("tls_sni_sample",)
FTP_KEYS = ("ftp_response_codes",)
PROMPT_KEY_PATTERNS = {
    "http_body_observed_true": re.compile(r'"?http_body_observed"?\s*[:=]\s*true', re.IGNORECASE),
    "body_snippets": re.compile(r"(?:request_|response_)?body_snippets_sanitized", re.IGNORECASE),
    "suspicious_payload_snippets": re.compile(r"suspicious_payload_snippets", re.IGNORECASE),
    "http_context": re.compile(r"http_(?:uris_sample|full_uri_sample|hosts|methods|status_codes|user_agents)", re.IGNORECASE),
    "dns_context": re.compile(r"dns_(?:summary|queries_sample)", re.IGNORECASE),
    "tls_context": re.compile(r"tls_(?:summary|sni_sample)", re.IGNORECASE),
    "ftp_context": re.compile(r"ftp_response_codes|auth_protocol.{0,40}ftp|password_field_seen|username_field_seen", re.IGNORECASE | re.DOTALL),
}
TSHARK_FILTERS = {
    "http_file_data_frames": "http.file_data",
    "http_app_frames": "http.request || http.response || http.host || http.request.uri || http.user_agent || http.content_type",
    "dns_query_frames": "dns.qry.name",
    "tls_sni_frames": "tls.handshake.extensions_server_name",
    "ftp_command_frames": "ftp.request.command",
    "ftp_response_code_frames": "ftp.response.code",
}


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def as_list(value: Any) -> list[Any]:
    if value in (None, "", {}, []):
        return []
    return value if isinstance(value, list) else [value]


def nested_get_values(item: Any, key: str) -> list[Any]:
    values: list[Any] = []
    if isinstance(item, dict):
        for current_key, current_value in item.items():
            if current_key == key:
                values.extend(as_list(current_value))
            values.extend(nested_get_values(current_value, key))
    elif isinstance(item, list):
        for child in item:
            values.extend(nested_get_values(child, key))
    return values


def has_truthy_key(item: dict[str, Any], key: str) -> bool:
    return bool(item.get(key)) or any(bool(value) for value in nested_get_values(item, key))


def safe_example(value: Any, limit: int = 180) -> str:
    text = redact_sensitive_text(value, limit)
    return text if len(text) <= limit else text[: max(0, limit - 14)] + "...[truncated]"


def iter_pcaps(input_path: Path) -> list[Path]:
    if not input_path.exists():
        return []
    if input_path.is_file():
        return [input_path] if input_path.suffix.lower() in PCAP_SUFFIXES else []
    return sorted(path for path in input_path.rglob("*") if path.is_file() and path.suffix.lower() in PCAP_SUFFIXES)


def count_tshark_frames(pcap: Path, display_filter: str) -> tuple[int | None, str]:
    if not shutil.which("tshark"):
        return None, "tshark not found"
    command = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields", "-e", "frame.number"]
    proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        return None, " ".join(proc.stderr.split())[:300] or f"tshark rc={proc.returncode}"
    frames = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    return len(frames), ""


def inspect_raw_pcaps(input_path: Path, max_pcaps: int) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    pcaps = iter_pcaps(input_path)
    if not input_path.exists():
        return [], [f"input path does not exist: {input_path}"]
    if not pcaps:
        return [], [f"no PCAP files found under: {input_path}"]
    if max_pcaps and len(pcaps) > max_pcaps:
        warnings.append(f"limited raw inspection to first {max_pcaps} of {len(pcaps)} PCAPs")
        pcaps = pcaps[:max_pcaps]

    rows: list[dict[str, Any]] = []
    for pcap in pcaps:
        row: dict[str, Any] = {"pcap_name": pcap.name, "pcap_path": display_path(pcap)}
        errors: list[str] = []
        for field, display_filter in TSHARK_FILTERS.items():
            count, error = count_tshark_frames(pcap, display_filter)
            row[field] = count
            if error:
                errors.append(f"{field}: {error}")
        row["errors"] = errors
        rows.append(row)
    return rows, warnings


def load_json_rows(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def candidate_json_files(output_dir: Path, kind: str) -> list[Path]:
    if kind == "cards":
        return sorted(
            path for path in output_dir.rglob("*.json")
            if path.name in {"session_cards.json", "session_cards_all.json"}
            or (
                path.name.endswith("_session_cards.json")
                and not path.name.startswith("llm_")
                and not path.name.endswith("_llm_session_cards.json")
            )
        )
    if kind == "records":
        full_records = sorted(
            path for path in output_dir.rglob("*.json")
            if path.name in {"classification_records.json", "classification_records_all.json"}
        )
        return full_records or sorted(path for path in output_dir.rglob("*.json") if path.name == "selected_records.json")
    return []


def prompt_files(output_dir: Path) -> list[Path]:
    out: list[Path] = []
    for path in output_dir.rglob("*.txt"):
        parts = [part.lower() for part in path.relative_to(output_dir).parts]
        if any("prompt_samples" == part for part in parts):
            continue
        if any("prompt" in part for part in parts):
            out.append(path)
    return sorted(out)


def item_has_any(item: dict[str, Any], keys: Iterable[str]) -> bool:
    return any(has_truthy_key(item, key) for key in keys)


def item_has_body_snippet(item: dict[str, Any]) -> bool:
    return item_has_any(item, BODY_KEYS)


def item_has_dns(item: dict[str, Any]) -> bool:
    if item_has_any(item, DNS_KEYS):
        return True
    dns = item.get("dns_summary")
    return isinstance(dns, dict) and bool(dns.get("queries"))


def item_has_tls(item: dict[str, Any]) -> bool:
    if item_has_any(item, TLS_KEYS):
        return True
    tls = item.get("tls_summary")
    return isinstance(tls, dict) and bool(tls.get("server_names"))


def item_has_ftp(item: dict[str, Any]) -> bool:
    if item_has_any(item, FTP_KEYS):
        return True
    auth = item.get("auth_indicators")
    if not isinstance(auth, dict):
        return False
    return bool(
        auth.get("auth_protocol") == "ftp"
        or auth.get("ftp_response_codes")
        or auth.get("username_field_seen")
        or auth.get("password_field_seen")
    )


def collect_examples(items: list[dict[str, Any]], limit: int) -> list[dict[str, str]]:
    examples: list[dict[str, str]] = []
    seen: set[str] = set()
    keys = (*BODY_KEYS, "suspicious_payload_snippets", "http_upload_hints", "suspicious_http_parameters")
    for item in items:
        record_id = str(item.get("record_id") or item.get("session_id") or item.get("pcap_id") or "<unknown>")
        for key in keys:
            for value in nested_get_values(item, key):
                if value in (None, "", [], {}):
                    continue
                if isinstance(value, (dict, list)):
                    raw = json.dumps(value, ensure_ascii=False, sort_keys=True)
                else:
                    raw = str(value)
                text = safe_example(raw)
                marker = f"{record_id}:{key}:{text}"
                if text and marker not in seen:
                    seen.add(marker)
                    examples.append({"record_id": record_id, "field": key, "snippet": text})
                    if len(examples) >= limit:
                        return examples
    return examples


def count_json_layer(kind: str, files: list[Path]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for path in files:
        rows.extend(load_json_rows(path))
    return {
        "kind": kind,
        "files": len(files),
        "items": len(rows),
        "http_body_observed_true": sum(1 for item in rows if has_truthy_key(item, "http_body_observed")),
        "body_snippets": sum(1 for item in rows if item_has_body_snippet(item)),
        "suspicious_payload_snippets": sum(1 for item in rows if has_truthy_key(item, "suspicious_payload_snippets")),
        "http_context": sum(1 for item in rows if item_has_any(item, HTTP_KEYS)),
        "dns_context": sum(1 for item in rows if item_has_dns(item)),
        "tls_context": sum(1 for item in rows if item_has_tls(item)),
        "ftp_context": sum(1 for item in rows if item_has_ftp(item)),
        "examples": collect_examples(rows, 5),
        "paths": [display_path(path) for path in files[:12]],
    }


def prompt_excerpt(text: str, key: str, limit: int = 180) -> str:
    index = text.lower().find(key.lower())
    if index < 0:
        return ""
    start = max(0, index - 60)
    end = min(len(text), index + 220)
    return safe_example(text[start:end], limit)


def inspect_prompts(files: list[Path], example_limit: int) -> dict[str, Any]:
    counts = Counter()
    examples: list[dict[str, str]] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, pattern in PROMPT_KEY_PATTERNS.items():
            if pattern.search(text):
                counts[name] += 1
        if len(examples) < example_limit:
            for key in ("suspicious_payload_snippets", "body_snippets_sanitized", "http_upload_hints", "http_body_observed"):
                snippet = prompt_excerpt(text, key)
                if snippet:
                    examples.append({"prompt_file": display_path(path), "field": key, "snippet": snippet})
                    break
    return {
        "kind": "prompts",
        "files": len(files),
        "items": len(files),
        **{name: counts.get(name, 0) for name in PROMPT_KEY_PATTERNS},
        "examples": examples,
        "paths": [display_path(path) for path in files[:12]],
    }


def inspect_pipeline_output(output_dir: Path, example_limit: int) -> tuple[dict[str, Any] | None, list[str]]:
    if not output_dir.exists():
        return None, [f"output directory does not exist: {output_dir}"]
    card_files = candidate_json_files(output_dir, "cards")
    record_files = candidate_json_files(output_dir, "records")
    prompts = prompt_files(output_dir)
    return {
        "output_dir": display_path(output_dir),
        "cards": count_json_layer("cards", card_files),
        "records": count_json_layer("records", record_files),
        "prompts": inspect_prompts(prompts, example_limit),
    }, []


def sum_raw(rows: list[dict[str, Any]], key: str) -> int:
    return sum(int(row.get(key) or 0) for row in rows if isinstance(row.get(key), int))


def judge(raw_rows: list[dict[str, Any]], pipeline: dict[str, Any] | None) -> list[str]:
    lines: list[str] = []
    if not raw_rows or pipeline is None:
        lines.append("diagnosis: need both --input and --output-dir for cross-layer judgement")
        return lines
    raw_body = sum_raw(raw_rows, "http_file_data_frames")
    raw_http = sum_raw(raw_rows, "http_app_frames")
    raw_dns = sum_raw(raw_rows, "dns_query_frames")
    raw_tls = sum_raw(raw_rows, "tls_sni_frames")
    raw_ftp = sum_raw(raw_rows, "ftp_command_frames") + sum_raw(raw_rows, "ftp_response_code_frames")
    cards = pipeline["cards"]
    records = pipeline["records"]
    prompts = pipeline["prompts"]

    records_present = bool(records.get("items"))
    prompts_present = bool(prompts.get("items"))

    if raw_body and not cards["http_body_observed_true"]:
        lines.append("possible loss: raw http.file_data exists, but no card has http_body_observed=true; inspect parse/supplement and observation merge.")
    elif cards["http_body_observed_true"] and records_present and not records["http_body_observed_true"]:
        lines.append("possible loss: cards contain http_body_observed, but classification records do not; inspect record field propagation.")
    elif cards["http_body_observed_true"] and not records_present:
        lines.append("record layer: no classification record file was found, so card-to-record propagation was not assessed.")
    elif records["http_body_observed_true"] and prompts_present and not prompts["http_body_observed_true"]:
        lines.append("possible loss: records contain http_body_observed, but prompts do not; inspect prompt compaction/budget.")
    elif raw_body:
        lines.append("body chain: raw http.file_data exists and at least one downstream layer exposes safe body evidence.")
    else:
        lines.append("body chain: no raw http.file_data was counted; low downstream body coverage may reflect the input PCAPs.")

    if raw_http and not (cards["http_context"] or records["http_context"] or prompts["http_context"]):
        lines.append("possible loss: raw HTTP metadata exists, but output layers show no HTTP context.")
    if raw_dns and not (cards["dns_context"] or records["dns_context"] or prompts["dns_context"]):
        lines.append("possible loss: raw DNS queries exist, but output layers show no DNS context.")
    if raw_tls and not (cards["tls_context"] or records["tls_context"] or prompts["tls_context"]):
        lines.append("possible loss: raw TLS SNI exists, but output layers show no TLS context.")
    if raw_ftp and not (cards["ftp_context"] or records["ftp_context"] or prompts["ftp_context"]):
        lines.append("possible loss: raw FTP command/response evidence exists, but output layers show no FTP context.")

    if raw_http >= 20 and cards["http_context"] <= 1 and (not records_present or records["http_context"] <= 1):
        lines.append("coverage note: raw HTTP metadata is relatively frequent but card/record HTTP context is very sparse; inspect parser source and session merge.")
    if raw_body >= 20 and (not records_present or records["body_snippets"] <= 1) and prompts["body_snippets"] <= 1:
        lines.append("coverage note: many raw body frames but very few snippets downstream; inspect sanitizer filters and prompt compaction.")
    if len(lines) == 1 and "body chain" in lines[0]:
        lines.append("diagnosis: no obvious cross-layer payload evidence drop detected by aggregate checks.")
    return lines


def print_table(title: str, rows: list[dict[str, Any]], fields: list[str]) -> None:
    print(f"\n## {title}")
    if not rows:
        print("none")
        return
    widths = {field: max(len(field), *(len(str(row.get(field, ""))) for row in rows)) for field in fields}
    print(" | ".join(field.ljust(widths[field]) for field in fields))
    print(" | ".join("-" * widths[field] for field in fields))
    for row in rows:
        print(" | ".join(str(row.get(field, "")).ljust(widths[field]) for field in fields))


def print_layer(layer: dict[str, Any]) -> None:
    print(f"\n## Pipeline {layer['kind']}")
    print(f"files: {layer['files']}")
    print(f"items: {layer['items']}")
    for key in (
        "http_body_observed_true",
        "body_snippets",
        "suspicious_payload_snippets",
        "http_context",
        "dns_context",
        "tls_context",
        "ftp_context",
    ):
        if key in layer:
            print(f"{key}: {layer[key]}")
    if layer.get("paths"):
        print("sample_files:")
        for path in layer["paths"][:5]:
            print(f"- {path}")
    if layer.get("examples"):
        print("safe_examples:")
        for example in layer["examples"]:
            owner = example.get("record_id") or example.get("prompt_file")
            print(f"- {owner} :: {example['field']} :: {example['snippet']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate raw PCAP application-layer observables against generated cards, records, and prompts."
    )
    parser.add_argument("--input", type=Path, help="PCAP file or directory to inspect with TShark.")
    parser.add_argument("--output-dir", type=Path, help="Pipeline output directory containing cards/records/prompts.")
    parser.add_argument("--max-pcaps", type=int, default=0, help="Limit raw PCAP inspection count; 0 means all.")
    parser.add_argument("--example-limit", type=int, default=5, help="Maximum safe examples per pipeline layer.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.input and not args.output_dir:
        parser.error("provide --input, --output-dir, or both")

    raw_rows: list[dict[str, Any]] = []
    raw_warnings: list[str] = []
    pipeline: dict[str, Any] | None = None
    pipeline_warnings: list[str] = []
    if args.input:
        raw_rows, raw_warnings = inspect_raw_pcaps(args.input, args.max_pcaps)
    if args.output_dir:
        pipeline, pipeline_warnings = inspect_pipeline_output(args.output_dir, args.example_limit)
    diagnosis = judge(raw_rows, pipeline)

    result = {
        "raw_pcaps": raw_rows,
        "pipeline": pipeline,
        "warnings": raw_warnings + pipeline_warnings,
        "diagnosis": diagnosis,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print("# Payload observable pipeline validation")
    for warning in result["warnings"]:
        print(f"warning: {warning}")
    if args.input:
        print_table(
            "Raw PCAP TShark counts",
            raw_rows,
            [
                "pcap_name",
                "http_file_data_frames",
                "http_app_frames",
                "dns_query_frames",
                "tls_sni_frames",
                "ftp_command_frames",
                "ftp_response_code_frames",
            ],
        )
        raw_errors = [(row["pcap_name"], error) for row in raw_rows for error in row.get("errors", [])]
        if raw_errors:
            print("\n## Raw inspection errors")
            for pcap_name, error in raw_errors[:20]:
                print(f"- {pcap_name}: {error}")
    if pipeline:
        print_layer(pipeline["cards"])
        print_layer(pipeline["records"])
        print_layer(pipeline["prompts"])
    print("\n## Diagnosis")
    for line in diagnosis:
        print(f"- {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
