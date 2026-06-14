#!/usr/bin/env python3
"""Shared helpers for the Qwen3.5-27B RAG baseline pipeline."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(os.environ.get("PCAP_LLM_ROOT", Path(__file__).resolve().parents[1])).resolve()
MICRO_DIR = ROOT / "微型testv2"
REAL_MICRO_DIR = ROOT / "微型test_v2"

ATTACK_TYPES = {"normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"}
ATTACK_STAGES = {"none", "reconnaissance", "initial_access", "persistence", "command_and_control"}
FORBIDDEN_KEYS = {
    "case_id",
    "pcap_id",
    "pcap_case",
    "original_case_id",
    "original_pcap_path",
    "expected_attack_type",
    "expected_attack_stage",
    "expected_attack_subtype",
    "label_quality",
    "label_source",
}
FORBIDDEN_TEXT_RE = re.compile(
    r"case_|pcap_case|original_case|original_pcap|expected_attack|expected_stage|"
    r"expected_subtype|label_quality|label_source|mta_2024|nmap_standard_scan|"
    r"nmap_OS_scan|nmap_zombie_scan|eternalblue_wannacry",
    re.IGNORECASE,
)


def micro_path(*parts: str) -> Path:
    if MICRO_DIR.exists():
        return MICRO_DIR.joinpath(*parts)
    return REAL_MICRO_DIR.joinpath(*parts)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def parse_markdown_front_matter(path: Path) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"missing YAML front matter: {path}")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError(f"missing closing YAML front matter: {path}")
    metadata = yaml.safe_load(text[4:end])
    body = text[end + 5 :].strip()
    if not isinstance(metadata, dict):
        raise ValueError(f"front matter is not a mapping: {path}")
    return metadata, body


def tokenize(text: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9_.:/+-]+|[\u4e00-\u9fff]+", text.lower())
    out: list[str] = []
    for token in tokens:
        token = token.strip(".,;()[]{}<>\"'")
        if len(token) >= 2:
            out.append(token)
    return out


def flatten_strings(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            strings.extend(flatten_strings(item))
    elif isinstance(value, list):
        for item in value:
            strings.extend(flatten_strings(item))
    return strings


def sanitize_for_prompt(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: sanitize_for_prompt(item)
            for key, item in value.items()
            if key not in FORBIDDEN_KEYS and not key.startswith("expected_") and not key.startswith("original_")
        }
    if isinstance(value, list):
        return [sanitize_for_prompt(item) for item in value]
    return value


def strip_markdown_fence(text: str) -> str:
    cleaned = text.strip()
    match = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def parse_json_array(text: str) -> list[Any]:
    cleaned = strip_markdown_fence(text)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start < 0 or end <= start:
            raise
        parsed = json.loads(cleaned[start : end + 1])
    if not isinstance(parsed, list):
        raise ValueError("model output is JSON but not an array")
    return parsed


def validate_llm_results(results: Any, expected_ids: set[str]) -> list[str]:
    errors: list[str] = []
    if not isinstance(results, list):
        return ["result is not a JSON array"]
    seen: set[str] = set()
    for idx, item in enumerate(results):
        if not isinstance(item, dict):
            errors.append(f"item {idx} is not an object")
            continue
        event_id = item.get("event_id")
        if event_id not in expected_ids:
            errors.append(f"unexpected event_id at item {idx}: {event_id}")
        elif event_id in seen:
            errors.append(f"duplicate event_id: {event_id}")
        else:
            seen.add(event_id)
        if item.get("attack_type") not in ATTACK_TYPES:
            errors.append(f"{event_id}: invalid attack_type {item.get('attack_type')}")
        if item.get("attack_stage") not in ATTACK_STAGES:
            errors.append(f"{event_id}: invalid attack_stage {item.get('attack_stage')}")
        confidence = item.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
            errors.append(f"{event_id}: invalid confidence {confidence}")
        if not item.get("evidence"):
            errors.append(f"{event_id}: empty evidence")
    missing = sorted(expected_ids - seen)
    if missing:
        errors.append("missing event_ids: " + ", ".join(missing))
    return errors


def ensure_no_forbidden_text(text: str, context: str) -> None:
    match = FORBIDDEN_TEXT_RE.search(text)
    if match:
        raise ValueError(f"forbidden leaked token in {context}: {match.group(0)}")
