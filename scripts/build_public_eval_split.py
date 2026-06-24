#!/usr/bin/env python3
"""Build a deterministic, confidence-aware coverage evaluation split."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TECHNIQUE_CODES = ["TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"]
REQUIRED = ["record_id", "dataset_id", "source_file", "source_label", "technique_code", "label_confidence", "record_type", "pcap_id", "evidence_summary", "notes"]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Select a confidence-aware public coverage eval split.")
    parser.add_argument("--input", type=Path, default=ROOT / "datasets/public_eval/candidate_records.jsonl")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "datasets/public_eval")
    parser.add_argument("--max-per-class", type=int, default=20)
    args = parser.parse_args()
    if args.max_per_class < 1:
        parser.error("--max-per-class must be positive")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[str] = set()
    for item in load_jsonl(args.input):
        missing = [key for key in REQUIRED if key not in item]
        if missing:
            raise ValueError(f"{item.get('record_id', '<unknown>')}: missing fields {missing}")
        if item["technique_code"] not in TECHNIQUE_CODES:
            raise ValueError(f"illegal technique_code: {item['technique_code']}")
        if item["label_confidence"] not in {"high", "medium", "low"}:
            raise ValueError(f"illegal label_confidence: {item['label_confidence']}")
        if item["record_type"] not in {"session", "scan_group", "flow_only", "auth_attempt_group", "c2_callback_group"}:
            raise ValueError(f"illegal record_type: {item['record_type']}")
        if item["record_id"] in seen:
            raise ValueError(f"duplicate record_id: {item['record_id']}")
        seen.add(item["record_id"])
        groups[item["technique_code"]].append(item)
    rank = {"high": 0, "medium": 1, "low": 2}
    selected: list[dict[str, Any]] = []
    for code in TECHNIQUE_CODES:
        rows = sorted(groups.get(code, []), key=lambda item: (rank[item["label_confidence"]], item["dataset_id"], item["record_id"]))
        selected.extend(rows[: args.max_per_class])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    records_path = args.output_dir / "coverage_eval_records.jsonl"
    records_path.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in selected), encoding="utf-8")
    manifest_path = args.output_dir / "coverage_eval_manifest.csv"
    manifest_fields = REQUIRED + ["evaluation_tier"]
    with manifest_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=manifest_fields, extrasaction="ignore")
        writer.writeheader()
        for item in selected:
            writer.writerow({**item, "evaluation_tier": "high_confidence" if item["label_confidence"] == "high" else "exploratory"})
    counts = Counter((item["technique_code"], item["label_confidence"], item["record_type"]) for item in selected)
    missing_codes = [code for code in TECHNIQUE_CODES if not groups.get(code)]
    policy = [
        "# Coverage evaluation label policy", "",
        "- `high` rows form the primary test metric.",
        "- `medium` and `low` rows remain in the coverage file as `exploratory`; reports must not merge them into the high-confidence metric.",
        "- `flow_only` rows test prompt/RAG boundaries and are always reported separately from PCAP/session-derived rows.",
        "- A public source label is not official competition ground truth; provenance and mapping confidence remain attached to every record.",
        "- Missing classes are left empty rather than filled with guessed labels.", "",
        "## Current split", "",
        f"- Records: {len(selected)}",
        f"- Missing technique codes: {', '.join(missing_codes) if missing_codes else 'none'}", "",
        "| Technique | Confidence | Record type | Count |", "|---|---|---|---:|",
    ]
    for (code, confidence, record_type), count in sorted(counts.items()):
        policy.append(f"| `{code}` | {confidence} | `{record_type}` | {count} |")
    policy.extend(["", "## Known semantic gaps", "", "- `TA43_02`: service enumeration is only a proxy for vulnerability scanning.", "- `TA03_01`: broad infiltration or malware-family labels do not prove network-visible backdoor installation.", "- `TA11_01`: backdoor-family labels do not prove operator access direction or phase."])
    (args.output_dir / "coverage_eval_label_policy.md").write_text("\n".join(policy) + "\n", encoding="utf-8")
    print(json.dumps({"records": len(selected), "missing_codes": missing_codes, "output": str(records_path.relative_to(ROOT))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
