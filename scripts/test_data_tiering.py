#!/usr/bin/env python3
"""Assert strict/coverage/synthetic separation for evaluation assets."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CODES = {"TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"}
STRICT = {"external_high_pcap", "external_high_flow"}


def main() -> int:
    candidates = [json.loads(line) for line in (ROOT / "datasets/public_eval/real_api_candidate_records.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(candidates) == 24
    assert Counter(row["intended_technique_code"] for row in candidates) == Counter({code: 3 for code in CODES})
    assert len({row["record_id"] for row in candidates}) == len(candidates)
    strict = [row for row in candidates if "strict_subset" in row["subset_membership"]]
    assert len(strict) == 6
    assert all(row["confidence_level"] in STRICT and not row["is_synthetic"] for row in strict)
    assert not any(row["technique_code"] in {"TA01_01", "TA11_02"} for row in strict)
    assert all("strict_subset" not in row["subset_membership"] for row in candidates if row["confidence_level"] in {"external_medium", "external_low", "synthetic_controlled"})
    for row in candidates:
        assert row["technique_code"] == row["intended_technique_code"]
        assert bool(row["is_flow_only"]) != bool(row["is_pcap_derived"])
        model_blob = json.dumps(row["classification_record"]).lower()
        assert not any(token in model_blob for token in ("bruteforce", "webattack", "ctu13", "wireshark", "synthetic_ta", "source_label", "flow_source"))

    with (ROOT / "datasets/metadata/synthetic_controlled_manifest.csv").open(encoding="utf-8", newline="") as handle:
        synthetic = list(csv.DictReader(handle))
    assert len(synthetic) == 25
    assert all("external_high" not in json.dumps(row) for row in synthetic)
    assert all("never external or strict" in row["limitations"] for row in synthetic)

    with (ROOT / "datasets/public_eval/coverage_eval_manifest.csv").open(encoding="utf-8", newline="") as handle:
        coverage = list(csv.DictReader(handle))
    for row in coverage:
        if row["is_synthetic"] == "True" or row["confidence_level"] in {"external_medium", "external_low", "synthetic_controlled"}:
            assert row["evaluation_tier"] != "strict_external"
    print(json.dumps({"candidates": len(candidates), "strict": len(strict), "synthetic_manifest": len(synthetic), "coverage_manifest": len(coverage)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
