#!/usr/bin/env python3
"""Verify official field order and technique-first stage mapping for both tasks."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from export_competition_csv import COMMON_FIELDS, REASON_FIELD, STAGE_LABEL_FIELD, TECHNIQUE_LABEL_FIELD
from qwen35_rag_utils import ROOT


def main() -> int:
    record = {
        "record_id": "case::session::000001", "session_id": "000001", "pcap": "/input/original-example.pcap",
        "start_time": 1.25, "end_time": 2.5, "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 443, "record_type": "session",
    }
    result = {"record_id": record["record_id"], "predicted_code": "TA11_02", "reason": "Repeated victim-initiated callback."}
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        records = base / "records.json"
        results = base / "results.json"
        records.write_text(json.dumps([record]), encoding="utf-8")
        results.write_text(json.dumps([result]), encoding="utf-8")
        expected = {"stage1": (STAGE_LABEL_FIELD, "TA11"), "stage2": (TECHNIQUE_LABEL_FIELD, "TA11_02")}
        for mode, (label_field, label) in expected.items():
            output = base / f"{mode}.csv"
            subprocess.run([
                sys.executable, str(ROOT / "scripts/export_competition_csv.py"), "--records", str(records),
                "--technique-results", str(results), "--task-mode", mode, "--output", str(output),
                "--report", str(base / f"{mode}.md"),
            ], cwd=ROOT, check=True)
            with output.open(encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                rows = list(reader)
                assert reader.fieldnames == COMMON_FIELDS + [label_field, REASON_FIELD]
            assert rows[0]["pcap"] == "original-example.pcap"
            assert rows[0]["编号"] == "000001"
            assert rows[0][label_field] == label
    print("stage1/stage2 submission schemas passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
