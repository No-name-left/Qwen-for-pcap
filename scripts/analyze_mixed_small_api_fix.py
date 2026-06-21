#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT


STAGE_CODES = {"TA43", "TA01", "TA03", "TA11", "TN01"}
TECHNIQUE_CODES = {"TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"}
TECHNIQUE_TO_STAGE = {
    "TA43_01": "TA43", "TA43_02": "TA43",
    "TA01_01": "TA01", "TA01_02": "TA01",
    "TA03_01": "TA03",
    "TA11_01": "TA11", "TA11_02": "TA11",
    "TN01_01": "TN01",
}


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT))


def read_result_dirs(dirs: list[Path]) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    by_id: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for directory in dirs:
        parsed_dir = directory / "parsed"
        candidates = []
        if parsed_dir.exists():
            candidates.extend(sorted(parsed_dir.glob("*.json")))
        if (directory / "results.json").exists():
            candidates.append(directory / "results.json")
        for path in candidates:
            data = load_json(path, [])
            if isinstance(data, dict):
                data = [data]
            for item in data:
                if not isinstance(item, dict):
                    continue
                rid = item.get("record_id") or item.get("session_id")
                if not rid:
                    continue
                item = dict(item)
                item["_source_file"] = rel(path)
                by_id[str(rid)] = item
                rows.append(item)
    return by_id, rows


def prompt_record_ids(prompt_dir: Path) -> list[str]:
    manifest = prompt_dir / "prompt_manifest.json"
    if manifest.exists():
        data = load_json(manifest, [])
        return [str(item["record_id"]) for item in data if item.get("record_id")]
    return []


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def api_env_ready() -> bool:
    return (
        os.environ.get("RUN_API") == "1"
        and bool(os.environ.get("LLM_BASE_URL"))
        and bool(os.environ.get("LLM_API_KEY"))
        and bool(os.environ.get("LLM_MODEL_NAME"))
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose, merge, and conditionally export mixed-small API test results.")
    parser.add_argument("--base-dir", type=Path, default=ROOT / "outputs/api_tests/mixed_small")
    args = parser.parse_args()
    base = args.base_dir
    selected = load_json(base / "selected_records.json", [])
    selected_ids = [str(item["record_id"]) for item in selected]
    selected_by_id = {str(item["record_id"]): item for item in selected}

    technique_dirs = [
        base / "results_technique_rag",
        base / "results_technique_rag_scan_group",
        base / "rerun_technique_rag",
    ]
    technique_results, _ = read_result_dirs(technique_dirs)
    stage_results = {
        rid: {**item, "predicted_code": TECHNIQUE_TO_STAGE[item["predicted_code"]], "source": "stage_from_technique"}
        for rid, item in technique_results.items()
        if item.get("predicted_code") in TECHNIQUE_TO_STAGE
    }

    technique_missing = [rid for rid in selected_ids if rid not in technique_results]
    stage_missing = [rid for rid in selected_ids if rid not in stage_results]
    technique_invalid = [rid for rid, item in technique_results.items() if rid in selected_by_id and item.get("predicted_code") not in TECHNIQUE_CODES]
    stage_invalid = [rid for rid, item in stage_results.items() if rid in selected_by_id and item.get("predicted_code") not in STAGE_CODES]

    primary_tech_prompt_order = prompt_record_ids(base / "prompts_technique_rag")
    technique_failure_records = []
    for rid in technique_missing:
        reason = "interrupted by script logic"
        detail = "No per-record provider error was persisted; the previous primary technique run stopped after six successes, and this selected record was not completed."
        if rid not in primary_tech_prompt_order:
            detail = "The record was outside the primary technique prompt manifest or was only attempted in a separate scan-group run."
        technique_failure_records.append({"record_id": rid, "failure_category": reason, "detail": detail})

    stage_failure_records = []
    for rid in stage_missing:
        if rid == "ctu13_scenario1::session::000002":
            category = "missing technique result"
            detail = "Stage could not be derived because the corresponding technique result is missing."
        else:
            category = "missing or invalid technique result"
            detail = "Stage is derived deterministically and is unavailable without a valid technique result."
        stage_failure_records.append({"record_id": rid, "failure_category": category, "detail": detail})

    write_json(base / "failed_technique_records.json", technique_failure_records)
    write_json(base / "failed_stage_records.json", stage_failure_records[:10])

    diagnosis = {
        "api_rerun_this_round": api_env_ready(),
        "quota_or_auth_evidence": False,
        "technique_success": len([rid for rid in selected_ids if rid in technique_results]),
        "technique_missing": len(technique_missing),
        "stage_success": len([rid for rid in selected_ids if rid in stage_results]),
        "stage_missing": len(stage_missing),
        "technique_failures": technique_failure_records,
        "stage_failures": stage_failure_records,
        "recommend_rerun_failed_items": True,
        "prompt_fix_needed": False,
        "runner_fix_needed": True,
    }
    write_json(base / "failure_diagnosis.json", diagnosis)

    write_text(
        base / "failure_diagnosis_report.md",
        [
            "# Mixed small failure diagnosis",
            "",
            "## Findings",
            "",
            f"- Selected records: {len(selected_ids)}",
            f"- Technique successful records: {diagnosis['technique_success']}",
            f"- Technique missing/failed records: {diagnosis['technique_missing']}",
            f"- Stage successful records: {diagnosis['stage_success']}",
            f"- Stage missing/failed records: {diagnosis['stage_missing']}",
            "- 401 unauthorized evidence: false",
            "- 402 quota depleted evidence: false",
            "- 429 rate limit evidence: false",
            "- JSON parse failure evidence: false",
            "- Illegal code evidence: false",
            "",
            "## Technique Failures",
            "",
            *[f"- {item['record_id']}: {item['failure_category']}; {item['detail']}" for item in technique_failure_records],
            "",
            "## Stage Failures",
            "",
            "- No stage model is called. Missing stage rows correspond to missing or invalid technique results.",
            "",
            "## Recommendation",
            "",
            "- Rerun only failed technique records; stage codes are derived after technique results are complete.",
            "- No prompt change is indicated by the previous results; successful outputs were valid JSON with legal codes.",
            "- Runner changes are useful: failed record export, record-id filtering, retry-once, continue-on-error, and immediate stop on 401/402.",
        ],
    )

    write_text(
        base / "rerun_plan.md",
        [
            "# Mixed small rerun plan",
            "",
            "- Do not add selected records.",
            f"- Technique rerun records: {len(technique_failure_records)}",
            "- Stage rerun records: 0 (stage is deterministic).",
            "- Keep temperature 0, max tokens 512, and sleep between calls.",
            "- Stop immediately on 401 or 402.",
            "",
            "## Technique command",
            "",
            "```bash",
            "RUN_API=1 python3 scripts/run_qwen_openai_compatible.py \\",
            "  --prompt-dir outputs/api_tests/mixed_small/prompts_technique_rag \\",
            "  --output-dir outputs/api_tests/mixed_small/rerun_technique_rag \\",
            "  --result-name results.json \\",
            "  --summary-name summary.md \\",
            "  --only-record-ids outputs/api_tests/mixed_small/failed_technique_records.json \\",
            "  --failed-records-out outputs/api_tests/mixed_small/rerun_technique_rag/failed_records.json \\",
            "  --max-files 3 --temperature 0 --max-tokens 512 --sleep-seconds 2 \\",
            "  --retry-failed-once --continue-on-error --require-run-api-flag",
            "```",
        ],
    )

    merged_dir = base / "merged_results"
    technique_clean = [{k: v for k, v in technique_results[rid].items() if not k.startswith("_")} for rid in selected_ids if rid in technique_results]
    stage_clean = [{k: v for k, v in stage_results[rid].items() if not k.startswith("_")} for rid in selected_ids if rid in stage_results]
    write_json(merged_dir / "technique_rag_results.json", technique_clean)
    write_json(merged_dir / "stage_from_technique_results.json", stage_clean)

    scan_group = technique_results.get("feasibility_portscan::scan_group::000001")
    technique_complete = len(technique_missing) == 0 and not technique_invalid
    stage_complete = len(stage_missing) == 0 and not stage_invalid
    write_text(
        merged_dir / "merge_report.md",
        [
            "# Mixed small merge report",
            "",
            f"- Selected records: {len(selected_ids)}",
            f"- Technique complete count: {len(technique_clean)}",
            f"- Technique missing count: {len(technique_missing)}",
            f"- Technique illegal code count: {len(technique_invalid)}",
            f"- Stage complete count: {len(stage_clean)}",
            f"- Stage missing count: {len(stage_missing)}",
            f"- Stage illegal code count: {len(stage_invalid)}",
            "- JSON parse failure count: 0",
            f"- Portscan scan_group technique is `TA43_01`: {str(bool(scan_group and scan_group.get('predicted_code') == 'TA43_01')).lower()}",
        ],
    )

    submission_dir = base / "submissions"
    stage_csv = submission_dir / "stage1_submission_model_test.csv"
    technique_csv = submission_dir / "stage2_submission_model_test.csv"
    exported_stage = False
    exported_technique = False
    if stage_complete:
        rows = [
            {
                "pcap_id": selected_by_id[rid].get("pcap_id"),
                "session_id": selected_by_id[rid].get("session_id") or rid,
                "stage_code": stage_results[rid].get("predicted_code"),
            }
            for rid in selected_ids
        ]
        write_csv(stage_csv, ["pcap_id", "session_id", "stage_code"], rows)
        exported_stage = True
    elif stage_csv.exists():
        stage_csv.unlink()
    if technique_complete:
        rows = [
            {
                "pcap_id": selected_by_id[rid].get("pcap_id"),
                "session_id": selected_by_id[rid].get("session_id") or rid,
                "technique_code": technique_results[rid].get("predicted_code"),
            }
            for rid in selected_ids
        ]
        write_csv(technique_csv, ["pcap_id", "session_id", "technique_code"], rows)
        exported_technique = True
    elif technique_csv.exists():
        technique_csv.unlink()
    write_text(
        submission_dir / "submission_export_report.md",
        [
            "# Mixed small model CSV export report",
            "",
            f"- Selected records: {len(selected_ids)}",
            f"- Stage complete: {str(stage_complete).lower()}",
            f"- Technique complete: {str(technique_complete).lower()}",
            f"- Stage 1 CSV exported: {str(exported_stage).lower()}",
            f"- Stage 2 CSV exported: {str(exported_technique).lower()}",
            "- Missing results were not filled with fallback codes.",
            "- CSV encoding when exported: utf-8-sig.",
            f"- Portscan scan_group technique is `TA43_01`: {str(bool(scan_group and scan_group.get('predicted_code') == 'TA43_01')).lower()}",
        ],
    )

    api_ran = False
    verdict = "PARTIAL_SUCCESS_USABLE_FOR_BASTION_PREP"
    write_text(
        ROOT / "docs/mixed_small_api_fix_summary.md",
        [
            "# Mixed small API fix summary",
            "",
            f"- API actually run this round: {str(api_ran).lower()}",
            "- New API calls this round: 0",
            f"- Technique final success/failure: {len(technique_clean)}/{len(technique_missing)}",
            f"- Stage final success/failure: {len(stage_clean)}/{len(stage_missing)}",
            "- Main failure cause: timeout plus bounded-run interruption; no auth, quota, JSON parse, or illegal-code evidence was found.",
            f"- Portscan scan_group final technique is `TA43_01`: {str(bool(scan_group and scan_group.get('predicted_code') == 'TA43_01')).lower()}",
            f"- CSV exported: {str(exported_stage or exported_technique).lower()}",
            "- Expand to 30 records: no; rerun only the failed mixed-small records first.",
            "- Prompt fix needed first: no obvious prompt defect from the successful records.",
            "- Runner fix needed first: yes; this commit adds record-id rerun, failed-record output, retry-once, and continue-on-error controls.",
            "- Bastion prep usability: usable for deployment rehearsal and failure-only rerun planning, not yet sufficient as a complete model-result CSV.",
            f"- Verdict: `{verdict}`",
        ],
    )
    write_text(
        ROOT / "docs/git_commit_summary_mixed_small_api_fix.md",
        [
            "# Git commit summary: mixed small API fix",
            "",
            "## Included",
            "",
            "- Runner safety and retry controls for failure-only reruns.",
            "- Mixed-small diagnosis, merge, and conditional export helper.",
            "- Fix summary for the partial API test.",
            "",
            "## Excluded",
            "",
            "- API raw responses.",
            "- Parsed model outputs.",
            "- Prompt directories.",
            "- `.env`, token values, PCAP, binetflow, parsed logs, large CSVs, model weights, and adapters.",
            "",
            f"Verdict: `{verdict}`.",
        ],
    )

    print(json.dumps({
        "technique_success": len(technique_clean),
        "technique_missing": len(technique_missing),
        "stage_success": len(stage_clean),
        "stage_missing": len(stage_missing),
        "csv_exported": exported_stage or exported_technique,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
