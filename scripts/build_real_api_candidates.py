#!/usr/bin/env python3
"""Build tiered public coverage and a balanced real-API candidate set."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TECHNIQUE_CODES = ["TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"]
TECHNIQUE_TO_STAGE = {
    "TA43_01": "TA43", "TA43_02": "TA43", "TA01_01": "TA01", "TA01_02": "TA01",
    "TA03_01": "TA03", "TA11_01": "TA11", "TA11_02": "TA11", "TN01_01": "TN01",
}
TIERS = ["external_high_pcap", "external_high_flow", "external_medium", "external_low", "synthetic_controlled"]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def legacy_tier(row: dict[str, Any]) -> str:
    if row.get("dataset_id") == "controlled_portscan_pcap":
        return "synthetic_controlled"
    confidence = row.get("label_confidence")
    if confidence == "high":
        return "external_high_flow" if row.get("record_type") == "flow_only" else "external_high_pcap"
    return "external_medium" if confidence == "medium" else "external_low"


def clean_record(record: dict[str, Any]) -> dict[str, Any]:
    forbidden = {
        "candidate_hint", "member_session_ids", "expected_technique_code", "technique_code", "stage_code",
        "flow_source", "source_file", "source_label", "dataset_id", "label_confidence", "confidence_level",
    }
    return {key: value for key, value in record.items() if key not in forbidden}


def enrich_public(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    tier = item.get("confidence_level") or legacy_tier(item)
    item["confidence_level"] = tier
    if tier == "synthetic_controlled":
        item["label_confidence"] = "synthetic"
    item["is_pcap_derived"] = item.get("record_type") != "flow_only"
    item["is_flow_only"] = item.get("record_type") == "flow_only"
    item["is_synthetic"] = tier == "synthetic_controlled"
    item["classification_record"] = clean_record(item["classification_record"])
    return item


def refresh_pcap_records(rows: list[dict[str, Any]], records_path: Path) -> list[dict[str, Any]]:
    """Replace stale PCAP-derived evidence with cards rebuilt by the current pipeline."""
    if not records_path.exists():
        return rows
    refreshed = {item["record_id"]: item for item in load_json(records_path)}
    output = []
    for row in rows:
        item = dict(row)
        current = refreshed.get(str(item.get("record_id")))
        if current is not None and item.get("record_type") != "flow_only":
            item["classification_record"] = clean_record(current)
        output.append(item)
    return output


def wireshark_rows(records_path: Path) -> list[dict[str, Any]]:
    source_map = {
        "wireshark_nmap_001_nmap_OS_scan": ("datasets/public/wireshark_nmap/raw/nmap_OS_scan.pcap", "nmap -O -Pn 192.168.100.102"),
        "wireshark_nmap_002_nmap_OS_scan_successful": ("datasets/public/wireshark_nmap/raw/nmap_OS_scan_successful.pcap", "nmap -O -Pn 192.168.100.101"),
        "wireshark_nmap_003_nmap_standard_scan": ("datasets/public/wireshark_nmap/raw/nmap_standard_scan.pcap", "nmap 192.168.100.102"),
    }
    rows = []
    for record in load_json(records_path):
        if record.get("record_type") != "scan_group" or record.get("pcap_id") not in source_map:
            continue
        source_file, command = source_map[record["pcap_id"]]
        rows.append({
            "record_id": record["record_id"], "dataset_id": "wireshark_nmap", "source_file": source_file,
            "source_label": f"Wireshark official SampleCaptures README: {command}", "technique_code": "TA43_01",
            "label_confidence": "high", "confidence_level": "external_high_pcap",
            "record_type": "scan_group", "pcap_id": record["pcap_id"],
            "evidence_summary": f"Official README gives `{command}`; Zeek scan_group has {record.get('unique_dst_ports')} destination ports and failed rate {record.get('failed_conn_rate')}.",
            "notes": "Public Nmap port/OS discovery capture; not a vulnerability-specific NSE/Nikto scan.",
            "is_pcap_derived": True, "is_flow_only": False, "is_synthetic": False,
            "classification_record": clean_record(record),
        })
    if len(rows) != 3:
        raise ValueError(f"expected 3 Wireshark scan groups, got {len(rows)}")
    return rows


def uri_text(record: dict[str, Any]) -> str:
    return json.dumps(record.get("http_summary") or {}, ensure_ascii=False).lower()


def choose_synthetic(records: list[dict[str, Any]], report_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_pcap: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_pcap[record["pcap_id"]].append(record)
    report_by_scenario = {row["scenario_id"]: row for row in report_rows}
    selected = []
    for pcap_id, pcap_records in sorted(by_pcap.items()):
        code = next((code for code in TECHNIQUE_CODES if f"synthetic_{code.lower()}_" in pcap_id), None)
        if not code:
            continue
        scenario_id = next((name for name in report_by_scenario if name in pcap_id), None)
        if not scenario_id:
            raise ValueError(f"no generation report row for {pcap_id}")
        if code == "TA43_01":
            candidates = [row for row in pcap_records if row.get("record_type") == "scan_group"]
        else:
            candidates = [row for row in pcap_records if row.get("record_type") == "session"]
        preference = {
            "TA43_02": ("/nse/http-enum", "/nikto/plugin-check", "/server-status"),
            "TA01_01": ("/login",), "TA01_02": ("cmd=echo", "../", "search?q="),
            "TA03_01": ("/admin/plugin/upload",), "TA11_01": ("/mock-webshell/control",),
            "TA11_02": ("/dummy-c2/heartbeat",), "TN01_01": ("/docs/index.html", "/health",),
        }.get(code, ())
        chosen = None
        for needle in preference:
            chosen = next((row for row in candidates if needle in uri_text(row)), None)
            if chosen:
                break
        chosen = chosen or candidates[0]
        meta = report_by_scenario[scenario_id]
        selected.append({
            "record_id": chosen["record_id"], "dataset_id": "synthetic_controlled",
            "source_file": meta["pcap_path"], "source_label": f"controlled intended label {code}",
            "technique_code": code, "label_confidence": "synthetic", "confidence_level": "synthetic_controlled",
            "record_type": chosen["record_type"], "pcap_id": chosen["pcap_id"],
            "evidence_summary": meta["evidence_summary"], "notes": meta["limitations"],
            "is_pcap_derived": True, "is_flow_only": False, "is_synthetic": True,
            "classification_record": clean_record(chosen),
        })
    counts = Counter(row["technique_code"] for row in selected)
    if any(counts[code] != 3 for code in TECHNIQUE_CODES):
        raise ValueError(f"synthetic selection is not 3/class: {counts}")
    return selected


def candidate_row(row: dict[str, Any], subsets: list[str]) -> dict[str, Any]:
    tier = row["confidence_level"]
    return {
        "record_id": row["record_id"], "pcap_id": row["pcap_id"],
        "source_dataset": row["dataset_id"], "dataset_id": row["dataset_id"],
        "source_type": "synthetic_controlled_pcap" if row["is_synthetic"] else "external_public_flow" if row["is_flow_only"] else "external_public_pcap",
        "intended_technique_code": row["technique_code"], "technique_code": row["technique_code"],
        "mapped_stage_code": TECHNIQUE_TO_STAGE[row["technique_code"]],
        "confidence_level": tier, "label_confidence": row["label_confidence"],
        "is_pcap_derived": row["is_pcap_derived"], "is_flow_only": row["is_flow_only"], "is_synthetic": row["is_synthetic"],
        "record_type": row["record_type"], "source_file": row["source_file"],
        "evidence_summary": row["evidence_summary"], "limitation": row["notes"],
        "recommended_usage": "strict_subset_and_coverage" if "strict_subset" in subsets else "coverage_subset_only",
        "subset_membership": subsets, "classification_record": row["classification_record"],
    }


def strict_evidence_supported(row: dict[str, Any]) -> bool:
    if row.get("confidence_level") not in {"external_high_pcap", "external_high_flow"} or row.get("is_synthetic"):
        return False
    record = row.get("classification_record") or {}
    code = row.get("technique_code")
    if code == "TA01_01":
        auth = record.get("auth_indicators") or {}
        return bool(auth.get("repeated_login_attempts") and auth.get("failed_login_hint"))
    if code == "TA11_02":
        c2 = record.get("c2_indicators") or {}
        return (
            record.get("record_type") == "c2_callback_group"
            and record.get("evidence_tier") == "high_callback_behavioral"
            and float(c2.get("beacon_score") or 0) >= 0.65
        )
    return True


def anonymize_candidates(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pcap_aliases: dict[str, str] = {}
    output = []
    for index, row in enumerate(rows, start=1):
        item = dict(row)
        source_record_id = item["record_id"]
        source_pcap_id = item["pcap_id"]
        pcap_alias = pcap_aliases.setdefault(source_pcap_id, f"realapi_pcap_{len(pcap_aliases) + 1:03d}")
        record_alias = f"realapi_record_{index:03d}"
        classification_record = dict(item["classification_record"])
        classification_record["record_id"] = record_alias
        classification_record["session_id"] = record_alias
        classification_record["pcap_id"] = pcap_alias
        if isinstance(classification_record.get("pcap_summary"), dict):
            classification_record["pcap_summary"] = {**classification_record["pcap_summary"], "pcap_id": pcap_alias}
        classification_record.pop("pcap", None)
        item.update({
            "record_id": record_alias, "pcap_id": pcap_alias,
            "source_record_id": source_record_id, "source_pcap_id": source_pcap_id,
            "classification_record": classification_record,
        })
        output.append(item)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build tiered data completion and real API candidate manifests.")
    parser.add_argument("--coverage-records", type=Path, default=ROOT / "datasets/public_eval/coverage_eval_records.jsonl")
    parser.add_argument("--wireshark-records", type=Path, default=ROOT / "outputs/data_completion/wireshark_nmap_cards/classification_records.json")
    parser.add_argument("--synthetic-records", type=Path, default=ROOT / "outputs/data_completion/synthetic_cards/classification_records.json")
    parser.add_argument("--synthetic-generation-report", type=Path, default=ROOT / "outputs/data_completion/synthetic_generation_report.json")
    parser.add_argument(
        "--refreshed-pcap-records", type=Path,
        default=ROOT / "outputs/zeek_rebuild/classification_records/classification_records_all.json",
    )
    parser.add_argument("--output-dir", type=Path, default=ROOT / "datasets/public_eval")
    args = parser.parse_args()

    existing = [enrich_public(row) for row in load_jsonl(args.coverage_records) if row.get("dataset_id") != "wireshark_nmap"]
    existing = refresh_pcap_records(existing, args.refreshed_pcap_records)
    external_new = wireshark_rows(args.wireshark_records)
    public_rows = existing + external_new
    write_jsonl(args.coverage_records, public_rows)
    coverage_fields = [
        "record_id", "dataset_id", "source_file", "source_label", "technique_code", "label_confidence",
        "confidence_level", "record_type", "pcap_id", "is_pcap_derived", "is_flow_only", "is_synthetic",
        "evidence_summary", "notes", "evaluation_tier",
    ]
    coverage_manifest = []
    for row in public_rows:
        strict = row["confidence_level"] in {"external_high_pcap", "external_high_flow"}
        coverage_manifest.append({**row, "evaluation_tier": "strict_external" if strict else "coverage_only"})
    write_csv(args.output_dir / "coverage_eval_manifest.csv", coverage_fields, coverage_manifest)

    generation_rows = load_json(args.synthetic_generation_report)
    generation_rows.append({
        "scenario_id": "feasibility_portscan_local", "intended_label": "TA43_01", "variant": 0,
        "pcap_path": "datasets/public/feasibility/raw/portscan/generated_nmap_local_scan.pcap",
        "bytes": 95168, "sha256": "b32b5f8bdf170ec9c6ea42e12932ce63f51e9b752f99207dd632be6c9f456a7a",
        "generation_script": "historical controlled Python TCP-connect fixture",
        "evidence_summary": "Controlled localhost scan_group with 181 unique destination ports.",
        "safety_notes": "localhost only; no public target",
        "limitations": "synthetic_controlled historical fixture; never external or strict evidence",
    })
    synthetic_manifest_fields = [
        "scenario_id", "intended_label", "variant", "pcap_path", "bytes", "sha256", "generation_script",
        "evidence_summary", "safety_notes", "limitations",
    ]
    write_csv(ROOT / "datasets/metadata/synthetic_controlled_manifest.csv", synthetic_manifest_fields, generation_rows)
    synthetic_rows = choose_synthetic(load_json(args.synthetic_records), [row for row in generation_rows if row["variant"] != 0])

    by_code: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in public_rows:
        by_code[row["technique_code"]].append(row)
    synthetic_by_code: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in synthetic_rows:
        synthetic_by_code[row["technique_code"]].append(row)
    candidates = []
    for code in TECHNIQUE_CODES:
        strict_rows = [row for row in by_code[code] if row["confidence_level"] in {"external_high_pcap", "external_high_flow"} and not row["is_synthetic"]]
        strict_rows.sort(key=lambda row: (row["dataset_id"], row["record_id"]))
        chosen = strict_rows[:3]
        if len(chosen) < 3:
            medium_rows = sorted([row for row in by_code[code] if row["confidence_level"] == "external_medium"], key=lambda row: row["record_id"])
            chosen.extend(medium_rows[: 3 - len(chosen)])
        if len(chosen) < 3:
            chosen.extend(sorted(synthetic_by_code[code], key=lambda row: row["record_id"])[: 3 - len(chosen)])
        if len(chosen) != 3:
            raise ValueError(f"could not select 3 records for {code}")
        for row in chosen:
            strict = strict_evidence_supported(row)
            candidates.append(candidate_row(row, ["coverage_subset", "strict_subset"] if strict else ["coverage_subset"]))

    candidates = anonymize_candidates(candidates)
    write_jsonl(args.output_dir / "real_api_candidate_records.jsonl", candidates)
    candidate_fields = [
        "record_id", "pcap_id", "source_record_id", "source_pcap_id", "source_dataset", "source_type", "intended_technique_code", "mapped_stage_code",
        "confidence_level", "is_pcap_derived", "is_flow_only", "is_synthetic", "evidence_summary", "limitation",
        "recommended_usage", "subset_membership",
    ]
    manifest_rows = [{**row, "subset_membership": "|".join(row["subset_membership"])} for row in candidates]
    write_csv(args.output_dir / "real_api_candidate_manifest.csv", candidate_fields, manifest_rows)

    counts = Counter((row["intended_technique_code"], row["confidence_level"]) for row in candidates)
    strict_count = sum("strict_subset" in row["subset_membership"] for row in candidates)
    lines = [
        "# Real API candidate selection", "", "This is a readiness set, not proof of final model quality.", "",
        f"- Coverage subset: {len(candidates)} records, exactly 3 per technique.",
        f"- Strict subset: {strict_count} external-high records only.",
        "- Medium and synthetic rows are coverage-only and must never enter strict metrics.", "",
        "| Technique | Tier | Count |", "|---|---|---:|",
    ]
    for (code, tier), count in sorted(counts.items()):
        lines.append(f"| `{code}` | `{tier}` | {count} |")
    lines.extend(["", "## Selection policy", "", "- Prefer external high PCAP, then external high flow.", "- Use external medium only when no high source covers the class.", "- Use synthetic controlled only to expose a missing boundary shape.", "- Model-visible record/PCAP IDs are stable opaque aliases; semantic source IDs remain audit-only fields outside `classification_record`.", "- PCAP relationships are preserved through one alias per source PCAP; three synthetic variants are different captures."])
    (ROOT / "docs/reports/real_api_candidate_selection.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"coverage_records": len(public_rows), "real_api_candidates": len(candidates), "strict_subset": strict_count, "candidate_counts": {f"{code}:{tier}": count for (code, tier), count in sorted(counts.items())}}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
