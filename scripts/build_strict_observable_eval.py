#!/usr/bin/env python3
"""Build an evidence-first strict observable-v3 evaluation set."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TECHNIQUE_TO_STAGE = {
    "TA43_01": "TA43", "TA43_02": "TA43", "TA01_01": "TA01", "TA01_02": "TA01",
    "TA03_01": "TA03", "TA11_01": "TA11", "TA11_02": "TA11", "TN01_01": "TN01",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def endpoint_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("SrcAddr") or row.get("src_ip") or ""),
        str(row.get("DstAddr") or row.get("dst_ip") or ""),
        str(row.get("Dport") or row.get("dst_port") or ""),
        str(row.get("Proto") or row.get("proto") or "").lower(),
    )


def explicit_c2_labels(path: Path) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            label = str(row.get("Label") or "")
            if label.startswith("flow=From-Botnet") and "-TCP-CC" in label:
                grouped[endpoint_key(row)].append(row)
    output = {}
    for key, rows in grouped.items():
        labels = Counter(str(row.get("Label")) for row in rows)
        output[key] = {
            "label_count": len(rows), "labels": dict(labels),
            "primary_label": labels.most_common(1)[0][0],
        }
    return output


def clean_group_record(record: dict[str, Any], record_id: str, pcap_id: str) -> dict[str, Any]:
    forbidden = {"member_session_ids", "candidate_hint", "technique_code", "stage_code", "expected_technique_code"}
    cleaned = {key: value for key, value in record.items() if key not in forbidden}
    cleaned.update({"record_id": record_id, "session_id": record_id, "c2_group_id": record_id, "pcap_id": pcap_id})
    return cleaned


def candidate(
    record_id: str, pcap_id: str, dataset_id: str, code: str, record_type: str,
    confidence_level: str, evidence_tier: str, evidence_summary: str,
    why_label_trusted: str, limitation: str, classification_record: dict[str, Any],
) -> dict[str, Any]:
    is_flow = record_type == "flow_only"
    return {
        "record_id": record_id, "pcap_id": pcap_id, "dataset_id": dataset_id,
        "source_dataset": dataset_id, "technique_code": code,
        "intended_technique_code": code, "mapped_stage_code": TECHNIQUE_TO_STAGE[code],
        "label_confidence": "high", "confidence_level": confidence_level,
        "evidence_tier": evidence_tier, "record_type": record_type,
        "is_pcap_derived": not is_flow, "is_flow_only": is_flow, "is_synthetic": False,
        "evidence_summary": evidence_summary, "why_label_trusted": why_label_trusted,
        "limitation": limitation, "subset_membership": ["strict_subset"],
        "recommended_usage": "strict_observable_v3", "classification_record": classification_record,
    }


def select_c2_groups(configs: list[tuple[str, Path, Path]], limit: int) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    eligible: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for dataset_id, groups_path, labels_path in configs:
        labels = explicit_c2_labels(labels_path)
        for group in load_json(groups_path):
            label = labels.get(endpoint_key(group))
            if not label or label["label_count"] < 5 or int(group.get("connection_count") or 0) < 5:
                continue
            if float(group.get("beacon_score") or 0) < 0.45:
                continue
            if group.get("evidence_tier") != "high_callback_behavioral":
                continue
            eligible.append((dataset_id, group, label))
    eligible.sort(key=lambda item: (float(item[1].get("beacon_score") or 0), item[2]["label_count"]), reverse=True)
    selected: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    seen_labels: set[str] = set()
    for item in eligible:
        label = item[2]["primary_label"]
        if label in seen_labels:
            continue
        selected.append(item)
        seen_labels.add(label)
        if len(selected) >= limit:
            break
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Build strict observable-v3 records without weak-label balancing.")
    parser.add_argument("--base-candidates", type=Path, default=ROOT / "datasets/public_eval/real_api_candidate_records.jsonl")
    parser.add_argument("--scenario1-c2-groups", type=Path, default=ROOT / "outputs/strict_observable_v3/scenario1_c2_groups.json")
    parser.add_argument("--scenario1-labels", type=Path, default=ROOT / "datasets/public/ctu13/labels/capture20110810.binetflow")
    parser.add_argument("--scenario6-c2-groups", type=Path, default=ROOT / "outputs/strict_observable_v3/scenario6_c2_groups.json")
    parser.add_argument("--scenario6-labels", type=Path, default=ROOT / "datasets/public/ctu13/labels/capture20110816.binetflow.2format")
    parser.add_argument("--output", type=Path, default=ROOT / "datasets/public_eval/strict_observable_v3_records.jsonl")
    parser.add_argument("--manifest", type=Path, default=ROOT / "datasets/public_eval/strict_observable_v3_manifest.csv")
    parser.add_argument("--exclusions", type=Path, default=ROOT / "datasets/public_eval/strict_observable_v3_exclusions.csv")
    parser.add_argument("--report", type=Path, default=ROOT / "docs/reports/strict_observable_v3_selection.md")
    args = parser.parse_args()

    base = load_jsonl(args.base_candidates)
    selected: list[dict[str, Any]] = []
    pcap_aliases: dict[str, str] = {}
    for code, tier in (("TA43_01", "high_confidence_pcap_scan_group"), ("TN01_01", "high_confidence_flow_secondary")):
        rows = [row for row in base if row["technique_code"] == code and "strict_subset" in row.get("subset_membership", [])][:3]
        for index, row in enumerate(rows, start=1):
            record_id = f"strict_v3_{code.lower()}_{index:03d}"
            pcap_id = pcap_aliases.setdefault(row["pcap_id"], f"strict_v3_pcap_{len(pcap_aliases) + 1:03d}")
            visible = dict(row["classification_record"])
            visible.update({"record_id": record_id, "session_id": record_id, "pcap_id": pcap_id})
            if isinstance(visible.get("pcap_summary"), dict):
                visible["pcap_summary"] = {**visible["pcap_summary"], "pcap_id": pcap_id}
            why = "Official Wireshark Nmap capture plus approximately 1,000-port failed scan group." if code == "TA43_01" else "Public benign flow label agrees with a single flow that has no observable attack pattern."
            limitation = row.get("limitation") or row.get("notes") or ""
            selected.append(candidate(
                record_id, pcap_id, str(row.get("dataset_id")), code, str(row["record_type"]),
                str(row["confidence_level"]), tier, str(row.get("evidence_summary") or ""), why, limitation, visible,
            ))

    c2_configs = [
        ("ctu13_scenario1", args.scenario1_c2_groups, args.scenario1_labels),
        ("ctu13_scenario6", args.scenario6_c2_groups, args.scenario6_labels),
    ]
    c2_selected = select_c2_groups(c2_configs, 3)
    for index, (dataset_id, group, label) in enumerate(c2_selected, start=1):
        record_id = f"strict_v3_ta11_02_{index:03d}"
        pcap_id = pcap_aliases.setdefault(group["pcap_id"], f"strict_v3_pcap_{len(pcap_aliases) + 1:03d}")
        summary = (
            f"{group['connection_count']} source-initiated connections to one endpoint; "
            f"beacon_score={group['beacon_score']}, periodicity_score={group['periodicity_score']}."
        )
        trusted = (
            f"PCAP endpoint behavior matches {label['label_count']} public bidirectional flows explicitly labeled "
            f"{label['primary_label'].removeprefix('flow=')}."
        )
        selected.append(candidate(
            record_id, pcap_id, dataset_id, "TA11_02", "c2_callback_group", "external_high_pcap",
            "high_confidence_pcap_callback_group", summary, trusted,
            "Groups from one infected-host capture are correlated and are not independent malware families.",
            clean_group_record(group, record_id, pcap_id),
        ))

    order = {code: index for index, code in enumerate(TECHNIQUE_TO_STAGE)}
    selected.sort(key=lambda row: (order[row["technique_code"]], row["record_id"]))
    write_jsonl(args.output, selected)
    manifest_fields = [
        "record_id", "pcap_id", "dataset_id", "technique_code", "mapped_stage_code", "record_type",
        "confidence_level", "evidence_tier", "evidence_summary", "why_label_trusted", "limitation",
        "is_pcap_derived", "is_flow_only", "is_synthetic",
    ]
    write_csv(args.manifest, selected, manifest_fields)

    exclusions = []
    for row in base:
        if row["technique_code"] == "TA01_01" and row.get("confidence_level") == "external_high_flow":
            exclusions.append({
                "record_id": row["record_id"], "old_code": "TA01_01", "action": "remove_from_strict",
                "new_evidence_tier": "weak_auth_evidence", "reason": "Flow-only row lacks endpoint identity, repeated attempts, USER/PASS, and explicit authentication failures.",
            })
        if row["technique_code"] == "TA11_02" and row.get("confidence_level") == "external_high_pcap":
            exclusions.append({
                "record_id": row["record_id"], "old_code": "TA11_02", "action": "replace_with_group",
                "new_evidence_tier": "session_label_granularity_mismatch", "reason": "Single Google Update/WPAD/DNS session lacks callback evidence despite broad From-Botnet source labeling.",
            })
    write_csv(args.exclusions, exclusions, ["record_id", "old_code", "action", "new_evidence_tier", "reason"])

    counts = Counter((row["technique_code"], row["evidence_tier"]) for row in selected)
    lines = [
        "# Strict observable-v3 selection", "",
        "Evidence quality takes priority over class balance.", "",
        f"- Strict records: {len(selected)}", f"- Excluded old weak/misaligned records: {len(exclusions)}",
        "- TA01_01 strict count: 0; current flow-only source cannot prove repeated authentication failures.",
        "- Synthetic and external-medium rows: 0.", "", "| Technique | Evidence tier | Count |", "|---|---|---:|",
    ]
    for (code, tier), count in sorted(counts.items()):
        lines.append(f"| `{code}` | `{tier}` | {count} |")
    lines.extend(["", "## C2 group policy", ""])
    for row in selected:
        if row["technique_code"] == "TA11_02":
            lines.append(f"- `{row['record_id']}`: {row['evidence_summary']} {row['why_label_trusted']}")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"strict_records": len(selected), "counts": {f"{code}:{tier}": count for (code, tier), count in sorted(counts.items())}, "exclusions": len(exclusions)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
