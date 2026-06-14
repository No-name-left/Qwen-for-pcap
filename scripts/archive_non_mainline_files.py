#!/usr/bin/env python3
"""Archive non-mainline PCAP-LLM project files.

The script is intentionally conservative:
- dry-run writes candidate reports but moves nothing;
- apply moves only candidates marked as certain non-mainline;
- uncertain files are reported but left in place;
- protected current-mainline paths are never moved.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable


ARCHIVE_DIR = "_non_mainline_archive"

ARCHIVE_SUBDIRS = [
    "legacy_qwen14b",
    "legacy_qwen35_event_level",
    "legacy_event_card_pipeline",
    "old_prompts",
    "partial_runs",
    "old_reports",
    "old_docs",
    "old_scripts",
    "uncertain_need_review",
]

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".py",
    ".csv",
}

PROTECTED_PREFIXES = {
    ".git/",
    f"{ARCHIVE_DIR}/",
    "datasets/",
    "outputs/parsed/",
    "outputs/session_cards/",
    "outputs/rag_queries/",
    "outputs/rag_retrieval/",
    "outputs/submissions/",
    "rag/knowledge/",
    "rag/sources/",
}

PROTECTED_EXACT = {
    "README.md",
    "configs/competition_label_schema.yaml",
    "configs/llm_qwen35_27b.yaml",
    "docs/current_task_definition.md",
    "docs/project_paths.md",
    "docs/project_context_migration_scan_report.md",
    "docs/task_context_update_summary.md",
    "docs/project_structure_after_archive.md",
    "docs/non_mainline_archive_summary.md",
    "rag/README.md",
    "rag/chunks/README.md",
    "rag/chunks/rag_chunks.jsonl",
    "rag/index/README.md",
    "rag/index/keyword_index.json",
    "rag/metadata/rag_manifest.csv",
    "rag/metadata/source_manifest.csv",
    "rag/metadata/retrieval_test_queries.jsonl",
    "rag/reports/rag_final_coverage_review.md",
    "rag/reports/rag_fact_check_report.md",
    "rag/reports/rag_source_grounding_report.md",
    "scripts/archive_non_mainline_files.py",
    "scripts/build_session_cards.py",
    "scripts/build_qwen35_session_test_set.py",
    "scripts/build_qwen35_session_prompts.py",
    "scripts/export_competition_csv.py",
    "scripts/build_rag_chunks.py",
    "scripts/build_keyword_index.py",
    "scripts/build_rag_query.py",
    "scripts/retrieve_rag.py",
    "scripts/test_rag_retrieval.py",
    "scripts/run_qwen_openai_compatible.py",
    "scripts/qwen35_rag_utils.py",
    "scripts/parse_public_pcaps.py",
    "scripts/build_parse_summary.py",
    "scripts/rag_README_NEXT_STEPS.md",
}

REFERENCE_SCAN_PREFIXES = ("README.md", "docs/", "scripts/")

QWEN14_PATTERNS = [
    "qwen3_14b",
    "qwen14b",
    "qwen3-14b",
    "qwen14b",
]

QWEN35_EVENT_PATTERNS = [
    "qwen35_27b_no_rag",
    "qwen35_27b_rag",
    "prompts_qwen35_27b_no_rag",
    "prompts_qwen35_27b_rag",
    "llm_results_qwen35_27b_no_rag",
    "llm_results_qwen35_27b_rag",
]

EVENT_PIPELINE_PATTERNS = [
    "event_cards",
    "llm_event_cards_all",
    "public_event_cards",
    "llm_event_label_map",
    "llm_event_id_map",
    "public_event_labels",
    "event_card.schema",
    "llm_output.schema",
    "attack_taxonomy",
]

OLD_RESULT_PATTERNS = [
    "raw_batch_",
    "parsed_batch_",
    "qwen3_14b_test_result",
    "rag_ablation_comparison",
    "qwen35_27b_no_rag_result.json",
    "qwen35_27b_rag_result.json",
]

LEGACY_CONTENT_PATTERNS = [
    "attack_type",
    "attack_stage",
    "event_results",
    "pcap_summary",
    "event-level",
    "event card",
    "normal, port_scan",
    "trojan_callback",
    "other_attack",
    "json classification",
]


@dataclass
class Candidate:
    original_path: str
    suggested_subdir: str
    reason: str
    certainty: str
    reference_risk: bool
    references: list[str]
    file_type: str
    planned_new_path: str | None = None
    moved: bool = False
    new_path: str | None = None
    timestamp: str | None = None
    note: str = ""


def relpath(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def is_protected(rel: str) -> bool:
    if rel in PROTECTED_EXACT:
        return True
    return any(rel.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def is_text_like(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS


def safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def contains_any(haystack: str, needles: Iterable[str]) -> list[str]:
    low = haystack.lower()
    return [needle for needle in needles if needle.lower() in low]


def classify(path: Path, root: Path) -> tuple[str, str, str] | None:
    rel = relpath(path, root)
    low_rel = rel.lower()
    text = safe_read_text(path).lower() if is_text_like(path) else ""

    if is_protected(rel):
        return None

    if rel.startswith("微型test_v1/"):
        return (
            "legacy_event_card_pipeline",
            "legacy micro demo directory from the pre-session-card pipeline",
            "yes",
        )

    if rel.startswith("outputs/archive/legacy_qwen14b") or contains_any(low_rel, QWEN14_PATTERNS):
        return ("legacy_qwen14b", "Qwen3-14B legacy prompt/result/script/report", "yes")

    if "prompts" in low_rel and contains_any(low_rel, QWEN35_EVENT_PATTERNS + QWEN14_PATTERNS):
        return ("old_prompts", "legacy prompt directory not aligned with session-level CSV output", "yes")

    if contains_any(low_rel, OLD_RESULT_PATTERNS) or "llm_results_qwen35_27b" in low_rel:
        return ("partial_runs", "legacy or partial run result", "yes")

    if rel.startswith("outputs/archive/qwen35_27b"):
        return ("partial_runs", "archived Qwen3.5 event-level or partial run", "yes")

    if rel.startswith("微型test_v2/outputs/prompts_qwen35_27b"):
        return ("old_prompts", "legacy Qwen3.5 event-level prompt", "yes")

    if rel.startswith("微型test_v2/outputs/llm_results_qwen35_27b"):
        return ("partial_runs", "legacy Qwen3.5 event-level result", "yes")

    if rel.startswith("微型test_v2/outputs/rag_eval_qwen35_27b"):
        return ("partial_runs", "legacy event-level RAG ablation/evaluation output", "yes")

    if rel.startswith("微型test_v2/outputs/event_cards/") or rel.startswith("outputs/event_cards/"):
        return ("legacy_event_card_pipeline", "legacy event-card output", "yes")

    if rel.startswith("outputs/evaluation/"):
        return ("legacy_event_card_pipeline", "legacy event-card evaluation/mapping output", "yes")

    if rel.startswith("schemas/") and contains_any(low_rel, EVENT_PIPELINE_PATTERNS):
        return ("legacy_event_card_pipeline", "legacy event-card or JSON-output schema", "yes")

    if rel == "configs/attack_taxonomy.yaml":
        return ("legacy_event_card_pipeline", "legacy attack_type / attack_stage taxonomy", "yes")

    if rel == "scripts/build_event_cards.py":
        return ("old_scripts", "legacy event-card builder script", "yes")

    if rel in {
        "scripts/build_qwen35_27b_no_rag_prompt.py",
        "scripts/build_rag_augmented_prompt.py",
        "scripts/compare_rag_vs_no_rag.py",
    }:
        return ("old_scripts", "legacy event-level Qwen3.5 prompt/evaluation script", "yes")

    if rel.startswith("rag/reports/"):
        if rel in PROTECTED_EXACT:
            return None
        return ("old_reports", "non-final historical RAG/Qwen report", "yes")

    if rel.startswith("outputs/archive/"):
        if "qwen35_27b" in low_rel:
            return ("partial_runs", "historical Qwen3.5 archived run", "yes")
        return ("old_reports", "old archive content under outputs/archive", "yes")

    if rel.startswith("scripts/") and path.suffix.lower() == ".py":
        if contains_any(low_rel + "\n" + text, QWEN35_EVENT_PATTERNS + QWEN14_PATTERNS + LEGACY_CONTENT_PATTERNS):
            return ("old_scripts", "script contains legacy model/event-level/JSON-output terms", "yes")
        return ("uncertain_need_review", "non-whitelisted script; left for manual review", "uncertain")

    if rel.startswith("docs/"):
        if contains_any(text, ["event-level json pipeline", "qwen3-14b"]) and rel not in PROTECTED_EXACT:
            return ("old_docs", "old documentation conflicts with current session-level CSV mainline", "yes")
        return None

    if rel.endswith((".md", ".txt")) and contains_any(low_rel + "\n" + text, QWEN14_PATTERNS):
        return ("legacy_qwen14b", "documentation or prompt mentions Qwen3-14B legacy work", "yes")

    if is_text_like(path) and contains_any(low_rel + "\n" + text, QWEN35_EVENT_PATTERNS):
        return ("legacy_qwen35_event_level", "legacy Qwen3.5 event-level artifact", "yes")

    return None


def build_reference_index(root: Path) -> dict[str, str]:
    index: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = relpath(path, root)
        if rel.startswith(f"{ARCHIVE_DIR}/"):
            continue
        if not rel.startswith(REFERENCE_SCAN_PREFIXES):
            continue
        if not is_text_like(path):
            continue
        index[rel] = safe_read_text(path)
    return index


def find_references(candidate_rel: str, reference_index: dict[str, str]) -> list[str]:
    basename = Path(candidate_rel).name
    probes = {candidate_rel, basename}
    stem = Path(candidate_rel).stem
    if len(stem) > 5:
        probes.add(stem)
    refs = []
    for rel, text in reference_index.items():
        if rel == candidate_rel:
            continue
        for probe in probes:
            if probe and probe in text:
                refs.append(rel)
                break
    return sorted(set(refs))


def archive_destination(root: Path, rel: str, subdir: str) -> Path:
    dest = root / ARCHIVE_DIR / subdir / rel
    if not dest.exists():
        return dest
    stem = dest.stem
    suffix = dest.suffix
    parent = dest.parent
    i = 1
    while True:
        alt = parent / f"{stem}__archived_{i}{suffix}"
        if not alt.exists():
            return alt
        i += 1


def collect_candidates(root: Path) -> list[Candidate]:
    refs = build_reference_index(root)
    candidates: list[Candidate] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = relpath(path, root)
        if rel.startswith(f"{ARCHIVE_DIR}/"):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and not any(token in rel.lower() for token in ["prompt", "llm_results", "archive"]):
            continue
        classification = classify(path, root)
        if classification is None:
            continue
        subdir, reason, certainty = classification
        references = find_references(rel, refs)
        planned = archive_destination(root, rel, subdir)
        candidates.append(
            Candidate(
                original_path=rel,
                suggested_subdir=subdir,
                reason=reason,
                certainty="yes" if certainty == "yes" else "uncertain",
                reference_risk=bool(references),
                references=references,
                file_type=path.suffix.lower().lstrip(".") or "file",
                planned_new_path=relpath(planned, root),
            )
        )
    return candidates


def ensure_archive_dirs(root: Path) -> None:
    for subdir in ARCHIVE_SUBDIRS:
        (root / ARCHIVE_DIR / subdir).mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_dry_run_reports(root: Path, candidates: list[Candidate]) -> None:
    archive = root / ARCHIVE_DIR
    write_json(archive / "dry_run_candidates.json", [asdict(c) for c in candidates])
    counts = Counter(c.suggested_subdir for c in candidates)
    uncertain = sum(1 for c in candidates if c.certainty != "yes")
    lines = [
        "# Dry-run Non-mainline Archive Candidates",
        "",
        f"Generated at: {datetime.now().isoformat(timespec='seconds')}",
        f"Candidate count: {len(candidates)}",
        f"Certain non-mainline: {len(candidates) - uncertain}",
        f"Uncertain / needs review: {uncertain}",
        "",
        "## Counts by Suggested Subdirectory",
        "",
    ]
    for subdir, count in sorted(counts.items()):
        lines.append(f"- `{subdir}`: {count}")
    lines.extend(["", "## Candidates", ""])
    for c in candidates:
        refs = ", ".join(f"`{r}`" for r in c.references) if c.references else "none"
        lines.extend(
            [
                f"### `{c.original_path}`",
                "",
                f"- Suggested subdir: `{c.suggested_subdir}`",
                f"- Planned path: `{c.planned_new_path}`",
                f"- Reason: {c.reason}",
                f"- Certain non-mainline: {c.certainty}",
                f"- Reference risk: {'yes' if c.reference_risk else 'no'}",
                f"- References: {refs}",
                "",
            ]
        )
    (archive / "dry_run_candidates.md").write_text("\n".join(lines), encoding="utf-8")


def apply_archive(root: Path, candidates: list[Candidate]) -> list[Candidate]:
    moved: list[Candidate] = []
    timestamp = datetime.now().isoformat(timespec="seconds")
    for c in candidates:
        if c.certainty != "yes":
            c.note = "uncertain candidate left in place"
            continue
        source = root / c.original_path
        if not source.exists():
            c.note = "source missing at apply time"
            continue
        dest = archive_destination(root, c.original_path, c.suggested_subdir)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(dest))
        c.moved = True
        c.new_path = relpath(dest, root)
        c.timestamp = timestamp
        moved.append(c)
    return moved


def write_archive_manifest(root: Path, moved: list[Candidate]) -> None:
    archive = root / ARCHIVE_DIR
    write_json(archive / "archive_manifest.json", [asdict(c) for c in moved])
    counts = Counter(c.suggested_subdir for c in moved)
    lines = [
        "# Non-mainline Archive Manifest",
        "",
        f"Generated at: {datetime.now().isoformat(timespec='seconds')}",
        f"Moved file count: {len(moved)}",
        "",
        "## Counts by Subdirectory",
        "",
    ]
    for subdir, count in sorted(counts.items()):
        lines.append(f"- `{subdir}`: {count}")
    lines.extend(["", "## Moved Files", ""])
    for c in moved:
        lines.extend(
            [
                f"### `{c.original_path}`",
                "",
                f"- New path: `{c.new_path}`",
                f"- File type: `{c.file_type}`",
                f"- Reason: {c.reason}",
                f"- Timestamp: {c.timestamp}",
                f"- Certain: {c.certainty}",
                f"- Reference risk: {'yes' if c.reference_risk else 'no'}",
                f"- References: {', '.join(c.references) if c.references else 'none'}",
                f"- Note: {c.note or 'moved'}",
                "",
            ]
        )
    (archive / "archive_manifest.md").write_text("\n".join(lines), encoding="utf-8")


def exists_status(root: Path, rels: Iterable[str]) -> list[dict[str, str | bool]]:
    rows = []
    for rel in rels:
        path = root / rel
        rows.append(
            {
                "path": rel,
                "exists": path.exists(),
                "type": "dir" if path.is_dir() else "file" if path.is_file() else "",
            }
        )
    return rows


def remaining_suspects(root: Path) -> list[str]:
    candidates = collect_candidates(root)
    return [c.original_path for c in candidates]


def write_health_report(root: Path, moved: list[Candidate], dry_run_count: int, uncertain_count: int) -> None:
    docs = root / "docs"
    docs.mkdir(exist_ok=True)
    mainline = [
        "rag/knowledge",
        "rag/chunks/rag_chunks.jsonl",
        "rag/index/keyword_index.json",
        "rag/metadata/source_manifest.csv",
        "rag/metadata/rag_manifest.csv",
        "configs/competition_label_schema.yaml",
        "configs/llm_qwen35_27b.yaml",
        "docs/current_task_definition.md",
        "docs/project_paths.md",
        "outputs/session_cards",
        "outputs/submissions",
        "scripts/build_session_cards.py",
        "scripts/build_qwen35_session_test_set.py",
        "scripts/build_qwen35_session_prompts.py",
        "scripts/export_competition_csv.py",
    ]
    statuses = exists_status(root, mainline)
    suspects = remaining_suspects(root)
    test_dirs = sorted(p.name for p in root.iterdir() if p.is_dir() and "test" in p.name)
    counts = Counter(c.suggested_subdir for c in moved)
    lines = [
        "# Project Structure After Non-mainline Archive",
        "",
        f"Generated at: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "## Current Mainline Structure",
        "",
        "```text",
        "PCAP",
        "-> tshark / Zeek / Suricata parsing",
        "-> sessionization / session card",
        "-> deterministic RAG query builder",
        "-> RAG retriever",
        "-> Qwen3.5-27B session-level classification",
        "-> stage / technique code prediction",
        "-> competition CSV submission",
        "-> human-readable analysis report",
        "```",
        "",
        "## Archived Content Overview",
        "",
        f"- Dry-run candidates before apply: {dry_run_count}",
        f"- Actually moved files: {len(moved)}",
        f"- Uncertain candidates left in place: {uncertain_count}",
    ]
    for subdir, count in sorted(counts.items()):
        lines.append(f"- `{subdir}`: {count}")
    lines.extend(["", "## Mainline Must-exist Check", ""])
    for row in statuses:
        lines.append(f"- `{row['path']}`: {'exists' if row['exists'] else 'missing / not generated yet'}")
    lines.extend(["", "## Remaining Suspected Legacy Files", ""])
    if suspects:
        for rel in suspects[:200]:
            lines.append(f"- `{rel}`")
        if len(suspects) > 200:
            lines.append(f"- ... {len(suspects) - 200} more")
    else:
        lines.append("- None detected by the archive script.")
    lines.extend(["", "## Micro-test Directory Naming", ""])
    lines.append(f"- Detected test-like top-level dirs: {', '.join(f'`{d}`' for d in test_dirs) if test_dirs else 'none'}")
    if "微型testv2" in test_dirs and "微型test_v2" in test_dirs:
        lines.append("- Both `微型testv2` and `微型test_v2` exist; unify naming later.")
    elif "微型test_v2" in test_dirs:
        lines.append("- Only `微型test_v2` exists after archive; keep this spelling for future work.")
    elif "微型testv2" in test_dirs:
        lines.append("- Only `微型testv2` exists; consider renaming to `微型test_v2` for consistency.")
    else:
        lines.append("- No active micro-test directory remains at top level.")
    lines.extend(["", "## Recommendation", ""])
    lines.append("Keep current mainline files in place and implement missing session-card, prompt, and CSV exporter scripts before formal runs.")
    (docs / "project_structure_after_archive.md").write_text("\n".join(lines), encoding="utf-8")


def write_summary(root: Path, moved: list[Candidate], dry_run_count: int, uncertain_count: int, candidates: list[Candidate]) -> None:
    docs = root / "docs"
    docs.mkdir(exist_ok=True)
    counts = Counter(c.suggested_subdir for c in moved)
    mainline_status = exists_status(
        root,
        [
            "rag/knowledge",
            "rag/chunks/rag_chunks.jsonl",
            "rag/index/keyword_index.json",
            "rag/metadata/source_manifest.csv",
            "configs/competition_label_schema.yaml",
            "docs/current_task_definition.md",
        ],
    )
    missing_mainline = [row["path"] for row in mainline_status if not row["exists"]]
    reference_risk = [c for c in candidates if c.reference_risk]
    test_dirs = sorted(p.name for p in root.iterdir() if p.is_dir() and "test" in p.name)
    verdict = "NON_MAINLINE_ARCHIVE_COMPLETED" if moved and not missing_mainline else "PARTIAL_ARCHIVE_NEEDS_REVIEW"
    lines = [
        "# Non-mainline Archive Summary",
        "",
        f"Generated at: {datetime.now().isoformat(timespec='seconds')}",
        "",
        f"1. Dry-run candidate count: {dry_run_count}",
        f"2. Actual archived file count: {len(moved)}",
        "3. Counts by archive subdirectory:",
    ]
    for subdir in ARCHIVE_SUBDIRS:
        lines.append(f"   - `{subdir}`: {counts.get(subdir, 0)}")
    lines.extend(
        [
            f"4. Mainline files complete: {'yes' if not missing_mainline else 'no'}",
            f"5. Uncertain files requiring manual review: {uncertain_count}",
            f"6. Potential path-reference risks: {len(reference_risk)}",
            f"7. Micro-test directory mix: {', '.join(test_dirs) if test_dirs else 'none'}",
            "",
            "## Reference Risk Notes",
            "",
        ]
    )
    if reference_risk:
        for c in reference_risk[:100]:
            lines.append(f"- `{c.original_path}` referenced by: {', '.join(c.references)}")
        if len(reference_risk) > 100:
            lines.append(f"- ... {len(reference_risk) - 100} more")
    else:
        lines.append("- No moved/flagged file references detected in README/docs/scripts scan.")
    lines.extend(
        [
            "",
            "## Next Steps",
            "",
            "- Review `archive_manifest.md` for moved files with reference risk.",
            "- Implement or confirm session-card generation and competition CSV export scripts.",
            "- Keep legacy artifacts in `_non_mainline_archive/` unless a specific file is needed for migration.",
            "",
            "## Clear Verdict",
            "",
            f"`{verdict}`",
        ]
    )
    (docs / "non_mainline_archive_summary.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    ensure_archive_dirs(root)
    candidates = collect_candidates(root)
    write_dry_run_reports(root, candidates)

    if args.dry_run:
        print(f"Dry-run candidates: {len(candidates)}")
        print(f"Report: {root / ARCHIVE_DIR / 'dry_run_candidates.md'}")
        return 0

    uncertain_count = sum(1 for c in candidates if c.certainty != "yes")
    moved = apply_archive(root, candidates)
    write_archive_manifest(root, moved)
    write_health_report(root, moved, len(candidates), uncertain_count)
    write_summary(root, moved, len(candidates), uncertain_count, candidates)
    print(f"Dry-run candidates: {len(candidates)}")
    print(f"Moved files: {len(moved)}")
    print(f"Uncertain left in place: {uncertain_count}")
    print(f"Manifest: {root / ARCHIVE_DIR / 'archive_manifest.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
