#!/usr/bin/env python3
"""Conservative, auditable downloader for public network-traffic datasets.

The allowlist contains only PCAP, flow labels, README files and source pages.
It never downloads or extracts malware executables or password-protected samples.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "datasets/metadata/download_manifest.csv"
TEN_GB = 10 * 1024**3
USER_AGENT = "Qwen-for-pcap-public-dataset-inventory/1.0"
FIELDS = [
    "dataset_id",
    "file_name",
    "source_url_or_page",
    "local_path",
    "bytes",
    "sha256",
    "downloaded_at",
    "status",
    "reason",
    "notes",
]


def artifact(
    dataset_id: str,
    file_name: str,
    url: str,
    local_path: str,
    profiles: tuple[str, ...] = ("minimal", "coverage", "pcap-heavy"),
    expected_bytes: int | None = None,
    notes: str = "",
) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "file_name": file_name,
        "url": url,
        "local_path": local_path,
        "profiles": set(profiles),
        "expected_bytes": expected_bytes,
        "notes": notes,
    }


EXISTING_ASSETS = [
    artifact("ctu13", "botnet-capture-20110810-neris.pcap", "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/", "datasets/public/ctu13/raw/botnet-capture-20110810-neris.pcap"),
    artifact("ctu13", "capture20110810.binetflow", "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/", "datasets/public/ctu13/labels/capture20110810.binetflow"),
    artifact("ctu13", "CTU-Malware-Capture-Botnet-42_README.md", "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/README.md", "datasets/public/ctu13/metadata/CTU-Malware-Capture-Botnet-42_README.md"),
    artifact("cse_cic_ids2018", "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", "https://registry.opendata.aws/cse-cic-ids2018/", "datasets/public/cse_cic_ids2018/labels/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", notes="flow_only"),
    artifact("cse_cic_ids2018", "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv", "https://registry.opendata.aws/cse-cic-ids2018/", "datasets/public/cse_cic_ids2018/labels/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv", notes="flow_only"),
    artifact("cse_cic_ids2018", "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv", "https://registry.opendata.aws/cse-cic-ids2018/", "datasets/public/cse_cic_ids2018/labels/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv", notes="flow_only"),
    artifact("cse_cic_ids2018", "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", "https://registry.opendata.aws/cse-cic-ids2018/", "datasets/public/cse_cic_ids2018/labels/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", notes="flow_only; infiltration substage mapping is low confidence"),
    artifact("controlled_portscan", "generated_nmap_local_scan.pcap", "local controlled generation", "datasets/public/feasibility/raw/portscan/generated_nmap_local_scan.pcap", notes="controlled local public-eval fixture"),
    artifact("cic_ids2017", "unb_ids_2017_page.html", "https://www.unb.ca/cic/datasets/ids-2017.html", "datasets/public/cicids2017/metadata/unb_ids_2017_page.html"),
    artifact("cse_cic_ids2018", "unb_ids_2018_page.html", "https://www.unb.ca/cic/datasets/ids-2018.html", "datasets/public/cse_cic_ids2018/metadata/unb_ids_2018_page.html"),
    artifact("cse_cic_ids2018", "aws_registry_cse_cic_ids2018.html", "https://registry.opendata.aws/cse-cic-ids2018/", "datasets/public/cse_cic_ids2018/metadata/aws_registry_cse_cic_ids2018.html"),
    artifact("cse_cic_ids2018", "s3_list_max60.xml", "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/?list-type=2&max-keys=60", "datasets/public/cse_cic_ids2018/metadata/s3_list_max60.xml"),
    artifact("unsw_nb15", "unsw_nb15_page.html", "https://research.unsw.edu.au/projects/unsw-nb15-dataset", "datasets/public/unsw_nb15/metadata/unsw_nb15_page.html"),
    artifact("wireshark_nmap", "NMap-Captures.zip", "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/NMap-Captures.zip", "datasets/public/wireshark_nmap/raw/NMap-Captures.zip", notes="zero-byte historical failed download; not used"),
]


AUTO_ARTIFACTS = [
    artifact("ctu13", "ctu13_official_page.html", "https://www.stratosphereips.org/datasets-ctu13", "datasets/public/ctu13/metadata/ctu13_official_page.html"),
    artifact("iot23", "iot23_official_page.html", "https://www.stratosphereips.org/datasets-iot23", "datasets/public/iot23/metadata/iot23_official_page.html"),
    artifact("bot_iot", "bot_iot_official_page.html", "https://research.unsw.edu.au/projects/bot-iot-dataset", "datasets/public/bot_iot/metadata/bot_iot_official_page.html"),
    artifact("ton_iot_family", "ton_iot_official_page.html", "https://research.unsw.edu.au/projects/toniot-datasets", "datasets/public/ton_iot/metadata/ton_iot_official_page.html"),
    artifact("cic_iot2023", "cic_iot2023_official_page.html", "https://www.unb.ca/cic/datasets/iotdataset-2023.html", "datasets/public/cic_iot2023/metadata/cic_iot2023_official_page.html"),
    artifact("malware_traffic_analysis", "mta_home_page.html", "https://www.malware-traffic-analysis.net/", "datasets/public/malware_traffic_analysis/metadata/mta_home_page.html", notes="metadata only; exercise PCAP selection remains manual"),
]


def ctu_artifacts(number: int, date: str, family: str, flow_name: str, pcap_mb: int, flow_mb: int) -> list[dict[str, Any]]:
    base = f"https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-{number}"
    pcap = f"botnet-capture-{date}-{family}.pcap"
    return [
        artifact("ctu13", f"MCFP-{number}_README.md", f"{base}/README.md", f"datasets/public/ctu13/metadata/MCFP-{number}_README.md", ("coverage", "pcap-heavy")),
        artifact("ctu13", pcap, f"{base}/{pcap}", f"datasets/public/ctu13/raw/{pcap}", ("coverage", "pcap-heavy"), pcap_mb * 1024**2, f"botnet-only PCAP; MCFP scenario {number}"),
        artifact("ctu13", flow_name, f"{base}/{flow_name}", f"datasets/public/ctu13/labels/{flow_name}", ("coverage", "pcap-heavy"), flow_mb * 1024**2, f"labeled flow file for MCFP scenario {number}"),
    ]


AUTO_ARTIFACTS += ctu_artifacts(43, "20110811", "neris", "capture20110811.binetflow.2format", 35, 424)
AUTO_ARTIFACTS += ctu_artifacts(46, "20110815", "fast-flux", "capture20110815-2.binetflow.2format", 30, 31)
AUTO_ARTIFACTS += ctu_artifacts(47, "20110816", "donbot", "capture20110816.binetflow.2format", 5, 132)


MANUAL_ITEMS = [
    ("cic_ids2017", "full PCAP bundle", "https://www.unb.ca/cic/datasets/ids-2017.html", "skipped_large", "portal/manual acquisition; do not bulk-download by default"),
    ("cse_cic_ids2018", "full AWS PCAP corpus", "https://registry.opendata.aws/cse-cic-ids2018/", "skipped_large", "hundreds of GB; select individual objects instead of aws s3 sync"),
    ("unsw_nb15", "complete PCAP set", "https://research.unsw.edu.au/projects/unsw-nb15-dataset", "skipped_large", "roughly 100GB; processed training/testing CSVs are preferred"),
    ("unsw_nb15", "training/testing CSV + features + ground truth", "https://research.unsw.edu.au/projects/unsw-nb15-dataset", "manual_required", "official page links require manual selection/terms review"),
    ("stratosphere_mcf", "malware executable or password-protected sample archive", "https://www.stratosphereips.org/datasets-malware", "manual_required", "skipped_malware_binary; forbidden by project safety policy"),
    ("iot23", "full IoT-23 PCAP corpus", "https://www.stratosphereips.org/datasets-iot23", "skipped_large", "prefer small/labeled-flow archive; full PCAP is opt-in"),
    ("bot_iot", "69GB full PCAP", "https://research.unsw.edu.au/projects/bot-iot-dataset", "skipped_large", "prefer 5% CSV/Argus subset"),
    ("bot_iot", "5% CSV/Argus subset", "https://research.unsw.edu.au/projects/bot-iot-dataset", "manual_required", "select official processed package after terms review"),
    ("ton_iot_family", "processed ToN-IoT / NF-ToN-IoT flows", "https://research.unsw.edu.au/projects/toniot-datasets", "manual_required", "derived variants need source and license confirmation"),
    ("cic_iot2023", "small labeled CSV subset", "https://www.unb.ca/cic/datasets/iotdataset-2023.html", "manual_required", "portal/package selection required; full corpus not automatic"),
    ("malware_traffic_analysis", "analyst-selected exercise PCAP", "https://www.malware-traffic-analysis.net/", "manual_required", "PCAP-only allowlist and answer-key review required"),
    ("malware_traffic_analysis", "malware sample ZIP/executable", "https://www.malware-traffic-analysis.net/", "manual_required", "skipped_malware_binary; never download or extract"),
]


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def timestamp_for(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")


def row_for_existing(item: dict[str, Any], previous: dict[str, dict[str, str]]) -> dict[str, str]:
    path = ROOT / item["local_path"]
    if not path.exists() or not path.is_file():
        return {}
    size = path.stat().st_size
    if size == 0:
        return {
            "dataset_id": item["dataset_id"], "file_name": item["file_name"],
            "source_url_or_page": item["url"], "local_path": item["local_path"],
            "bytes": "0", "sha256": "", "downloaded_at": timestamp_for(path),
            "status": "failed", "reason": "empty_file", "notes": item.get("notes", ""),
        }
    digest = sha256_file(path)
    old = previous.get(item["local_path"], {})
    was_downloaded_here = old.get("status") == "downloaded" and old.get("sha256") == digest
    return {
        "dataset_id": item["dataset_id"], "file_name": item["file_name"],
        "source_url_or_page": item["url"], "local_path": item["local_path"],
        "bytes": str(size), "sha256": digest,
        "downloaded_at": old.get("downloaded_at") if was_downloaded_here else timestamp_for(path),
        "status": "downloaded" if was_downloaded_here else "already_exists",
        "reason": "previous_download_verified" if was_downloaded_here else "non_empty_file_verified",
        "notes": item.get("notes", ""),
    }


def content_length(url: str) -> int | None:
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        value = response.headers.get("Content-Length")
        return int(value) if value and value.isdigit() else None


def download_with_resume(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_name(destination.name + ".part")
    offset = part.stat().st_size if part.exists() else 0
    headers = {"User-Agent": USER_AGENT}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=120) as response:
        append = offset > 0 and getattr(response, "status", None) == 206
        mode = "ab" if append else "wb"
        with part.open(mode) as handle:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                handle.write(block)
    if not part.exists() or part.stat().st_size == 0:
        raise OSError("download produced an empty file")
    os.replace(part, destination)


def write_manifest(rows: list[dict[str, str]]) -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    rows.sort(key=lambda row: (row["dataset_id"], row["file_name"], row["local_path"]))
    with MANIFEST.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def previous_manifest_rows() -> dict[str, dict[str, str]]:
    if not MANIFEST.exists():
        return {}
    with MANIFEST.open(encoding="utf-8", newline="") as handle:
        return {row["local_path"]: row for row in csv.DictReader(handle) if row.get("local_path")}


def main() -> int:
    parser = argparse.ArgumentParser(description="Download only allowlisted, size-bounded public traffic artifacts.")
    parser.add_argument("--dry-run", action="store_true", help="Plan and record actions without downloading.")
    parser.add_argument("--profile", choices=["minimal", "coverage", "pcap-heavy"], default="coverage")
    parser.add_argument("--allow-large", action="store_true", help="Permit an allowlisted artifact over 10GB; budget still applies.")
    parser.add_argument("--max-gb", type=float, default=1.0, help="Maximum new bytes for this run; default 1GB.")
    parser.add_argument("--dataset-id", action="append", help="Restrict to one or more dataset IDs.")
    parser.add_argument("--skip-existing", action="store_true", help="Explicitly retain existing files (also the safe default).")
    args = parser.parse_args()
    if args.max_gb <= 0:
        parser.error("--max-gb must be greater than zero")
    selected = set(args.dataset_id or [])
    known_ids = {item["dataset_id"] for item in EXISTING_ASSETS + AUTO_ARTIFACTS} | {item[0] for item in MANUAL_ITEMS}
    unknown = selected - known_ids
    if unknown:
        parser.error("unknown --dataset-id: " + ", ".join(sorted(unknown)))

    rows: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    previous = previous_manifest_rows()
    for item in EXISTING_ASSETS + AUTO_ARTIFACTS:
        existing = row_for_existing(item, previous)
        if existing and item["local_path"] not in seen_paths:
            rows.append(existing)
            seen_paths.add(item["local_path"])

    budget = int(args.max_gb * 1024**3)
    planned_or_downloaded = 0
    failures = 0
    for item in AUTO_ARTIFACTS:
        if selected and item["dataset_id"] not in selected:
            continue
        if args.profile not in item["profiles"]:
            continue
        destination = ROOT / item["local_path"]
        if destination.exists() and destination.stat().st_size > 0:
            continue
        expected = item.get("expected_bytes")
        if expected is None:
            try:
                expected = content_length(item["url"])
            except Exception:
                expected = None
        base = {
            "dataset_id": item["dataset_id"], "file_name": item["file_name"],
            "source_url_or_page": item["url"], "local_path": item["local_path"],
            "bytes": str(expected or 0), "sha256": "", "downloaded_at": "",
            "notes": item.get("notes", ""),
        }
        if expected is not None and expected > TEN_GB and not args.allow_large:
            rows.append({**base, "status": "skipped_large", "reason": "single_artifact_over_10gb"})
            continue
        if expected is not None and planned_or_downloaded + expected > budget:
            rows.append({**base, "status": "skipped_large", "reason": "run_budget_exceeded"})
            continue
        if args.dry_run:
            planned_or_downloaded += expected or 0
            rows.append({**base, "status": "manual_required", "reason": "dry_run_planned_download"})
            print(f"PLAN {item['dataset_id']}: {item['file_name']} ({expected or 'unknown'} bytes)")
            continue
        try:
            download_with_resume(item["url"], destination)
            size = destination.stat().st_size
            planned_or_downloaded += size
            rows.append({
                **base, "bytes": str(size), "sha256": sha256_file(destination),
                "downloaded_at": timestamp_for(destination), "status": "downloaded",
                "reason": "allowlisted_profile_download",
            })
            seen_paths.add(item["local_path"])
            print(f"DOWNLOADED {item['dataset_id']}: {item['file_name']} ({size} bytes)")
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            failures += 1
            rows.append({**base, "status": "failed", "reason": type(exc).__name__, "notes": f"{base['notes']}; {str(exc)[:300]}".strip("; ")})
            print(f"FAILED {item['dataset_id']}: {item['file_name']}: {exc}", file=sys.stderr)

    for dataset_id, name, source, status, reason in MANUAL_ITEMS:
        rows.append({
            "dataset_id": dataset_id, "file_name": name, "source_url_or_page": source,
            "local_path": "", "bytes": "", "sha256": "", "downloaded_at": "",
            "status": status, "reason": reason, "notes": "not downloaded by the automated allowlist",
        })
    write_manifest(rows)
    print(f"manifest: {rel(MANIFEST)}; rows={len(rows)}; failures={failures}; new_bytes={planned_or_downloaded}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
