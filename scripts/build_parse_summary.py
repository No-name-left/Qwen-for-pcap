#!/usr/bin/env python3
import json
from pathlib import Path


ROOT = Path("/root/autodl-tmp/pcap_llm_demo")
PARSED = ROOT / "outputs" / "parsed"

CASES = [
    ("nmap_standard_scan", ROOT / "datasets/raw/nmap/nmap_standard_scan.pcap"),
    ("nmap_OS_scan", ROOT / "datasets/raw/nmap/nmap_OS_scan.pcap"),
    ("nmap_zombie_scan", ROOT / "datasets/raw/nmap/nmap_zombie_scan.pcap"),
    (
        "mta_2024_07_30_exercise",
        ROOT / "datasets/raw/malware_traffic_analysis/2024-07-30-traffic-analysis-exercise.pcap",
    ),
    (
        "eternalblue_wannacry_2017_05_18",
        ROOT / "datasets/raw/eternalblue/2017-05-18-WannaCry-ransomware-using-EnternalBlue-exploit.pcap",
    ),
]


def files(path):
    if not path.exists():
        return []
    return sorted(p.name for p in path.iterdir() if p.is_file())


def count_alerts(eve_path):
    alerts = 0
    if not eve_path.exists():
        return alerts
    with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts += 1
    return alerts


def concise_errors(stderr_path):
    if not stderr_path.exists():
        return []
    seen = []
    with stderr_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if "<Error>" in line or "<Warning>" in line:
                cleaned = " ".join(line.split())
                if cleaned not in seen:
                    seen.append(cleaned)
    return seen[:6]


def main():
    summary = []
    for case_id, pcap in CASES:
        case_dir = PARSED / case_id
        tshark_csv = case_dir / "tshark" / "packets.csv"
        zeek_dir = case_dir / "zeek"
        suricata_dir = case_dir / "suricata"
        zeek_logs = [
            f for f in files(zeek_dir) if f.endswith(".log") and not f.startswith("zeek_run.")
        ]
        suricata_files = files(suricata_dir)
        status_path = suricata_dir / "suricata_run.status"
        suricata_status = status_path.read_text(encoding="utf-8").strip() if status_path.exists() else ""
        alert_count = count_alerts(suricata_dir / "eve.json")
        warnings = []
        warnings.extend(concise_errors(zeek_dir / "zeek_run.stderr"))
        warnings.extend(concise_errors(suricata_dir / "suricata_run.stderr"))
        if (suricata_dir / "eve.json").exists() and alert_count == 0:
            warnings.append("suricata eve.json exists but no alert events matched enabled rules")

        summary.append(
            {
                "case_id": case_id,
                "pcap_path": str(pcap.relative_to(ROOT)),
                "pcap_size": pcap.stat().st_size if pcap.exists() else None,
                "tshark_success": tshark_csv.exists() and tshark_csv.stat().st_size > 0,
                "zeek_success": bool(zeek_logs),
                "suricata_success": suricata_status == "0" and (suricata_dir / "eve.json").exists(),
                "tshark_packets_csv": str(tshark_csv.relative_to(ROOT)),
                "zeek_generated_logs": zeek_logs,
                "suricata_generated_files": suricata_files,
                "suricata_alert_count": alert_count,
                "warnings": warnings,
            }
        )

    (PARSED / "parse_all_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
