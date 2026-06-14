#!/usr/bin/env python3
import json
import os
import shlex
import subprocess
from pathlib import Path


ROOT = Path("/root/autodl-tmp/pcap_llm_demo")
PARSED = ROOT / "outputs" / "parsed"
RULES = PARSED / "suricata_rules" / "suricata.rules"

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

TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "_ws.col.Protocol",
    "frame.len",
    "http.host",
    "http.request.uri",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
]


def run(cmd, cwd=None, env=None, stdout_path=None):
    if stdout_path:
        with open(stdout_path, "w", encoding="utf-8") as stdout:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                stdout=stdout,
                stderr=subprocess.PIPE,
                text=True,
            )
    else:
        proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    return proc.returncode, proc.stdout if not stdout_path else "", proc.stderr


def list_files(path):
    if not path.exists():
        return []
    return sorted(p.name for p in path.iterdir() if p.is_file())


def count_suricata_alerts(eve_path):
    if not eve_path.exists():
        return 0
    alerts = 0
    with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts += 1
    return alerts


def concise_error(stderr):
    lines = []
    for line in stderr.splitlines():
        if "<Error>" in line or "<Warning>" in line:
            cleaned = " ".join(line.split())
            if cleaned not in lines:
                lines.append(cleaned)
    if not lines and stderr.strip():
        lines.append(" ".join(stderr.strip().split()))
    return " | ".join(lines[:6])


def main():
    env = os.environ.copy()
    env["PATH"] = f"/opt/zeek/bin:{env.get('PATH', '')}"
    summary = []

    for case_id, pcap in CASES:
        case_dir = PARSED / case_id
        tshark_dir = case_dir / "tshark"
        zeek_dir = case_dir / "zeek"
        suricata_dir = case_dir / "suricata"
        for d in (tshark_dir, zeek_dir, suricata_dir):
            d.mkdir(parents=True, exist_ok=True)

        warnings = []
        pcap_size = pcap.stat().st_size if pcap.exists() else None

        packets_csv = tshark_dir / "packets.csv"
        tshark_cmd = [
            "tshark",
            "-r",
            str(pcap),
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]
        for field in TSHARK_FIELDS:
            tshark_cmd.extend(["-e", field])
        tshark_rc, _, tshark_err = run(tshark_cmd, stdout_path=packets_csv)
        if tshark_rc != 0:
            warnings.append(f"tshark failed rc={tshark_rc}: {tshark_err.strip()}")

        zeek_cmd = ["zeek", "-C", "-r", str(pcap)]
        zeek_rc, zeek_out, zeek_err = run(zeek_cmd, cwd=zeek_dir, env=env)
        (zeek_dir / "zeek_run.stdout").write_text(zeek_out, encoding="utf-8")
        (zeek_dir / "zeek_run.stderr").write_text(zeek_err, encoding="utf-8")
        if zeek_rc != 0:
            warnings.append(f"zeek failed rc={zeek_rc}: {zeek_err.strip()}")

        suricata_cmd = [
            "suricata",
            "--runmode",
            "single",
            "-r",
            str(pcap),
            "-l",
            str(suricata_dir),
            "-k",
            "none",
        ]
        if RULES.exists():
            suricata_cmd.extend(["-S", str(RULES)])
        suricata_rc, suricata_out, suricata_err = run(suricata_cmd)
        (suricata_dir / "suricata_run.stdout").write_text(suricata_out, encoding="utf-8")
        (suricata_dir / "suricata_run.stderr").write_text(suricata_err, encoding="utf-8")
        if suricata_rc != 0:
            warnings.append(
                "suricata failed rc="
                f"{suricata_rc}: {concise_error(suricata_err)}"
            )

        zeek_logs = [
            f
            for f in list_files(zeek_dir)
            if f.endswith(".log") and not f.startswith("zeek_run.")
        ]
        suricata_files = list_files(suricata_dir)
        alert_count = count_suricata_alerts(suricata_dir / "eve.json")
        if (suricata_dir / "eve.json").exists() and alert_count == 0:
            warnings.append("suricata eve.json exists but no alert events matched enabled rules")

        summary.append(
            {
                "case_id": case_id,
                "pcap_path": str(pcap.relative_to(ROOT)),
                "pcap_size": pcap_size,
                "tshark_success": tshark_rc == 0 and packets_csv.exists(),
                "zeek_success": zeek_rc == 0,
                "suricata_success": suricata_rc == 0 and (suricata_dir / "eve.json").exists(),
                "tshark_packets_csv": str(packets_csv.relative_to(ROOT)),
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
