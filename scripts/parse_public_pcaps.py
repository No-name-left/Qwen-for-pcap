#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(os.environ.get("PCAP_LLM_ROOT", Path(__file__).resolve().parents[1])).resolve()

TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
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


def command_exists(name: str) -> bool:
    return subprocess.run(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"]).returncode == 0


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None, stdout_path: Path | None = None) -> tuple[int | None, str, str]:
    try:
        if stdout_path:
            with stdout_path.open("w", encoding="utf-8") as stdout:
                proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=stdout, stderr=subprocess.PIPE, text=True)
            return proc.returncode, "", proc.stderr
        proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return None, "", str(exc)


def list_files(path: Path) -> list[str]:
    if not path.exists():
        return []
    return sorted(p.name for p in path.iterdir() if p.is_file())


def count_suricata_alerts(eve_path: Path) -> int:
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


def concise_error(stderr: str) -> str:
    lines: list[str] = []
    for line in stderr.splitlines():
        if "<Error>" in line or "<Warning>" in line or "No such file" in line or "not found" in line:
            cleaned = " ".join(line.split())
            if cleaned not in lines:
                lines.append(cleaned)
    if not lines and stderr.strip():
        lines.append(" ".join(stderr.strip().split()))
    return " | ".join(lines[:6])


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(path)


def discover_pcaps(input_dir: Path, dataset_id: str | None) -> list[tuple[str, Path]]:
    pcaps = sorted([*input_dir.glob("*.pcap"), *input_dir.glob("*.pcapng"), *input_dir.glob("*.cap")])
    out = []
    for idx, pcap in enumerate(pcaps, start=1):
        case_id = dataset_id or pcap.stem
        if len(pcaps) > 1 and dataset_id:
            case_id = f"{dataset_id}_{idx:03d}_{pcap.stem}"
        out.append((case_id, pcap))
    return out


def parse_case(case_id: str, pcap: Path, output_dir: Path, rules: Path | None) -> dict:
    case_dir = output_dir / case_id
    tshark_dir = case_dir / "tshark"
    zeek_dir = case_dir / "zeek"
    suricata_dir = case_dir / "suricata"
    for d in (tshark_dir, zeek_dir, suricata_dir):
        d.mkdir(parents=True, exist_ok=True)

    warnings: list[str] = []
    packets_csv = tshark_dir / "packets.csv"
    tshark_rc = None
    if command_exists("tshark"):
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
            warnings.append(f"tshark failed rc={tshark_rc}: {concise_error(tshark_err)}")
    else:
        warnings.append("tshark missing; packet CSV not generated")

    zeek_rc = None
    env = os.environ.copy()
    env["PATH"] = f"/opt/zeek/bin:{env.get('PATH', '')}"
    if command_exists("zeek"):
        zeek_rc, zeek_out, zeek_err = run(["zeek", "-C", "-r", str(pcap)], cwd=zeek_dir, env=env)
        (zeek_dir / "zeek_run.stdout").write_text(zeek_out, encoding="utf-8")
        (zeek_dir / "zeek_run.stderr").write_text(zeek_err, encoding="utf-8")
        if zeek_rc != 0:
            warnings.append(f"zeek failed rc={zeek_rc}: {concise_error(zeek_err)}")
    else:
        (zeek_dir / "zeek_run.stderr").write_text("zeek missing\n", encoding="utf-8")
        warnings.append("zeek missing; session card builder will use tshark packet aggregation fallback")

    suricata_rc = None
    if command_exists("suricata"):
        suricata_cmd = ["suricata", "--runmode", "single", "-r", str(pcap), "-l", str(suricata_dir), "-k", "none"]
        if rules and rules.exists():
            suricata_cmd.extend(["-S", str(rules)])
        suricata_rc, suricata_out, suricata_err = run(suricata_cmd)
        (suricata_dir / "suricata_run.stdout").write_text(suricata_out, encoding="utf-8")
        (suricata_dir / "suricata_run.stderr").write_text(suricata_err, encoding="utf-8")
        (suricata_dir / "suricata_run.status").write_text(str(suricata_rc), encoding="utf-8")
        if suricata_rc != 0:
            warnings.append(f"suricata failed rc={suricata_rc}: {concise_error(suricata_err)}")
    else:
        warnings.append("suricata missing; alerts not generated")

    zeek_logs = [f for f in list_files(zeek_dir) if f.endswith(".log") and not f.startswith("zeek_run.")]
    suricata_files = list_files(suricata_dir)
    alert_count = count_suricata_alerts(suricata_dir / "eve.json")
    if (suricata_dir / "eve.json").exists() and alert_count == 0:
        warnings.append("suricata eve.json exists but no alert events matched enabled rules")

    return {
        "case_id": case_id,
        "pcap_path": display_path(pcap),
        "pcap_size": pcap.stat().st_size if pcap.exists() else None,
        "tshark_success": tshark_rc == 0 and packets_csv.exists() and packets_csv.stat().st_size > 0,
        "zeek_success": zeek_rc == 0,
        "suricata_success": suricata_rc == 0 and (suricata_dir / "eve.json").exists(),
        "tshark_packets_csv": display_path(packets_csv),
        "zeek_generated_logs": zeek_logs,
        "suricata_generated_files": suricata_files,
        "suricata_alert_count": alert_count,
        "warnings": warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse selected public PCAP files with local tools only.")
    parser.add_argument("--input-dir", type=Path, default=ROOT / "datasets/public/feasibility/raw")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/parsed/feasibility")
    parser.add_argument("--dataset-id", default=None)
    parser.add_argument("--rules", type=Path, default=ROOT / "outputs/parsed/suricata_rules/suricata.rules")
    args = parser.parse_args()

    cases = discover_pcaps(args.input_dir, args.dataset_id)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = [parse_case(case_id, pcap, args.output_dir, args.rules) for case_id, pcap in cases]
    (args.output_dir / "parse_all_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"parsed {len(summary)} pcap files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
