#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
from pathlib import Path

from session_card_indicators import make_safe_http_observation, sanitize_uri


ROOT = Path(os.environ.get("PCAP_LLM_ROOT", Path(__file__).resolve().parents[1])).resolve()
DEFAULT_ZEEK_DOCKER_IMAGE = "public.ecr.aws/zeek/zeek:8.0.6-arm64"

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
    "http.request.method",
    "http.host",
    "http.response.code",
    "http.user_agent",
    "http.content_type",
    "http.content_length",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    # FTP command names and response codes are safe metadata. Never persist ftp.request.arg.
    "ftp.request.command",
    "ftp.response.code",
]

TSHARK_HTTP_OBSERVABLE_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.request.full_uri",
    "http.response.code",
    "http.user_agent",
    "http.referer",
    "http.content_type",
    "http.content_length",
    # Values from the next two headers are never persisted; only presence flags are kept.
    "http.cookie",
    "http.authorization",
    # Body/form values are reduced in memory to redacted keyword contexts.
    "http.file_data",
    "urlencoded-form.key",
    "urlencoded-form.value",
]


def command_exists(name: str, env: dict | None = None) -> bool:
    path = env.get("PATH") if env else None
    return shutil.which(name, path=path) is not None


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


def sanitize_zeek_application_logs(zeek_dir: Path) -> None:
    """Redact secrets that default Zeek application logs may expose."""
    for name in ("http.log", "ftp.log"):
        path = zeek_dir / name
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        fields: list[str] = []
        out: list[str] = []
        for line in lines:
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                out.append(line)
                continue
            if line.startswith("#") or not fields:
                out.append(line)
                continue
            parts = line.split("\t")
            if len(parts) < len(fields):
                parts.extend([""] * (len(fields) - len(parts)))
            row = dict(zip(fields, parts))
            if name == "http.log":
                for field in ("uri", "referrer"):
                    if field in row and row[field] not in {"", "-"}:
                        parts[fields.index(field)] = sanitize_uri(row[field])
                for field in ("username", "password"):
                    if field in row and row[field] not in {"", "-"}:
                        parts[fields.index(field)] = "[REDACTED]"
            elif str(row.get("command") or "").upper() == "PASS" and "arg" in fields:
                parts[fields.index("arg")] = "[REDACTED]"
            out.append("\t".join(parts))
        path.write_text("\n".join(out) + "\n", encoding="utf-8")


def run_tshark_fallback(pcap_abs: Path, tshark_dir: Path) -> tuple[bool, int, str]:
    packets_csv = tshark_dir / "packets.csv"
    observable_http = tshark_dir / "observable_http.jsonl"
    observable_http_count = 0
    if not command_exists("tshark"):
        return False, observable_http_count, "tshark missing; packet CSV not generated"
    tshark_cmd = [
        "tshark",
        "-r",
        str(pcap_abs),
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
        return False, observable_http_count, f"tshark failed rc={tshark_rc}: {concise_error(tshark_err)}"
    observable_rc, observable_http_count, observable_err = extract_safe_http_observations(pcap_abs, observable_http)
    if observable_rc != 0:
        return True, observable_http_count, f"tshark observable HTTP extraction failed rc={observable_rc}: {concise_error(observable_err)}"
    return True, observable_http_count, ""


def run_system_zeek(pcap_abs: Path, zeek_dir: Path) -> tuple[bool, str]:
    env = os.environ.copy()
    env["PATH"] = f"/opt/zeek/bin:{env.get('PATH', '')}"
    if not command_exists("zeek", env):
        return False, "system zeek missing"
    zeek_rc, zeek_out, zeek_err = run(["zeek", "-C", "-r", str(pcap_abs)], cwd=zeek_dir, env=env)
    (zeek_dir / "zeek_run.stdout").write_text(zeek_out, encoding="utf-8")
    (zeek_dir / "zeek_run.stderr").write_text(zeek_err, encoding="utf-8")
    if zeek_rc != 0:
        return False, f"system zeek failed rc={zeek_rc}: {concise_error(zeek_err)}"
    sanitize_zeek_application_logs(zeek_dir)
    return True, ""


def docker_image_available(image: str) -> tuple[bool, str]:
    if not command_exists("docker"):
        return False, "docker missing"
    inspect_rc, _, inspect_err = run(["docker", "image", "inspect", image])
    if inspect_rc != 0:
        return False, f"docker image unavailable: {image}: {concise_error(inspect_err)}"
    return True, ""


def run_docker_zeek(pcap_abs: Path, zeek_dir: Path, image: str) -> tuple[bool, str]:
    if not image:
        return False, "zeek Docker image not configured"
    available, error = docker_image_available(image)
    if not available:
        return False, error
    pcap_mount = pcap_abs.parent.resolve()
    output_mount = zeek_dir.resolve()
    container_pcap = f"/pcap/{pcap_abs.name}"
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{pcap_mount}:/pcap:ro",
        "-v", f"{output_mount}:/zeek",
        "-w", "/zeek",
        image,
        "zeek", "-C", "-r", container_pcap,
    ]
    zeek_rc, zeek_out, zeek_err = run(cmd)
    (zeek_dir / "zeek_docker_run.stdout").write_text(zeek_out, encoding="utf-8")
    (zeek_dir / "zeek_docker_run.stderr").write_text(zeek_err, encoding="utf-8")
    if zeek_rc != 0:
        return False, f"docker zeek failed rc={zeek_rc}: {concise_error(zeek_err)}"
    sanitize_zeek_application_logs(zeek_dir)
    return True, ""


def extract_safe_http_observations(pcap: Path, output: Path) -> tuple[int | None, int, str]:
    """Stream selected TShark fields and persist only bounded, redacted evidence."""
    cmd = [
        "tshark", "-r", str(pcap),
        "-o", "tcp.desegment_tcp_streams:TRUE",
        "-o", "http.desegment_body:TRUE",
        # Skip large/unknown reassembled bodies; Zeek metadata remains available.
        "-Y", "http && (!http.file_data || (http.content_length && http.content_length <= 32768))",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=/t",
        "-E", "quote=d",
        "-E", "occurrence=a",
        "-E", "aggregator=|",
    ]
    for field in TSHARK_HTTP_OBSERVABLE_FIELDS:
        cmd.extend(["-e", field])
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        return None, 0, str(exc)
    count = 0
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        assert proc.stdout is not None
        reader = csv.DictReader(proc.stdout, delimiter="\t", quotechar='"')
        for row in reader:
            safe = make_safe_http_observation(row)
            if safe is None:
                continue
            handle.write(json.dumps(safe, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    assert proc.stderr is not None
    stderr = proc.stderr.read()
    rc = proc.wait()
    return rc, count, stderr


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(path)


def discover_pcaps(input_dir: Path, dataset_id: str | None, neutral_case_ids: bool = False) -> list[tuple[str, Path]]:
    pcaps = sorted([*input_dir.glob("*.pcap"), *input_dir.glob("*.pcapng"), *input_dir.glob("*.cap")])
    out = []
    for idx, pcap in enumerate(pcaps, start=1):
        case_id = dataset_id or pcap.stem
        if dataset_id and neutral_case_ids:
            case_id = f"{dataset_id}_{idx:03d}"
        elif len(pcaps) > 1 and dataset_id:
            case_id = f"{dataset_id}_{idx:03d}_{pcap.stem}"
        out.append((case_id, pcap))
    return out


def parse_case(
    case_id: str,
    pcap: Path,
    output_dir: Path,
    prefer_zeek: bool = True,
    allow_tshark_fallback: bool = True,
    zeek_docker_image: str | None = None,
) -> dict:
    pcap_abs = pcap.resolve()
    case_dir = output_dir / case_id
    tshark_dir = case_dir / "tshark"
    zeek_dir = case_dir / "zeek"
    for d in (tshark_dir, zeek_dir):
        d.mkdir(parents=True, exist_ok=True)

    warnings: list[str] = []
    packets_csv = tshark_dir / "packets.csv"
    observable_http = tshark_dir / "observable_http.jsonl"
    observable_http_count = 0
    tshark_attempted = False
    tshark_success = False
    tshark_error = ""
    zeek_success = False
    zeek_error = ""
    zeek_mode = "not_attempted"
    parser_source = "none"
    zeek_docker_image = zeek_docker_image or None

    if prefer_zeek:
        zeek_mode = "system"
        zeek_success, zeek_error = run_system_zeek(pcap_abs, zeek_dir)
        if zeek_success:
            parser_source = "zeek_conn"
        elif zeek_docker_image:
            system_zeek_error = zeek_error
            zeek_mode = "docker"
            zeek_success, zeek_error = run_docker_zeek(pcap_abs, zeek_dir, zeek_docker_image)
            if zeek_success:
                parser_source = "zeek_docker"
            else:
                zeek_error = "; ".join(error for error in (system_zeek_error, zeek_error) if error)
    else:
        zeek_error = "prefer_zeek disabled"

    if not zeek_success:
        (zeek_dir / "zeek_run.stderr").write_text(zeek_error + "\n", encoding="utf-8")
        if allow_tshark_fallback:
            tshark_attempted = True
            tshark_success, observable_http_count, tshark_error = run_tshark_fallback(pcap_abs, tshark_dir)
            if tshark_success:
                parser_source = "tshark_fallback"
            if tshark_error:
                warnings.append(tshark_error)
            if tshark_success:
                warnings.append(f"Zeek unavailable or failed ({zeek_error}); using tshark packet aggregation fallback")
            else:
                warnings.append(f"Zeek unavailable or failed ({zeek_error}); tshark fallback failed")
        else:
            warnings.append(f"Zeek unavailable or failed ({zeek_error}); tshark fallback disabled")

    zeek_logs = [f for f in list_files(zeek_dir) if f.endswith(".log") and not f.startswith("zeek_run.")]

    return {
        "case_id": case_id,
        "pcap_path": display_path(pcap),
        "pcap_size": pcap.stat().st_size if pcap.exists() else None,
        "parser_source": parser_source,
        "tshark_success": tshark_success and packets_csv.exists() and packets_csv.stat().st_size > 0,
        "tshark_attempted": tshark_attempted,
        "tshark_error": tshark_error,
        "zeek_success": zeek_success,
        "zeek_mode": zeek_mode,
        "zeek_docker_image": zeek_docker_image,
        "zeek_error": "" if zeek_success else zeek_error,
        "tshark_packets_csv": display_path(packets_csv),
        "tshark_observable_http": display_path(observable_http),
        "tshark_observable_http_rows": observable_http_count,
        "zeek_generated_logs": zeek_logs,
        "session_parser_preference": "zeek_conn_then_zeek_docker_then_tshark_fallback",
        "warnings": warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse selected public PCAP files with local tools only.")
    parser.add_argument("--input-dir", type=Path, default=ROOT / "datasets/public/feasibility/raw")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/parsed/feasibility")
    parser.add_argument("--dataset-id", default=None)
    parser.add_argument("--neutral-case-ids", action="store_true", help="Do not expose source filenames in generated case/session identifiers.")
    parser.add_argument("--prefer-zeek", action=argparse.BooleanOptionalAction, default=True, help="Prefer system/Docker Zeek before TShark fallback.")
    parser.add_argument("--allow-tshark-fallback", action=argparse.BooleanOptionalAction, default=True, help="Use TShark packet aggregation if Zeek is unavailable or fails.")
    parser.add_argument("--zeek-docker-image", default=os.environ.get("ZEEK_DOCKER_IMAGE", DEFAULT_ZEEK_DOCKER_IMAGE), help="Local Docker image to use when system Zeek is unavailable or fails.")
    args = parser.parse_args()

    cases = discover_pcaps(args.input_dir, args.dataset_id, args.neutral_case_ids)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = [
        parse_case(
            case_id,
            pcap,
            args.output_dir,
            prefer_zeek=args.prefer_zeek,
            allow_tshark_fallback=args.allow_tshark_fallback,
            zeek_docker_image=args.zeek_docker_image,
        )
        for case_id, pcap in cases
    ]
    (args.output_dir / "parse_all_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"parsed {len(summary)} pcap files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
