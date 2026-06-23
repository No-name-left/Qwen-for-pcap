#!/usr/bin/env python3
"""Generate harmless localhost-only PCAP fixtures for closed-set boundary tests.

The server never executes commands, persists uploads, or contacts non-loopback
addresses. Attack-looking strings are inert HTTP paths/bodies for parser tests.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import shutil
import signal
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "datasets/public/synthetic_controlled/raw"
SCENARIOS: dict[str, dict[str, str]] = {
    "TA43_01": {"name": "localhost_tcp_connect_scan", "evidence": "TCP connect attempts across 20 closed localhost ports."},
    "TA43_02": {"name": "mock_vulnerability_scanner", "evidence": "Nmap-NSE/Nikto-labelled HTTP service, version and scanner-path probes."},
    "TA01_01": {"name": "dummy_login_failures", "evidence": "Ten repeated POST /login requests receive fixed 401 responses."},
    "TA01_02": {"name": "inert_exploit_strings", "evidence": "Traversal/injection-shaped URI strings receive fixed 400 responses; nothing executes."},
    "TA03_01": {"name": "harmless_marker_deployment", "evidence": "POST upload of a non-executable marker receives fixed 201; server discards it."},
    "TA11_01": {"name": "mock_backdoor_access", "evidence": "Client visits a mock-webshell control URI; endpoint returns fixed status only."},
    "TA11_02": {"name": "dummy_callback_heartbeat", "evidence": "Eight localhost callbacks send a fixed heartbeat string to a dummy endpoint."},
    "TN01_01": {"name": "benign_http", "evidence": "Ordinary localhost HTTP GET requests for index, documentation and health."},
}


class FixedHandler(BaseHTTPRequestHandler):
    scenario = "TN01_01"
    protocol_version = "HTTP/1.0"

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.scenario == "TA01_02":
            self._reply(400, b"inert training string rejected\n")
        elif self.scenario == "TA11_01":
            self._reply(200, b"mock endpoint status: disabled\n")
        else:
            self._reply(200, b"harmless localhost fixture\n")

    def do_POST(self) -> None:  # noqa: N802
        length = min(int(self.headers.get("Content-Length", "0") or 0), 4096)
        if length:
            self.rfile.read(length)  # discard; never parse, save, or execute
        status = 401 if self.scenario == "TA01_01" else 201 if self.scenario == "TA03_01" else 200
        self._reply(status, b"fixed simulation response\n")

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def request(port: int, method: str, path: str, body: str = "", user_agent: str = "Controlled-Fixture/1.0") -> None:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    headers = {"User-Agent": user_agent, "X-Controlled-Simulation": "true"}
    if body:
        headers["Content-Type"] = "text/plain"
    conn.request(method, path, body=body.encode(), headers=headers)
    response = conn.getresponse()
    response.read()
    conn.close()


def generate_traffic(code: str, port: int, variant: int) -> None:
    if code == "TA43_01":
        start = 22000 + variant * 100
        for dst_port in range(start, start + 20):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.08)
            try:
                sock.connect(("127.0.0.1", dst_port))
            except OSError:
                pass
            finally:
                sock.close()
        return
    if code == "TA43_02":
        probes = ["/server-status", "/.git/HEAD", "/manager/html", "/cgi-bin/test", "/robots.txt", "/admin/", "/nse/http-enum", "/nikto/plugin-check"]
        for path in probes:
            request(port, "GET", path, user_agent=f"Nmap Scripting Engine Nikto harmless-v{variant}")
    elif code == "TA01_01":
        for attempt in range(10):
            request(port, "POST", f"/login?attempt={attempt}", body="username=fixture&password=incorrect", user_agent="Controlled-Login-Failure-Tester/1.0")
    elif code == "TA01_02":
        for path in ["/download?file=..%2F..%2Ftraining-marker", "/search?q=%27+OR+%271%27%3D%271", "/run?cmd=%3Bexec+master..xp_cmdshell+%27whoami%27%3B", "/view?template=%3Cscript%3EINERT%3C%2Fscript%3E"]:
            request(port, "GET", path, user_agent="Controlled-Inert-Exploit-String/1.0")
        request(
            port,
            "POST",
            "/api/query",
            body="statement=;exec master..xp_cmdshell 'whoami';&token=fixture-secret",
            user_agent="Controlled-Inert-Exploit-String/1.0",
        )
    elif code == "TA03_01":
        for index in range(3):
            request(port, "POST", f"/admin/plugin/upload?filename=harmless-marker-{variant}-{index}.txt", body="NON_EXECUTABLE_TRAINING_MARKER", user_agent="Controlled-Harmless-Deployment/1.0")
    elif code == "TA11_01":
        for index in range(3):
            request(port, "GET", f"/mock-webshell/control?action=fixed-status&request={index}", user_agent="Controlled-Mock-Backdoor-Access/1.0")
    elif code == "TA11_02":
        for sequence in range(8):
            request(port, "POST", f"/dummy-c2/heartbeat?sequence={sequence}", body="FIXED_HEARTBEAT_ONLY", user_agent="Controlled-Dummy-Callback/1.0")
            time.sleep(0.04)
    elif code == "TN01_01":
        for path in ["/", "/docs/index.html", "/health"]:
            request(port, "GET", path, user_agent="Controlled-Benign-Browser/1.0")


def capture_one(code: str, variant: int, output: Path, interface: str) -> dict[str, Any]:
    port = 18000 + list(SCENARIOS).index(code) * 100 + variant
    scan_start = 22000 + variant * 100
    capture_filter = (
        f"host 127.0.0.1 and tcp portrange {scan_start}-{scan_start + 19}"
        if code == "TA43_01"
        else f"host 127.0.0.1 and tcp port {port}"
    )
    server = None
    thread = None
    if code != "TA43_01":
        handler = type(f"Handler_{code}_{variant}", (FixedHandler,), {"scenario": code})
        server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

    output.parent.mkdir(parents=True, exist_ok=True)
    capture = subprocess.Popen(
        ["dumpcap", "-q", "-i", interface, "-f", capture_filter, "-P", "-w", str(output)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        time.sleep(0.35)
        generate_traffic(code, port, variant)
        time.sleep(0.35)
    finally:
        capture.send_signal(signal.SIGINT)
        _, stderr = capture.communicate(timeout=10)
        if server:
            server.shutdown()
            server.server_close()
        if thread:
            thread.join(timeout=2)
    if capture.returncode not in {0, 130} or not output.exists() or output.stat().st_size <= 24:
        raise RuntimeError(f"capture failed for {code} v{variant}: rc={capture.returncode}; {stderr.strip()}")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    try:
        output_label = str(output.relative_to(ROOT))
    except ValueError:
        output_label = str(output)
    return {
        "scenario_id": f"synthetic_{code.lower()}_v{variant}",
        "intended_label": code,
        "variant": variant,
        "pcap_path": output_label,
        "bytes": output.stat().st_size,
        "sha256": digest,
        "generation_script": "scripts/generate_controlled_pcaps/generate_safe_http_scenarios.py",
        "evidence_summary": SCENARIOS[code]["evidence"],
        "safety_notes": "localhost only; fixed responses; no command execution; uploads discarded; no real malware",
        "limitations": "synthetic_controlled; coverage/pipeline boundary testing only; never external or strict evidence",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate safe localhost-only controlled PCAP fixtures.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report-json", type=Path, default=ROOT / "outputs/data_completion/synthetic_generation_report.json")
    parser.add_argument("--variants", type=int, default=3)
    parser.add_argument("--interface", default="lo")
    args = parser.parse_args()
    if shutil.which("dumpcap") is None:
        raise RuntimeError("dumpcap is required")
    if not 1 <= args.variants <= 5:
        parser.error("--variants must be 1..5")
    rows = []
    for code in SCENARIOS:
        for variant in range(1, args.variants + 1):
            output = args.output_dir / code.lower() / f"synthetic_{code.lower()}_v{variant}.pcap"
            rows.append(capture_one(code, variant, output, args.interface))
    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        report_label = str(args.report_json.relative_to(ROOT))
    except ValueError:
        report_label = str(args.report_json)
    print(json.dumps({"pcaps": len(rows), "bytes": sum(row["bytes"] for row in rows), "report": report_label}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
