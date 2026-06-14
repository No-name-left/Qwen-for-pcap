# Generated local port scan PCAP report

This is a controlled local port-scan-like PCAP generated because no old Nmap PCAP was present and the official Wireshark `NMap-Captures.zip` download failed in this environment.

- Actual generator: Python TCP connect probe, not Nmap, because `nmap` is not installed and was not force-installed.
- Target: `127.0.0.1` only.
- Ports probed: `1-200`.
- Capture interface: loopback `lo` through `dumpcap`.
- Output PCAP: `datasets/public/feasibility/raw/portscan/generated_nmap_local_scan.pcap`.
- Size bytes: 95168.
- SHA256: `b32b5f8bdf170ec9c6ea42e12932ce63f51e9b752f99207dd632be6c9f456a7a`.
- Git ignored: True.
- Safety: no public, campus, company, or unknown host was scanned.
- Intended use: scan_group pipeline test only; not a public dataset and not a formal training label source.
