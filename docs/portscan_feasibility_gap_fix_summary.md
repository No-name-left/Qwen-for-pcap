# Port scan feasibility gap fix summary

## Verdict

`PORTSCAN_SCAN_GROUP_READY_FOR_API_TEST`

The port-scan gap is fixed for pipeline validation. A controlled localhost TCP connect scan PCAP was generated because no old Nmap PCAP existed in the current tree and the official Wireshark `NMap-Captures.zip` download was blocked by TLS/proxy errors.

## Why the Previous Run Had No Port Scan Data

The previous feasibility run used CTU-13 Scenario 1 and CSE-CIC-IDS2018 flow CSVs. Those covered C2/callback, brute force, web attack, and normal flow-label evaluation, but no reliable Nmap or port-scan PCAP was present. Therefore `scan_groups.json` was empty.

## Data Source and Safety

- Old Nmap PCAP found: no.
- Wireshark official SampleCaptures page found `NMap-Captures.zip`, but download failed in this environment.
- Generated PCAP: `datasets/public/feasibility/raw/portscan/generated_nmap_local_scan.pcap`.
- Generation target: `127.0.0.1` only.
- Ports probed: `1-200`.
- Capture interface: loopback `lo` through `dumpcap`.
- `nmap` was not installed and was not force-installed; a Python TCP connect probe was used.
- No public, campus, company, or unknown host was scanned.

The generated PCAP is for scan_group pipeline testing only. It is not a public dataset and not a formal training-label source.

## Pipeline Results

- Parsed PCAP files: 1.
- Session cards: 368.
- Scan groups: 1.
- Classification records: 6.
- RAG retrieval: successful, 6 records retrieved top-5 snippets.
- Four prompt sets: non-empty, 6 prompts each.
- Dry-run CSV: non-empty, 6 rows for stage and 6 rows for technique.
- Dry-run CSV status: placeholder only, not model predictions.

## Scan Group Validation

- `record_type=scan_group`: yes.
- `candidate_hint=TA43_01`: yes.
- `session_count`: 363.
- `unique_dst_ports`: 360.
- `failed_conn_rate`: 0.4931.
- Covered member sessions are not emitted again as individual final records.

Thresholds used: `min_scan_ports=10`, `min_scan_sessions=10`, `min_failed_rate=0.4`, `window_seconds=300`.

## Remaining Gaps

- `TA43_02`: reliable vulnerability-scan sample still missing.
- `TA03_01`: reliable implant/backdoor-placement sample still missing.
- `TA11_01`: reliable access-backdoor sample still missing.

## API Test Readiness

The port-scan path is ready for a small Qwen3.5-27B API smoke test after explicit user approval. It is still not a balanced public benchmark for all official labels.
