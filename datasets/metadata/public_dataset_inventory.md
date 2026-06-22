# Public dataset inventory

Updated: 2026-06-22. This inventory describes files observed on disk, not stale historical manifest claims.

## Existing traffic assets

| Dataset | Local asset | Type | Size | Status | Notes |
|---|---|---:|---:|---|---|
| CTU-13 Scenario 1 | `datasets/public/ctu13/raw/botnet-capture-20110810-neris.pcap` | PCAP | 58,266,506 bytes | existing | Botnet-only capture; Zeek-derived sessions already exist locally. |
| CTU-13 Scenario 1 | `datasets/public/ctu13/labels/capture20110810.binetflow` | flow labels | 386,629,271 bytes | existing | Contains `From-Botnet*`, `From-Normal*`, and noisy `Background*`. |
| CTU-13 MCFP-43 | `botnet-capture-20110811-neris.pcap` / `capture20110811.binetflow.2format` | PCAP + flow labels | 36,261,479 + 444,103,095 bytes | downloaded | Botnet-only PCAP, matching scenario labels and README; no executable sample. |
| CTU-13 MCFP-46 | `botnet-capture-20110815-fast-flux.pcap` / `capture20110815-2.binetflow.2format` | PCAP + flow labels | 30,941,919 + 32,079,494 bytes | downloaded | Botnet-only PCAP, matching scenario labels and README; no executable sample. |
| CTU-13 MCFP-47 | `botnet-capture-20110816-donbot.pcap` / `capture20110816.binetflow.2format` | PCAP + flow labels | 5,284,095 + 138,477,291 bytes | downloaded | Botnet-only PCAP, matching scenario labels and README; no executable sample. |
| CSE-CIC-IDS2018 | `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | flow CSV | 358,223,333 bytes | existing | Brute-force and benign; flow-only. |
| CSE-CIC-IDS2018 | `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | flow CSV | 382,636,202 bytes | existing | Web attacks and benign; flow-only. |
| CSE-CIC-IDS2018 | `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | flow CSV | 352,368,373 bytes | existing | Bot and benign; flow-only. |
| CSE-CIC-IDS2018 | `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | flow CSV | 107,842,858 bytes | existing | Infiltration is low-confidence for substage mapping; flow-only. |
| Controlled port scan | `datasets/public/feasibility/raw/portscan/generated_nmap_local_scan.pcap` | PCAP | 95,168 bytes | existing | Local controlled sample; one Zeek `scan_group` with 181 destination ports. |
| Wireshark NMap Captures | `nmap_standard_scan.pcap`, `nmap_OS_scan.pcap`, `nmap_OS_scan_successful.pcap` | PCAP | 152,292 + 161,520 + 157,862 bytes | downloaded | Official archive README records exact Nmap commands; three external-high `TA43_01` scan groups, not vulnerability scans. |
| Synthetic controlled | 24 loopback fixtures under `datasets/public/synthetic_controlled/raw/` | PCAP | 183,114 bytes total | generated local | Three per code; coverage-only, tracked separately, never external or strict. |

Exact hashes and statuses are maintained in `download_manifest.csv`.

## Existing metadata

- Official/source pages are present for CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15 and the AWS registry/listing.
- Source-page snapshots were added for CTU-13, IoT-23, BoT-IoT, ToN-IoT, CICIoT2023, and Malware-Traffic-Analysis.net.
- The historical zero-byte Wireshark Nmap ZIP was repaired using the current official GitLab wiki attachment; selected captures and command README now validate successfully.
- `datasets/metadata/dataset_manifest.csv` contains historical paths that are currently absent. Those rows remain historical and are not promoted to `already_exists`.

## Other scanned roots

- `datasets/`, `data/`, and `outputs/` were scanned for PCAP, flow CSV, labels and public-evaluation artifacts.
- `/data/datasets/` was not present at review time.
- `/data/models/` was not present at review time; no model-file details were recorded.
- Generated `outputs/` artifacts are pipeline products, not additional public raw datasets.

## Current limitations

- No high-confidence **external** local data yet exists for `TA43_02`, `TA03_01`, or `TA11_01`; their new runnable fixtures are synthetic controlled only.
- CSE-CIC flow records must stay `flow_only`; they are useful for prompt boundaries but not for PCAP/session accuracy claims.
- Additional downloaded CTU scenarios strengthen `TA11_02` only; they do not close backdoor-install/access gaps.
