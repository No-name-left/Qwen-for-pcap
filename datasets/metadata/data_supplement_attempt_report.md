# Data supplement attempt report

- New downloads in this run: 0.
- Reason: existing local public data already includes CTU PCAP, local portscan PCAP, and CSE-CIC-IDS2018 flow CSVs; missing PCAP types would require larger or manually vetted downloads, so they are recorded as gaps rather than fetched blindly.
- No malware, public scanning, or external target interaction was performed.

- TA43_01: generated local nmap portscan PCAP; Zeek scan_group; quality=high_controlled; limitation=Engineering validation PCAP, not a broad real-world benchmark.
- TA43_02: CIC/UNSW metadata only; no reliable local PCAP/flow row isolated; quality=missing; limitation=Needs vulnerability scan PCAP or clearly labeled flow data.
- TA01_01: CSE-CIC-IDS2018 brute-force flow CSV; quality=high_flow_only; limitation=Flow-only; does not validate PCAP parser.
- TA01_02: CSE-CIC-IDS2018 web attack flow CSV SQL Injection/XSS; quality=medium_flow_only; limitation=Exploit mapping is medium confidence; payload unavailable.
- TA03_01: CSE infiltration metadata/flow broad label only; quality=low; limitation=Infiltration does not distinguish implant installation.
- TA11_01: UNSW Backdoors metadata only; no reliable local sample; quality=missing; limitation=Needs access-to-existing-backdoor evidence.
- TA11_02: CTU-13 From-Botnet PCAP+binetflow; CSE Bot flow CSV; quality=high_pcap_and_medium_flow; limitation=CTU PCAP join gives high-confidence botnet-like sessions; CSE Bot is flow-only secondary.
- TN01_01: CSE benign flow CSV; CTU background low-confidence only; quality=high_flow_only_or_low_ctu_background; limitation=No reliable Zeek PCAP normal set in current tree.
