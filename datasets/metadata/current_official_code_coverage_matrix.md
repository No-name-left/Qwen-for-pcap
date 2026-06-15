# Current official-code coverage matrix

| official_code | sources | pcap | flow_csv | zeek | label_quality | mapping_confidence | api_eval | sft | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TA43_01 | generated local nmap portscan PCAP; Zeek scan_group | True | False | True | high_controlled | high | True | True | Engineering validation PCAP, not a broad real-world benchmark. |
| TA43_02 | CIC/UNSW metadata only; no reliable local PCAP/flow row isolated | False | False | False | missing | missing | False | False | Needs vulnerability scan PCAP or clearly labeled flow data. |
| TA01_01 | CSE-CIC-IDS2018 brute-force flow CSV | False | True | False | high_flow_only | high | secondary_only | True | Flow-only; does not validate PCAP parser. |
| TA01_02 | CSE-CIC-IDS2018 web attack flow CSV SQL Injection/XSS | False | True | False | medium_flow_only | medium | secondary_only | manual_review_recommended | Exploit mapping is medium confidence; payload unavailable. |
| TA03_01 | CSE infiltration metadata/flow broad label only | False | True | False | low | low | False | False | Infiltration does not distinguish implant installation. |
| TA11_01 | UNSW Backdoors metadata only; no reliable local sample | False | False | False | missing | missing | False | False | Needs access-to-existing-backdoor evidence. |
| TA11_02 | CTU-13 From-Botnet PCAP+binetflow; CSE Bot flow CSV | True | True | True | high_pcap_and_medium_flow | high_for_CTU_medium_for_CSE | True | True | CTU PCAP join gives high-confidence botnet-like sessions; CSE Bot is flow-only secondary. |
| TN01_01 | CSE benign flow CSV; CTU background low-confidence only | False | True | False | high_flow_only_or_low_ctu_background | high_for_CSE_benign_low_for_CTU_background | secondary_only | flow_only_ok_manual_review | No reliable Zeek PCAP normal set in current tree. |
