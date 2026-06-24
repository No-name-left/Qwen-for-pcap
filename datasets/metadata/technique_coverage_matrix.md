# Official technique coverage matrix

Updated: 2026-06-24. Counts are runnable classification records. Synthetic and external domains are never merged. Strict admission additionally requires positive observable evidence at the classification-record granularity.

| Technique | ext high PCAP | ext high flow | ext medium | ext low | synthetic | Strict status | Main limitation / acquisition target |
|---|---:|---:|---:|---:|---:|---|---|
| `TA43_01` | 3 | 0 | 0 | 0 | 4 | small PCAP subset | Wireshark Nmap is explicit but only one tool/family; add Zmap/SYN/connect diversity. |
| `TA43_02` | 0 | 0 | 0 | 0 | 3 | no external strict data | Acquire explicit Nmap NSE/Nikto/OpenVAS/service-version/plugin PCAP. |
| `TA01_01` | 0 | 5 | 0 | 0 | 3 | coverage-only; 0 strict | Current rows lack endpoint and authentication-attempt fields; add PCAP-aligned SSH/FTP/RDP/HTTP repeated failures. |
| `TA01_02` | 0 | 0 | 5 | 0 | 3 | coverage-only | Current CSE SQLi/XSS rows lack packet payload; acquire payload-visible exploit-attempt PCAP. |
| `TA03_01` | 0 | 0 | 0 | 0 | 3 | synthetic only | Acquire packet/timeline-visible harmless marker or real incident upload/deployment evidence without malware samples. |
| `TA11_01` | 0 | 0 | 0 | 0 | 3 | synthetic only | Acquire direction-verified operator access to an existing webshell/backdoor. |
| `TA11_02` | 3 | 0 | 2 | 0 | 3 | 3 PCAP callback groups | Endpoint-aligned CTU TCP-CC labels support the groups; add independent family diversity and benign callback-like negatives. |
| `TN01_01` | 0 | 4 | 0 | 0 | 3 | 3 flow-secondary strict | Add diverse benign HTTP/DNS/TLS/login PCAP sessions. |

## Policy

- Strict subset: high source tier plus positive observable evidence at the evaluation-unit granularity; source tier alone is insufficient. PCAP groups and flow-secondary records are reported separately.
- Coverage subset: may add `external_medium` and `synthetic_controlled`, visibly tiered.
- `external_low` remains catalog/manual analysis only; there are currently zero normalized low runnable records.
- No SFT/LoRA construction is performed in this round.
