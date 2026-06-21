# Official technique coverage matrix

Updated: 2026-06-22. “High” means the public source label is a close semantic match; it does not mean official competition ground truth.

| Technique | Existing high-confidence source | Medium candidate | Low/manual candidate | PCAP | Flow label | Train | Test | Current gap |
|---|---|---|---|---|---|---|---|---|
| `TA43_01` port scan | Controlled Nmap `scan_group` | UNSW Reconnaissance; IoT-23 horizontal scan | CSE infiltration sweep after time alignment | Yes | Partial | Controlled only | Yes, with source split | More diverse public PCAP scans and negative service-probing cases. |
| `TA43_02` vulnerability scan | None | BoT-IoT Service Scan; Nmap NSE/Nikto/OpenVAS if manually generated | UNSW Analysis; CSE service enumeration | No current trusted PCAP | Candidate only | No | Boundary eval only | No perfect public label; service enumeration must not be forced to high confidence. |
| `TA01_01` password brute force | CSE-CIC-IDS2018 FTP/SSH brute force flow rows | CIC web brute-force variants | None | No current labeled PCAP | Yes | Yes, flow-only | Yes, reported separately | Add PCAP-aligned Patator/brute-force sessions. |
| `TA01_02` vulnerability exploitation | UNSW Exploits candidate after acquisition; CIC Heartbleed candidate | CSE SQL Injection/XSS flow rows; ToN-IoT web attacks | Generic fuzzing without payload confirmation | Not local | Yes | High only after source acquisition | Medium boundary eval now | Need raw packet/payload-aligned exploit sessions. |
| `TA03_01` implant backdoor | None | CSE infiltration only after timeline/manual evidence | UNSW Shellcode/Backdoors; MCF host narrative | No | Broad scenario only | No | Manual only | Network evidence rarely proves installation; requires curated timeline/packet evidence. |
| `TA11_01` access backdoor | None | Manually confirmed operator-to-implant sessions | CSE infiltration; UNSW Backdoors category | No | Broad scenario only | No | Manual only | Must establish direction and existing-backdoor context; family labels are insufficient. |
| `TA11_02` trojan callback | CTU-13 botnet-only PCAP plus `From-Botnet*` labels | CSE Bot flow rows; IoT-23 C&C; verified MCF/MTA sessions | Generic Bot/Mirai/Backdoors categories | Yes | Yes | CTU high-confidence subset | Yes; flow-only separate | Add multiple malware families and benign callback-like negatives. |
| `TN01_01` normal business | CSE Benign flow rows; CTU `From-Normal*` | IoT-23 benign captures; UNSW Normal | CTU `Background*` | Partial | Yes | Explicit normal only | Yes; source-aware | Add diverse real business PCAP; avoid treating unlabeled background as clean normal. |

## Coverage conclusion

- All eight codes have at least a candidate source recorded.
- Locally runnable high/medium evaluation currently covers five codes: `TA43_01`, `TA01_01`, `TA01_02`, `TA11_02`, `TN01_01`.
- `TA43_02`, `TA03_01`, and `TA11_01` remain explicit gaps; they are not filled with synthetic high-confidence labels.
