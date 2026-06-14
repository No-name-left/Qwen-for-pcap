# Public label mapping policy

Public dataset original labels are not official competition labels. They may only be mapped for pipeline tests, RAG tests, candidate SFT samples, or manual review. Do not write these public labels into the RAG main knowledge base.

## Mapping table

| Source family | Original label | Stage | Technique | Quality | Notes |
| --- | --- | --- | --- | --- | --- |
| CIC/CSE-CIC | PortScan / Nmap Portscan | TA43 | TA43_01 | high | Use when label clearly denotes port scanning. |
| CIC/CSE-CIC | Vulnerability scan / probing | TA43 | TA43_02 | medium | Requires scan-without-exploit details. |
| CIC/CSE-CIC | FTP-Patator / SSH-Patator / FTP-BruteForce / SSH-Bruteforce / Brute Force | TA01 | TA01_01 | high | Password brute force. |
| CIC/CSE-CIC | Web Attack SQL Injection / XSS / Command Injection / Heartbleed | TA01 | TA01_02 | medium | Exploit-like web/vulnerability activity; verify ambiguous web brute force separately. |
| CIC/CSE-CIC | Botnet / Bot / C2 / callback | TA11 | TA11_02 | medium | Useful for callback/C2 feasibility, but flow-only CSV may lack payload detail. |
| CIC/CSE-CIC | Benign / Normal | TN01 | TN01_01 | high | Normal/business traffic for feasibility; avoid overfitting dataset artifacts. |
| CTU-13 | From-Botnet* / C&C / malware callback | TA11 | TA11_02 | high | Use From-Botnet labels; To-Botnet is not automatically malicious. |
| CTU-13 | From-Normal* | TN01 | TN01_01 | medium | Normal host labels; background labels are noisier. |
| CTU-13 | Background* | TN01 | TN01_01 | low | Noisy background; prefer for manual review or robustness tests, not clean SFT. |
| UNSW-NB15 | Reconnaissance | TA43 | TA43_01 or TA43_02 | medium | Technique requires details. |
| UNSW-NB15 | Exploits | TA01 | TA01_02 | medium | Flow CSV only; manual review recommended. |
| UNSW-NB15 | Backdoors | TA03 or TA11 | TA03_01 or TA11_01 | low | Implant versus access boundary requires manual review. |
| UNSW-NB15 | Normal | TN01 | TN01_01 | high | Normal flow rows. |
| UNSW-NB15 | DoS / Generic / Fuzzers / Shellcode / Worms |  |  | exclude | Not directly aligned with current official labels; exclude from SFT by default. |
