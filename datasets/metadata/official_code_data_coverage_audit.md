# Official-code data coverage audit

- Gate: `PASS`
- Unknown statuses: 0
- High-confidence PCAP-based coverage: `TA43_01`, `TA11_02`.
- Flow-only secondary coverage: `TA01_01`, `TA01_02`, `TN01_01`; CSE Bot also supports secondary `TA11_02`.
- Missing/low-confidence gaps: `TA43_02`, `TA03_01`, `TA11_01`.

| official_code | category | label_quality | primary | secondary | sft | current_sources | missing_reason | next_action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TA43_01 | 端口扫描 | high_controlled | True | True | True | controlled local nmap portscan PCAP; Zeek scan_group under outputs/zeek_rebuild |  | Keep as engineering validation; add real public portscan/vulnerability-scan PCAP later for diversity. |
| TA43_02 | 漏洞扫描 | missing | False | False | False | RAG concept docs only; UNSW/CIC metadata mentions reconnaissance but no isolated local vulnerability-scan sample | No local public PCAP/flow row with clear vulnerability scan label distinct from generic port scan or exploit. | Find small public vulnerability scanner PCAP or labeled flow with scanner/probe evidence; do not use exploit rows as TA43_02. |
| TA01_01 | 密码爆破 | high_flow_only | False | True | medium_after_review | CSE-CIC-IDS2018 brute force flow CSV (FTP-BruteForce/SSH-Bruteforce); RAG bruteforce boundary docs | No matching raw PCAP/Zeek evidence in local tree. | Use secondary eval/SFT candidate only; seek PCAP brute-force subset for primary eval. |
| TA01_02 | 漏洞利用 | medium_flow_only | False | True | medium_after_review | CSE-CIC-IDS2018 webattack flow CSV (SQL Injection/XSS); RAG exploit boundary docs | Flow-only labels lack payload/HTTP evidence; web brute force rows are not exploitation. | Use SQL Injection/XSS only as secondary; add PCAP with exploit payload for primary. |
| TA03_01 | 植入后门 | low | False | False | False | RAG concept docs only; CSE infiltration flow is broad and not an implant-install label | No reliable evidence of installation/persistence/dropper distinct from access or callback. | Need manually vetted PCAP/flow with backdoor installation or persistence evidence. |
| TA11_01 | 访问后门 | missing | False | False | False | RAG concept docs only; UNSW Backdoors metadata only; no local sample | No local sample showing operator/inbound access to existing backdoor distinct from implant or callback. | Find small vetted backdoor-access PCAP/flow metadata; require manual review. |
| TA11_02 | 木马回连 | high_pcap_and_medium_flow | True | True | True | CTU-13 From-Botnet joined to Zeek conn records; CSE-CIC-IDS2018 Bot flow CSV; RAG callback/C2 docs |  | Prefer CTU Zeek records for primary; manually review flow-only Bot rows before SFT. |
| TN01_01 | 上网及业务访问 | high_flow_only_or_low_ctu_background | False | True | medium_after_review | CSE-CIC-IDS2018 Benign flow CSV; CTU Background low-confidence only; RAG normal boundary docs | No high-confidence normal PCAP+Zeek eval set in current tree. | Use flow-only secondary; add benign PCAP/Zeek sessions for primary normal eval. |
