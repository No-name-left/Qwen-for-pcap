# Feasibility label mapping

Public labels are not competition official answers. They are used only for feasibility evaluation, manual review, and candidate sample planning.

| Source | Public label | Mapped official code | Quality | Use |
| --- | --- | --- | --- | --- |
| CTU-13 | `From-Botnet*` | `TA11` / `TA11_02` | high | PCAP parser and C2/callback feasibility |
| CTU-13 | `From-Normal*` | `TN01` / `TN01_01` | medium | normal feasibility |
| CTU-13 | `Background*` | `TN01` / `TN01_01` | low | noisy background/manual review |
| CSE-CIC-IDS2018 | `FTP-BruteForce`, `SSH-Bruteforce` | `TA01` / `TA01_01` | high | flow-label evaluation only |
| CSE-CIC-IDS2018 | `SQL Injection`, `Brute Force -XSS` | `TA01` / `TA01_02` | medium | flow-label evaluation/manual review |
| CSE-CIC-IDS2018 | `Bot` | `TA11` / `TA11_02` | medium | flow-label evaluation |
| CSE-CIC-IDS2018 | `Benign` | `TN01` / `TN01_01` | high | flow-label evaluation |
| CSE-CIC-IDS2018 | `Infilteration` | possible `TA01_02` / `TA03_01` / `TA11_01` | low | manual review only |

No public labels should be written into `rag/knowledge/`.
| Controlled localhost TCP connect scan | multi-port localhost probe | `TA43` / `TA43_01` | high_for_pipeline_test | scan_group pipeline validation only, not public dataset/training label |
