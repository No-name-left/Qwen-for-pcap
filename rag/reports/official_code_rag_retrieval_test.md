# Official-code RAG retrieval test

- Gate: `PASS`
- Queries: 17
- Top K: 5
- Zero-hit queries: 0

| query_id | hits | top docs |
| --- | ---: | --- |
| q_code_TA43_01 | 5 | competition_TA43_01_port_scan, competition_TA43_01_port_scan, competition_port_scan_vs_vulnerability_scan |
| q_code_TA43_02 | 5 | competition_TA43_02_vulnerability_scan, competition_boundary_TA43_02_vs_TA01_02, competition_boundary_TA43_01_vs_TA43_02 |
| q_code_TA01_01 | 5 | competition_TA01_01_bruteforce, competition_bruteforce_boundary, competition_boundary_TA01_01_vs_TN01_01 |
| q_code_TA01_02 | 5 | competition_TA01_02_exploit, competition_boundary_TA43_02_vs_TA01_02, web_exploit_detection |
| q_code_TA03_01 | 5 | competition_TA03_01_backdoor_install, competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02, competition_backdoor_implant_access_callback_boundary |
| q_code_TA11_01 | 5 | competition_TA11_01_backdoor_access, competition_backdoor_implant_access_callback_boundary, competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02 |
| q_code_TA11_02 | 5 | competition_TA11_02_trojan_callback, competition_boundary_TA11_02_vs_TN01_01, competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02 |
| q_code_TN01_01 | 5 | competition_TN01_01_normal_business, competition_normal_business_traffic_boundary, competition_boundary_TA01_01_vs_TN01_01 |
| q_boundary_TA43_01_TA43_02 | 5 | competition_boundary_TA43_01_vs_TA43_02, competition_port_scan_vs_vulnerability_scan, competition_TA43_02_vulnerability_scan |
| q_boundary_TA43_02_TA01_02 | 5 | competition_boundary_TA43_02_vs_TA01_02, competition_vulnerability_scan_vs_exploitation, competition_TA43_02_vulnerability_scan |
| q_boundary_TA01_01_TN01_01 | 5 | competition_boundary_TA01_01_vs_TN01_01, competition_TA01_01_bruteforce, competition_bruteforce_boundary |
| q_boundary_TA11_02_TN01_01 | 5 | competition_boundary_TA11_02_vs_TN01_01, competition_TA11_02_trojan_callback, competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02 |
| q_boundary_TA03_TA11 | 5 | competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02, competition_backdoor_implant_access_callback_boundary, competition_TA11_01_backdoor_access |
| q_normal_vs_c2_low_signal | 5 | competition_boundary_TA11_02_vs_TN01_01, competition_TN01_01_normal_business, competition_normal_business_traffic_boundary |
| q_normal_vs_c2_strong | 5 | competition_TA11_02_trojan_callback, competition_boundary_TA11_02_vs_TN01_01, competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02 |
| q_portscan_scan_group | 5 | competition_TA43_01_port_scan, competition_TA43_01_port_scan, competition_session_and_scan_group_policy |
| q_exploit_vulnscan | 5 | competition_boundary_TA43_02_vs_TA01_02, competition_TA01_02_exploit, competition_TA43_02_vulnerability_scan |

## Coverage notes

- Queries cover all 8 official codes, 5 required boundaries, two normal-vs-C2 cases, one portscan scan_group case, and one exploit/vulnerability-scan boundary case.
- This is a local keyword retrieval smoke test; it does not call the LLM API.
