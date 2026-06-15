# Official-code RAG coverage audit

- Gate: `PASS`
- Official-code docs ready: 8/8
- Boundary docs ready: 5/5

## Official-code documents

| code | document | definition | evidence | boundary | normal avoidance | keywords | source grounding |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TA43_01 | `rag/knowledge/competition_labels/TA43_01_port_scan.md` | True | True | True | True | True | True |
| TA43_02 | `rag/knowledge/competition_labels/TA43_02_vulnerability_scan.md` | True | True | True | True | True | True |
| TA01_01 | `rag/knowledge/competition_labels/TA01_01_bruteforce.md` | True | True | True | True | True | True |
| TA01_02 | `rag/knowledge/competition_labels/TA01_02_exploit.md` | True | True | True | True | True | True |
| TA03_01 | `rag/knowledge/competition_labels/TA03_01_backdoor_install.md` | True | True | True | True | True | True |
| TA11_01 | `rag/knowledge/competition_labels/TA11_01_backdoor_access.md` | True | True | True | True | True | True |
| TA11_02 | `rag/knowledge/competition_labels/TA11_02_trojan_callback.md` | True | True | True | True | True | True |
| TN01_01 | `rag/knowledge/competition_labels/TN01_01_normal_business.md` | True | True | True | True | True | True |

## Boundary documents

| boundary | document | exists | keywords | guidance | source grounding |
| --- | --- | --- | --- | --- | --- |
| TA43_01_vs_TA43_02 | `rag/knowledge/competition_labels/boundary_TA43_01_vs_TA43_02.md` | True | True | True | True |
| TA43_02_vs_TA01_02 | `rag/knowledge/competition_labels/boundary_TA43_02_vs_TA01_02.md` | True | True | True | True |
| TA01_01_vs_TN01_01 | `rag/knowledge/competition_labels/boundary_TA01_01_vs_TN01_01.md` | True | True | True | True |
| TA11_02_vs_TN01_01 | `rag/knowledge/competition_labels/boundary_TA11_02_vs_TN01_01.md` | True | True | True | True |
| TA03_01_vs_TA11_01_vs_TA11_02 | `rag/knowledge/competition_labels/boundary_TA03_01_vs_TA11_01_vs_TA11_02.md` | True | True | True | True |

## Safety

- RAG docs contain definitions, network evidence, and decision boundaries only.
- They do not include eval expected labels, official test answers, or sample answer rows.
- Candidate hints remain weak retrieval cues, not labels.
