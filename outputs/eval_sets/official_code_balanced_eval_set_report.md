# Official-code balanced eval set report

- Gate: `PARTIAL_PASS`
- Input records: 181
- Balanced eval records: 121
- Excluded low-confidence records: 10
- Covered official codes: 5/8
- Missing official codes: TA43_02, TA03_01, TA11_01

| code | category | total | primary | secondary | small_test | notes |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| TA43_01 | port scan | 1 | 1 | 1 | 1 | controlled Zeek scan_group; high-confidence but only one record |
| TA43_02 | vulnerability scan | 0 | 0 | 0 | 0 | missing reliable local sample; not used for eval |
| TA01_01 | password brute force | 30 | 0 | 30 | 5 | flow-only secondary eval; no PCAP parser validation |
| TA01_02 | vulnerability exploitation | 30 | 0 | 30 | 5 | flow-only secondary eval; no PCAP parser validation |
| TA03_01 | backdoor installation | 0 | 0 | 0 | 0 | missing reliable local sample; not used for eval |
| TA11_01 | backdoor access | 0 | 0 | 0 | 0 | missing reliable local sample; not used for eval |
| TA11_02 | trojan callback | 30 | 20 | 30 | 5 | mixed CTU Zeek primary and CSE flow-only secondary |
| TN01_01 | normal business access | 30 | 0 | 30 | 4 | flow-only secondary eval; no PCAP parser validation |

## Gate rationale

- The eval set is usable for a limited small coverage test because it covers at least five official codes.
- It is not a full official-code benchmark because `TA43_02`, `TA03_01`, and `TA11_01` remain missing or too uncertain.
- All expected labels stay in eval metadata and are excluded from prompts.
