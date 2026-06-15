# Small coverage test set report

- Gate: `PARTIAL_PASS`
- Records: 20
- Covered official codes: 5/8
- Missing from small test: TA43_02, TA03_01, TA11_01

| code | count | confidence/profile |
| --- | ---: | --- |
| TA43_01 | 1 | high-confidence controlled scan_group |
| TA43_02 | 0 | not included: no reliable local sample |
| TA01_01 | 5 | flow-only secondary sample; hidden labels only |
| TA01_02 | 5 | flow-only secondary sample; hidden labels only |
| TA03_01 | 0 | not included: no reliable local sample |
| TA11_01 | 0 | not included: no reliable local sample |
| TA11_02 | 5 | high-confidence CTU Zeek plus medium flow-only Bot diversity |
| TN01_01 | 4 | flow-only secondary sample; hidden labels only |

## Required inclusions

- Portscan scan_group included: True
- Normal-like records included: True
- Botnet/callback-like records included: True
- Brute force records included: True
- Exploit-like records included: True

## Safety

- Expected labels are stored only in this eval metadata and future hidden labels.
- The small test deliberately omits missing categories rather than assigning weak samples as reliable labels.
