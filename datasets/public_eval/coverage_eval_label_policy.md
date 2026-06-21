# Coverage evaluation label policy

- `high` rows form the primary test metric.
- `medium` and `low` rows remain in the coverage file as `exploratory`; reports must not merge them into the high-confidence metric.
- `flow_only` rows test prompt/RAG boundaries and are always reported separately from PCAP/session-derived rows.
- A public source label is not official competition ground truth; provenance and mapping confidence remain attached to every record.
- Missing classes are left empty rather than filled with guessed labels.

## Current split

- Records: 20
- Missing technique codes: TA43_02, TA03_01, TA11_01

| Technique | Confidence | Record type | Count |
|---|---|---|---:|
| `TA01_01` | high | `flow_only` | 5 |
| `TA01_02` | medium | `flow_only` | 5 |
| `TA11_02` | high | `session` | 3 |
| `TA11_02` | medium | `flow_only` | 2 |
| `TA43_01` | high | `scan_group` | 1 |
| `TN01_01` | high | `flow_only` | 4 |

## Known semantic gaps

- `TA43_02`: service enumeration is only a proxy for vulnerability scanning.
- `TA03_01`: broad infiltration or malware-family labels do not prove network-visible backdoor installation.
- `TA11_01`: backdoor-family labels do not prove operator access direction or phase.
