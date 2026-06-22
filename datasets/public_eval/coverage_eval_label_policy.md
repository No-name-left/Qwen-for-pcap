# Coverage evaluation label policy

The `confidence_level` field is authoritative:

- `external_high_pcap`: public high-confidence PCAP/session-derived; eligible for strict PCAP metrics.
- `external_high_flow`: public high-confidence flow-only; eligible for strict flow metrics, reported separately.
- `external_medium`: prompt/RAG boundary debugging only.
- `external_low`: candidate/background analysis only.
- `synthetic_controlled`: pipeline and missing-behavior coverage only; never public/external or strict evidence.

Strict combined summaries may include both external-high tiers only when their PCAP and flow components are also shown separately. No medium, low or synthetic row enters strict accuracy.

## Current public coverage records

- Records: 23
- Strict external: 15 (6 PCAP/session-derived, 9 flow-only)
- Coverage-only: 7 external-medium plus 1 legacy controlled fixture
- Missing external high PCAP classes: `TA43_02`, `TA01_01`, `TA01_02`, `TA03_01`, `TA11_01`, `TN01_01`

| Technique | Tier | Record type | Count |
|---|---|---|---:|
| `TA43_01` | `external_high_pcap` | `scan_group` | 3 |
| `TA43_01` | `synthetic_controlled` | `scan_group` | 1 |
| `TA01_01` | `external_high_flow` | `flow_only` | 5 |
| `TA01_02` | `external_medium` | `flow_only` | 5 |
| `TA11_02` | `external_high_pcap` | `session` | 3 |
| `TA11_02` | `external_medium` | `flow_only` | 2 |
| `TN01_01` | `external_high_flow` | `flow_only` | 4 |

`TA43_02`, `TA03_01`, and `TA11_01` have no runnable external record. Their three-per-class real-API coverage candidates are maintained only in `synthetic_controlled_manifest.csv` and `real_api_candidate_manifest.csv`.
