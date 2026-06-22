# Real API candidate selection

This is a readiness set, not proof of final model quality.

- Coverage subset: 24 records, exactly 3 per technique.
- Strict subset: 12 external-high records only.
- Medium and synthetic rows are coverage-only and must never enter strict metrics.

| Technique | Tier | Count |
|---|---|---:|
| `TA01_01` | `external_high_flow` | 3 |
| `TA01_02` | `external_medium` | 3 |
| `TA03_01` | `synthetic_controlled` | 3 |
| `TA11_01` | `synthetic_controlled` | 3 |
| `TA11_02` | `external_high_pcap` | 3 |
| `TA43_01` | `external_high_pcap` | 3 |
| `TA43_02` | `synthetic_controlled` | 3 |
| `TN01_01` | `external_high_flow` | 3 |

## Selection policy

- Prefer external high PCAP, then external high flow.
- Use external medium only when no high source covers the class.
- Use synthetic controlled only to expose a missing boundary shape.
- Model-visible record/PCAP IDs are stable opaque aliases; semantic source IDs remain audit-only fields outside `classification_record`.
- PCAP relationships are preserved through one alias per source PCAP; three synthetic variants are different captures.
