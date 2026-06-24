# Strict observable-v3 selection

Evidence quality takes priority over class balance.

- Strict records: 9
- Excluded old weak/misaligned records: 6
- TA01_01 strict count: 0; current flow-only source cannot prove repeated authentication failures.
- Synthetic and external-medium rows: 0.

| Technique | Evidence tier | Count |
|---|---|---:|
| `TA11_02` | `high_confidence_pcap_callback_group` | 3 |
| `TA43_01` | `high_confidence_pcap_scan_group` | 3 |
| `TN01_01` | `high_confidence_flow_secondary` | 3 |

## C2 group policy

- `strict_v3_ta11_02_001`: 197 source-initiated connections to one endpoint; beacon_score=0.9, periodicity_score=0.621. PCAP endpoint behavior matches 199 public bidirectional flows explicitly labeled From-Botnet-V47-TCP-CC73-Not-Encrypted.
- `strict_v3_ta11_02_002`: 5 source-initiated connections to one endpoint; beacon_score=0.8, periodicity_score=0.933. PCAP endpoint behavior matches 9 public bidirectional flows explicitly labeled From-Botnet-V42-TCP-CC55-Custom-Encryption.
- `strict_v3_ta11_02_003`: 54 source-initiated connections to one endpoint; beacon_score=0.75, periodicity_score=0.64. PCAP endpoint behavior matches 53 public bidirectional flows explicitly labeled From-Botnet-V42-TCP-CC53-HTTP-Not-Encrypted.
