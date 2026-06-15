# Classification records report

- Input session cards: `outputs/zeek_rebuild/session_cards/session_cards_all.json`
- Session cards: 31920
- Scan groups: 1
- Scan thresholds: window_seconds=300.0, min_ports=8, min_sessions=8, min_failed_rate=0.4
- Covered scan member sessions: 181
- Final classification records: 31740
- Scan groups output: `outputs/zeek_rebuild/classification_records/scan_groups.json`
- Classification records output: `outputs/zeek_rebuild/classification_records/classification_records_all.json`

## Scan group policy

- Multi-port port-scan sessions are grouped within the same PCAP by source IP, destination IP, protocol, time window, high unique destination ports, and high failed connection rate.
- `dst_port` is written as `multiple`; `dst_ports_sample` records representative observed ports.
- Clear scan-group member sessions are not emitted as separate final classification records, avoiding duplicated final output rows.
- No cross-PCAP statistics, expected labels, or IP/domain reputation are used.
