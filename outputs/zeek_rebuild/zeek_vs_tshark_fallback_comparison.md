# Zeek vs tshark_fallback comparison

- Old records: 206
- New records: 31740
- Old scan groups: 1
- New scan groups: 1
- Old avg duration: 681.2421829365854
- New avg duration: 6.347284004042063
- Old extreme duration >1h: 10
- New extreme duration >1h: 9
- New proto distribution: `{"icmp": 124, "tcp": 22664, "udp": 8951, "unknown_transport": 1}`
- New service non-null: 10300
- New conn_state non-null: 31739
- New history non-null: 31614
- Direction splitting improved because Zeek conn.log provides bidirectional connection records; portscan scan_group is still aggregated as behavior-level output.
- Conclusion: subsequent tests should prefer Zeek rebuild records; tshark fallback should be reserved for missing conn.log cases.
