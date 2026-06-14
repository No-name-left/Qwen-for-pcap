# Portscan parse report

- Parsed PCAP files: 1

| case_id | packets_csv_rows | session_cards | tshark | zeek | suricata | alerts | warnings |
| --- | ---: | ---: | --- | --- | --- | ---: | --- |
| feasibility_portscan | 417 | 368 | True | False | True | 0 | zeek missing; session card builder will use tshark packet aggregation fallback; suricata eve.json exists but no alert events matched enabled rules |
