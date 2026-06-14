# Feasibility parse report

- Parsed dir: `outputs/parsed/feasibility`
- Parsed PCAP files: 1

| case_id | tshark | zeek | suricata | alerts | warnings |
| --- | --- | --- | --- | --- | --- |
| ctu13_scenario1 | True | False | True | 0 | zeek missing; session card builder will use tshark packet aggregation fallback; suricata eve.json exists but no alert events matched enabled rules |
