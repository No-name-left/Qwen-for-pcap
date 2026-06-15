# Suricata PCAP parse test

## ctu13_scenario1_test

- PCAP: `datasets/public/ctu13/raw/botnet-capture-20110810-neris.pcap`
- Output dir: `outputs/suricata_logs/ctu13_scenario1_test`
- Return code: 0
- Usable eve.json: true
- Files: `{"eve.json": true, "fast.log": true, "stats.log": true}`
- Event counts: `{"anomaly": 11, "dns": 84570, "fileinfo": 1020, "flow": 17346, "http": 1404, "sip": 1, "smb": 36, "smtp": 81, "snmp": 16, "stats": 1, "tls": 63}`
## portscan_generated_test

- PCAP: `datasets/public/feasibility/raw/portscan/generated_nmap_local_scan.pcap`
- Output dir: `outputs/suricata_logs/portscan_generated_test`
- Return code: 0
- Usable eve.json: true
- Files: `{"eve.json": true, "fast.log": true, "stats.log": true}`
- Event counts: `{"flow": 184, "ssh": 1, "stats": 1}`
