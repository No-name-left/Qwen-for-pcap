# Public feasibility test plan

Use a small, balanced sample first. Do not send all downloaded data through the pipeline at once. Public labels are mapped test labels, not official competition answers.

| Technique | Minimum | Fuller | Status | Source candidates | Notes |
| --- | --- | --- | --- | --- | --- |
| TA43_01 | 5-20 | 50-200 | gap_for_downloaded_data | CIC-IDS2017 Port Scan manual download; CSE-CIC-IDS2018 infiltration Nmap/port scan only after PCAP/manual review | No downloaded reliable port-scan sample yet. |
| TA43_02 | 5-20 | 50-200 | gap | CIC/CSE vulnerability scanner/probing labels if available | No reliable downloaded vulnerability-scan label yet. |
| TA01_01 | 20 | 200 | ready_flow_csv | CSE-CIC-IDS2018 Wednesday-14 FTP-BruteForce/SSH-Bruteforce; CIC-IDS2017 FTP/SSH Patator manual download | Flow CSV ready; PCAP not downloaded. |
| TA01_02 | 20 | 50-200 | partial_flow_csv | CSE-CIC-IDS2018 Thursday-22 SQL Injection/XSS; CIC-IDS2017 web attack/Heartbleed manual download | SQL Injection/XSS counts are small but enough for a minimal flow-record feasibility sample. |
| TA03_01 | 5-20 | 50-200 | gap_low_confidence | UNSW Backdoors manual download; CSE infiltration manual review | No reliable implant-placement sample downloaded. |
| TA11_01 | 5-20 | 50-200 | gap_low_confidence | UNSW Backdoors manual review; webshell/backdoor-access public PCAP if sourced later | Access-backdoor boundary is not reliably covered by current downloads. |
| TA11_02 | 20 | 200 | ready | CTU-13 From-Botnet labels and botnet-only PCAP; CSE-CIC-IDS2018 Friday-02 Bot CSV | Good coverage for malware callback/C2 feasibility. |
| TN01_01 | 20 | 200 | ready | CSE-CIC-IDS2018 Benign rows; CTU-13 From-Normal rows; Background lower confidence | Use benign/from-normal rows; mark CTU background as noisy. |
