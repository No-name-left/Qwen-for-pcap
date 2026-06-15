# Zeek PCAP parse test

## ctu13_scenario1_test

- PCAP: `datasets/public/ctu13/raw/botnet-capture-20110810-neris.pcap`
- Output dir: `outputs/zeek_logs/ctu13_scenario1_test`
- Return code: 0
- Usable conn.log: true
- conn.log rows: 31736
- Logs: `{"conn.log": true, "dns.log": true, "http.log": true, "ssl.log": true, "tls.log": false, "weird.log": true, "x509.log": true}`

### Sample conn rows

- `1312967066.683089	Cbrbq2sEpsICunI53	147.32.84.165	1027	74.125.232.195	80	tcp	http	0.045136	393	77	RSTO	F	F	0	ShADTadR	8	1122	3	205	-	6`
- `1312967063.241037	CzYcNj2hV6L0J8w6M7	147.32.84.165	137	147.32.84.255	137	udp	dns	12.452268	2476	0	S0	F	F	0	D	38	3540	0	0	-	17`
- `1312967064.405753	CDcUdncIoYIs0A5Zg	147.32.84.165	1025	147.32.80.9	53	udp	dns	2.276383	134	558	SF	F	F	0	Dd	4	246	2	614	-	17`
- `1312967072.432327	C1LbiqK3Qsmz2qwHb	147.32.84.165	138	147.32.84.255	138	udp	-	4.013247	1160	0	S0	F	F	0	D	6	1328	0	0	-	17`
- `1312967072.734678	C5PfWGHJukCdsg114	147.32.84.165	0	224.0.0.22	0	unknown_transport	-	0.835910	0	0	OTH	F	T	0	-	4	160	0	0	-	2`
## portscan_generated_test

- PCAP: `datasets/public/feasibility/raw/portscan/generated_nmap_local_scan.pcap`
- Output dir: `outputs/zeek_logs/portscan_generated_test`
- Return code: 0
- Usable conn.log: true
- conn.log rows: 185
- Logs: `{"conn.log": true, "dns.log": false, "http.log": false, "ssl.log": false, "tls.log": false, "weird.log": true, "x509.log": false}`

### Sample conn rows

- `1781441845.024226	C4DP6h2Y5nQCACKBHk	127.0.0.1	41744	127.0.0.1	22	tcp	-	-	-	-	OTH	T	T	0	C	0	0	0	0	-	6`
- `1781441845.516734	CGBbrd2IrNfttmqUAd	127.0.0.1	49354	127.0.0.1	180	tcp	-	0.000007	0	0	RSTRH	T	T	0	Cr	0	0	1	40	-	6`
- `1781441845.504268	CLNyurMWdaDRGz199	127.0.0.1	47978	127.0.0.1	176	tcp	-	0.000005	0	0	RSTRH	T	T	0	Cr	0	0	1	40	-	6`
- `1781441845.501152	CIW0FkURGhtjx6uC9	127.0.0.1	37296	127.0.0.1	175	tcp	-	0.000006	0	0	RSTRH	T	T	0	Cr	0	0	1	40	-	6`
- `1781441845.494922	CvrTnmYdmPWR0Ocbe	127.0.0.1	42752	127.0.0.1	173	tcp	-	0.000006	0	0	RSTRH	T	T	0	Cr	0	0	1	40	-	6`

### stderr tail

```text
1781441845.516741 warning in /opt/zeek/share/zeek/base/misc/find-checksum-offloading.zeek, line 54: Your trace file likely has invalid TCP checksums, most likely from NIC checksum offloading.  By default, packets with invalid checksums are discarded by Zeek unless using the -C command-line option or toggling the 'ignore_checksums' variable.  Alternatively, disable checksum offloading by the network adapter to ensure Zeek analyzes the actual checksums that are transmitted.
1781441845.516741 warning in /opt/zeek/share/zeek/base/misc/find-filtered-trace.zeek, line 69: The analyzed trace file was determined to contain only TCP control packets, which may indicate it's been pre-filtered.  By default, Zeek reports the missing segments for this type of trace, but the 'detect_filtered_trace' option may be toggled if that's not desired.

```
