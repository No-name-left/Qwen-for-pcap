# Official-code data supplement report

- Gate: `PASS`
- New downloads: 0
- Reason: existing local public data covers five codes; missing three codes require vetted samples, so this run records gaps rather than inventing labels or downloading large datasets blindly.

- TA43_01 / controlled_portscan_pcap: used=True; quality=high_controlled; confidence=high; limitation=Controlled local sample, not broad public corpus.
- TA11_02 / ctu13_scenario1_pcap: used=True; quality=high; confidence=high; limitation=Public labels are feasibility references, not official competition truth.
- TA01_01 / cse_cic_ids2018_bruteforce_flow: used=True; quality=high_flow_only; confidence=high; limitation=Flow-only; no Zeek/PCAP validation.
- TA01_02 / cse_cic_ids2018_webattack_flow: used=True; quality=medium_flow_only; confidence=medium; limitation=Flow-only and payload unavailable; web brute-force excluded from exploit.
- TA11_02 / cse_cic_ids2018_bot_flow: used=True; quality=medium_flow_only; confidence=medium; limitation=Flow-only; lacks raw callback payload/timing context.
- TN01_01 / cse_cic_ids2018_benign_flows: used=True; quality=high_flow_only; confidence=high; limitation=Flow-only; no high-confidence normal PCAP in current tree.
- TA43_02 / missing_vulnerability_scan: used=False; quality=missing; confidence=missing; limitation=Need public scanner/probe PCAP/flow; not downloaded blindly.
- TA03_01 / missing_backdoor_install: used=False; quality=low; confidence=low; limitation=Need manual vetted implant/persistence evidence.
- TA11_01 / missing_backdoor_access: used=False; quality=missing; confidence=missing; limitation=Need manual vetted backdoor-access evidence.
