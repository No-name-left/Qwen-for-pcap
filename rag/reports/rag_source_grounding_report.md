# RAG source grounding report

## Final patch summary

- Retained failed/deprecated STRRAT and CISA/DOUBLEPULSAR source records for audit continuity.
- Added stable STRRAT sources: Malpedia `jar.strrat`, NHS Digital CC-3867, Microsoft threat search, and ThreatFox.
- Added stable DOUBLEPULSAR / SMB post-exploitation sources: NHS Digital CC-1354, Help Net Security, ExtraHop, and Microsoft MS17-010.
- Updated source manifest and official source notes.
- Reconfirmed local ET Open Suricata rules as `msg` / `classtype` / `sid` grounding only.

## URL checks

- MITRE ATT&CK home: `200`; title/summary: MITRE ATT&CK®; usage: Attack knowledge-base entry point.; URL: https://attack.mitre.org/
- MITRE ATT&CK tactics: `200`; title/summary: (title not found); usage: Tactic/stage mapping overview.; URL: https://attack.mitre.org/tactics/
- MITRE Reconnaissance: `200`; title/summary: Reconnaissance, Tactic TA0043 - Enterprise | MITRE ATT&CK®; usage: Reconnaissance-stage grounding.; URL: https://attack.mitre.org/tactics/TA0043/
- MITRE Initial Access: `200`; title/summary: Initial Access, Tactic TA0001 - Enterprise | MITRE ATT&CK®; usage: Initial-access-stage grounding.; URL: https://attack.mitre.org/tactics/TA0001/
- MITRE Persistence: `200`; title/summary: Persistence, Tactic TA0003 - Enterprise | MITRE ATT&CK®; usage: Persistence-stage grounding.; URL: https://attack.mitre.org/tactics/TA0003/
- MITRE Command and Control: `200`; title/summary: Command and Control, Tactic TA0011 - Enterprise | MITRE ATT&CK®; usage: Command-and-control-stage grounding.; URL: https://attack.mitre.org/tactics/TA0011/
- Zeek conn.log: `200`; title/summary: conn.log — Book of Zeek (9.0.0-dev.369); usage: Zeek connection-summary fields.; URL: https://docs.zeek.org/en/master/reference/logs/conn.html
- Zeek dns.log: `200`; title/summary: dns.log — Book of Zeek (9.0.0-dev.369); usage: Zeek DNS fields.; URL: https://docs.zeek.org/en/master/reference/logs/dns.html
- Suricata EVE JSON format: `200`; title/summary: 15.1.2. Eve JSON Format — Suricata 9.0.0-dev documentation; usage: Suricata EVE alert fields.; URL: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- Microsoft MS17-010: `200`; title/summary: Microsoft Security Bulletin MS17-010 - Critical | Microsoft Learn; usage: SMBv1 RCE and SMB exploit grounding.; URL: https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010
- Malpedia STRRAT jar.strrat: `200`; title/summary: STRRAT (Malware Family); usage: Stable STRRAT malware-family grounding.; URL: https://malpedia.caad.fkie.fraunhofer.de/details/jar.strrat
- NHS Digital STRRAT CC-3867: `failed_to_fetch`; title/summary: HTTP Error 403: Forbidden; usage: Backup STRRAT public reference.; URL: https://digital.nhs.uk/cyber-alerts/2021/cc-3867
- Microsoft STRRAT threat search: `200`; title/summary: Threat description search results - Microsoft Security Intelligence; usage: Backup STRRAT vendor naming.; URL: https://www.microsoft.com/en-us/wdsi/threats/threat-search?query=Trojan%3AJava%2FStrRat.A%21MTB
- ThreatFox jar.strrat: `200`; title/summary: ThreatFox | STRRAT; usage: Backup STRRAT threat-intel tag.; URL: https://threatfox.abuse.ch/browse/malware/jar.strrat/
- NHS Digital DoublePulsar CC-1354: `failed_to_fetch`; title/summary: HTTP Error 403: Forbidden; usage: Backup DoublePulsar / SMB post-exploitation reference.; URL: https://digital.nhs.uk/cyber-alerts/2017/cc-1354
- Help Net Security DoublePulsar: `200`; title/summary: Tens of thousands Windows systems implanted with NSA's DoublePulsar - Help Net Security; usage: Stable DoublePulsar backdoor reference.; URL: https://www.helpnetsecurity.com/2017/04/24/windows-doublepulsar-backdoor/
- ExtraHop DoublePulsar detected: `200`; title/summary: DoublePulsar Detected — ExtraHop; usage: Stable DoublePulsar detection reference.; URL: https://www.extrahop.com/blog/double-pulsar-detected
- Local ET Open rules: `local_file`; title/summary: outputs/parsed/suricata_rules/suricata.rules; usage: Local Suricata msg/classtype/sid grounding.; URL: outputs/parsed/suricata_rules/suricata.rules
- Deprecated Malpedia STRRAT win.strrat: `failed_to_fetch`; title/summary: HTTP Error 404: Not Found; usage: Deprecated failed STRRAT URL; replaced by jar.strrat plus backups.; URL: https://malpedia.caad.fkie.fraunhofer.de/details/win.strrat
- Deprecated CISA SMB/DOUBLEPULSAR page: `failed_to_fetch`; title/summary: HTTP Error 404: Not Found; usage: Deprecated failed DOUBLEPULSAR-related URL; replaced by NHS, Help Net Security, ExtraHop, and Microsoft MS17-010.; URL: https://www.cisa.gov/news-events/alerts/2017/06/12/microsoft-windows-smbv1-vulnerability-and-mitigation

## Key RAG documents checked

- rag/knowledge/signatures/signature_strrat.md
- rag/knowledge/signatures/signature_doublepulsar.md
- rag/knowledge/signatures/signature_ms17_010_smb.md
- rag/knowledge/signatures/signature_protocol_anomaly.md
- rag/knowledge/tool_fields/suricata_eve_alerts.md
- rag/knowledge/tool_fields/zeek_conn_log_fields.md
- rag/knowledge/attack_stages/reconnaissance_stage.md
- rag/knowledge/attack_stages/initial_access_stage.md
- rag/knowledge/attack_stages/command_and_control_stage.md

## Source manifest status

- source_manifest rows: 35
- Stable source additions are present.
- Deprecated failed source records are retained and marked as deprecated_failed_reference.

## Current grounding gaps

- NHS Digital pages returned 403 from this environment but remain recorded as stable public URLs.
- False-positive policy and aggregation policy are mostly distilled/project-analysis knowledge; optional manual source enrichment can be added later.

## Test answer leakage

- Current test answers were not added.
- Expected labels, original PCAP paths, and answer-PDF conclusions were not added.
