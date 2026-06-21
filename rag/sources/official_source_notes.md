# Official source notes

This file records lightweight source-grounding references. It stores URL status, page title or fetch error, and one-line usage notes only. It does not store full webpages, full malware reports, current test answers, or evaluation mappings.

## Deprecated failed sources retained for audit continuity

- Malpedia `win.strrat` previously returned 404 and is deprecated for this project; stable replacement is Malpedia `jar.strrat` plus NHS Digital, Microsoft, and ThreatFox references.
- A CISA SMB/DOUBLEPULSAR-related URL previously failed and is deprecated for this project; stable replacements are NHS Digital, Help Net Security, ExtraHop, and Microsoft MS17-010 references.

## Stable source categories

- MITRE ATT&CK: tactic and stage terminology.
- Zeek official docs: conn.log and dns.log field semantics.
- Microsoft MS17-010: SMBv1 remote-code-execution and SMB exploit grounding.
- STRRAT public sources: Java RAT / Remote Access Trojan / C2 and checkin behavior.
- DOUBLEPULSAR public sources: backdoor / implant / post-exploitation / beacon behavior.

## URL checks

- MITRE ATT&CK home: `200`; title/summary: MITRE ATT&CK®; usage: Attack knowledge-base entry point.; URL: https://attack.mitre.org/
- MITRE ATT&CK tactics: `200`; title/summary: (title not found); usage: Tactic/stage mapping overview.; URL: https://attack.mitre.org/tactics/
- MITRE Reconnaissance: `200`; title/summary: Reconnaissance, Tactic TA0043 - Enterprise | MITRE ATT&CK®; usage: Reconnaissance-stage grounding.; URL: https://attack.mitre.org/tactics/TA0043/
- MITRE Initial Access: `200`; title/summary: Initial Access, Tactic TA0001 - Enterprise | MITRE ATT&CK®; usage: Initial-access-stage grounding.; URL: https://attack.mitre.org/tactics/TA0001/
- MITRE Persistence: `200`; title/summary: Persistence, Tactic TA0003 - Enterprise | MITRE ATT&CK®; usage: Persistence-stage grounding.; URL: https://attack.mitre.org/tactics/TA0003/
- MITRE Command and Control: `200`; title/summary: Command and Control, Tactic TA0011 - Enterprise | MITRE ATT&CK®; usage: Command-and-control-stage grounding.; URL: https://attack.mitre.org/tactics/TA0011/
- Zeek conn.log: `200`; title/summary: conn.log — Book of Zeek (9.0.0-dev.369); usage: Zeek connection-summary fields.; URL: https://docs.zeek.org/en/master/reference/logs/conn.html
- Zeek dns.log: `200`; title/summary: dns.log — Book of Zeek (9.0.0-dev.369); usage: Zeek DNS fields.; URL: https://docs.zeek.org/en/master/reference/logs/dns.html
- Microsoft MS17-010: `200`; title/summary: Microsoft Security Bulletin MS17-010 - Critical | Microsoft Learn; usage: SMBv1 RCE and SMB exploit grounding.; URL: https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010
- Malpedia STRRAT jar.strrat: `200`; title/summary: STRRAT (Malware Family); usage: Stable STRRAT malware-family grounding.; URL: https://malpedia.caad.fkie.fraunhofer.de/details/jar.strrat
- NHS Digital STRRAT CC-3867: `failed_to_fetch`; title/summary: HTTP Error 403: Forbidden; usage: Backup STRRAT public reference.; URL: https://digital.nhs.uk/cyber-alerts/2021/cc-3867
- Microsoft STRRAT threat search: `200`; title/summary: Threat description search results - Microsoft Security Intelligence; usage: Backup STRRAT vendor naming.; URL: https://www.microsoft.com/en-us/wdsi/threats/threat-search?query=Trojan%3AJava%2FStrRat.A%21MTB
- ThreatFox jar.strrat: `200`; title/summary: ThreatFox | STRRAT; usage: Backup STRRAT threat-intel tag.; URL: https://threatfox.abuse.ch/browse/malware/jar.strrat/
- NHS Digital DoublePulsar CC-1354: `failed_to_fetch`; title/summary: HTTP Error 403: Forbidden; usage: Backup DoublePulsar / SMB post-exploitation reference.; URL: https://digital.nhs.uk/cyber-alerts/2017/cc-1354
- Help Net Security DoublePulsar: `200`; title/summary: Tens of thousands Windows systems implanted with NSA's DoublePulsar - Help Net Security; usage: Stable DoublePulsar backdoor reference.; URL: https://www.helpnetsecurity.com/2017/04/24/windows-doublepulsar-backdoor/
- ExtraHop DoublePulsar detected: `200`; title/summary: DoublePulsar Detected — ExtraHop; usage: Stable DoublePulsar detection reference.; URL: https://www.extrahop.com/blog/double-pulsar-detected
- Deprecated Malpedia STRRAT win.strrat: `failed_to_fetch`; title/summary: HTTP Error 404: Not Found; usage: Deprecated failed STRRAT URL; replaced by jar.strrat plus backups.; URL: https://malpedia.caad.fkie.fraunhofer.de/details/win.strrat
- Deprecated CISA SMB/DOUBLEPULSAR page: `failed_to_fetch`; title/summary: HTTP Error 404: Not Found; usage: Deprecated failed DOUBLEPULSAR-related URL; replaced by NHS, Help Net Security, ExtraHop, and Microsoft MS17-010.; URL: https://www.cisa.gov/news-events/alerts/2017/06/12/microsoft-windows-smbv1-vulnerability-and-mitigation

## Safety boundary

- These notes provide source grounding only.
- They do not include current test answers, sample-to-label mappings, original PCAP paths, or answer-PDF details.
