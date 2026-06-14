# Local Suricata rule notes

- Rule file used: `/root/autodl-tmp/pcap_llm_demo/outputs/parsed/suricata_rules/suricata.rules`
- Role: ground Suricata alert wording in local ET Open rules.
- Extraction policy: store only `msg`, `classtype`, and `sid`; do not copy full rule bodies.

## STRRAT

- sid=2030358; classtype=command-and-control; msg=ET MALWARE STRRAT CnC Checkin
- sid=2030359; classtype=command-and-control; msg=ET MALWARE STRRAT Initial HTTP Activity
- sid=2030360; classtype=command-and-control; msg=ET MALWARE STRRAT Requesting License Check

## MS17-010

- sid=2024208; classtype=trojan-activity; msg=ET EXPLOIT Possible ETERNALROMANCE MS17-010
- sid=2024212; classtype=trojan-activity; msg=ET EXPLOIT Possible ETERNALCHAMPION MS17-010 Sync Request (set)
- sid=2024297; classtype=attempted-admin; msg=ET EXPLOIT ETERNALBLUE Exploit M2 MS17-010
- sid=2024430; classtype=trojan-activity; msg=ET EXPLOIT Possible ETERNALBLUE Exploit M3 MS17-010
- sid=2024218; classtype=trojan-activity; msg=ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response
- sid=2024220; classtype=trojan-activity; msg=ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Request (set)
- sid=2024219; classtype=trojan-activity; msg=ET EXPLOIT Possible ETERNALROMANCE MS17-010 Heap Spray
- sid=2025649; classtype=trojan-activity; msg=ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style)

## DOUBLEPULSAR

- sid=2024216; classtype=trojan-activity; msg=ET EXPLOIT Possible DOUBLEPULSAR Beacon Response

## SMB exploit

- sid=2020916; classtype=attempted-user; msg=ET EXPLOIT Possible Redirect to SMB exploit attempt - 302
- sid=2020917; classtype=attempted-user; msg=ET EXPLOIT Possible Redirect to SMB exploit attempt - 301
- sid=2020976; classtype=attempted-user; msg=ET EXPLOIT Possible Redirect to SMB exploit attempt - 307
- sid=2020977; classtype=attempted-user; msg=ET EXPLOIT Possible Redirect to SMB exploit attempt - 303

## invalid checksum

- sid=2200073; classtype=protocol-command-decode; msg=SURICATA IPv4 invalid checksum
- sid=2200074; classtype=protocol-command-decode; msg=SURICATA TCPv4 invalid checksum
- sid=2200075; classtype=protocol-command-decode; msg=SURICATA UDPv4 invalid checksum
- sid=2200076; classtype=protocol-command-decode; msg=SURICATA ICMPv4 invalid checksum
- sid=2200077; classtype=protocol-command-decode; msg=SURICATA TCPv6 invalid checksum
- sid=2200078; classtype=protocol-command-decode; msg=SURICATA UDPv6 invalid checksum
- sid=2200079; classtype=protocol-command-decode; msg=SURICATA ICMPv6 invalid checksum

## SQL injection

- sid=2010375; classtype=attempted-admin; msg=ET EXPLOIT Possible Oracle Database Text Component ctxsys.drvxtabc.create_tables Remote SQL Injection Attempt
- sid=2025772; classtype=attempted-user; msg=ET EXPLOIT Nagios XI SQL Injection
- sid=2025775; classtype=attempted-user; msg=ET EXPLOIT Nagios XI SQL Injection 2
- sid=2018288; classtype=web-application-attack; msg=ET EXPLOIT Joomla 3.2.1 SQL injection attempt
- sid=2018289; classtype=web-application-attack; msg=ET EXPLOIT Joomla 3.2.1 SQL injection attempt 2
- sid=2017060; classtype=trojan-activity; msg=ET EXPLOIT SolusVM 1.13.03 SQL injection
- sid=2033411; classtype=attempted-admin; msg=ET EXPLOIT Cisco Data Center Network Manager SQL Injection Inbound (CVE-2019-15984)
- sid=2034270; classtype=trojan-activity; msg=ET EXPLOIT PHP Melody v3.0 SQL Injection Attempt

## XSS

- sid=2024412; classtype=attempted-user; msg=ET EXPLOIT Possible SharePoint XSS (CVE-2017-8514) Inbound
- sid=2012193; classtype=web-application-attack; msg=ET EXPLOIT Lexmark Printer RDYMSG Cross Site Scripting Attempt
- sid=2031939; classtype=attempted-admin; msg=ET EXPLOIT Netgear ProSAFE Plus Stored XSS Inbound (CVE-2020-35228)
- sid=2032533; classtype=attempted-admin; msg=ET EXPLOIT Trend Micro IWSVA Unauthenticated Command Injection Inbound (CVE-2020-8466)
- sid=2033349; classtype=web-application-attack; msg=ET EXPLOIT Stored XSS Vulnerability CVE-2021-31250 M1
- sid=2033350; classtype=web-application-attack; msg=ET EXPLOIT Stored XSS Vulnerability CVE-2021-31250 M2
- sid=2033351; classtype=web-application-attack; msg=ET EXPLOIT Stored XSS Vulnerability CVE-2021-31250 M3
- sid=2033352; classtype=web-application-attack; msg=ET EXPLOIT Stored XSS Vulnerability CVE-2021-31250 M4

## brute force

- sid=2059376; classtype=misc-activity; msg=ET DOS Possible Brute Force Attack Using FastHTTP
- sid=2042956; classtype=misc-attack; msg=ET EXPLOIT Observed Mirai/Gafgyt Post Brute Force Activity (GET)
- sid=2033717; classtype=trojan-activity; msg=ET MALWARE GoBrut/StealthWorker Requesting Brute Force List (flowbit set)
- sid=2018253; classtype=command-and-control; msg=ET MALWARE RDP Brute Force Bot Checkin
- sid=2010642; classtype=attempted-recon; msg=ET SCAN Multiple FTP Root Login Attempts from Single Source - Possible Brute Force Attempt
- sid=2010643; classtype=attempted-recon; msg=ET SCAN Multiple FTP Administrator Login Attempts from Single Source - Possible Brute Force Attempt
- sid=2001906; classtype=protocol-command-decode; msg=ET SCAN MYSQL 4.0 brute force root login attempt
- sid=2002842; classtype=protocol-command-decode; msg=ET SCAN MYSQL 4.1 brute force root login attempt

## DDoS

- sid=2024977; classtype=trojan-activity; msg=ET ATTACK_RESPONSE 401TRG Perl DDoS IRCBot File Download
- sid=2017918; classtype=attempted-dos; msg=ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x02
- sid=2017920; classtype=attempted-dos; msg=ET DOS Possible NTP DDoS Multiple MON_LIST Seq 0 Response Spanning Multiple Packets IMPL 0x02
- sid=2017921; classtype=attempted-dos; msg=ET DOS Possible NTP DDoS Multiple MON_LIST Seq 0 Response Spanning Multiple Packets IMPL 0x03
- sid=2017965; classtype=attempted-dos; msg=ET DOS Likely NTP DDoS In Progress MON_LIST Response to Non-Ephemeral Port IMPL 0x02
- sid=2019010; classtype=attempted-dos; msg=ET DOS Likely NTP DDoS In Progress PEER_LIST Response to Non-Ephemeral Port IMPL 0x02
- sid=2019011; classtype=attempted-dos; msg=ET DOS Likely NTP DDoS In Progress PEER_LIST Response to Non-Ephemeral Port IMPL 0x03
- sid=2019012; classtype=attempted-dos; msg=ET DOS Likely NTP DDoS In Progress PEER_LIST_SUM Response to Non-Ephemeral Port IMPL 0x02
