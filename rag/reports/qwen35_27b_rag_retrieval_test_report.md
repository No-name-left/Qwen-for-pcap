# Qwen3.5-27B RAG retrieval test report

- Queries: 15
- Passed: 15/15
- Ready for retrieval test: yes

## q001_strrat_cnc_checkin
- pass: True
- expected: c2_detection, signature_strrat, suricata_eve_alerts
- retrieved: c2_detection, command_and_control_stage, signature_generic_malware_callback, signature_strrat

## q002_ms17_010_smb_port_445
- pass: True
- expected: protocol_smb, signature_ms17_010_smb, smb_exploit_detection
- retrieved: normal_smb_vs_smb_exploit, protocol_smb, signature_ms17_010_smb, smb_exploit_detection

## q003_doublepulsar_beacon_response
- pass: True
- expected: backdoor_detection, protocol_smb, signature_doublepulsar
- retrieved: backdoor_detection, competition_backdoor_implant_access_callback_boundary, signature_doublepulsar, signature_ms17_010_smb

## q004_icmpv6_invalid_checksum
- pass: True
- expected: protocol_anomaly_low_confidence, protocol_icmp_icmpv6, signature_protocol_anomaly
- retrieved: protocol_anomaly_low_confidence, protocol_dns, protocol_icmp_icmpv6, signature_protocol_anomaly, zeek_weird_notice_logs

## q005_many_destination_ports_failed_connections
- pass: True
- expected: port_scan_detection, reconnaissance_stage, zeek_conn_log_fields
- retrieved: competition_port_scan_vs_vulnerability_scan, port_scan_detection, protocol_udp_services, reconnaissance_stage, zeek_conn_log_fields

## q006_tcp_syn_scan
- pass: True
- expected: port_scan_detection, protocol_tcp_flags, signature_et_scan
- retrieved: port_scan_detection, protocol_tcp_flags, reconnaissance_stage, signature_et_scan, tshark_packet_fields

## q007_sql_injection_union_select
- pass: True
- expected: protocol_http, signature_web_sql_injection, web_exploit_detection
- retrieved: normal_http_vs_web_exploit, protocol_http, signature_web_sql_injection, signature_web_xss, web_exploit_detection

## q008_xss_script_injection
- pass: True
- expected: protocol_http, signature_web_xss, web_exploit_detection
- retrieved: normal_http_vs_web_exploit, protocol_http, signature_web_sql_injection, signature_web_xss, web_exploit_detection

## q009_directory_traversal_passwd
- pass: True
- expected: protocol_http, signature_directory_traversal, web_exploit_detection
- retrieved: attack_chain_summary, protocol_http, signature_directory_traversal, web_exploit_detection, zeek_http_log_fields

## q010_command_injection_wget_curl_shell
- pass: True
- expected: protocol_http, signature_command_injection, web_exploit_detection
- retrieved: backdoor_detection, signature_command_injection, signature_reverse_shell, signature_web_sql_injection, web_exploit_detection

## q011_dns_tunnel_long_domain
- pass: True
- expected: normal_dns_vs_dns_tunnel, protocol_dns, signature_dns_tunnel
- retrieved: data_exfiltration_detection, normal_dns_vs_dns_tunnel, protocol_dns, signature_dns_tunnel, zeek_dns_log_fields

## q012_periodic_tls_sni_beacon
- pass: True
- expected: normal_periodic_connection_vs_c2, protocol_tls_sni, signature_tls_c2
- retrieved: command_and_control_stage, competition_backdoor_implant_access_callback_boundary, normal_periodic_connection_vs_c2, protocol_tls_sni, signature_tls_c2

## q013_ssh_brute_force_login_attempt
- pass: True
- expected: bruteforce_detection, protocol_ssh_ftp_rdp, signature_bruteforce
- retrieved: bruteforce_detection, competition_bruteforce_boundary, initial_access_stage, protocol_ssh_ftp_rdp, signature_bruteforce

## q014_high_volume_possible_ddos
- pass: True
- expected: dos_ddos_detection, normal_high_volume_traffic, signature_dos_ddos
- retrieved: dos_ddos_detection, false_positive_low_signal_events, normal_high_volume_traffic, signature_dos_ddos, tshark_packet_fields

## q015_normal_smb_without_exploit_alert
- pass: True
- expected: normal_smb_vs_smb_exploit, protocol_smb, smb_exploit_detection
- retrieved: normal_smb_vs_smb_exploit, protocol_smb, signature_ms17_010_smb, smb_exploit_detection
