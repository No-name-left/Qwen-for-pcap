# Qwen3.5-27B RAG retrieval test report

- Queries: 26
- Passed: 26/26
- Ready for retrieval test: yes

## q001_strrat_cnc_checkin
- pass: True
- expected: c2_detection, competition_TA11_02_trojan_callback, signature_strrat
- retrieved: c2_detection, command_and_control_stage, signature_generic_malware_callback, signature_strrat, trojan_callback_detection

## q002_ms17_010_smb_port_445
- pass: True
- expected: protocol_smb, signature_ms17_010_smb, smb_exploit_detection
- retrieved: initial_access_stage, normal_smb_vs_smb_exploit, protocol_smb, signature_ms17_010_smb, smb_exploit_detection

## q003_doublepulsar_beacon_response
- pass: True
- expected: backdoor_detection, protocol_smb, signature_doublepulsar
- retrieved: backdoor_detection, competition_backdoor_implant_access_callback_boundary, competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02, signature_doublepulsar

## q004_icmpv6_invalid_checksum
- pass: True
- expected: protocol_anomaly_low_confidence, protocol_icmp_icmpv6, signature_protocol_anomaly
- retrieved: protocol_anomaly_low_confidence, protocol_icmp_icmpv6, signature_protocol_anomaly, signature_strrat, zeek_weird_notice_logs

## q005_many_destination_ports_failed_connections
- pass: True
- expected: port_scan_detection, reconnaissance_stage, zeek_conn_log_fields
- retrieved: competition_TA43_01_port_scan, competition_port_scan_vs_vulnerability_scan, port_scan_detection, reconnaissance_stage

## q006_tcp_syn_scan
- pass: True
- expected: port_scan_detection, protocol_tcp_flags, signature_et_scan
- retrieved: competition_TA43_01_port_scan, port_scan_detection, reconnaissance_stage, signature_et_scan

## q007_sql_injection_union_select
- pass: True
- expected: protocol_http, signature_web_sql_injection, web_exploit_detection
- retrieved: boundary_ta01_02_vs_tn01_01, normal_http_vs_web_exploit, protocol_http, signature_web_sql_injection, web_exploit_detection

## q008_xss_script_injection
- pass: True
- expected: protocol_http, signature_web_xss, web_exploit_detection
- retrieved: competition_TA01_02_exploit, observable_http_payload_indicators, protocol_http, signature_web_xss, web_exploit_detection

## q009_directory_traversal_passwd
- pass: True
- expected: protocol_http, signature_directory_traversal, web_exploit_detection
- retrieved: boundary_ta01_02_vs_tn01_01, competition_TA01_02_exploit, observable_exploit_indicator_mapping, signature_directory_traversal, web_exploit_detection

## q010_command_injection_wget_curl_shell
- pass: True
- expected: protocol_http, signature_command_injection, web_exploit_detection
- retrieved: boundary_ta01_02_vs_tn01_01, competition_TA01_02_exploit, competition_TA11_01_backdoor_access, signature_command_injection, web_exploit_detection

## q011_dns_tunnel_long_domain
- pass: True
- expected: normal_dns_vs_dns_tunnel, protocol_dns, signature_dns_tunnel
- retrieved: data_exfiltration_detection, normal_dns_vs_dns_tunnel, protocol_dns, signature_dns_tunnel, zeek_dns_log_fields

## q012_periodic_tls_sni_beacon
- pass: True
- expected: normal_periodic_connection_vs_c2, protocol_tls_sni, signature_tls_c2
- retrieved: boundary_ta11_02_vs_tn01_01, competition_boundary_TA11_02_vs_TN01_01, normal_periodic_connection_vs_c2, protocol_tls_sni, signature_tls_c2

## q013_ssh_brute_force_login_attempt
- pass: True
- expected: bruteforce_detection, observable_auth_bruteforce_indicators, protocol_ssh_ftp_rdp, signature_bruteforce
- retrieved: boundary_ta01_01_vs_tn01_01, competition_TA01_01_bruteforce, competition_boundary_TA01_01_vs_TN01_01, competition_bruteforce_boundary, observable_auth_bruteforce_indicators

## q014_high_volume_possible_ddos
- pass: True
- expected: dos_ddos_detection, normal_high_volume_traffic, signature_dos_ddos
- retrieved: dos_ddos_detection, false_positive_low_signal_events, normal_high_volume_traffic, signature_dos_ddos, tshark_packet_fields

## q015_normal_smb_without_exploit_alert
- pass: True
- expected: normal_smb_vs_smb_exploit, protocol_smb, smb_exploit_detection
- retrieved: exploit_detection, normal_smb_vs_smb_exploit, protocol_smb, signature_ms17_010_smb, smb_exploit_detection

## q016_boundary_scan_vs_vuln_scan
- pass: True
- expected: boundary_ta43_01_vs_ta43_02
- retrieved: boundary_ta43_01_vs_ta43_02, competition_TA43_01_port_scan, competition_boundary_TA43_01_vs_TA43_02, competition_port_scan_vs_vulnerability_scan, observable_vulnerability_scan_indicators

## q017_boundary_bruteforce_vs_normal
- pass: True
- expected: boundary_ta01_01_vs_tn01_01
- retrieved: boundary_ta01_01_vs_tn01_01, competition_TA01_01_bruteforce, competition_boundary_TA01_01_vs_TN01_01, competition_bruteforce_boundary, observable_auth_bruteforce_indicators

## q018_boundary_exploit_vs_normal
- pass: True
- expected: boundary_ta01_02_vs_tn01_01
- retrieved: boundary_ta01_02_vs_tn01_01, competition_TA01_02_exploit, competition_TN01_01_normal_business, competition_boundary_TA11_02_vs_TN01_01, normal_http_vs_web_exploit

## q019_boundary_backdoor_access_vs_callback
- pass: True
- expected: boundary_ta11_01_vs_ta11_02
- retrieved: boundary_ta11_01_vs_ta11_02, competition_TA11_01_backdoor_access, competition_backdoor_implant_access_callback_boundary, competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02, observable_backdoor_access_vs_callback

## q020_boundary_callback_vs_normal
- pass: True
- expected: boundary_ta11_02_vs_tn01_01
- retrieved: boundary_ta11_02_vs_tn01_01, competition_TN01_01_normal_business, competition_boundary_TA11_02_vs_TN01_01, competition_conservative_normal_vs_callback_boundary, competition_normal_business_traffic_boundary

## q021_observable_exploit_strings
- pass: True
- expected: observable_exploit_indicator_mapping
- retrieved: competition_TA11_01_backdoor_access, competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02, competition_technique_codes, observable_backdoor_access_vs_callback, observable_exploit_indicator_mapping

## q022_observable_vuln_scan
- pass: True
- expected: observable_vulnerability_scan_indicators
- retrieved: boundary_ta43_01_vs_ta43_02, competition_conservative_normal_vs_callback_boundary, normal_high_volume_traffic, observable_vulnerability_scan_indicators, port_scan_detection

## q023_observable_implant_upload
- pass: True
- expected: observable_file_upload_and_implant_hints
- retrieved: boundary_ta01_02_vs_tn01_01, competition_TA03_01_backdoor_install, competition_boundary_TA03_01_vs_TA11_01_vs_TA11_02, observable_file_upload_and_implant_hints, signature_webshell

## q024_observable_access_callback
- pass: True
- expected: observable_backdoor_access_vs_callback
- retrieved: boundary_ta11_01_vs_ta11_02, boundary_ta11_02_vs_tn01_01, competition_TA11_01_backdoor_access, observable_backdoor_access_vs_callback, signature_webshell

## q025_observable_auth
- pass: True
- expected: observable_auth_bruteforce_indicators
- retrieved: bruteforce_detection, competition_TA01_01_bruteforce, competition_boundary_TA01_01_vs_TN01_01, competition_bruteforce_boundary, observable_auth_bruteforce_indicators

## q026_observable_encrypted
- pass: True
- expected: observable_encrypted_visibility_limits
- retrieved: boundary_ta01_02_vs_tn01_01, competition_TN01_01_normal_business, competition_boundary_TA11_02_vs_TN01_01, competition_normal_business_traffic_boundary, observable_encrypted_visibility_limits
