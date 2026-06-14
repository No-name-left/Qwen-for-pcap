---
doc_id: "protocol_common_ports"
title: "Common port interpretation"
category: "protocols"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["22", "21", "53", "80", "443", "445", "139", "3389", "ports"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Common port interpretation

## Evidence

Common ports help interpret services: 21 FTP, 22 SSH, 53 DNS, 80 HTTP, 443 HTTPS, 139 NetBIOS/SMB, 445 SMB, and 3389 RDP. Ports are context, not verdicts.

## Judgment

Use ports to connect signatures and fields to likely protocols. For example, exploit evidence on 445 is different from ordinary file sharing on 445.

## Stage mapping

Stage mapping depends on behavior: scanning ports is reconnaissance, attacking a service is initial_access, and contacting control infrastructure is command_and_control.

## Boundaries

Never classify solely from a port number. Many attacks use common ports and many benign services do too.
