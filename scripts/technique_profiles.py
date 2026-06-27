#!/usr/bin/env python3
from __future__ import annotations

from typing import Any


TECHNIQUE_ORDER = ["TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"]

TECHNIQUE_PROFILES: dict[str, dict[str, list[str] | str]] = {
    "TA43_01": {
        "name": "port_scan",
        "positive_evidence": [
            "high destination port fanout",
            "many short failed connections",
            "SYN/connection attempts with little application payload",
        ],
        "negative_evidence": [
            "many URI/path probes on the same web service",
            "explicit exploit payload",
            "authentication service repeated login attempts",
        ],
        "weak_evidence": ["connection failures alone"],
        "common_false_positives": [
            "auth brute force to one service port",
            "C2-like repeated connections misread as scanning",
        ],
    },
    "TA43_02": {
        "name": "vulnerability_scan",
        "positive_evidence": [
            "sensitive path probing",
            "admin/config/db/backup/.env/.git/WEB-INF/phpinfo paths",
            "many URI fanout on web services",
            "scanner-like user agents or NSE/Nikto/sqlmap-like paths",
            "mostly 404/403/400/502 probe responses",
        ],
        "negative_evidence": [
            "successful command execution payload",
            "webshell command access",
            "file upload/drop evidence",
        ],
        "weak_evidence": ["a single unusual path without other context"],
        "common_false_positives": ["one-off application error", "benign admin path in ordinary browsing"],
    },
    "TA01_01": {
        "name": "brute_force",
        "positive_evidence": [
            "repeated connections or login attempts to authentication service ports",
            "FTP/SSH/MySQL/RDP/SMB/DB service repeated short attempts",
            "failed login indicators if observable",
        ],
        "negative_evidence": [
            "periodic fixed endpoint on non-auth service with small payloads",
            "broad multi-port scan",
        ],
        "weak_evidence": ["repeated short connections without service context"],
        "common_false_positives": ["database polling", "short-lived normal service checks"],
    },
    "TA01_02": {
        "name": "vulnerability_exploitation",
        "positive_evidence": [
            "command injection, traversal, SQLi, RCE, encoded exploit payload",
            "suspicious parameters such as cmd=, exec=, command= when not clearly an existing webshell access",
            "exploit-shaped POST/GET requests",
        ],
        "negative_evidence": [
            "clear webshell endpoint already being accessed interactively",
            "clear file upload/drop/implant placement evidence",
            "scanner-style many URI probes without exploitation",
        ],
        "weak_evidence": ["encoded or binary body alone"],
        "common_false_positives": ["software update chunks", "download content with encoded/binary data"],
    },
    "TA03_01": {
        "name": "implant_placement",
        "positive_evidence": [
            "upload/drop/write/file placement",
            "multipart/form-data with filename",
            "suspicious script/webshell file extensions",
            "executable/script payload delivery",
            "server-side path indicating placed file",
        ],
        "negative_evidence": [
            "exploit POST without file placement",
            "benign file upload/static resource upload",
        ],
        "weak_evidence": ["POST to a PHP endpoint with no body or file evidence"],
        "common_false_positives": ["ordinary form POST", "static resource transfer"],
    },
    "TA11_01": {
        "name": "backdoor_access",
        "positive_evidence": [
            "webshell-like endpoint plus command parameter",
            "/shell.php, /cmd.php, /webshell.php, /chopper.php-like path with cmd/exec/whoami/id/ipconfig",
            "interactive command execution through an existing endpoint",
        ],
        "negative_evidence": [
            "one-off initial exploit request without known backdoor path",
            "periodic outbound beaconing",
        ],
        "weak_evidence": ["shell-like word without command parameter"],
        "common_false_positives": ["exploit proof-of-concept URI", "benign shell-themed filename"],
    },
    "TA11_02": {
        "name": "c2_callback",
        "positive_evidence": [
            "repeated fixed endpoint",
            "periodic or beacon-like timing",
            "small similar transfers",
            "encrypted endpoint-fixed sessions that are repeated",
            "miner/ping/hashrate/ethminer/mining heartbeat",
        ],
        "negative_evidence": [
            "auth service port repeated attempts",
            "normal update/download/chunk traffic",
            "single ordinary TLS connection to standard port",
        ],
        "weak_evidence": ["encrypted traffic alone", "single fixed-endpoint connection"],
        "common_false_positives": ["software updater", "CDN polling", "NTP/DNS/browser telemetry"],
    },
    "TN01_01": {
        "name": "normal_traffic",
        "positive_evidence": [
            "known benign software/update/download/static asset patterns",
            "ordinary browser/CDN/TLS traffic",
            "no meaningful attack indicators",
        ],
        "negative_evidence": [
            "explicit exploit, brute-force, scan, beacon, webshell, or implant evidence",
        ],
        "weak_evidence": ["encrypted traffic alone"],
        "common_false_positives": ["hidden attack in otherwise normal PCAP", "benign-looking encrypted callback"],
    },
}

BOUNDARY_RULES: list[dict[str, Any]] = [
    {
        "id": "ta43_01_vs_ta43_02",
        "techniques": ["TA43_01", "TA43_02"],
        "text": "TA43_01 is port/host discovery with port fanout and little application probing; TA43_02 is web/service vulnerability discovery with URI/path fanout, sensitive paths, scanner UA, or probe responses.",
        "rag_doc_ids": ["boundary_ta43_01_vs_ta43_02", "observable_scan_probe_timing", "observable_vulnerability_scan_indicators"],
    },
    {
        "id": "ta43_02_vs_ta01_02",
        "techniques": ["TA43_02", "TA01_02"],
        "text": "TA43_02 enumerates paths/services and mostly fails; TA01_02 has an explicit exploit attempt such as command injection, traversal, SQLi, RCE, malicious parameters, or exploit payload.",
        "rag_doc_ids": ["boundary_ta43_01_vs_ta43_02", "observable_exploit_indicator_mapping", "observable_vulnerability_scan_indicators"],
    },
    {
        "id": "ta01_01_vs_ta43_01",
        "techniques": ["TA01_01", "TA43_01"],
        "text": "TA01_01 concentrates repeated attempts on authentication service ports; TA43_01 discovers many ports or hosts.",
        "rag_doc_ids": ["boundary_ta01_01_vs_tn01_01", "observable_auth_bruteforce_indicators", "observable_scan_probe_timing"],
    },
    {
        "id": "ta01_01_vs_ta11_02",
        "techniques": ["TA01_01", "TA11_02"],
        "text": "Repeated short connections on authentication service ports favor TA01_01 and are counter-evidence for TA11_02; TA11_02 needs non-auth fixed endpoints, timing regularity, small similar transfers, or callback context.",
        "rag_doc_ids": ["boundary_ta01_01_vs_tn01_01", "observable_auth_bruteforce_indicators", "boundary_ta11_02_vs_tn01_01", "observable_beacon_timing_boundary"],
    },
    {
        "id": "ta01_02_vs_ta03_01",
        "techniques": ["TA01_02", "TA03_01"],
        "text": "TA01_02 is exploit execution or malicious parameters; TA03_01 requires upload/drop/write/file placement evidence stronger than a generic exploit POST.",
        "rag_doc_ids": ["observable_exploit_indicator_mapping", "observable_file_upload_and_implant_hints", "observable_exploit_upload_access_sequence"],
    },
    {
        "id": "ta03_01_vs_ta11_01",
        "techniques": ["TA03_01", "TA11_01"],
        "text": "TA03_01 places or transfers an implant; TA11_01 accesses an already existing backdoor endpoint and sends interactive command parameters.",
        "rag_doc_ids": ["observable_file_upload_and_implant_hints", "observable_backdoor_access_vs_callback", "observable_exploit_upload_access_sequence"],
    },
    {
        "id": "ta11_01_vs_ta01_02",
        "techniques": ["TA11_01", "TA01_02"],
        "text": "TA11_01 is webshell/backdoor endpoint plus command parameter and interactive command intent; TA01_02 is an initial exploit request without a clear existing backdoor path.",
        "rag_doc_ids": ["observable_backdoor_access_vs_callback", "observable_exploit_indicator_mapping", "boundary_ta01_02_vs_ta11_01"],
    },
    {
        "id": "ta11_01_vs_ta11_02",
        "techniques": ["TA11_01", "TA11_02"],
        "text": "TA11_01 is attacker-initiated interactive backdoor access; TA11_02 is victim-initiated callback/beacon/C2 with repeated fixed endpoints or miner heartbeat.",
        "rag_doc_ids": ["boundary_ta11_01_vs_ta11_02", "observable_backdoor_access_vs_callback", "observable_beacon_timing_boundary"],
    },
    {
        "id": "ta11_02_vs_tn01_01",
        "techniques": ["TA11_02", "TN01_01"],
        "text": "Encrypted traffic alone is weak. Repeated fixed endpoints, non-standard ports, periodicity, small similar transfers, or miner heartbeat favor TA11_02; browser/CDN/update/download/chunk patterns favor TN01_01 when attack indicators are absent.",
        "rag_doc_ids": ["boundary_ta11_02_vs_tn01_01", "normal_periodic_connection_vs_c2", "observable_encrypted_visibility_limits"],
    },
    {
        "id": "weak_web_attack_vs_tn01_01",
        "techniques": ["TA01_02", "TA03_01", "TN01_01"],
        "text": "A single POST or encrypted body is weak. Raise attack candidates only when suspicious parameters, filenames, upload/drop evidence, script payload, non-business path, encoded exploit, or abnormal response context is present.",
        "rag_doc_ids": ["boundary_ta01_02_vs_tn01_01", "observable_file_upload_and_implant_hints", "observable_exploit_indicator_mapping"],
    },
]


def technique_codes() -> list[str]:
    return list(TECHNIQUE_ORDER)


def validate_profiles() -> None:
    missing = [code for code in TECHNIQUE_ORDER if code not in TECHNIQUE_PROFILES]
    if missing:
        raise ValueError(f"missing technique profiles: {', '.join(missing)}")
    required = {"name", "positive_evidence", "negative_evidence", "weak_evidence", "common_false_positives"}
    for code, profile in TECHNIQUE_PROFILES.items():
        absent = required - set(profile)
        if absent:
            raise ValueError(f"profile {code} missing fields: {', '.join(sorted(absent))}")


def profile_terms(candidates: list[str] | tuple[str, ...]) -> list[str]:
    terms: list[str] = []
    for code in candidates:
        profile = TECHNIQUE_PROFILES.get(code)
        if not profile:
            continue
        terms.append(code)
        terms.append(str(profile["name"]))
        for key in ("positive_evidence", "negative_evidence", "weak_evidence"):
            terms.extend(str(item) for item in profile.get(key, []))
    return terms


def boundary_rules_for_candidates(candidates: list[str] | tuple[str, ...], limit: int = 6) -> list[dict[str, Any]]:
    selected = set(candidates)
    exact: list[dict[str, Any]] = []
    partial: list[dict[str, Any]] = []
    for rule in BOUNDARY_RULES:
        techniques = set(rule["techniques"])
        if len(techniques & selected) >= 2:
            exact.append(rule)
        elif techniques & selected:
            partial.append(rule)
    return [*exact, *partial][:limit]


def boundary_doc_ids_for_candidates(candidates: list[str] | tuple[str, ...]) -> list[str]:
    docs: list[str] = []
    seen: set[str] = set()
    for rule in boundary_rules_for_candidates(candidates):
        for doc_id in rule.get("rag_doc_ids", []):
            if doc_id not in seen:
                seen.add(doc_id)
                docs.append(doc_id)
    return docs


def prompt_profile_summary(candidates: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    summaries = []
    for code in candidates:
        profile = TECHNIQUE_PROFILES.get(code)
        if profile:
            summaries.append({
                "technique": code,
                "name": profile["name"],
                "positive_evidence": profile["positive_evidence"],
                "negative_evidence": profile["negative_evidence"],
                "weak_evidence": profile["weak_evidence"],
            })
    return summaries
