#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, load_json


BOUNDARY_DOCS = {
    "ta43_01_vs_ta43_02": "boundary_ta43_01_vs_ta43_02",
    "ta01_01_vs_tn01_01": "boundary_ta01_01_vs_tn01_01",
    "ta01_02_vs_tn01_01": "boundary_ta01_02_vs_tn01_01",
    "ta11_01_vs_ta11_02": "boundary_ta11_01_vs_ta11_02",
    "ta11_02_vs_tn01_01": "boundary_ta11_02_vs_tn01_01",
    "ta01_02_vs_ta11_01": "observable_exploit_indicator_mapping",
    "ta03_01_vs_ta01_02": "observable_file_upload_and_implant_hints",
    "ta03_01_vs_ta11_01": "observable_file_upload_and_implant_hints",
    "ta01_02_vs_ta03_01_vs_ta11_01": "observable_exploit_upload_access_sequence",
}

INDICATOR_DOCS = {
    "vuln_scan_indicators": "observable_vulnerability_scan_indicators",
    "exploit_indicators": "observable_exploit_indicator_mapping",
    "auth_indicators": "observable_auth_bruteforce_indicators",
    "implant_indicators": "observable_file_upload_and_implant_hints",
    "backdoor_access_indicators": "observable_backdoor_access_vs_callback",
    "c2_indicators": "observable_backdoor_access_vs_callback",
}

TIMING_DOCS = {
    "auth": "observable_auth_bruteforce_timing",
    "scan": "observable_scan_probe_timing",
    "callback": "observable_beacon_timing_boundary",
    "sequence": "observable_exploit_upload_access_sequence",
    "benign_periodic": "normal_periodic_connection_vs_c2",
}


def add_term(terms: list[str], value: Any) -> None:
    if value is None:
        return
    if isinstance(value, (int, float)):
        terms.append(str(value))
    elif isinstance(value, str) and value.strip():
        terms.append(value.strip())
    elif isinstance(value, list):
        for item in value:
            add_term(terms, item)
    elif isinstance(value, dict):
        for item in value.values():
            add_term(terms, item)


def dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen = set()
    for value in values:
        value = str(value).strip()
        if not value:
            continue
        key = value.lower()
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def as_number(value: Any, default: float = 0.0) -> float:
    if value in (None, "", "-"):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def indicator_active(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, list):
        return bool(value)
    if isinstance(value, dict):
        return any(indicator_active(item) for key, item in value.items() if key not in {"weak_evidence", "auth_protocol", "interval_summary", "beacon_score"})
    return False


def field_indicator_active(record: dict[str, Any], field: str) -> bool:
    value = record.get(field) or {}
    if field == "auth_indicators":
        return any(bool(value.get(key)) for key in ("repeated_login_attempts", "failed_login_hint", "success_after_failures_hint", "username_field_seen", "password_field_seen"))
    if field == "c2_indicators":
        return as_number(value.get("beacon_score")) >= 0.5 or any(bool(value.get(key)) for key in ("periodic_connections", "dns_repeated_query", "tls_sni_repeated"))
    return indicator_active(value)


def indicator_fields_used(record: dict[str, Any]) -> list[str]:
    fields = [field for field in INDICATOR_DOCS if field_indicator_active(record, field)]
    if record.get("payload_visibility") == "encrypted_tls":
        fields.append("payload_visibility")
    return fields


def benign_periodic_active(record: dict[str, Any]) -> bool:
    hints = record.get("benign_periodic_hints") or {}
    direct = any(bool(hints.get(key)) for key in (
        "update_or_telemetry_text", "dns_refresh_like", "ntp_like", "periodicity_alone",
    ))
    return direct or bool(hints.get("short_burst_not_beacon") and field_indicator_active(record, "c2_indicators"))


def record_blob(record: dict[str, Any], fields: tuple[str, ...]) -> str:
    values = {field: record.get(field) for field in fields if record.get(field) not in (None, "", [], {})}
    return json.dumps(values, ensure_ascii=False).lower()


def http_404_rate_high(record: dict[str, Any]) -> bool:
    statuses = record.get("http_status_codes") or []
    if isinstance(statuses, dict):
        statuses = list(statuses.values())
    codes = [str(value) for value in statuses if value not in (None, "", "-")]
    return len(codes) >= 5 and sum(code == "404" for code in codes) / len(codes) >= 0.5


def uri_fanout_high(record: dict[str, Any]) -> bool:
    uris = record.get("http_uris_sample") or []
    paths = {str(uri).split("?", 1)[0].split("#", 1)[0].lower() for uri in uris if uri not in (None, "", "-")}
    return len(paths) >= 5


def probe_path_or_cve_active(record: dict[str, Any]) -> bool:
    blob = record_blob(record, ("http_uris_sample", "http_full_uri_sample", "suspicious_uri_patterns", "vuln_scan_indicators"))
    probe_terms = (
        "cve-", "phpmyadmin", "wp-admin", "wp-login", "/.git", "cgi-bin", "hnap1",
        "server-status", "../", "etc/passwd", "dirbuster", "gobuster",
    )
    return any(term in blob for term in probe_terms)


def scanner_user_agent_active(record: dict[str, Any]) -> bool:
    blob = record_blob(record, ("http_user_agents", "vuln_scan_indicators"))
    scanners = ("nikto", "openvas", "nessus", "nmap", "nmap nse", "sqlmap", "wpscan", "acunetix", "burp", "zaproxy")
    return any(scanner in blob for scanner in scanners)


def targeted_rag_metadata(record: dict[str, Any], groups: list[str]) -> tuple[list[str], list[str], list[str]]:
    used = indicator_fields_used(record)
    triggers: list[str] = []
    docs: list[str] = []
    for field in used:
        if field == "payload_visibility":
            triggers.append("payload_visibility=encrypted_tls")
            docs.append("observable_encrypted_visibility_limits")
        else:
            triggers.append(f"{field}=positive")
            docs.append(INDICATOR_DOCS[field])
    if record.get("record_type") == "auth_attempt_group" and record.get("attempt_rate") is not None:
        triggers.append("auth_timing=positive")
        docs.append(TIMING_DOCS["auth"])
    if record.get("record_type") == "scan_group" and record.get("probe_rate") is not None:
        triggers.append("scan_timing=positive")
        docs.append(TIMING_DOCS["scan"])
    port_fanout = max(
        as_number(record.get("same_src_unique_dst_ports")),
        as_number(record.get("unique_dst_ports")),
        as_number(record.get("same_src_unique_dst_ips")),
    ) >= 8
    if port_fanout:
        triggers.append("port_or_target_fanout=positive")
        docs.extend([BOUNDARY_DOCS["ta43_01_vs_ta43_02"], TIMING_DOCS["scan"]])
    scan_summary = record.get("scan_group_summary") or {}
    if as_number(scan_summary.get("max_unique_dst_ports")) >= 8 or as_number(scan_summary.get("scan_like_record_count")) > 0:
        triggers.append("pcap_scan_summary=positive")
        docs.extend([BOUNDARY_DOCS["ta43_01_vs_ta43_02"], TIMING_DOCS["scan"]])
    vuln = record.get("vuln_scan_indicators") or {}
    if vuln.get("high_uri_fanout") or uri_fanout_high(record):
        triggers.append("uri_fanout=positive")
        docs.extend([BOUNDARY_DOCS["ta43_01_vs_ta43_02"], INDICATOR_DOCS["vuln_scan_indicators"]])
    if vuln.get("high_404_rate") or http_404_rate_high(record):
        triggers.append("http_404_rate=positive")
        docs.extend([BOUNDARY_DOCS["ta43_01_vs_ta43_02"], INDICATOR_DOCS["vuln_scan_indicators"]])
    if vuln.get("scanner_user_agents") or scanner_user_agent_active(record):
        triggers.append("scanner_user_agent=positive")
        docs.extend([BOUNDARY_DOCS["ta43_01_vs_ta43_02"], INDICATOR_DOCS["vuln_scan_indicators"]])
    if vuln.get("cve_probe_hint") or vuln.get("suspicious_probe_paths") or probe_path_or_cve_active(record):
        triggers.append("cve_or_probe_path=positive")
        docs.extend([BOUNDARY_DOCS["ta43_01_vs_ta43_02"], INDICATOR_DOCS["vuln_scan_indicators"]])
    auth = record.get("auth_indicators") or {}
    if as_number(record.get("failed_login_count") or auth.get("failed_login_count")) > 0:
        triggers.append("failed_login_count=positive")
        docs.extend([BOUNDARY_DOCS["ta01_01_vs_tn01_01"], INDICATOR_DOCS["auth_indicators"], TIMING_DOCS["auth"]])
    if record.get("attempt_rate") is not None or auth.get("attempt_rate") is not None:
        triggers.append("attempt_rate=positive")
        docs.extend([BOUNDARY_DOCS["ta01_01_vs_tn01_01"], TIMING_DOCS["auth"]])
    if record.get("failure_burst") or auth.get("failure_burst"):
        triggers.append("failure_burst=positive")
        docs.extend([BOUNDARY_DOCS["ta01_01_vs_tn01_01"], TIMING_DOCS["auth"]])
    if record.get("success_after_failures_hint") or auth.get("success_after_failures_hint"):
        triggers.append("success_after_failures=positive")
        docs.extend([BOUNDARY_DOCS["ta01_01_vs_tn01_01"], INDICATOR_DOCS["auth_indicators"]])
    auth_summary = record.get("auth_attempt_summary") or {}
    if as_number(auth_summary.get("failed_login_count")) > 0 or as_number(auth_summary.get("max_attempt_count")) >= 5:
        triggers.append("pcap_auth_summary=positive")
        docs.extend([BOUNDARY_DOCS["ta01_01_vs_tn01_01"], INDICATOR_DOCS["auth_indicators"], TIMING_DOCS["auth"]])
    callback_timing = record.get("interval_summary") and (
        record.get("record_type") == "c2_callback_group"
        or as_number(record.get("beacon_score")) >= 0.5
        or as_number(record.get("regularity_score")) >= 0.6
        or as_number(record.get("periodicity_score")) >= 0.6
    )
    if callback_timing:
        triggers.append("callback_timing=positive")
        docs.append(TIMING_DOCS["callback"])
    c2 = record.get("c2_indicators") or {}
    if c2.get("fixed_remote_endpoint") or c2.get("source_initiated_fixed_endpoint"):
        triggers.append("fixed_endpoint=positive")
        docs.extend([BOUNDARY_DOCS["ta11_02_vs_tn01_01"], TIMING_DOCS["callback"]])
    if c2.get("dns_repeated_query") or c2.get("tls_sni_repeated") or record.get("dns_query_repetition") or record.get("tls_sni_repetition"):
        triggers.append("dns_sni_repetition=positive")
        docs.extend([BOUNDARY_DOCS["ta11_02_vs_tn01_01"], TIMING_DOCS["callback"]])
    if record.get("bytes_pattern") or c2.get("small_repeated_payload"):
        triggers.append("packet_size_pattern=positive")
        docs.extend([BOUNDARY_DOCS["ta11_02_vs_tn01_01"], TIMING_DOCS["callback"]])
    if record.get("payload_visibility") == "encrypted_tls" and (
        callback_timing or c2.get("fixed_remote_endpoint") or c2.get("periodic_connections")
    ):
        triggers.append("encrypted_timing_metadata=positive")
        docs.extend(["observable_encrypted_visibility_limits", TIMING_DOCS["callback"]])
    beacon_summary = record.get("beacon_like_summary") or {}
    if as_number(beacon_summary.get("max_beacon_score")) >= 0.5 or as_number(beacon_summary.get("fixed_endpoint_record_count")) > 0:
        triggers.append("pcap_beacon_summary=positive")
        docs.extend([BOUNDARY_DOCS["ta11_02_vs_tn01_01"], TIMING_DOCS["callback"]])
    if benign_periodic_active(record):
        triggers.append("benign_periodic_hints=positive")
        docs.extend([TIMING_DOCS["benign_periodic"], TIMING_DOCS["callback"]])
    if any(record.get(field) not in (None, "", [], {}) for field in (
        "ordered_event_summary", "relative_time_deltas", "scan_to_exploit_delta",
        "exploit_to_upload_delta", "upload_to_access_delta", "repeated_backdoor_access_intervals",
    )):
        triggers.append("ordered_event_sequence=positive")
        docs.append(TIMING_DOCS["sequence"])
    chain_blob = record_blob(record, (
        "exploit_indicators", "implant_indicators", "backdoor_access_indicators",
        "http_multipart_present", "http_upload_hints", "transferred_files_summary",
        "suspicious_http_parameters", "suspicious_uri_patterns",
    ))
    if (
        field_indicator_active(record, "exploit_indicators")
        and (field_indicator_active(record, "implant_indicators") or field_indicator_active(record, "backdoor_access_indicators"))
    ) or any(term in chain_blob for term in ("multipart", "webshell", "cmd=", "command=", "exec=", "upload", "filename")) or record.get("top_payload_evidence"):
        triggers.append("exploit_upload_access_boundary=positive")
        docs.extend([
            TIMING_DOCS["sequence"],
            INDICATOR_DOCS["exploit_indicators"],
            INDICATOR_DOCS["implant_indicators"],
            INDICATOR_DOCS["backdoor_access_indicators"],
            "competition_backdoor_implant_access_callback_boundary",
        ])
    docs.extend(BOUNDARY_DOCS[group] for group in groups)
    return dedupe(triggers), dedupe(docs), used


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(path)


def detect_confusion_groups(record: dict[str, Any]) -> list[str]:
    """Select short decision cards from observable record features only."""
    excluded = {
        "record_id", "session_id", "pcap_id", "pcap", "flow_source", "source_file", "parser_source",
        "pcap_summary", "evidence_limits", *INDICATOR_DOCS.keys(),
    }
    signals = {key: value for key, value in record.items() if key not in excluded}
    blob = json.dumps(signals, ensure_ascii=False).lower()
    tokens = set(re.findall(r"[a-z0-9_+-]+", blob))
    service = str(record.get("service") or "").lower()
    try:
        dst_port = int(record.get("dst_port"))
    except (TypeError, ValueError):
        dst_port = 0
    groups: list[str] = []
    vuln_active = field_indicator_active(record, "vuln_scan_indicators")
    exploit_active = field_indicator_active(record, "exploit_indicators")
    auth_active = field_indicator_active(record, "auth_indicators")
    implant_active = field_indicator_active(record, "implant_indicators")
    backdoor_active = field_indicator_active(record, "backdoor_access_indicators")
    c2_active = field_indicator_active(record, "c2_indicators")
    many_ports = max(
        as_number(record.get("same_src_unique_dst_ports")),
        as_number(record.get("unique_dst_ports")),
    ) >= 8
    scan_tokens = {"scan", "scanner", "nikto", "openvas", "nessus", "nmap"}
    if record.get("record_type") == "scan_group" or many_ports or vuln_active or bool(tokens & scan_tokens) or any(word in blob for word in ("service enumeration", "version probe")):
        groups.append("ta43_01_vs_ta43_02")

    auth_service = service in {"ssh", "ftp", "rdp", "smb", "smb2", "kerberos", "ldap"} or dst_port in {21, 22, 23, 445, 3389}
    repeated = max(
        as_number(record.get("same_src_same_dst_port_count")),
        as_number(record.get("same_src_conn_count")),
    ) >= 5
    auth_words = ("login", "authentication", "password", "bruteforce", "brute force", "patator")
    if auth_active or auth_service or repeated and any(proto in blob for proto in ("ssh", "ftp", "rdp", "login")) or any(word in blob for word in auth_words):
        groups.append("ta01_01_vs_tn01_01")

    web_context = service in {"http", "https", "ssl", "tls"} or dst_port in {80, 443, 8000, 8080, 8443} or bool(record.get("http_summary"))
    exploit_words = ("exploit", "cve-", "command injection", "sql injection", "xss", "../", "webshell", "payload")
    if exploit_active or web_context or any(word in blob for word in exploit_words):
        groups.append("ta01_02_vs_tn01_01")
    if exploit_active and (backdoor_active or any(word in blob for word in ("cmd=", "exec=", "webshell", "shell.php", "cmd.jsp"))):
        groups.append("ta01_02_vs_ta11_01")
    if implant_active:
        groups.extend(["ta03_01_vs_ta01_02", "ta03_01_vs_ta11_01"])
    if (
        any(record.get(field) not in (None, "", [], {}) for field in ("ordered_event_summary", "exploit_to_upload_delta", "upload_to_access_delta"))
        or (exploit_active and (implant_active or backdoor_active))
        or (implant_active and backdoor_active)
    ):
        groups.append("ta01_02_vs_ta03_01_vs_ta11_01")

    access_words = ("backdoor access", "webshell", "reverse shell", "interactive shell", "operator", "shell command")
    callback_words = ("callback", "beacon", "checkin", "botnet")
    has_access = any(word in blob for word in access_words)
    has_callback = any(word in blob for word in callback_words) or bool(tokens & {"c2", "cnc", "rat"})
    if backdoor_active or c2_active or has_access or has_callback:
        groups.append("ta11_01_vs_ta11_02")

    outbound_context = service in {"dns", "http", "https", "ssl", "tls"} or bool(record.get("dns_summary")) or bool(record.get("tls_summary"))
    if c2_active or has_callback or outbound_context or benign_periodic_active(record):
        groups.append("ta11_02_vs_tn01_01")
    return dedupe(groups)


def record_terms(record: dict[str, Any]) -> tuple[list[str], list[str], bool]:
    record_type = str(record.get("record_type", "session") or "session")
    level = "pcap-level classification" if record_type == "pcap" else "session-level classification"
    terms: list[str] = ["official competition code", level, record_type]
    rules: list[str] = []
    low_signal = False

    add_term(terms, record.get("proto"))
    add_term(terms, record.get("service"))
    add_term(terms, record.get("conn_state"))
    add_term(terms, record.get("history"))
    for field in ("duration", "packet_rate", "byte_rate", "orig_pkts", "resp_pkts", "orig_bytes", "resp_bytes"):
        value = record.get(field)
        if value not in (None, "", "-"):
            terms.append(f"{field}={value}")
    add_term(terms, record.get("http_summary"))
    add_term(terms, record.get("dns_summary"))
    add_term(terms, record.get("tls_summary"))
    for field in INDICATOR_DOCS:
        if field_indicator_active(record, field):
            terms.append(field)
            add_term(terms, record.get(field))
    add_term(terms, record.get("payload_visibility"))
    add_term(terms, record.get("suspicious_payload_snippets"))
    add_term(terms, record.get("suspicious_uri_patterns"))
    if record_type == "pcap":
        terms.extend(["whole PCAP", "aggregate sessions", "one stage per pcap", "representative suspicious sessions"])
        for field in (
            "payload_visibility_summary", "http_context_summary", "dns_context_summary",
            "tls_context_summary", "ftp_context_summary", "top_suspicious_sessions",
            "top_payload_evidence", "suspicious_indicator_counts",
        ):
            add_term(terms, record.get(field))
        scan_summary = record.get("scan_group_summary") or {}
        auth_summary = record.get("auth_attempt_summary") or {}
        beacon_summary = record.get("beacon_like_summary") or {}
        add_term(terms, scan_summary)
        add_term(terms, auth_summary)
        add_term(terms, beacon_summary)
        if as_number(scan_summary.get("max_unique_dst_ports")) >= 8 or as_number(scan_summary.get("scan_like_record_count")) > 0:
            terms.extend(["PCAP scan summary", "port fanout across PCAP", "TA43"])
            rules.append("pcap_scan_summary:TA43")
        if as_number(auth_summary.get("failed_login_count")) > 0 or as_number(auth_summary.get("max_attempt_count")) >= 5:
            terms.extend(["PCAP authentication attempts", "failed login count across PCAP", "TA01_01"])
            rules.append("pcap_auth_summary:TA01_01")
        if as_number(beacon_summary.get("max_beacon_score")) >= 0.5 or as_number(beacon_summary.get("fixed_endpoint_record_count")) > 0:
            terms.extend(["PCAP beacon summary", "callback timing across PCAP", "TA11_02"])
            rules.append("pcap_beacon_summary:TA11_02")
        if record.get("top_payload_evidence"):
            terms.extend(["PCAP payload evidence", "exploit upload backdoor boundary", "TA01_02 TA03_01 TA11_01"])
            rules.append("pcap_payload_evidence")
    for field in (
        "time_span", "inter_arrival_summary", "inter_attempt_intervals", "interval_summary",
        "attempt_rate", "probe_rate", "burstiness_score", "periodicity_score", "regularity_score",
        "beacon_score", "fixed_endpoint_duration", "failure_burst", "benign_periodic_hints",
        "ordered_event_summary", "relative_time_deltas", "scan_to_exploit_delta",
        "exploit_to_upload_delta", "upload_to_access_delta", "repeated_backdoor_access_intervals",
    ):
        if record.get(field) not in (None, "", [], {}) and (field != "benign_periodic_hints" or benign_periodic_active(record)):
            terms.append(field)
            add_term(terms, record.get(field))

    if record.get("record_type") == "auth_attempt_group":
        terms.extend([
            "authentication attempt group", "repeated login attempts", "authentication failures",
            "failed_login_count", "attempt_rate", "inter-attempt interval", "failure burst",
            "success after failures", "single failed login is not brute force", "FTP SSH HTTP login", "TA01_01",
        ])
        add_term(terms, record.get("auth_protocol"))
        add_term(terms, record.get("failed_login_count"))
        add_term(terms, record.get("status_code_summary"))
        add_term(terms, record.get("attempt_rate"))
        add_term(terms, record.get("inter_attempt_intervals"))
        terms.append("authentication failure timing burst")
        rules.append("auth_attempt_group:TA01_01_boundary")
    if record.get("record_type") == "c2_callback_group":
        terms.extend(["callback group", "fixed remote endpoint", "periodic connection pattern", "C2", "TA11_02"])
        add_term(terms, record.get("interval_summary"))
        add_term(terms, record.get("bytes_pattern"))
        add_term(terms, record.get("callback_direction_hint"))
        add_term(terms, record.get("benign_periodic_hints"))
        terms.extend(["beacon timing boundary", "benign periodic update telemetry DNS NTP WPAD cloud sync health check", "packet size pattern", "TLS SNI DNS query fixed endpoint"])
        rules.append("c2_callback_group:TA11_02_boundary")

    if record.get("record_type") == "scan_group":
        terms.extend(["scan_group", "many destination ports", "dst_port fanout", "target fanout", "failed connections", "probe rate", "burstiness_score", "scan burst", "port scan", "TA43_01"])
        rules.append("scan_group:TA43_01")
    if as_number(record.get("same_src_unique_dst_ports")) >= 8 or as_number(record.get("unique_dst_ports")) >= 8:
        terms.extend(["many ports", "port fanout", "dst_port fanout", "port scan", "TA43_01"])
        rules.append("many_ports:TA43_01")
    if as_number(record.get("same_src_failed_conn_rate")) >= 0.5 or as_number(record.get("failed_conn_rate")) >= 0.5:
        terms.extend(["failed connection rate", "reconnaissance", "TA43_01"])
        rules.append("failed_rate")

    legacy_values = [
        record.get(key) for key in (
            "proto", "service", "http_summary", "dns_summary", "tls_summary",
            "alert_summary", "notice_summary", "weird_summary", "candidate_hint",
            "suspicious_payload_snippets", "suspicious_uri_patterns",
        ) if record.get(key) not in (None, "", [], {})
    ]
    blob = json.dumps(legacy_values, ensure_ascii=False).lower()
    blob_tokens = set(re.findall(r"[a-z0-9_+-]+", blob))
    if field_indicator_active(record, "vuln_scan_indicators") or any(s in blob for s in ["vulnerability scan", "scanner", "nikto", "nessus", "openvas", "version probe"]):
        terms.extend(["vulnerability scan signs", "URI fanout", "HTTP 404 rate", "scanner User-Agent", "CVE path", "probe path keywords", "directory scan", "TA43_02"])
        rules.append("vulnerability_scan:TA43_02")
    if field_indicator_active(record, "auth_indicators") or any(s in blob for s in ["login", "authentication", "bruteforce", "brute force", "ssh", "ftp", "rdp"]):
        terms.extend(["login failures", "password bruteforce", "failed_login_count", "attempt_rate", "failure burst", "success-after-failure hint", "TA01_01"])
        rules.append("login_failures:TA01_01")
    if field_indicator_active(record, "exploit_indicators") or any(s in blob for s in ["exploit", "cve", "command injection", "sql injection", "xss", "ms17-010"]):
        terms.extend(["exploit request", "payload", "vulnerability exploitation", "command injection", "SQLi", "path traversal", "malicious parameter", "TA01_02"])
        rules.append("exploit_payload:TA01_02")
    if field_indicator_active(record, "implant_indicators") or any(s in blob for s in ["implant", "persistence", "webshell", "backdoor placement"]):
        terms.extend(["implant", "persistence", "multipart/form-data", "webshell filename", "payload delivery", "TA03_01"])
        rules.append("implant:TA03_01")
    if field_indicator_active(record, "backdoor_access_indicators") or any(s in blob for s in ["backdoor access", "reverse shell", "webshell command"]):
        terms.extend(["backdoor access", "backdoor endpoint", "cmd parameter", "command interaction", "TA11_01"])
        rules.append("backdoor_access:TA11_01")
    if field_indicator_active(record, "c2_indicators") or any(s in blob for s in ["callback", "c2", "cnc", "beacon", "checkin"]) or "rat" in blob_tokens:
        terms.extend(["callback", "C2", "periodic beacon", "beacon_score", "regularity_score", "fixed endpoint", "benign periodic boundary", "TA11_02"])
        rules.append("callback_c2:TA11_02")

    packets = (record.get("orig_pkts") or 0) + (record.get("resp_pkts") or 0)
    total_bytes = (record.get("orig_bytes") or 0) + (record.get("resp_bytes") or 0)
    has_app_summary = any(record.get(field) for field in ("http_summary", "dns_summary", "tls_summary"))
    if record.get("record_type") == "session" and packets <= 3 and total_bytes <= 512 and not has_app_summary and not rules:
        terms.extend(["normal business", "weak-only signal", "TN01_01"])
        rules.append("low_volume_no_behavior_pattern:TN01_01")
        low_signal = True
    if not rules:
        terms.extend(["normal business", "weak-only signal", "TN01_01"])
        rules.append("default_boundary:TN01_01")

    confusion_groups = detect_confusion_groups(record)
    for group in confusion_groups:
        terms.extend([group, BOUNDARY_DOCS[group]])
        rules.append(f"confusion_boundary:{group}")
    return dedupe(terms), rules, low_signal


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic RAG queries from classification records.")
    parser.add_argument("--input", type=Path, default=ROOT / "outputs/session_cards/classification_records_all.json")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/rag_queries/qwen35_session_records_rag_queries.jsonl")
    parser.add_argument("--report", type=Path, default=ROOT / "outputs/rag_queries/qwen35_session_records_rag_query_report.md")
    args = parser.parse_args()

    records = load_json(args.input) if args.input.exists() else []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    with args.output.open("w", encoding="utf-8") as f:
        for record in records:
            record_id = record.get("record_id") or record.get("event_id")
            terms, rules, low_signal = record_terms(record)
            confusion_groups = detect_confusion_groups(record)
            triggers, targeted_docs, used_fields = targeted_rag_metadata(record, confusion_groups)
            row = {
                "record_id": record_id,
                "query_id": record_id,
                "pcap_id": record.get("pcap_id"),
                "record_type": record.get("record_type", "session"),
                "query": " ".join(terms[:100]),
                "query_terms": terms,
                "matched_rules": rules,
                "confusion_groups": confusion_groups,
                "targeted_boundary_doc_ids": targeted_docs,
                "targeted_rag_triggers": triggers,
                "targeted_boundary_cards": targeted_docs,
                "indicator_fields_used": used_fields,
                "low_signal": low_signal,
            }
            rows.append(row)
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    low_count = sum(1 for row in rows if row["low_signal"])
    lines = [
        "# Qwen3.5-27B session-record RAG query report",
        "",
        f"- Input: `{display_path(args.input)}`",
        f"- Records: {len(rows)}",
        f"- Low-signal records: {low_count}",
        f"- Output: `{display_path(args.output)}`",
        "",
        "## Rule notes",
        "",
        "- Query IDs use `record_id`.",
        "- `session` and `scan_group` records are handled separately.",
        "- Query expansion includes official code candidates.",
        "- Confusion groups are feature-triggered and name targeted decision-boundary documents.",
        "- Expected labels are not read and no LLM is used.",
    ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"built {len(rows)} rag queries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
