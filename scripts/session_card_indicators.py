#!/usr/bin/env python3
"""Bounded, redacted observable-evidence helpers for session cards.

This module only inspects network-visible text.  It never writes extracted files,
executes payloads, or preserves complete HTTP bodies or secret header values.
"""

from __future__ import annotations

import re
from pathlib import PurePath
from typing import Any, Iterable
from urllib.parse import unquote_plus


MAX_SAMPLE_ITEMS = 5
MAX_SNIPPET_CHARS = 220
MAX_URI_CHARS = 320
MAX_TRANSIENT_BODY_CHARS = 32768
EVIDENCE_LIMITS = {
    "max_samples_per_field": MAX_SAMPLE_ITEMS,
    "max_snippets_per_direction": 3,
    "max_suspicious_snippets": 5,
    "max_snippet_chars": MAX_SNIPPET_CHARS,
    "max_uri_chars": MAX_URI_CHARS,
    "max_transient_body_chars": MAX_TRANSIENT_BODY_CHARS,
    "body_policy": "classification-relevant context only; no complete payload or extracted file",
}

SENSITIVE_KEY_RE = re.compile(
    r"(?i)\b(username|user|password|passwd|pwd|token|access_token|refresh_token|authorization|cookie|sessionid|session_id|jwt)"
    r"(\s*(?:=|:|%3d)\s*)([^&;\s,]+)"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?\b")
PRINTABLE_RE = re.compile(r"[^\x20-\x7e\u4e00-\u9fff]+")

PATTERNS: dict[str, re.Pattern[str]] = {
    "xp_cmdshell": re.compile(r"(?i)\bxp_cmdshell\b"),
    "cmd_exe": re.compile(r"(?i)\bcmd(?:\.exe)?\b"),
    "powershell": re.compile(r"(?i)\bpowershell(?:\.exe)?\b"),
    "bin_shell": re.compile(r"(?i)/(?:bin/)?(?:ba|z|k|c)?sh\b"),
    "shell_command_keyword": re.compile(r"(?i)\b(?:whoami|uname|ipconfig|ifconfig|net\s+user|bash\s+-i)\b"),
    "download_command": re.compile(r"(?i)\b(?:wget|curl|netcat|nc)\b"),
    "path_traversal": re.compile(r"(?i)(?:\.\./|\.\.%2f|%2e%2e(?:%2f|/)|/etc/passwd)"),
    "sql_injection": re.compile(r"(?i)(?:union\s+(?:all\s+)?select|select\s+.+\s+from|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|xp_cmdshell)"),
    "xss": re.compile(r"(?i)(?:<script\b|%3cscript\b|onerror\s*=)"),
    "jndi": re.compile(r"(?i)\$\{jndi:"),
    "eval": re.compile(r"(?i)\beval\s*\("),
    "encoded_payload": re.compile(r"(?i)(?:\bbase64\b|(?:[A-Za-z0-9+/]{80,}={0,2})|%[0-9a-f]{2}(?:[^%]{0,3}%[0-9a-f]{2}){5,})"),
    "command_separator": re.compile(r"(?:;|&&|\|\|)\s*(?:exec\b|whoami\b|id\b|ls\b|dir\b|uname\b|wget\b|curl\b|cmd\b|powershell\b)"),
    "cve": re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b"),
}

SCANNER_RE = re.compile(r"(?i)\b(?:nikto|openvas|nessus|nmap scripting engine|nmap[-_/ ]?nse|wpscan|dirbuster|gobuster|sqlmap|acunetix|burp|zaproxy|owasp zap)\b")
PROBE_PATH_RE = re.compile(r"(?i)(?:/phpmyadmin\b|/\.git/|/wp-admin\b|/wp-login\.php\b|/cgi-bin/|/hnap1\b|/server-status\b|/etc/passwd\b|\bCVE-\d{4}-\d+)" )
LOGIN_PATH_RE = re.compile(r"(?i)/(?:login|signin|auth|session|administrator)(?:[/?#]|$)")
UPLOAD_RE = re.compile(r"(?i)(?:multipart/form-data|/(?:upload|plugin/install|admin/upload)\b|\bfilename\s*=)")
WEB_SHELL_RE = re.compile(r"(?i)(?:webshell|(?:shell|cmd|c99|r57)\.(?:php|jsp|jspx|asp|aspx)|/(?:shell|cmd|c99|r57)(?:[./?]))")
COMMAND_PARAM_RE = re.compile(r"(?i)(?:[?&](?:cmd|command|exec|action)=|\baction=cmd\b)")
SUSPICIOUS_FILE_RE = re.compile(r"(?i)\.(?:php|jsp|jspx|asp|aspx|war|jar|exe|dll|elf|sh|py)(?:$|[?&#])")
ARCHIVE_RE = re.compile(r"(?i)\.(?:zip|rar|7z|tar|tgz|gz|bz2)(?:$|[?&#])")
IMAGE_STATIC_RE = re.compile(r"(?i)\.(?:png|jpe?g|gif|svg|css|js|ico|woff2?)(?:$|[?&#])")


def _dedupe(values: Iterable[Any], limit: int = MAX_SAMPLE_ITEMS) -> list[Any]:
    out: list[Any] = []
    seen: set[str] = set()
    for value in values:
        if value in (None, "", "-"):
            continue
        key = str(value).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "t"}


def _integer(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def decode_visible_text(value: Any) -> str:
    """Decode one URL-encoding layer and remove non-printable bytes."""
    text = str(value or "")
    try:
        text = unquote_plus(text)
    except (UnicodeDecodeError, ValueError):
        pass
    return " ".join(PRINTABLE_RE.sub(" ", text).split())


def redact_sensitive_text(value: Any, limit: int = MAX_SNIPPET_CHARS) -> str:
    text = decode_visible_text(value)
    text = SENSITIVE_KEY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    text = JWT_RE.sub("[REDACTED_JWT]", text)
    if len(text) > limit:
        text = text[: max(0, limit - 14)] + "...[truncated]"
    return text


def sanitize_uri(value: Any) -> str:
    return redact_sensitive_text(value, MAX_URI_CHARS)


def matched_keywords(text: str) -> list[str]:
    return [name for name, pattern in PATTERNS.items() if pattern.search(text)]


def suspicious_contexts(value: Any, limit: int = MAX_SAMPLE_ITEMS) -> list[str]:
    text = decode_visible_text(value)
    matches: list[tuple[int, int]] = []
    for pattern in PATTERNS.values():
        for match in pattern.finditer(text):
            matches.append((match.start(), match.end()))
    if SCANNER_RE.search(text) or PROBE_PATH_RE.search(text) or WEB_SHELL_RE.search(text) or UPLOAD_RE.search(text):
        matches.append((0, min(len(text), MAX_SNIPPET_CHARS)))
    snippets: list[str] = []
    for start, end in sorted(matches)[: limit * 2]:
        left = max(0, start - 80)
        right = min(len(text), end + 100)
        snippet = redact_sensitive_text(text[left:right], MAX_SNIPPET_CHARS)
        if snippet and snippet not in snippets:
            snippets.append(snippet)
        if len(snippets) >= limit:
            break
    return snippets


def make_safe_http_observation(row: dict[str, Any]) -> dict[str, Any] | None:
    """Reduce one TShark HTTP row to safe metadata and bounded indicators."""
    method = row.get("http.request.method")
    host = row.get("http.host")
    uri = sanitize_uri(row.get("http.request.uri")) if row.get("http.request.uri") else None
    full_uri = sanitize_uri(row.get("http.request.full_uri")) if row.get("http.request.full_uri") else None
    status = _integer(row.get("http.response.code"))
    content_type = redact_sensitive_text(row.get("http.content_type"), 120) or None
    body = str(row.get("http.file_data") or "")[:MAX_TRANSIENT_BODY_CHARS]
    form_keys = [part for part in str(row.get("urlencoded-form.key") or "").split("|") if part]
    form_values = [part for part in str(row.get("urlencoded-form.value") or "").split("|") if part]
    body_seen = bool(body)
    combined = " ".join(str(item or "") for item in (uri, full_uri, body, " ".join(form_keys), " ".join(form_values)))
    suspicious = suspicious_contexts(combined)
    if not any((method, host, uri, full_uri, status, content_type, body_seen, row.get("http.user_agent"))):
        return None
    sensitive_fields = {"username", "user", "password", "passwd", "pwd", "token", "authorization", "cookie", "sessionid", "session_id", "jwt"}
    params = []
    for index, key in enumerate(form_keys[:10]):
        clean_key = redact_sensitive_text(key, 80)
        value = form_values[index] if index < len(form_values) else ""
        relevant = bool(matched_keywords(decode_visible_text(value))) or clean_key.lower() in sensitive_fields or clean_key.lower() in {"cmd", "command", "exec", "action", "file", "path", "url", "username", "user"}
        if relevant:
            clean_value = "[REDACTED]" if clean_key.lower() in sensitive_fields else redact_sensitive_text(value, 100)
            params.append(f"{clean_key}={clean_value}" if clean_value else clean_key)
    role = "request" if method else "response" if status is not None else "unknown"
    snippets = suspicious_contexts(body, 3) if body_seen else []
    return {
        "timestamp": row.get("frame.time_epoch"),
        "src_ip": row.get("ip.src") or None,
        "src_port": _integer(row.get("tcp.srcport")),
        "dst_ip": row.get("ip.dst") or None,
        "dst_port": _integer(row.get("tcp.dstport")),
        "tcp_stream": _integer(row.get("tcp.stream")),
        "body_role": role,
        "method": method or None,
        "host": redact_sensitive_text(host, 160) or None,
        "uri": uri,
        "full_uri": full_uri,
        "status_code": status,
        "user_agent": redact_sensitive_text(row.get("http.user_agent"), 180) or None,
        "referrer": sanitize_uri(row.get("http.referer")) if row.get("http.referer") else None,
        "content_type": content_type,
        "content_length": _integer(row.get("http.content_length")),
        "cookie_present": bool(row.get("http.cookie")),
        "auth_header_present": bool(row.get("http.authorization")),
        "body_observed": body_seen,
        "body_snippets_sanitized": snippets,
        "suspicious_payload_snippets": suspicious,
        "suspicious_http_parameters": _dedupe(params),
        "suspicious_uri_patterns": matched_keywords(" ".join((uri or "", full_uri or ""))),
        "matched_keywords": matched_keywords(decode_visible_text(combined)),
    }


def _indicator_template(names: list[str]) -> dict[str, Any]:
    return {**{name: False for name in names}, "matched_keywords": []}


def build_http_fields(zeek_rows: list[dict[str, Any]], observations: list[dict[str, Any]]) -> dict[str, Any]:
    methods = [row.get("method") for row in zeek_rows] + [row.get("method") for row in observations]
    hosts = [row.get("host") for row in zeek_rows] + [row.get("host") for row in observations]
    uris = [sanitize_uri(row.get("uri")) for row in zeek_rows if row.get("uri")] + [row.get("uri") for row in observations]
    full_uris = [sanitize_uri(f"http://{row.get('host')}{row.get('uri')}") for row in zeek_rows if row.get("host") and row.get("uri")] + [row.get("full_uri") for row in observations]
    statuses = [_integer(row.get("status_code")) for row in zeek_rows] + [row.get("status_code") for row in observations]
    user_agents = [redact_sensitive_text(row.get("user_agent"), 180) for row in zeek_rows] + [row.get("user_agent") for row in observations]
    referrers = [sanitize_uri(row.get("referrer")) for row in zeek_rows if row.get("referrer")] + [row.get("referrer") for row in observations]
    content_types = [redact_sensitive_text(row.get("mime_type"), 120) for row in zeek_rows] + [row.get("content_type") for row in observations]
    zeek_request_lengths = [_integer(row.get("request_body_len")) for row in zeek_rows]
    zeek_response_lengths = [_integer(row.get("response_body_len")) for row in zeek_rows]
    observed_request_lengths: list[int | None] = []
    observed_response_lengths: list[int | None] = []
    for row in observations:
        if row.get("body_role") == "request":
            observed_request_lengths.append(row.get("content_length"))
        elif row.get("body_role") == "response":
            observed_response_lengths.append(row.get("content_length"))
    request_total = max(
        sum(v for v in zeek_request_lengths if isinstance(v, int)),
        sum(v for v in observed_request_lengths if isinstance(v, int)),
    )
    response_total = max(
        sum(v for v in zeek_response_lengths if isinstance(v, int)),
        sum(v for v in observed_response_lengths if isinstance(v, int)),
    )
    request_snippets = [snippet for row in observations if row.get("body_role") == "request" for snippet in row.get("body_snippets_sanitized", [])]
    response_snippets = [snippet for row in observations if row.get("body_role") == "response" for snippet in row.get("body_snippets_sanitized", [])]
    suspicious = [snippet for row in observations for snippet in row.get("suspicious_payload_snippets", [])]
    params = [item for row in observations for item in row.get("suspicious_http_parameters", [])]
    uri_patterns = [item for row in observations for item in row.get("suspicious_uri_patterns", [])]
    return {
        "http_methods": _dedupe(methods),
        "http_hosts": _dedupe(hosts),
        "http_uris_sample": _dedupe(uris),
        "http_full_uri_sample": _dedupe(full_uris, 3),
        "http_status_codes": _dedupe(statuses),
        "http_user_agents": _dedupe(user_agents),
        "http_referrers": _dedupe(referrers, 3),
        "http_content_types": _dedupe(content_types),
        "http_request_body_len": request_total,
        "http_response_body_len": response_total,
        "http_cookie_present": any(bool(row.get("cookie_present")) for row in observations),
        "http_auth_header_present": any(bool(row.get("auth_header_present")) for row in observations),
        "http_multipart_present": any("multipart/form-data" in str(item).lower() for item in content_types),
        "http_upload_hints": _dedupe([value for value in [*uris, *content_types] if UPLOAD_RE.search(str(value))]),
        "http_body_observed": any(bool(row.get("body_observed")) for row in observations),
        "request_body_snippets_sanitized": _dedupe(request_snippets, 3),
        "response_body_snippets_sanitized": _dedupe(response_snippets, 3),
        "suspicious_payload_snippets": _dedupe(suspicious, 5),
        "suspicious_http_parameters": _dedupe(params, 5),
        "suspicious_uri_patterns": _dedupe(uri_patterns, 5),
    }


def build_file_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    filenames = _dedupe([redact_sensitive_text(row.get("filename"), 160) for row in rows])
    mime_types = _dedupe([row.get("mime_type") for row in rows])
    names_blob = " ".join(str(item) for item in filenames)
    mime_blob = " ".join(str(item) for item in mime_types).lower()
    directions = []
    for row in rows:
        if str(row.get("is_orig")).lower() in {"t", "true", "1"}:
            directions.append("originator_to_responder")
        elif str(row.get("is_orig")).lower() in {"f", "false", "0"}:
            directions.append("responder_to_originator")
    return {
        "filename_sample": filenames,
        "mime_type_sample": mime_types,
        "direction_hint": _dedupe(directions, 2),
        "total_files": len(rows),
        "executable_or_script_hint": bool(SUSPICIOUS_FILE_RE.search(names_blob) or any(x in mime_blob for x in ("executable", "x-dosexec", "x-sh", "java-archive"))),
        "archive_hint": bool(ARCHIVE_RE.search(names_blob) or "archive" in mime_blob or "zip" in mime_blob),
        "image_or_static_hint": bool(IMAGE_STATIC_RE.search(names_blob) or mime_blob.startswith("image/")),
        "suspicious_file_extension_hint": bool(SUSPICIOUS_FILE_RE.search(names_blob)),
    }


def build_indicators(http: dict[str, Any], files: dict[str, Any], ssh_rows: list[dict[str, Any]], ftp_rows: list[dict[str, Any]]) -> dict[str, Any]:
    text_values = []
    for key in ("http_uris_sample", "http_full_uri_sample", "http_user_agents", "request_body_snippets_sanitized", "response_body_snippets_sanitized", "suspicious_payload_snippets", "suspicious_http_parameters", "http_upload_hints"):
        text_values.extend(http.get(key, []))
    blob = decode_visible_text(" ".join(map(str, text_values)))
    keywords = matched_keywords(blob)

    exploit = _indicator_template([
        "command_injection", "sql_injection", "xss", "path_traversal", "file_inclusion",
        "deserialization_hint", "shell_command_keyword", "windows_command_keyword",
        "linux_command_keyword", "xp_cmdshell", "powershell", "cmd_exe",
        "wget_curl_download", "encoded_payload_hint", "suspicious_params",
    ])
    exploit.update({
        "command_injection": any(name in keywords for name in ("command_separator", "xp_cmdshell", "jndi", "eval")),
        "sql_injection": "sql_injection" in keywords or "xp_cmdshell" in keywords,
        "xss": "xss" in keywords,
        "path_traversal": "path_traversal" in keywords,
        "file_inclusion": bool(re.search(r"(?i)(?:file|page|include|template)=.*(?:\.\./|/etc/passwd)", blob)),
        "deserialization_hint": bool(re.search(r"(?i)(?:rO0AB|aced0005|ysoserial|objectinputstream)", blob)),
        "shell_command_keyword": any(name in keywords for name in ("shell_command_keyword", "bin_shell")),
        "windows_command_keyword": any(name in keywords for name in ("cmd_exe", "powershell")) or bool(re.search(r"(?i)\b(?:dir|net user|ipconfig)\b", blob)),
        "linux_command_keyword": any(name in keywords for name in ("bin_shell", "shell_command_keyword")) or bool(re.search(r"(?i)\b(?:whoami|uname|ifconfig)\b", blob)),
        "xp_cmdshell": "xp_cmdshell" in keywords,
        "powershell": "powershell" in keywords,
        "cmd_exe": "cmd_exe" in keywords,
        "wget_curl_download": "download_command" in keywords,
        "encoded_payload_hint": "encoded_payload" in keywords,
        "suspicious_params": bool(http.get("suspicious_http_parameters")),
        "matched_keywords": keywords,
    })

    uas = " ".join(http.get("http_user_agents", []))
    uris = " ".join(http.get("http_uris_sample", []))
    scanner_matches = _dedupe(SCANNER_RE.findall(uas + " " + uris), 8)
    vuln = _indicator_template([
        "nikto_user_agent", "openvas_user_agent", "nmap_nse_user_agent",
        "masscan_zmap_vs_vulnscan_hint", "service_version_probe", "cve_probe_hint",
        "suspicious_probe_paths", "high_uri_fanout", "high_404_rate", "scanner_user_agents",
    ])
    status_codes = http.get("http_status_codes", [])
    vuln.update({
        "nikto_user_agent": "nikto" in uas.lower(),
        "openvas_user_agent": "openvas" in uas.lower(),
        "nmap_nse_user_agent": "nmap scripting engine" in uas.lower() or "nmap-nse" in uas.lower(),
        "masscan_zmap_vs_vulnscan_hint": bool(re.search(r"(?i)\b(?:masscan|zmap)\b", uas)),
        "service_version_probe": bool(re.search(r"(?i)(?:nmap.*(?:service|version)|http-enum|banner)", uas + " " + uris)),
        "cve_probe_hint": bool(PATTERNS["cve"].search(blob)),
        "suspicious_probe_paths": _dedupe([uri for uri in http.get("http_uris_sample", []) if PROBE_PATH_RE.search(uri)]),
        "high_uri_fanout": len(set(http.get("http_uris_sample", []))) >= 8,
        "high_404_rate": len(status_codes) >= 4 and sum(str(code) == "404" for code in status_codes) / len(status_codes) >= 0.6,
        "scanner_user_agents": _dedupe([ua for ua in http.get("http_user_agents", []) if SCANNER_RE.search(ua)]),
        "matched_keywords": scanner_matches + (["CVE"] if PATTERNS["cve"].search(blob) else []),
    })

    login_paths = [uri for uri in http.get("http_uris_sample", []) if LOGIN_PATH_RE.search(uri)]
    ftp_commands = [str(row.get("command") or "").upper() for row in ftp_rows]
    ftp_response_codes = _dedupe([
        str(row.get("reply_code")) for row in ftp_rows
        if row.get("reply_code") not in (None, "", "-")
    ])
    ftp_usernames = {
        str(row.get("arg")) for row in ftp_rows
        if str(row.get("command") or "").upper() == "USER" and row.get("arg") not in (None, "", "-", "[REDACTED]")
    }
    ssh_attempts = [_integer(row.get("auth_attempts")) or 0 for row in ssh_rows]
    ssh_auth_failure_hint = any(str(row.get("auth_success")).lower() in {"f", "false"} for row in ssh_rows)
    session_auth_attempt_count = max(len(login_paths), max(ssh_attempts, default=0), ftp_commands.count("PASS"))
    ftp_failure_codes = {"430", "530"}
    ftp_success_codes = {"230"}
    ftp_failed = sum(str(row.get("reply_code")) in ftp_failure_codes for row in ftp_rows)
    ftp_failure_seen = False
    ftp_success_after_failure = False
    for row in ftp_rows:
        code = str(row.get("reply_code") or "")
        ftp_failure_seen = ftp_failure_seen or code in ftp_failure_codes
        ftp_success_after_failure = ftp_success_after_failure or (ftp_failure_seen and code in ftp_success_codes)
    ssh_failed = sum(
        max(1, _integer(row.get("auth_attempts")) or 0)
        for row in ssh_rows if str(row.get("auth_success")).lower() in {"f", "false"}
    )
    auth_context = bool(login_paths or http.get("http_auth_header_present") or ssh_rows or ftp_rows)
    auth_statuses = [code for code in status_codes if auth_context and str(code) in {"401", "403", "407", "200", "204", "302"}]
    http_failed = sum(str(code) in {"401", "403", "407"} for code in auth_statuses)
    failed_login_count = http_failed + ftp_failed + ssh_failed
    auth = {
        "auth_protocol": "ssh" if ssh_rows else "ftp" if ftp_rows else "http" if login_paths or http.get("http_auth_header_present") else "unknown",
        "repeated_login_attempts": session_auth_attempt_count >= 5,
        "failed_login_hint": failed_login_count > 0,
        "success_after_failures_hint": ftp_success_after_failure or (
            http_failed > 0 and any(str(code) in {"200", "204", "302"} for code in auth_statuses)
        ),
        "http_login_paths": _dedupe(login_paths),
        "auth_status_codes": _dedupe(auth_statuses),
        "session_auth_attempt_count": session_auth_attempt_count,
        "same_src_same_dst_auth_attempts": session_auth_attempt_count,
        "username_field_seen": any(re.search(r"(?i)^(?:user|username)=", p) for p in http.get("suspicious_http_parameters", [])) or "USER" in ftp_commands,
        "password_field_seen": any(re.search(r"(?i)^(?:password|passwd|pwd)=", p) for p in http.get("suspicious_http_parameters", [])) or "PASS" in ftp_commands,
        "unique_usernames_seen": len(ftp_usernames) or (1 if any(re.search(r"(?i)^(?:user|username)=", p) for p in http.get("suspicious_http_parameters", [])) else 0),
        "failed_login_count": failed_login_count,
        "ftp_response_codes": ftp_response_codes,
        "ssh_auth_failure_hint": ssh_auth_failure_hint,
        "weak_evidence": session_auth_attempt_count >= 5 and failed_login_count == 0,
    }

    file_names = " ".join(files.get("filename_sample", []))
    implant = _indicator_template([
        "upload_to_server_hint", "multipart_upload", "suspicious_uploaded_filename",
        "webshell_extension_hint", "payload_download_hint", "dropper_download_hint",
        "archive_or_executable_transfer_hint", "file_write_like_request",
    ])
    upload_to_server_hint = bool(http.get("http_upload_hints")) or bool(
            "originator_to_responder" in files.get("direction_hint", [])
            and (files.get("filename_sample") or files.get("executable_or_script_hint") or files.get("archive_hint"))
        )
    implant.update({
        "upload_to_server_hint": upload_to_server_hint,
        "multipart_upload": bool(http.get("http_multipart_present")),
        "suspicious_uploaded_filename": bool(upload_to_server_hint and SUSPICIOUS_FILE_RE.search(blob + " " + file_names)),
        "webshell_extension_hint": bool(WEB_SHELL_RE.search(blob + " " + file_names)),
        "payload_download_hint": bool(exploit.get("wget_curl_download")),
        "dropper_download_hint": bool(exploit.get("wget_curl_download") and files.get("executable_or_script_hint")),
        "archive_or_executable_transfer_hint": bool(files.get("archive_hint") or files.get("executable_or_script_hint")),
        "file_write_like_request": bool(re.search(r"(?i)\b(?:PUT|POST)\b", " ".join(http.get("http_methods", []))) and UPLOAD_RE.search(blob)),
        "matched_keywords": _dedupe([name for name in ("multipart/form-data", "upload", "webshell extension", "executable transfer") if name.lower().split()[0] in (blob + " " + file_names).lower()]),
    })

    backdoor = _indicator_template([
        "webshell_path_hint", "command_param_hint", "interactive_command_hint",
        "attacker_initiated_access_hint", "response_output_like_hint",
        "repeated_backdoor_endpoint_access",
    ])
    webshell_path_hint = bool(WEB_SHELL_RE.search(blob))
    command_param_hint = bool(COMMAND_PARAM_RE.search(blob))
    interactive_command_hint = bool(
        exploit.get("shell_command_keyword") or exploit.get("windows_command_keyword") or exploit.get("linux_command_keyword")
    )
    backdoor.update({
        "webshell_path_hint": webshell_path_hint,
        "command_param_hint": command_param_hint,
        "interactive_command_hint": interactive_command_hint,
        "attacker_initiated_access_hint": bool(webshell_path_hint and http.get("http_methods")),
        "response_output_like_hint": bool(http.get("response_body_snippets_sanitized") and exploit.get("shell_command_keyword")),
        "repeated_backdoor_endpoint_access": sum(1 for uri in http.get("http_uris_sample", []) if WEB_SHELL_RE.search(uri)) >= 2,
        "matched_keywords": _dedupe([
            name for name, hit in (
                ("webshell", webshell_path_hint),
                ("command parameter", command_param_hint),
                ("interactive command", interactive_command_hint),
            ) if hit
        ]),
    })
    return {
        "exploit_indicators": exploit,
        "vuln_scan_indicators": vuln,
        "auth_indicators": auth,
        "implant_indicators": implant,
        "backdoor_access_indicators": backdoor,
    }


def filename_extension(value: str) -> str:
    """Return a bounded extension without interpreting or opening the file."""
    return PurePath(value.split("?", 1)[0]).suffix.lower()[:12]


def has_positive_indicator(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        if "auth_protocol" in value:
            return any(bool(value.get(key)) for key in (
                "repeated_login_attempts", "failed_login_hint", "success_after_failures_hint",
                "username_field_seen", "password_field_seen",
            ))
        if "beacon_score" in value:
            return float(value.get("beacon_score") or 0) >= 0.5 or any(bool(value.get(key)) for key in ("periodic_connections", "dns_repeated_query", "tls_sni_repeated"))
        return any(has_positive_indicator(item) for key, item in value.items() if key not in {"weak_evidence", "auth_protocol"})
    if isinstance(value, list):
        return bool(value)
    return False
