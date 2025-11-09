#!/usr/bin/env python3
# -*- coding: utf-8 -*-import subprocess

"""
Cross-platform Interactive Web Vulnerability Scanner for Ethical Diagnostics.

Requirements:
 - Python 3.8+
 - pip install requests

Checks performed (for the requested URL):
 - HTTP request & response metadata (status code, URL, final URL after redirects, content-type, server header, content-length)
 - Security headers presence and values (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy)
 - Cookie analysis (parses Set-Cookie headers and looks for Secure, HttpOnly, SameSite)
 - Basic reflected XSS pattern search (passive pattern matching only)
 - Simple injection-like pattern search in body (SQLi-like keywords) — passive only
 - TLS / certificate info for https targets: certificate subject, issuer, validity, and TLS protocol version
 - Report includes a full checklist section describing each check and its result

"""

import sys
import os
import time
import requests
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime, timezone

# --- Configuration ----
REPORTS_DIR = os.path.join(os.getcwd(), 'reports')
VULN_CHECKS = [
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Strict-Transport-Security',
    'Content-Security-Policy'
]
REFLECTED_XSS_PATTERNS = ["<script>alert(1)</script>"]
SQLI_KEYWORDS = ['select ', 'union ', 'insert ', 'update ', 'delete ', 'drop ', 'or 1=1', "' or '1'='1"]


def ensure_reports_dir():
    if not os.path.isdir(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, exist_ok=True)

def now_utc_ts():
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')

def validate_url(u):
    try:
        p = urlparse(u)
        return p.scheme in ('http', 'https') and p.netloc != ''
    except Exception:
        return False

def fetch_url(url):
    # follow redirects, record final URL
    r = requests.get(url, timeout=15, allow_redirects=True)
    return r

def get_set_cookie_headers(resp):
    # Best-effort collection of Set-Cookie headers
    set_cookie_headers = []
    # Try to access raw headers structure if available
    try:
        raw_headers = getattr(resp, 'raw', None)
        if raw_headers is not None:
            # urllib3 HTTPResponse.headers may be an HTTPHeaderDict with getlist
            headers_obj = getattr(raw_headers, 'headers', None) or getattr(raw_headers, '_original_response', None)
            if headers_obj is not None:
                # try a few ways
                try:
                    # http.client.HTTPMessage provides getallmatchingheaders in some variants
                    if hasattr(headers_obj, 'get_all'):
                        vals = headers_obj.get_all('Set-Cookie')
                        if vals:
                            set_cookie_headers.extend(vals)
                except Exception:
                    pass
    except Exception:
        pass

    # Fallback: look at resp.headers (may consolidate Set-Cookie)
    if 'Set-Cookie' in resp.headers:
        raw = resp.headers.get('Set-Cookie')
        if raw:
            # Try splitting by '\n' or ' , ' as a fallback — not perfect but best-effort
            parts = [p.strip() for p in raw.split('\n') if p.strip()]
            if len(parts) == 1:
                # sometimes cookies separated by comma — split and warn
                parts = [p.strip() for p in raw.split(',') if '=' in p]
            set_cookie_headers.extend(parts)

    # Deduplicate while preserving order
    seen = set()
    out = []
    for s in set_cookie_headers:
        if s not in seen and s.strip():
            seen.add(s)
            out.append(s)
    return out

def parse_set_cookie(cookie_header):
    # Parse basic attributes from a Set-Cookie header string
    parts = [p.strip() for p in cookie_header.split(';')]
    name_val = parts[0] if parts else ''
    attrs = { }
    for p in parts[1:]:
        if '=' in p:
            k, v = p.split('=', 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.strip().lower()] = True
    return name_val, attrs


def tls_info_for_host(netloc):
    # netloc may include :port
    hostname = netloc.split(':')[0]
    port = 443
    if ':' in netloc:
        try:
            port = int(netloc.split(':')[1])
        except Exception:
            port = 443
    info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                info['protocol'] = proto
                info['cert'] = cert
    except Exception as e:
        info['error'] = str(e)
    return info

def analyze_response(resp):
    findings = []
    details = {}

    details['status_code'] = resp.status_code
    details['final_url'] = resp.url
    details['headers'] = dict(resp.headers)
    details['content_type'] = resp.headers.get('Content-Type', '')
    details['server'] = resp.headers.get('Server', '')
    details['content_length'] = resp.headers.get('Content-Length', str(len(resp.content)))

    # Security headers
    sec_headers = {}
    for h in VULN_CHECKS:
        val = resp.headers.get(h)
        sec_headers[h] = val if val is not None else None
        if val is None:
            findings.append(f"Missing security header: {h}")
    details['security_headers'] = sec_headers

    # Cookie analysis
    set_cookie_hdrs = get_set_cookie_headers(resp)
    cookie_details = []
    if not set_cookie_hdrs:
        details['cookie_note'] = 'No Set-Cookie headers detected.'
    else:
        for sch in set_cookie_hdrs:
            name_val, attrs = parse_set_cookie(sch)
            cookie_details.append({'raw': sch, 'name_val': name_val, 'attrs': attrs})
            # look for flags
            if 'secure' not in attrs:
                findings.append(f"Cookie {name_val} missing Secure flag")
            if 'httponly' not in attrs:
                findings.append(f"Cookie {name_val} missing HttpOnly flag")
            if 'samesite' not in attrs:
                findings.append(f"Cookie {name_val} missing SameSite attribute")
    details['cookies'] = cookie_details

    # Passive reflected XSS detection
    body = resp.text.lower() if resp.text else ''
    reflected = []
    for p in REFLECTED_XSS_PATTERNS:
        if p.lower() in body:
            findings.append('Potential reflected XSS pattern found in page content')
            reflected.append(p)
    details['reflected_xss_patterns'] = reflected

    # Passive SQLi-like keyword search
    sqli_found = []
    for kw in SQLI_KEYWORDS:
        if kw in body:
            sqli_found.append(kw)
    if sqli_found:
        findings.append('Suspicious SQL-like keywords found in response body: ' + ', '.join(sqli_found))
    details['sqli_keywords_found'] = sqli_found

    return findings, details

def save_raw_response_files(report_base, resp):
    headers_file = report_base + '_raw_headers.txt'
    body_file = report_base + '_raw_body.html'
    # Save headers (as lines)
    try:
        with open(headers_file, 'w', encoding='utf-8') as f:
            for k, v in resp.headers.items():
                f.write(f"{k}: {v}\n")
    except Exception as e:
        print('Failed saving raw headers:', e)
    # Save body
    try:
        with open(body_file, 'w', encoding='utf-8') as f:
            f.write(resp.text if resp.text else '')
    except Exception as e:
        print('Failed saving raw body:', e)
    return headers_file, body_file

def generate_html_report(report_path, target_url, ts, findings, details, tls_info, raw_headers_path, raw_body_path):
    # Create a detailed HTML report documenting every check
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('<!doctype html>\n<html><head><meta charset="utf-8"><title>Scan Report</title></head><body>\n')
        f.write(f'<h1>Scan Report for {target_url}</h1>\n')
        f.write(f'<p>Timestamp (UTC): {ts}</p>\n')
        f.write('<h2>Summary of Findings</h2>\n')
        if findings:
            f.write('<ul>\n')
            for it in findings:
                f.write(f'<li><b>{it}</b></li>\n')
            f.write('</ul>\n')
        else:
            f.write('<p>No issues detected (basic passive checks only).</p>\n')

        f.write('<h2>Checks Performed (detailed)</h2>\n')
        # HTTP metadata
        f.write('<h3>HTTP Response Metadata</h3>\n')
        f.write('<ul>\n')
        f.write(f"<li>Status code: {details.get('status_code')}</li>\n")
        f.write(f"<li>Final URL (after redirects): {details.get('final_url')}</li>\n")
        f.write(f"<li>Content-Type: {details.get('content_type')}</li>\n")
        f.write(f"<li>Server header: {details.get('server')}</li>\n")
        f.write(f"<li>Content-Length: {details.get('content_length')}</li>\n")
        f.write('</ul>\n')

        # Security headers
        f.write('<h3>Security Headers</h3>\n')
        f.write('<table border="1" cellpadding="6"><tr><th>Header</th><th>Value</th><th>Result</th></tr>\n')
        for h, v in details.get('security_headers', {}).items():
            res = 'Present' if v is not None else 'Missing'
            val = v if v is not None else ''
            f.write(f'<tr><td>{h}</td><td>{val}</td><td>{res}</td></tr>\n')
        f.write('</table>\n')

        # Cookies
        f.write('<h3>Cookies (Set-Cookie headers)</h3>\n')
        if details.get('cookies'):
            f.write('<table border="1" cellpadding="6"><tr><th>Raw Header</th><th>Name=Value</th><th>Parsed Attributes</th></tr>\n')
            for c in details.get('cookies'):
                attrs = ', '.join([f"{k}={v}" if v is not True else k for k,v in c['attrs'].items()])
                f.write(f"<tr><td>{c['raw']}</td><td>{c['name_val']}</td><td>{attrs}</td></tr>\n")
            f.write('</table>\n')
        else:
            f.write(f"<p>{details.get('cookie_note', 'No cookies parsed.')}</p>\n")

        # Reflected XSS
        f.write('<h3>Passive XSS / Body Pattern Checks</h3>\n')
        if details.get('reflected_xss_patterns'):
            f.write('<p>Reflected XSS-like patterns found: ' + ', '.join(details.get('reflected_xss_patterns')) + '</p>\n')
        else:
            f.write('<p>No simple reflected XSS patterns detected (passive check).</p>\n')

        # SQLi keywords
        f.write('<h3>Passive SQL-like Keyword Scan</h3>\n')
        if details.get('sqli_keywords_found'):
            f.write('<p>Suspicious keywords: ' + ', '.join(details.get('sqli_keywords_found')) + '</p>\n')
        else:
            f.write('<p>No SQL-like keywords found in response body (passive).</p>\n')

        # TLS
        f.write('<h3>TLS / Certificate Info</h3>\n')
        if tls_info:
            if 'error' in tls_info:
                f.write(f"<p>TLS check error: {tls_info['error']}</p>\n")
            else:
                cert = tls_info.get('cert', {})
                proto = tls_info.get('protocol')
                f.write(f"<p>Protocol negotiated: {proto}</p>\n")
                f.write('<h4>Certificate (subject / issuer / validity)</h4>\n')
                f.write('<ul>\n')
                f.write(f"<li>Subject: {cert.get('subject')}</li>\n")
                f.write(f"<li>Issuer: {cert.get('issuer')}</li>\n")
                f.write(f"<li>Valid from: {cert.get('notBefore')}</li>\n")
                f.write(f"<li>Valid to: {cert.get('notAfter')}</li>\n")
                f.write('</ul>\n')
        else:
            f.write('<p>Not an HTTPS target or TLS check not performed.</p>\n')

        # Links to raw files
        f.write('<h3>Raw Response Files</h3>\n')
        f.write(f'<ul><li><a href="{os.path.basename(raw_headers_path)}">Raw response headers</a></li>')
        f.write(f'<li><a href="{os.path.basename(raw_body_path)}">Raw response body (HTML)</a></li></ul>\n')

        f.write('<hr><p>Note: These are passive, non-destructive checks intended for training. For full dynamic scans use a specialized scanner (ZAP, Burp, etc.) with authorization.</p>\n')
        f.write('</body></html>')

def scan_and_report(target):
    ensure_reports_dir()
    ts = now_utc_ts()
    safe_host = urlparse(target).netloc.replace(':', '_')
    base = os.path.join(REPORTS_DIR, f'report_{safe_host}_{ts}')
    html_report = base + '.html'

    resp = None
    findings = []
    details = {}
    tls_info = None

    try:
        resp = fetch_url(target)
    except Exception as e:
        findings.append(f'Failed to fetch target: {e}')

    if resp is not None:
        # Save raw
        raw_headers_path, raw_body_path = save_raw_response_files(base, resp)
        # Analyze
        fnds, det = analyze_response(resp)
        findings.extend(fnds)
        details.update(det)
        # TLS info for https
        if urlparse(target).scheme == 'https':
            tls_info = tls_info_for_host(urlparse(target).netloc)
    else:
        raw_headers_path = base + '_raw_headers.txt'
        raw_body_path = base + '_raw_body.html'
        # create placeholder files
        with open(raw_headers_path, 'w', encoding='utf-8') as f:
            f.write('No response')
        with open(raw_body_path, 'w', encoding='utf-8') as f:
            f.write('')

    # Write HTML report
    generate_html_report(html_report, target, ts, findings, details, tls_info, raw_headers_path, raw_body_path)
    return html_report

def main():
    print('=== Interactive Web Vulnerability Scanner (detailed report, passive checks) ===')
    print('LEGAL: You MUST have explicit written permission to scan any target that is not your own lab.')
    consent = input('I confirm I have permission to test the target described below (type YES to continue): ').strip()
    if consent.upper() != 'YES':
        print('Consent not given. Exiting.')
        return

    target = input('Enter the full target URL (including http:// or https://) to scan: ').strip()
    if not validate_url(target):
        print('Invalid URL. Make sure it includes http:// or https://')
        return

    print(f'Scanning {target} ... (this may take a few seconds)')
    report = scan_and_report(target)
    print(f'Done. Detailed report saved to: {report}')
    input("\nScan finished! Press Enter to exit...")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nInterrupted by user.')
        sys.exit(1)
    except Exception as e:
        print(f'Error: {e}')
        sys.exit(1)
