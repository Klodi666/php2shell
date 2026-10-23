#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP2SHELL SENTINEL — Authorized PHP security assessment toolkit
Python 3 standard library only.

Features:
  [1] Check one authorized HTTP(S) URL
  [2] Batch-check URLs from a text file
  [3] Export latest findings as JSON, CSV, or HTML
  [4] Show remediation guidance
  [5] View recent diagnostic log
  [0] Exit

This tool performs non-invasive HTTP header checks only. It does not exploit
PHP2Shell, send crafted multipart payloads, or execute remote commands.
A version banner is only a hint and cannot prove vulnerability or patch status.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import urlparse

APP_NAME = "PHP2SHELL SENTINEL"
VERSION = "1.0"
OUT_DIR = Path("php2shell_sentinel_output")
LOG_DIR = OUT_DIR / "logs"
REPORT_DIR = OUT_DIR / "reports"
LOG_FILE = LOG_DIR / "sentinel.log"
USER_AGENT = f"PHP2Shell-Sentinel/{VERSION} (authorized non-invasive audit)"
DEFAULT_TIMEOUT = 8.0
MAX_URLS = 500

OUT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

ASCII = r"""
 ____  _   _ ____  ____   ____  _   _ _____ _     _
|  _ \| | | |  _ \/ ___| / ___|| | | | ____| |   | |
| |_) | |_| | |_) \___ \ \___ \| |_| |  _| | |   | |
|  __/|  _  |  __/ ___) | ___) |  _  | |___| |___| |___
|_|   |_| |_|_|   |____/ |____/|_| |_|_____|_____|_____|
             S E N T I N E L   //   DEFENSIVE AUDIT
"""

LATEST_RESULTS: list[dict] = []


def paint(text: str, code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def info(message: str) -> None:
    print(paint("[*] ", "96") + message)


def good(message: str) -> None:
    print(paint("[+] ", "92") + message)


def warn(message: str) -> None:
    print(paint("[!] ", "93") + message)


def bad(message: str) -> None:
    print(paint("[-] ", "91") + message)


def line() -> None:
    print(paint("-" * 68, "90"))


def normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("URL is empty.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are accepted.")
    if not parsed.hostname:
        raise ValueError("URL must contain a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    return value


def check_url(raw_url: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Make one ordinary HEAD request; fallback to GET only if HEAD is rejected."""
    url = normalize_url(raw_url)
    started = time.monotonic()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.5",
        "Connection": "close",
    }
    status = None
    response_headers = {}
    method = "HEAD"
    error = None

    def request(method_name: str):
        req = urllib.request.Request(url, headers=headers, method=method_name)
        return urllib.request.urlopen(req, timeout=timeout)

    try:
        try:
            with request("HEAD") as response:
                status = response.status
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            if status in (400, 403, 405, 501):
                method = "GET"
                # Read no response body; close promptly.
                try:
                    with request("GET") as response:
                        status = response.status
                        response_headers = dict(response.headers.items())
                except urllib.error.HTTPError as get_exc:
                    status = get_exc.code
                    response_headers = dict(get_exc.headers.items()) if get_exc.headers else {}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = f"{type(exc).__name__}: {exc}"

    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    server = response_headers.get("Server", "")
    powered = response_headers.get("X-Powered-By", "")
    combined = f"{server} {powered}"
    php_match = re.search(r"(?:PHP/|PHP\s*)(\d+\.\d+(?:\.\d+)?)", combined, re.I)
    php_version = php_match.group(1) if php_match else None

    if error:
        status_label = "unreachable_or_blocked"
    elif php_version:
        status_label = "php_version_disclosed_review_required"
    else:
        status_label = "reachable_version_unknown"

    result = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "url": url,
        "http_status": status,
        "method": method,
        "server_header": server or None,
        "x_powered_by": powered or None,
        "php_version_disclosed": php_version,
        "assessment": status_label,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "error": error,
        "limitations": (
            "Non-invasive header check only. Does not confirm PHP2Shell exposure, "
            "CVE applicability, or successful remediation."
        ),
    }
    logging.info("Checked %s status=%s assessment=%s error=%s",
                 url, status, status_label, error)
    return result


def show_result(result: dict) -> None:
    line()
    print(f"URL:          {result['url']}")
    print(f"HTTP status:  {result['http_status'] if result['http_status'] is not None else 'n/a'}")
    print(f"Assessment:   {result['assessment']}")
    print(f"PHP version:  {result['php_version_disclosed'] or 'not disclosed'}")
    print(f"Server:       {result['server_header'] or 'not disclosed'}")
    print(f"X-Powered-By: {result['x_powered_by'] or 'not disclosed'}")
    print(f"Elapsed:      {result['elapsed_seconds']} sec")
    if result["error"]:
        warn("Error: " + result["error"])
    line()


def ask_timeout() -> float:
    raw = input("Timeout seconds [8]: ").strip()
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        value = float(raw)
        if not 1 <= value <= 30:
            raise ValueError
        return value
    except ValueError:
        warn("Invalid timeout; using 8 seconds.")
        return DEFAULT_TIMEOUT


def one_target() -> None:
    global LATEST_RESULTS
    url = input("Authorized target URL: ").strip()
    timeout = ask_timeout()
    try:
        result = check_url(url, timeout)
        LATEST_RESULTS = [result]
        show_result(result)
    except ValueError as exc:
        bad(str(exc))


def load_url_file(path_string: str) -> list[str]:
    path = Path(path_string).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    urls: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        value = value.split(",", 1)[0].strip().split()[0]
        try:
            urls.append(normalize_url(value))
        except (ValueError, IndexError):
            logging.warning("Skipped invalid input line: %r", raw[:200])
    # Deduplicate while preserving order; cap accidental huge lists.
    unique = list(dict.fromkeys(urls))
    if len(unique) > MAX_URLS:
        warn(f"Input capped at {MAX_URLS} URLs.")
        unique = unique[:MAX_URLS]
    return unique


def batch_targets() -> None:
    global LATEST_RESULTS
    path = input("Path to URL list (one URL per line): ").strip()
    try:
        urls = load_url_file(path)
    except (OSError, ValueError) as exc:
        bad(str(exc))
        return
    if not urls:
        warn("No valid URLs found.")
        return
    timeout = ask_timeout()
    results = []
    info(f"Checking {len(urls)} URL(s), one request at a time.")
    for index, url in enumerate(urls, 1):
        print(f"\n[{index}/{len(urls)}] {url}")
        try:
            result = check_url(url, timeout)
        except Exception as exc:
            result = {
                "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "url": url, "http_status": None, "method": None,
                "server_header": None, "x_powered_by": None,
                "php_version_disclosed": None, "assessment": "error",
                "elapsed_seconds": 0, "error": f"{type(exc).__name__}: {exc}",
                "limitations": "Non-invasive header check only.",
            }
        results.append(result)
        print(f"    -> {result['assessment']} | HTTP {result['http_status'] or 'n/a'}")
        time.sleep(0.15)
    LATEST_RESULTS = results
    good(f"Completed: {len(results)} result(s). Use option 3 to export.")


def safe_filename(name: str, extension: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip()).strip("._")
    if not stem:
        stem = "php2shell_audit"
    if not stem.lower().endswith("." + extension):
        stem += "." + extension
    return stem


def export_results() -> None:
    if not LATEST_RESULTS:
        warn("No results yet. Run option 1 or 2 first.")
        return
    print("Export format: [1] JSON  [2] CSV  [3] HTML")
    choice = input("Format: ").strip()
    formats = {"1": "json", "2": "csv", "3": "html"}
    if choice not in formats:
        warn("Unknown format.")
        return
    fmt = formats[choice]
    default_name = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    name = input(f"Filename [{default_name}]: ").strip() or default_name
    filename = safe_filename(name, fmt)
    path = REPORT_DIR / filename

    try:
        if fmt == "json":
            path.write_text(json.dumps(LATEST_RESULTS, indent=2), encoding="utf-8")
        elif fmt == "csv":
            fields = list(dict.fromkeys(k for row in LATEST_RESULTS for k in row.keys()))
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(LATEST_RESULTS)
        else:
            headers = list(dict.fromkeys(k for row in LATEST_RESULTS for k in row.keys()))
            table_head = "".join(f"<th>{escape(str(key))}</th>" for key in headers)
            rows_html = []
            for row in LATEST_RESULTS:
                cells = "".join(
                    f"<td>{escape(json.dumps(row.get(key), ensure_ascii=False) if isinstance(row.get(key), (dict, list)) else str(row.get(key, '')))}</td>"
                    for key in headers
                )
                rows_html.append(f"<tr>{cells}</tr>")
            document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHP2Shell Sentinel Audit</title>
<style>
body{{font:14px system-ui,sans-serif;margin:2rem;background:#10151b;color:#e7edf3}}
h1{{color:#65e6b7}}.note{{padding:1rem;background:#202a34;border-radius:8px}}
table{{border-collapse:collapse;width:100%;display:block;overflow-x:auto}}
th,td{{padding:.6rem;border:1px solid #34414e;text-align:left;vertical-align:top}}
th{{background:#202a34}}tr:nth-child(even){{background:#151d25}}
</style></head><body><h1>PHP2Shell Sentinel — Audit Report</h1>
<p>Generated {escape(datetime.now(timezone.utc).isoformat())}</p>
<p class="note">Non-invasive header checks only. Results do not prove vulnerability or patch status.</p>
<table><thead><tr>{table_head}</tr></thead>
<tbody>{''.join(rows_html)}</tbody></table></body></html>"""
            path.write_text(document, encoding="utf-8")
        good(f"Report saved: {path.resolve()}")
    except OSError as exc:
        bad(f"Could not write report: {exc}")
        logging.exception("Report export failed")


def remediation() -> None:
    line()
    print("DEFENSIVE PHP2SHELL REVIEW")
    print("1. Confirm the exact CVE identifiers and affected version ranges using")
    print("   vendor advisories and trusted vulnerability databases.")
    print("2. Upgrade PHP and affected packages to a vendor-supported fixed release.")
    print("3. If advised by the vendor, disable session.upload_progress when not needed.")
    print("4. Review PHP-FPM/web-server logs for crashes, unusual multipart requests,")
    print("   repeated session identifiers, and unexpected 5xx responses.")
    print("5. Test fixes in staging; take backups and retain change records.")
    print("6. Avoid exposing PHP version banners and unnecessary diagnostic endpoints.")
    print()
    print("Important: a Server/X-Powered-By header is not proof of vulnerability.")
    print("Headers may be absent, modified, or unrelated to the actual PHP runtime.")
    line()


def show_log() -> None:
    if not LOG_FILE.exists():
        info("No log entries yet.")
        return
    try:
        lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        print("\n".join(lines[-40:]) if lines else "(log is empty)")
    except OSError as exc:
        bad(f"Unable to read log: {exc}")


def menu() -> None:
    while True:
        print()
        line()
        print(paint(" [1] Check one authorized URL", "92"))
        print(paint(" [2] Batch check from a text file", "92"))
        print(paint(" [3] Export latest findings (JSON/CSV/HTML)", "96"))
        print(paint(" [4] PHP2Shell remediation guidance", "93"))
        print(paint(" [5] View diagnostic log", "96"))
        print(paint(" [0] Exit", "91"))
        line()
        choice = input("sentinel@audit > ").strip().lower()
        if choice == "1":
            one_target()
        elif choice == "2":
            batch_targets()
        elif choice == "3":
            export_results()
        elif choice == "4":
            remediation()
        elif choice == "5":
            show_log()
        elif choice in ("0", "q", "quit", "exit"):
            good("Exiting. Stay authorized, stay safe.")
            break
        else:
            warn("Choose one of the listed menu numbers.")


def main() -> int:
    print(paint(ASCII, "92"))
    print(paint(f"  v{VERSION} | Python {sys.version.split()[0]} | NON-INVASIVE MODE", "90"))
    print("  Use only for systems you own or have explicit permission to assess.")
    try:
        menu()
    except KeyboardInterrupt:
        print("\n")
        warn("Interrupted by user. Existing logs and exported reports are preserved.")
        logging.info("User interrupted program")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
