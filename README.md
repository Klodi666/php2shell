# PHP2Shell Sentinel

**PHP2Shell Sentinel** is a lightweight Python 3 command-line tool for non-invasive, authorized PHP security checks. It has a hacker-style ASCII banner, a numbered menu, batch URL checks, diagnostic logging, and JSON, CSV, and HTML reports.

> **Safety note:** This project performs ordinary HTTP header/connectivity checks only. It does not exploit PHP2Shell vulnerabilities, send crafted exploit payloads, or execute commands on remote systems. Header checks cannot prove whether a host is vulnerable or patched.

## Features

- **Single URL check** — inspect HTTP status and selected response headers.
- **Batch checks** — read URLs from a text file, one URL per line.
- **PHP version hint** — report a PHP version if it is disclosed in `Server` or `X-Powered-By` headers.
- **Reports** — export results to JSON, CSV, or HTML.
- **Diagnostic logging** — record checks and errors locally.
- **Terminal UI** — numbered menu and ASCII banner.
- **No third-party dependencies** — uses the Python standard library.

## Requirements

- Python 3.9 or newer recommended
- Internet or network access to the systems you are authorized to assess

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/php2shell-sentinel.git
cd php2shell-sentinel
```

Run the script:

```bash
python3 php2shell_sentinel.py
```

No `pip install` step is required.

## Menu

```text
[1] Check one authorized URL
[2] Batch check from a text file
[3] Export latest findings (JSON/CSV/HTML)
[4] PHP2Shell remediation guidance
[5] View diagnostic log
[0] Exit
```

## Usage

### Check one URL

Choose menu option `1`, then enter a URL for a system you own or have explicit permission to test. For example, use a local lab:

```text
http://127.0.0.1/
```

The script makes a normal HTTP `HEAD` request and may fall back to a normal `GET` request if the server rejects `HEAD`. It does not send exploit payloads.

### Batch-check a URL list

Create a text file such as `targets.txt`:

```text
# One authorized URL per line
http://127.0.0.1/
https://staging.example.test/
```

Choose option `2` and enter the path to the file. Only include systems you are authorized to assess.

### Export results

Choose option `3` after running one or more checks. Select JSON, CSV, or HTML and enter a filename. Reports are saved under:

```text
php2shell_sentinel_output/reports/
```

Diagnostic logs are saved under:

```text
php2shell_sentinel_output/logs/sentinel.log
```

## Understanding the results

The tool reports basic observations such as HTTP status, disclosed server headers, and response time. A disclosed PHP version is only a **hint**:

- Headers can be missing, modified, or misleading.
- A server banner may not identify the PHP runtime serving the application.
- A version string alone does not establish whether a specific CVE applies.
- A successful HTTP response does not prove that the host is secure.

Confirm exposure and patch status using trustworthy vendor advisories, package/build information, and authorized testing in a controlled staging environment.

## Defensive recommendations

- Upgrade PHP and affected components to a vendor-supported fixed release.
- Review the applicable vendor advisory for exact affected versions and mitigations.
- If recommended by the vendor and compatible with your application, disable `session.upload_progress` when it is not needed.
- Review web-server and PHP-FPM logs for unexpected errors, crashes, and unusual multipart requests.
- Avoid exposing unnecessary version banners and diagnostic endpoints.
- Test changes in staging and keep backups and change records.

## Limitations

- This is not an exploit or proof-of-concept for remote code execution.
- It does not verify exploitability or certify that a system is patched.
- It performs no port scanning, brute forcing, or command execution.
- It makes ordinary HTTP requests to the URLs you provide.
- Network failures, access controls, reverse proxies, and rate limits can affect results.

## Responsible use

Use this project only on systems you own or where you have explicit authorization. Follow applicable laws, contracts, and organizational testing policies. Do not use it to access, disrupt, or exploit third-party systems.

The software is provided for educational and defensive purposes, without warranty. You are responsible for how you use it.

## License

Choose a license before publishing this repository. If you want a permissive open-source license, see the [MIT License](https://opensource.org/license/mit/). Do not claim a license until you have added the corresponding license file.
