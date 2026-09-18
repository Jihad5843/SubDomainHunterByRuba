# 🛰️ SubDomainHunter

> **Subdomain Enumeration and Reconnaissance Tool**

SubDomainHunter is a Python command-line cybersecurity tool for discovering subdomains and collecting basic reconnaissance information about them.

The tool combines passive and active subdomain enumeration, DNS resolution, CNAME lookup, wildcard detection, HTTP/HTTPS probing, basic technology fingerprinting, and report generation.

The project uses the **Python Standard Library only**, so no third-party Python packages are required.

> ⚠️ **Authorized Use:** Use SubDomainHunter only on domains that you own or have explicit permission to assess. Active enumeration and DNS/HTTP probing generate network traffic.

---

## 1. Problem Statement

Subdomain enumeration is an important step in cybersecurity reconnaissance. However, discovering subdomains from different sources and checking them manually can be time-consuming and may produce duplicate or unorganized results.

SubDomainHunter provides one tool that combines subdomain discovery, DNS inspection, web probing, result processing, and reporting in a single workflow.

---

## 2. Project Idea

The project aims to develop a lightweight Python-based command-line tool that can:

- Discover subdomains using passive sources.
- Discover possible subdomains using a wordlist.
- Remove duplicate results.
- Validate that results belong to the target domain.
- Resolve DNS information.
- Detect CNAME records and possible wildcard DNS.
- Check HTTP and HTTPS services.
- Collect basic web information.
- Perform lightweight technology fingerprinting.
- Display results in the terminal.
- Generate HTML, JSON, and CSV reports.

---

## 3. Project Objectives

The main objectives of SubDomainHunter are:

1. Discover subdomains of an authorized target.
2. Support passive and active enumeration.
3. Remove duplicate hostnames.
4. Keep results inside the target domain scope.
5. Resolve IPv4 and IPv6 addresses.
6. Detect CNAME records.
7. Detect possible wildcard DNS responses.
8. Check HTTP and HTTPS availability.
9. Collect basic web metadata such as status codes and page titles.
10. Perform basic technology fingerprinting.
11. Display discovered results directly in the terminal.
12. Generate HTML, JSON, and CSV reports.
13. Provide configurable scanning options.
14. Provide logging and error handling.
15. Include unit tests.
16. Keep the project dependency-free using Python Standard Library modules.

---

## 4. Main Features

| Feature                   | Description                                                  |
| ------------------------- | ------------------------------------------------------------ |
| Passive Discovery         | Finds subdomain names from Certificate Transparency          |
| Active Discovery          | Generates candidates from a customizable wordlist            |
| Deduplication             | Removes duplicate hostnames                                  |
| Scope Validation          | Keeps results inside the target domain                       |
| DNS Resolution            | Resolves IPv4 and IPv6 addresses                             |
| CNAME Lookup              | Collects CNAME information when available                    |
| Wildcard Detection        | Detects possible wildcard DNS responses                      |
| HTTP Probing              | Checks HTTP services                                         |
| HTTPS Probing             | Checks HTTPS services                                        |
| Redirect Detection        | Records redirects and final URLs                             |
| Web Metadata              | Collects status, title, content type, and server information |
| Technology Fingerprinting | Performs lightweight technology detection                    |
| Concurrent Scanning       | Uses multiple workers                                        |
| Progress Display          | Shows scan progress in the terminal                          |
| Terminal Results          | Displays discovered subdomains and collected information     |
| HTML Report               | Generates a readable report                                  |
| JSON Report               | Generates structured machine-readable data                   |
| CSV Report                | Generates spreadsheet-friendly data                          |
| Configuration             | Supports JSON configuration                                  |
| Logging                   | Supports DEBUG, INFO, WARNING, and ERROR levels              |
| Testing                   | Includes unit tests                                          |
| Cross-platform            | Designed for Windows and Linux                               |

---

## 5. How It Works

The scan follows this general workflow:

```text
                 Target Domain
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
 Passive Discovery            Active Discovery
 Certificate                  Wordlist
 Transparency
          │                         │
          └────────────┬────────────┘
                       ▼
              Remove Duplicates
                       │
                       ▼
                Scope Validation
                       │
                       ▼
                 DNS Resolution
                       │
              ┌────────┴────────┐
              ▼                 ▼
          CNAME Lookup     Wildcard Check
              │                 │
              └────────┬────────┘
                       ▼
                HTTP / HTTPS
                   Probing
                       │
                       ▼
             Collect Information
                       │
                       ▼
                Final Findings
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       Terminal       HTML       JSON / CSV
        Output       Report        Reports
```

---

## 6. Passive and Active Enumeration

### Passive Enumeration

Passive enumeration uses publicly available information instead of generating a large number of guessed hostnames.

SubDomainHunter uses Certificate Transparency data through `crt.sh`.

Example:

```bash
python -m subdomainhunter scan example.com --no-active
```

This disables active wordlist enumeration and keeps passive discovery enabled.

### Active Enumeration

Active enumeration generates possible subdomain names from a wordlist and checks them.

The default wordlist is:

```text
wordlists/common.txt
```

Example:

```bash
python -m subdomainhunter scan example.com --no-passive
```

This disables passive discovery and keeps active wordlist enumeration enabled.

### Both Modes

By default, passive and active enumeration can be used together:

```bash
python -m subdomainhunter scan example.com
```

---

## 7. Results and Outputs

After a scan, SubDomainHunter displays a summary in the terminal, including:

- Number of unique findings.
- Number of DNS-resolved hosts.
- Number of web-alive hosts.
- Number of wildcard matches.

The tool also displays the discovered findings and available reconnaissance information, such as:

- Hostname.
- Discovery source.
- IP addresses.
- CNAME.
- HTTP status.
- HTTPS status.
- Page title.
- Technologies.
- URLs.
- Wildcard status.

Example:

```text
RESULTS
------------------------------------------------------------------------
[1] api.example.com
    Source : crt.sh, wordlist
    IP     : 93.184.216.34
    CNAME  : -
    HTTP   : 200
    HTTPS  : 200
    Title  : Example API
    Tech   : nginx
------------------------------------------------------------------------
```

If no reachable or resolved findings are available, the tool reports that no such subdomains were found.

---

## 8. Report Formats

SubDomainHunter supports three output formats.

### HTML

HTML is designed for human-readable results.

```bash
python -m subdomainhunter scan example.com --format html
```

### JSON

JSON provides structured machine-readable data.

```bash
python -m subdomainhunter scan example.com --format json -o reports/example.json
```

### CSV

CSV provides spreadsheet-friendly results.

```bash
python -m subdomainhunter scan example.com --format csv -o reports/example.csv
```

---

## 9. Requirements

- Python 3.10 or newer.
- Internet connection for passive discovery, DNS-over-HTTPS, and web probing.
- Windows or Linux.
- Command Prompt, PowerShell, or Terminal.

No third-party Python packages are required.

---

## 10. Installation and Quick Start

Open a terminal inside the project directory.

Check Python:

```bash
python --version
```

Run the main help:

```bash
python -m subdomainhunter --help
```

Check the version:

```bash
python -m subdomainhunter --version
```

Run a scan:

```bash
python -m subdomainhunter scan example.com
```

Replace `example.com` with an authorized domain.

---

## 11. Command-Line Reference

### Main Help

```bash
python -m subdomainhunter --help
```

Displays the available commands and global options.

### Scan Help

```bash
python -m subdomainhunter scan --help
```

Displays the available scan options.

### Config Help

```bash
python -m subdomainhunter config --help
```

Displays configuration commands.

### Version

```bash
python -m subdomainhunter --version
```

or:

```bash
python -m subdomainhunter version
```

### Full Scan

```bash
python -m subdomainhunter scan example.com
```

Runs the scan using the configured discovery and probing options.

### Passive Only

```bash
python -m subdomainhunter scan example.com --no-active
```

Disables active wordlist enumeration.

### Active Only

```bash
python -m subdomainhunter scan example.com --no-passive
```

Disables passive discovery.

### Disable Web Probing

```bash
python -m subdomainhunter scan example.com --no-probe
```

Disables HTTP/HTTPS probing.

### Custom Wordlist

```bash
python -m subdomainhunter scan example.com --wordlist wordlists/common.txt
```

Uses the specified wordlist.

### Workers

```bash
python -m subdomainhunter scan example.com --workers 40
```

Changes the number of concurrent workers.

### Timeout

```bash
python -m subdomainhunter scan example.com --timeout 8
```

Sets the network timeout to 8 seconds.

### Maximum Candidates

```bash
python -m subdomainhunter scan example.com --max-candidates 1000
```

Limits the number of active candidates.

### Disable DNS-over-HTTPS

```bash
python -m subdomainhunter scan example.com --no-dns-over-https
```

Disables the DNS-over-HTTPS path.

### Show All Candidates

```bash
python -m subdomainhunter scan example.com --show-all
```

Keeps resolved or non-web candidates in the results instead of filtering them out.

### Log Level

```bash
python -m subdomainhunter --log-level DEBUG scan example.com
```

Supported levels:

```text
DEBUG
INFO
WARNING
ERROR
```

---

## 12. Configuration

Create a default configuration file:

```bash
python -m subdomainhunter config init
```

The command creates:

```text
subdomainhunter.json
```

Show the configuration:

```bash
python -m subdomainhunter config show
```

A configuration can contain settings such as:

```json
{
  "timeout": 5.0,
  "workers": 24,
  "retries": 1,
  "rate_limit": 0.0,
  "wordlist": "wordlists/common.txt",
  "passive": true,
  "active": true,
  "probe": true,
  "dns_over_https": true,
  "max_candidates": 5000,
  "output": "reports",
  "format": "html",
  "user_agent": "SubDomainHunter/2.0",
  "include_all_candidates": false
}
```

A custom configuration file can be selected with:

```bash
python -m subdomainhunter --config my-config.json scan example.com
```

Command-line options override matching configuration values.

---

## 13. Project Structure

```text
SubDomainHunter/
│
├── subdomainhunter/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── config.py
│   ├── enumerators.py
│   ├── logging_setup.py
│   ├── models.py
│   └── utils.py
│
├── wordlists/
│   └── common.txt
│
├── tests/
│   └── test_utils.py
│
├── subdomainhunter.json
├── requirements.txt
└── README.md
```

### File Descriptions

| File                   | Purpose                                                              |
| ---------------------- | -------------------------------------------------------------------- |
| `__init__.py`          | Package metadata, version, and author information                    |
| `__main__.py`          | Allows the project to run with `python -m subdomainhunter`           |
| `cli.py`               | Handles command-line arguments, commands, progress, and final output |
| `config.py`            | Handles configuration loading and initialization                     |
| `enumerators.py`       | Handles passive/active enumeration, DNS, and web inspection          |
| `logging_setup.py`     | Configures logging                                                   |
| `models.py`            | Defines the structured finding model                                 |
| `utils.py`             | Provides validation, wordlist, deduplication, and report helpers     |
| `common.txt`           | Wordlist used for active enumeration                                 |
| `test_utils.py`        | Unit tests                                                           |
| `subdomainhunter.json` | Project configuration                                                |
| `requirements.txt`     | Lists project dependencies                                           |
| `README.md`            | Project documentation                                                |

---

## 14. Testing

Run the built-in tests with:

```bash
python -m unittest discover -s tests -v
```

The project uses Python's built-in `unittest` framework.

---

## 15. Technical Design

SubDomainHunter uses Python Standard Library modules, including:

- `argparse` — command-line argument parsing.
- `urllib` — HTTP/HTTPS requests.
- `socket` — DNS/system resolution.
- `ssl` — HTTPS handling.
- `concurrent.futures` — concurrent scanning.
- `json` — configuration and JSON reports.
- `csv` — CSV reports.
- `logging` — diagnostic logging.
- `dataclasses` — structured findings.
- `unittest` — testing.
- `pathlib` — file and path handling.

---

## 16. Error Handling

The tool handles common problems such as:

- Invalid domain names.
- Missing configuration files.
- Invalid JSON configuration.
- Missing wordlists.
- Invalid worker values.
- Invalid candidate limits.
- Network failures.
- Interrupted scans.

Example:

```bash
python -m subdomainhunter scan not-a-domain
```

The tool should return a clear error message instead of crashing unexpectedly.

---

## 17. Security and Authorized Use

SubDomainHunter is intended for authorized cybersecurity reconnaissance.

The tool focuses on:

- Subdomain discovery.
- DNS information.
- Basic web-service inspection.
- Technology identification.
- Reporting.

It does not attempt to:

- Exploit vulnerabilities.
- Bypass authentication.
- Brute-force credentials.
- Modify target systems.
- Upload files.
- Execute commands on target systems.
- Perform destructive testing.

Always obtain appropriate authorization before scanning a real target.

---

## 18. Scan Lifecycle

```text
1. Validate target
        ↓
2. Load configuration
        ↓
3. Passive discovery
        ↓
4. Active wordlist enumeration
        ↓
5. Remove duplicates
        ↓
6. Validate domain scope
        ↓
7. DNS resolution
        ↓
8. CNAME lookup
        ↓
9. Wildcard detection
        ↓
10. HTTP/HTTPS probing
        ↓
11. Technology fingerprinting
        ↓
12. Display findings
        ↓
13. Generate report
```

---

## 19. Conclusion

SubDomainHunter provides a simple command-line workflow for subdomain enumeration and basic reconnaissance.

It combines multiple discovery methods, DNS inspection, web probing, result processing, terminal output, and report generation in one lightweight Python project.

**SubDomainHunter — Discover. Resolve. Inspect. Report.**
