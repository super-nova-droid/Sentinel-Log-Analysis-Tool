## SentinelLog 🔍

A small, local web-based log analysis project for detecting common server threats and demonstrating simple incident triage workflows.

---

## Overview



- **SentinelLog (web UI)**: a lightweight browser UI that scans pasted server logs for common attack patterns (SQLi, XSS, LFI/RFI, SSRF, command injection, brute force, recon/scanners, and more) and provides quick triage features (severity, dedupe, export).

Files of interest:
- `index.html` — UI and controls
- `style.css` — visual styling (dark / terminal-like theme)
- `logscript.js` — detection logic, regex signatures, sample logs, export and filter functions
- `RUNNING.md` — how to run the app locally
- `screenshot.png` — illustrative snapshot of the UI

---

## Objectives

- Provide a compact, easy-to-run demo that helps identify and label common malicious patterns in server logs.
- Make it trivial to test detection logic using built-in sample logs.
- Add basic triage utilities (severity filters, deduplication, CSV export) useful for quick incident response prototyping.

---

## Features

- Detection of multiple attack classes via regular expressions:
  - SQL Injection (including blind/time-based variants)
  - Cross-Site Scripting (XSS)
  - Local & Remote File Inclusion (LFI/RFI), Path Traversal
  - Server-Side Request Forgery (SSRF)
  - Command injection patterns
  - Brute-force / failed login detection
  - Malicious upload indicators and scanner/exploit tool fingerprints
- Severity labeling (Critical / High / Medium / Low)
- UI controls: severity filter, deduplicate toggle, Export CSV, Clear results
- Sample logs that demonstrate all detectors for quick local testing
- Results are escaped for safe display and include parsed IP and timestamp when available

---

## How to run (quick)

1. Open the project folder in a browser by double-clicking `index.html` (quick test), or run a local static server (recommended):
   - Python: `python -m http.server 8000` → open `http://localhost:8000`
   - Node: `npx http-server -p 8000`
   - VS Code: install **Live Server** and click **Go Live**
2. Open the page, click **Load Sample Logs**, then **Scan for Threats**.
3. Use the **Filter** dropdown, **Dedupe** checkbox, or **Export CSV** to validate behavior.

For more run details see `RUNNING.md`.

---

## Work done / Results

- Fixed a script reference bug in `index.html` (was referencing `script.js`, now `logscript.js`) so the app loads correctly.
- Expanded the detection engine in `logscript.js` with multiple realistic regex signatures and improved result rendering (badges, escaped content, IP/timestamp extraction).
- Added UI controls (filter, dedupe, export, clear) and polished styles in `style.css`.
- Wrote `RUNNING.md` with run/test instructions and created a sample `screenshot.png` demonstration.
- Verified signature coverage against an expanded set of sample log lines and ensured export/filter/dedupe functions work as intended.

---

## Learning outcomes & notes

- Regex-based detection is useful for quick prototyping but has limitations: false positives/negatives are possible and signatures should be validated against real logs.
- UI-level deduplication and export are helpful for triage but should be backed by server-side processing for production use.
- Recommended future improvements: per-IP aggregation, persistent history, sortable table view, unit tests for signatures, and headless-browser UI tests.

---

## Tools & libraries used

- Vanilla **HTML / CSS / JavaScript** for the frontend
- **Python** (built-in `http.server`) for serving locally during development and testing
- (Dev) **Pillow** used to generate a sample `screenshot.png`
- Optional: **Node / npx http-server**, **VS Code Live Server**

---


