# Ethical Web Scanner

Cross-platform Interactive Web Vulnerability Scanner.
Built for **Ethical Diagnostics** and **Security Awareness**.

---

## 📜 Legal Disclaimer

This tool is intended solely for lawful and authorized use.
You must obtain explicit permission from the network owner before scanning, auditing, or testing any systems.
The author assumes no liability for misuse or for actions that violate applicable laws or organizational policies.
Use responsibly and in compliance with your local governance.

---

## 🔍 Features

### Checks performed (for the requested URL):
- HTTP request & response metadata (status code, URL, final URL after redirects, content-type, server header, content-length)
- Security headers presence and values (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy)
- Cookie analysis (parses Set-Cookie headers and looks for Secure, HttpOnly, SameSite)
- Basic reflected XSS pattern search (passive pattern matching only)
- Simple injection-like pattern search in body (SQLi-like keywords), passive only
- TLS / certificate info for https targets: certificate subject, issuer and validity
- Report includes a full checklist section describing each check and its result

---

## ⚙️ Installation

### 1️ Requirements
- Python **3.0+**
- Works on **Windows**, **Linux**
- Install dependency:
  ```bash
  pip install requests

### 2️ Download & Run

---

### Third-Party Attributions
This project uses the Requests library (© 2019 Kenneth Reitz)  
Licensed under the Apache License 2.0  
https://github.com/psf/requests
