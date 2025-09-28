#    wifiscanmad1fy — `wifiscan`

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Nmap](https://img.shields.io/badge/nmap-required-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

> Network discovery + vulnerability helper — discovers devices on the LAN, then runs `nmap --script vuln` on the hosts you select. CLI-first tool made/edited by **mad1fy**.

---

## 🧩 Quick features
- Discovery scan (OS, hostname, MAC, vendor) using `python-nmap` bindings.
- Interactive menu: run vulnerability scans **only after discovery**.
- Save results to JSON/CSV, or POST results to a webhook.
- CLI flags for non-interactive automation.
- Pass extra `nmap` args to vuln scans.

---

## ⚙️ Requirements
- Python 3.8+
- `nmap` (binary) installed and in PATH: `sudo apt install nmap`
> **Note:** Some `nmap` checks require elevated privileges. Use `sudo` when running scans if you hit permission issues.

---

## 📁 Files in this repo
- `wifiscan` — main executable script (make sure it has `#!/usr/bin/env python3` at top and is executable)
- `README.md` (this file)

---

## 💾 Install

### system-wide (quick)

```bash
# clone repo and enter it
git clone https://github.com/mad1fyJourn3y/wifiscan.git
cd wifiscan

# install system deps
sudo apt update
sudo apt install -y nmap python3-pip

# install python deps system-wide
sudo python3 -m pip install --upgrade pip setuptools wheel --break-system-packages
sudo python3 -m pip install python-nmap --break-system-packages
```


## ▶️ Run

**Interactive (recommended):**

```bash
# if installed globally
sudo wifiscan

# or run directly from repo
sudo python3 /wifiscan/wifiscan.py
```

**Non-interactive examples:**

```bash
# Fast discovery and save JSON, then exit
sudo wifiscan --fast -j results.json --no-interactive

# Full discovery, save CSV, POST to webhook
sudo wifiscan -c devices.csv -w https://example.com/hook --no-interactive

# Custom CIDR
sudo wifiscan --range 10.0.0.0/24 --fast -j out.json
```

---

## 🧭 Interactive menu behavior
1. Script runs discovery first and prints a numbered device list (IP, MAC, vendor, OS).
2. After discovery choose:
   - `1` → run vulnerability scan (`nmap -sV --script vuln -Pn <ip>`) for **all** discovered devices.
   - `2` → choose a device number to run vulnerability scan on that host only.
3. Use `--vuln-args` to pass extra nmap flags to vuln scans (e.g. `--vuln-args "-p 22,80 -oN scans/host.txt"`).

---

## 🔧 CLI flags / Usage
```
Usage: wifiscan [options]

Options:
  -j, --save-json FILE       Save discovery results as JSON
  -c, --save-csv FILE        Save discovery results as CSV
  -w, --webhook URL          POST JSON results to a webhook URL
  --fast                     Use faster (lighter) discovery flags
  --timeout SECONDS          nmap host timeout (default: 30)
  --no-interactive           Do not prompt for vuln scans (discovery only)
  --range CIDR               Override auto network detection (e.g. 192.168.1.0/24)
  --vuln-args "ARGS"         Extra args to append to vuln-scan command
```
---

## 🧾 Example discovery output
```text
[1] Device: my-laptop
    IP Address: 192.168.1.10
    MAC: AA:BB:CC:11:22:33
    Vendor: Dell Inc.
    OS: Linux 5.x
    Status: up
```

---

## 🛠️ Auto-save for vuln outputs
The repo includes an autosave helper to create a `scans/` directory and save each vuln scan as a timestamped human-readable file.

Example (saved file):
```
scans/192.168.1.10-vuln-20250925-235959.txt
```

To use auto-saving, either call the provided autosave `run_vuln_scan()` in the script or pass `--vuln-args` with `-oN` output flags.

---

## 🧾 Troubleshooting & launcher fix
- If you see:
```
usage: wifiscan.py ... error: unrecognized arguments: $@
```
it usually means a shell wrapper is passing a literal `'$@'`. Run the Python script directly:
```bash
sudo python3 /path/to/wifiscan
```

- To fix a broken launcher, replace it with a wrapper that forwards arguments correctly:
```bash
sudo tee /usr/local/bin/wifiscan > /dev/null <<'EOF'
#!/bin/sh
exec python3 /usr/local/bin/wifiscan "$@"
EOF
sudo chmod +x /usr/local/bin/wifiscan
```

- Ensure `nmap` is installed:
```bash
nmap --version
```

- If `requests` is missing (webhook feature), install:
```bash
sudo pip3 install requests
```

- If `python-nmap` is missing:
```bash
sudo pip3 install python-nmap
```

---

## ⚖️ Security & Ethics
- Only scan networks and devices you own or have explicit permission to test. Unauthorized scanning and vulnerability assessment may be illegal.
- Use responsibly and follow responsible disclosure if you find vulnerabilities.

---

## 📜 License
MIT — see `LICENSE`.

---

## 🙌 Credits
Made/edited by **mad1fy** — https://mad1fyjourn3y.github.io/

---
