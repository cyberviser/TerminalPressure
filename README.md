# 💥 TerminalPressure — CyberViser Pentest Toolkit

<div align="center">

![TerminalPressure](https://img.shields.io/badge/CyberViser-TerminalPressure-ff3366?style=for-the-badge&logo=hackthebox&logoColor=white)

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Part of](https://img.shields.io/badge/Part%20of-Hancock%20Platform-00ff88)](https://github.com/cyberviser/Hancock)

**Authorized penetration testing toolkit — vulnerability scanning, stress testing, and exploit chain simulation.**

> ⚠️ **FOR AUTHORIZED USE ONLY.** Use only on systems you own or have explicit written permission to test. Unauthorized use is illegal.

</div>

---

## 🔧 Features

| Command | Description |
|---------|-------------|
| `scan` | nmap vulnerability scan (ports 1–1024, `-sV --script vuln`) |
| `stress` | Multi-threaded connection stress test (authorized load testing) |
| `exploit` | Exploit chain simulation framework |

---

## ⚡ Quick Start

```bash
git clone https://github.com/cyberviser/TerminalPressure.git
cd TerminalPressure
pip install -r requirements.txt

# Vulnerability scan (authorized targets only)
python terminal_pressure.py scan 192.168.1.1

# Stress test
python terminal_pressure.py stress 192.168.1.1 --port 80 --threads 50 --duration 60

# Exploit chain simulation
python terminal_pressure.py exploit 192.168.1.1 --payload default_backdoor
```

> Requires `nmap` installed on your system: `sudo apt install nmap`

---

## 🛡️ Part of the CyberViser Ecosystem

TerminalPressure is a standalone toolkit that integrates with the **Hancock AI agent** for AI-assisted pentest workflows.

→ [**Hancock — AI Security Agent**](https://github.com/cyberviser/Hancock)  
→ [**CyberViser Platform**](https://cyberviser.github.io/Hancock/)

---

## 📄 License

**CyberViser Proprietary License** — see [LICENSE](LICENSE).  
Commercial use requires a written agreement: contact@cyberviser.ai

© 2025 CyberViser. All Rights Reserved.
