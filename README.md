# ShopCo Security Lab

A deliberately vulnerable Flask web application used in the **JBI Training / BBC Academy Secure Web Application Development** two-day hands-on course.

---

## Repository Structure

```
shopco-security-lab/
├── vulnerable_shop.py            # Vulnerable app — 8 deliberate flaws (Module 4 Bingo exercise)
├── vulnerable_shop_CLEAN.py      # Clean version — no flaw comments (distribute to delegates)
├── vulnerable_shop_fixed.py      # Remediated version — used for comparison & discussion
├── requirements.txt              # Current, safe dependencies (for fixed app)
├── requirements_vulnerable.txt   # Deliberately outdated deps with known CVEs (Module 5 demo)
│
├── docs/                         # All course reference cards and supporting materials
│   ├── README.md                 # Index of all docs mapped to course modules
│   ├── Flask_Security_Supplement.docx
│   ├── Module4_OWASP_Bingo_Companion_Guide.docx
│   └── ... (all Module reference cards)
│
└── setup/                        # VM configuration and installation scripts
    ├── lab_setup_notes.md        # Full VM setup guide for instructors
    └── beef_install.sh           # Automated BeEF installation script for Ubuntu 20.04
```

---

## Quick Start (Ubuntu Linux Lab VM)

```bash
# 1. Clone the repository
git clone https://github.com/TimDWilliams-ProteQC-CTO/shopco-security-lab.git
cd shopco-security-lab

# 2. Install Flask
pip3 install flask --break-system-packages

# 3. Run the vulnerable app (Module 4 — OWASP Bingo exercise)
python3 vulnerable_shop.py

# 4. Open in Firefox
#    http://localhost:5000
```

### Pre-seeded accounts

| Username | Password | Role |
|---|---|---|
| admin | letmein | Administrator |
| alice | password123 | Standard user |
| bob | qwerty | Standard user |

---

## Quick Start (MacBook — macOS)

```bash
git clone https://github.com/TimDWilliams-ProteQC-CTO/shopco-security-lab.git
cd shopco-security-lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 vulnerable_shop.py
# Open http://localhost:5000 in Firefox
```

## Quick Start (Windows Laptop)

```bash
git clone https://github.com/TimDWilliams-ProteQC-CTO/shopco-security-lab.git
cd shopco-security-lab
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python vulnerable_shop.py
# Open http://localhost:5000 in Firefox
```

---

## Deliberate Security Flaws (vulnerable_shop.py)

Used in the **Module 4 OWASP Bingo** exercise. Delegates annotate the clean version (`vulnerable_shop_CLEAN.py`) before the instructor reveals the answer key.

| Flaw | OWASP Category | Description |
|---|---|---|
| 1 | A02 Cryptographic Failures | Hardcoded, trivial secret key |
| 2 | A05 Security Misconfiguration | `DEBUG=True` can reach production |
| 3 | A02 Cryptographic Failures | MD5 used for password hashing |
| 4 | A03 Injection | Raw f-string SQL (SQL injection vector) |
| 5 | A07 Auth Failures | Session stores username, not user_id |
| 6 | A01 Broken Access Control | `/profile` has no authentication check |
| 7 | A01 Broken Access Control | IDOR — any `user_id` accepted from URL |
| 8 | A03 Injection | Command injection via `os.popen()` |

> **Instructor note:** Distribute `vulnerable_shop_CLEAN.py` to delegates — this version has the flaw annotations stripped out.

---

## Module 5 — Supply Chain Demo

```bash
# Install pip-audit
pip3 install pip-audit --break-system-packages

# Scan the deliberately vulnerable requirements file
pip-audit -r requirements_vulnerable.txt

# Compare against the safe requirements file
pip-audit -r requirements.txt
```

---

## Lab Environment

See [`setup/lab_setup_notes.md`](setup/lab_setup_notes.md) for the complete VM configuration guide, including ZAP Proxy, Wireshark, BeEF, Juice Shop and DVWA setup instructions.

---

## Course Overview

| Day | Theme | Modules |
|---|---|---|
| Day 1 | Web Application Security Fundamentals | 1–6 |
| Day 2 | OWASP Top 10 Vulnerabilities & Mitigations | 7–12 |

**Delivered by:** JBI Training for BBC Academy  
**Lab environment:** Cloud-hosted Ubuntu 20.04 LTS VMs (1 per delegate)  
**Primary target app:** OWASP Juice Shop  
**Secondary apps:** ShopCo (this repo), DVWA, Google XSS Game

---

## Licence

[CC0-1.0](LICENSE) — This project is released into the public domain for educational use.
