# Lab Setup Notes
## ShopCo Security Lab — Ubuntu VM Configuration Guide
**BBC Academy / JBI Training | Secure Web Application Development**

---

## VM Specification

| Item | Detail |
|---|---|
| OS | Ubuntu 20.04 LTS (Desktop) |
| RAM | 4 GB minimum, 8 GB recommended |
| Disk | 40 GB minimum |
| User | `ubuntu` (all VMs — lowercase) |
| Access | RDP (port 3389) or HTTPS browser |

---

## Pre-Installed Tools (Configured on Lab VMs)

| Tool | Purpose | Module |
|---|---|---|
| Firefox (with Dev Tools) | Client-side analysis, HTTP inspection | 2 |
| ZAP Proxy | HTTP/HTTPS interception, IAST scanning | 2, 6, 7 |
| Wireshark | Packet capture, TLS handshake analysis | 2, 11 |
| OWASP Juice Shop | Primary target web app (Node.js) | 6–11 |
| DVWA | Secondary target app (PHP) | 6, 9 |
| BeEF Project | Browser hooking attacks | 3, 7 |
| SE Toolkit (SET) | Social engineering simulations | 3 |
| HashCat | Password hash cracking | 9 |
| pip-audit | Dependency vulnerability scanning | 5 |

---

## ShopCo Flask App — Quick Start

```bash
# 1. Install dependencies
pip3 install flask --break-system-packages

# 2. Run the vulnerable version (Module 4 OWASP Bingo exercise)
python3 vulnerable_shop.py

# 3. Access in Firefox
#    http://localhost:5000
#
# Pre-seeded accounts:
#   admin / letmein
#   alice / password123
#   bob   / qwerty

# 4. Run the fixed version (for comparison/remediation discussion)
pip3 install -r requirements.txt --break-system-packages
python3 vulnerable_shop_fixed.py
```

---

## ZAP Proxy — Firefox Configuration

1. Start ZAP: **Applications → Security → OWASP ZAP**
2. In Firefox: **Preferences → Network Settings → Manual Proxy**
   - HTTP Proxy: `127.0.0.1` Port: `8080`
   - Check: *Also use this proxy for HTTPS*
3. Install ZAP CA certificate:
   - ZAP → **Tools → Options → Dynamic SSL Certificates → Save**
   - Firefox → **Preferences → Privacy & Security → View Certificates → Import**
   - Import the saved `.cer` file and trust it for identifying websites

---

## BeEF — Installation & Start

```bash
# Install (first time only — takes 5–10 minutes)
chmod +x setup/beef_install.sh
./setup/beef_install.sh

# Start BeEF
cd ~/beef && ./beef

# Web UI
http://127.0.0.1:3000/ui/panel
# Default credentials: beef / beef

# Hook URL (inject into target pages)
http://<VM-IP>:3000/hook.js
```

> **See** `setup/beef_install.sh` for the full automated installation script.

---

## Juice Shop — Start / Stop

```bash
# Juice Shop runs as a systemd service on the lab VMs
sudo systemctl start juice-shop
sudo systemctl stop juice-shop
sudo systemctl status juice-shop

# Access in Firefox
http://localhost:3000
```

---

## DVWA — Start / Stop

```bash
sudo systemctl start apache2
sudo systemctl start mysql

# Access in Firefox
http://localhost/dvwa
# Default credentials: admin / password
```

---

## Supply Chain Audit Demo (Module 5)

```bash
# Install pip-audit
pip3 install pip-audit --break-system-packages

# Scan the deliberately vulnerable requirements file
pip-audit -r requirements_vulnerable.txt

# Compare against the safe requirements file
pip-audit -r requirements.txt
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| BeEF won't start | Run `cd ~/beef && bundle install` then retry |
| ZAP certificate not trusted | Re-import the ZAP CA cert into Firefox |
| Juice Shop not accessible | `sudo systemctl restart juice-shop` |
| ShopCo app DB error | Delete `shop.db` and rerun `python3 vulnerable_shop.py` |
| RDP connection refused | Check port 3389 is unblocked with BBC IT support |

---

*For instructor support, contact your JBI Training course coordinator.*
