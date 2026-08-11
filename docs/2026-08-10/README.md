# Course Materials — 10–11 August 2026

**Secure Web Application Development and Testing**
BBC Academy / JBI Training · OWASP Top 10:2025

These are the materials as delivered to the 10–11 August 2026 cohort. The
contents of this folder are frozen — later runs get their own dated folder,
so this link stays stable.

---

## Day 1

| File | Module | Covers |
|---|---|---|
| `Course_Outline.pdf` | — | Module sequence and timings |
| `WebAppSec_Module_02_Activities.pdf` | 2 | Client-side technologies, Firefox Developer Tools, ZAP proxy and CA trust |
| `WebAppSec_Module_03_Information_Security_and_Cybersecurity_Fundamentals.pdf` | 3 | CIA triad, threat/vulnerability/exploit/incident, BeEF browser hooking |
| `WebAppSec_Module_04_OWASP_2021_to_2025_Transition_Summary.pdf` | 4 | What changed between the 2021 and 2025 Top 10, and why |
| `WebAppSec_Module_05_OWASP_A01_..._Worksheet.pdf` | 5 | A01 Broken Access Control · A07 Identification and Authentication Failures |
| `WebAppSec_Module_06_OWASP_A05_Injection_Worksheet.pdf` | 6 | A05 Injection — SQLi, XSS, SSRF |

## Day 2

| File | Module | Covers |
|---|---|---|
| `WebAppSec_Module_07_SSDLC_and_Supporting_Tools_Worksheet.pdf` | 7 | SSDLC, ShopCo introduction, OWASP Bingo, pip-audit supply chain demo |
| `WebAppSec_Module_08_OWASP_A02_..._Worksheet.pdf` | 8 | A02 Security Misconfiguration · A03 Software Supply Chain Failures |
| `WebAppSec_Module_09_OWASP_A04_..._Worksheet.pdf` | 9 | A04 Cryptographic Failures · A08 Software and Data Integrity Failures |
| `WebAppSec_Module_09_OWASP_A04_..._Reference_Card.pdf` | 9 | Companion reference card |
| `WebAppSec_Module_10_OWASP_A06_..._Worksheet.pdf` | 10 | A06 Insecure Design · A10 Mishandling of Exceptional Conditions |
| `WebAppSec_Module_10_..._Malformed_Inputs_Supplement.pdf` | 10 | Malformed input handling |
| `WebAppSec_Module_11_OWASP_A09_..._Worksheet.pdf` | 11 | A09 Logging and Alerting Failures |
| `WebAppSec_Module_11_OWASP_A09_..._Reference_Card.pdf` | 11 | Log quality reference card |

## Across both days

| File | Covers |
|---|---|
| `WebAppSec_Modules_05_to_11_Flask_ShopCo_Remediation_Reference.pdf` | All eight ShopCo fixes — vulnerable and fixed code side by side, cross-language equivalents for Java, Node.js, C#, PHP and Go, CWE/CAPEC/ATT&CK references, and detection patterns for each vulnerability class |

---

## Three things worth doing this week

1. Run `pip-audit` (or the equivalent for your stack) against a repository you
   actually own, and triage what comes back.
2. Grade one of your team's services at https://securityheaders.com and work
   out which missing header matters most.
3. Pick one endpoint you wrote and ask the A01 question of it: *what stops a
   user supplying an identifier that isn't theirs?*

## Continuing further

- **OWASP Juice Shop companion guide** — https://pwning.owasp-juice.shop
- **PortSwigger Web Security Academy** — https://portswigger.net/web-security
- **OWASP Cheat Sheet Series** — https://cheatsheetseries.owasp.org
- **OWASP Top 10:2025** — https://owasp.org/Top10/

---

Questions after the course: contact JBI Training, or reach the instructor
via ProteQC.
