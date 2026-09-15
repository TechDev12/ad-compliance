<div align="center">

# 🛡️ AD Compliance Reporter

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&pause=1000&color=00A4EF&center=true&vCenter=true&width=600&lines=Audit+Active+Directory+in+seconds;CIS+%7C+NIST+%7C+SOX+%7C+GDPR+%7C+HIPAA;Interactive+HTML+Compliance+Reports)](https://git.io/typing-svg)

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server-0078D6?logo=windows&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active%20Directory-Domain%20Services-00A4EF?logo=microsoft&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

</div>

---

## 📋 Overview

**AD Compliance Reporter** (`.\ad-compliance.ps1`) is a PowerShell script that audits your Active Directory environment against real-world security benchmarks and generates a single, self-contained, interactive **HTML report**.

It answers three questions for any AD administrator, auditor, or security team:

1. **How compliant is my domain** against CIS, NIST, SOX, GDPR, and HIPAA baseline controls?
2. **Who are my users**, when did they last log on, and when do their passwords expire?
3. **Where is my risk concentrated**, at a glance, with visual gauges and a risk score?

No agents, no external services, no data leaves your domain controller — everything runs locally and outputs a portable HTML file you can open in any browser.

---

## ✨ Features

- ✅ **Multi-framework compliance checks** — CIS, NIST, SOX, GDPR, and HIPAA baseline controls evaluated automatically
- 📊 **Interactive Google Charts gauges** — per-framework compliance gauges plus an overall risk bar chart
- 🔍 **Filterable results table** — filter findings live by framework (CIS/NIST/SOX/GDPR/HIPAA) or by result (Compliant/Non-Compliant)
- 👥 **AD user enumeration** — domain-wide last-logon tracking (aggregated across all domain controllers) and password-expiry status per user
- 🔐 **Password policy insights** — surfaces domain password complexity, lockout, history, and age settings
- 🏢 **Domain stats snapshot** — total users, groups, disabled accounts, and Domain Admins at a glance
- 🖼️ **Brandable output** — drop in your own `Logo.jpg` and a custom signature/footer link
- 📦 **Single-file HTML output** — easy to share, archive, or attach to an audit ticket

---

## 🧪 What Gets Checked

| Framework | Example Controls |
|-----------|-------------------|
| **CIS** | Account lockout duration/threshold, password minimum length & history, maximum/minimum password age, delegation restrictions, network access rights |
| **NIST** | Security audit log retention, Windows Firewall domain profile, LSA audit settings |
| **SOX** | Logon event auditing enabled |
| **GDPR** | Privileged account (AdminCount) sprawl, data encryption policy enforcement |
| **HIPAA** | Audit controls (logon auditing), access control enforcement via privileged account counts |

Each check links out to its authoritative reference documentation directly from the report table.

---

## 🚀 Getting Started

### Prerequisites

- Windows Server with the **Active Directory PowerShell module** (`RSAT-AD-PowerShell`) and **Group Policy module** installed
- **Administrative privileges** on the domain — required for all metrics to resolve correctly
- PowerShell 5.1 or later

### Installation

```powershell
git clone https://github.com/TechDev12/ad-compliance.git
cd ad-compliance
```

*(Optional)* Drop a `Logo.jpg` file into the script's directory to have your organization's logo appear in the report header.

### Usage

Run the script from an elevated PowerShell session on (or with access to) your domain controller:

```powershell
.\ad-compliance.ps1 -dchostname "DC01.yourdomain.com" -domain "yourdomain.com" -signature_url "yourcompany.com"
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-dchostname` | ✅ | Hostname of the domain controller to query |
| `-domain` | ✅ | Your domain name, shown in the report title |
| `-signature_url` | ✅ | Text/URL shown in the report footer (e.g., your company name or site) |

Once complete, the script prints the report path:

```
Report generated at: C:\path\to\ad-compliance\Report.html
```

Open `Report.html` in any browser to view your results.

---

## 📈 Report Preview

The generated report includes:

- 5 compliance gauges (CIS / NIST / SOX / GDPR / HIPAA)
- An overall risk score bar chart (Low / Medium / High, color-coded)
- A domain statistics table
- A filterable, sortable compliance findings table
- A full AD user report with last-logon dates and password-expiry status

---

## 🤝 Contributing

Issues and pull requests are welcome — whether it's a new benchmark control, a bug fix, or a report styling improvement.

---

<div align="center">

Made with ❤️ for AD administrators who'd rather automate the audit than dread it.

</div>
