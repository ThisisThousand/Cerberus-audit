# 🐕 Cerberus-audit

> **Lightweight multi-platform CLI tool for auditing network connections and NPM dependencies, focused on security analysis, visibility, and threat detection.**

---

## 🚀 Overview

**Cerberus-audit** is a hybrid security auditing tool designed to provide deep visibility into:

* 🌐 System network connections
* 📦 NPM dependencies and supply chain risks

It helps developers and security enthusiasts detect:

* Suspicious network activity
* Vulnerable or outdated packages
* Malicious dependencies
* Dangerous scripts inside `package.json`

---

## 🧠 Key Features

### 🔍 Network Auditing

* Cross-platform support (Windows, Linux, macOS)
* Real-time connection inspection
* Process-level visibility (PID, command line, user)
* External vs private IP classification
* Unusual port detection
* Optional IP geolocation
* VirusTotal integration (optional)

---

### 📦 NPM Security Analysis

* Detects vulnerabilities (`npm audit`)
* Finds outdated packages
* Identifies known malicious packages
* Scans for suspicious scripts (e.g. `curl | bash`)
* Shows global and local package paths
* Lists globally installed packages

---

### 🖥️ Interactive CLI

* Command-based interface
* English / Spanish support
* Rich terminal UI (optional)
* Export reports to file

---

## ⚙️ Installation

```bash
git clone https://github.com/ThisisThousand/Cerberus-audit.git
cd Cerberus-audit
python main.py
```

---

## ⚠️ Requirements

* Python 3.8+
* (Optional) `npm` installed for dependency auditing
* (Optional) Administrator / root privileges for full network visibility

---

## 🔐 Usage

Run the tool:

```bash
python main.py
```

---

## 🧾 Commands

### 🌐 Network

```bash
list                    # Show all connections
list <pid>             # Filter by process ID
list external          # External connections only
list private           # Private network connections

process <pid>          # Process details
ipinfo <ip>            # IP geolocation + VirusTotal (optional)

summary                # General statistics
export report.txt      # Save report
```

---

### 📦 NPM

```bash
npm                    # Audit current directory
npm <path>             # Audit specific project

npm root               # Show npm roots
npm global             # List global packages
npm path <package>     # Find package location
```

---

## 🧪 Example

```bash
>> list external
>> process 1234
>> npm .
>> summary
```

---

## 🛡️ Security Focus

Cerberus-audit combines:

* **Host-level monitoring** (network activity)
* **Supply chain analysis** (dependencies)

This makes it useful for:

* Developers
* Security learners
* Pentesters (basic recon)
* Blue team / defensive analysis

---

## 🔑 Optional Configuration

Edit `.env` to enable:

```env
VT_API_KEY=your_virustotal_api_key
```

---

## 📁 Project Structure

```
Cerberus-audit/
│
├── core/               # Core logic
│   ├── network_logic.py
│   ├── platform_utils.py
│   └── constants.py
│
├── modules/            # Feature modules
│   ├── npm_auditor.py
│   └── external_api.py
│
├── main.py             # Entry point
└── .env
```

---

## 🚧 Future Improvements

* Web dashboard (optional UI)
* Real-time monitoring mode
* Alerts for suspicious behavior
* Plugin system
* More package managers (pip, etc.)

---

## 🤝 Contributing

Pull requests are welcome.
If you find bugs or want new features, open an issue.

---

## 📜 License

MIT License

---

> *Focused on security, automation, and building real-world tools.*
