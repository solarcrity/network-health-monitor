# Network Health Monitor 🌐

**Real-time network connection monitoring tool for Linux systems**

A professional security tool that monitors active network connections, detects suspicious activity, and alerts on unauthorized port access. Built for system administrators, security auditors, and DevSecOps engineers.

---

## ✨ Features

- **Real-time Connection Monitoring** - Captures active connections every 5 seconds
- **Suspicious Port Detection** - Alerts on dangerous ports (SSH, RDP, SMB)
- **Unknown IP Detection** - Flags new/unexpected connections
- **Live Statistics Dashboard** - Total connections, alerts, unique IPs
- **Color-coded Terminal UI** - Professional Kali-style ASCII interface
- **Persistent Database** - SQLite storage of connections and alerts
- **Structured Logging** - Audit trail in `logs/app.log`
- **Graceful Shutdown** - Clean exit on Ctrl+C

---

## 🚀 Quick Start

\`\`\`bash
# Clone
git clone https://github.com/solarcrity/network-health-monitor.git
cd network-health-monitor

# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run
sudo python3 network-health-monitor.py
\`\`\`

See [INSTALL.md](INSTALL.md) for detailed setup.

---

## 🎯 Use Cases

- **System Admin** - Detect unauthorized services
- **Security Auditor** - Real-time monitoring during assessments
- **DevSecOps** - Catch misconfigured services before deployment
- **Incident Response** - Investigate historical connection data
- **Security Student** - Learn network monitoring & threat detection

---

## 📊 How It Works

1. **Capture** - Executes `netstat -tuln` every 5 seconds
2. **Analyze** - Detects suspicious ports and new IPs
3. **Alert** - Generates warnings for risky activity
4. **Display** - Shows real-time dashboard in terminal
5. **Log** - Stores data in SQLite for audit trail

---

## 🔐 Suspicious Ports

| Port | Service | Risk |
|---|---|---|
| 22 | SSH | 🔴 Critical |
| 445 | SMB | 🔴 Critical |
| 3389 | RDP | 🔴 Critical |

---

## 📁 Files

- **network-health-monitor.py** - Main application
- **monitor.py** - Monitoring engine
- **config.py** - Configuration settings
- **requirements.txt** - Python dependencies
- **INSTALL.md** - Installation guide
- **CONTRIBUTING.md** - How to contribute

---

## 📜 License

MIT License - See LICENSE file

---

## 👤 Author

Arceus - Security Tools Portfolio

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to help!
