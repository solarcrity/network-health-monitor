# Installation Guide

## Linux (Ubuntu/Debian/Kali)

### Prerequisites
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git
```

### Clone & Setup

```bash
# Clone repository
git clone https://github.com/solarcrity/network-health-monitor.git
cd network-health-monitor

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run the Tool

```bash
# Make sure venv is activated
source venv/bin/activate

# Run with sudo (required for port monitoring)
sudo python3 network-health-monitor.py
```

## Features Tested On

- ✅ Ubuntu 20.04 LTS
- ✅ Ubuntu 22.04 LTS
- ✅ Debian 11
- ✅ Kali Linux 2024

## Troubleshooting

### Issue: "Command not found: netstat"
```bash
sudo apt install net-tools
```

### Issue: "Permission denied"
```bash
# Make sure to run with sudo
sudo python3 network-health-monitor.py
```

### Issue: "ModuleNotFoundError: No module named 'flask'"
```bash
# Activate virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

## What Gets Created

After first run:
- `data/connections.db` - SQLite database
- `logs/app.log` - Application logs

These are git-ignored (not uploaded to GitHub).

