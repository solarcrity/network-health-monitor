# Contributing to Network Health Monitor

We welcome contributions! This project is great for learning security monitoring.

## Feature Ideas

Help improve the tool with these features:

- [ ] **IP Geolocation** - Show where connections are from
- [ ] **Email Alerts** - Send critical alerts via email
- [ ] **Slack Integration** - Post alerts to Slack channel
- [ ] **Export Reports** - Save data as JSON/CSV
- [ ] **Web Dashboard** - Add web UI alternative
- [ ] **Threat Intelligence** - Integrate with IP reputation APIs
- [ ] **Docker Support** - Package as Docker container
- [ ] **Performance Metrics** - Track memory/CPU usage
- [ ] **Configuration UI** - Interactive setup wizard
- [ ] **Database Viewer** - Command to query historical data

## How to Contribute

### 1. Fork the Repository
Click "Fork" on GitHub to create your copy

### 2. Clone Your Fork
```bash
git clone https://github.com/YOUR_USERNAME/network-health-monitor.git
cd network-health-monitor
```

### 3. Create Feature Branch
```bash
git checkout -b feature/your-feature-name
```

Good branch names:
- `feature/email-alerts`
- `feature/ip-geolocation`
- `bugfix/connection-parsing`

### 4. Make Your Changes
Edit files, test thoroughly

### 5. Commit Changes
```bash
git add .
git commit -m "Add email alert feature

- Sends critical alerts via SMTP
- Configurable in config.py
- Tested on Gmail and Outlook"
```

### 6. Push to Your Fork
```bash
git push origin feature/your-feature-name
```

### 7. Create Pull Request
On GitHub, click "Compare & pull request"

## Code Style

### Python Code
- Use clear variable names
- Add comments for complex logic
- Follow PEP 8 guidelines
- Handle errors gracefully

### Example:
```python
def detect_suspicious_activity(connections):
    """
    Analyze connections for suspicious activity
    
    Args:
        connections: List of connection dictionaries
        
    Returns:
        List of alert dictionaries
    """
    alerts = []
    
    for conn in connections:
        if conn['port'] in SUSPICIOUS_PORTS:
            alerts.append({
                'type': 'SUSPICIOUS_PORT',
                'severity': 'WARNING'
            })
    
    return alerts
```

## Testing

Before submitting PR:

1. Test on Linux system
2. Verify no errors in logs/app.log
3. Check database integrity
4. Test with various scenarios

## Questions?

- Open an Issue on GitHub
- Ask in Pull Request comments
- Check existing issues first

## License

By contributing, you agree your code will be MIT licensed.

---

**Thank you for helping make this tool better!** 🙏
