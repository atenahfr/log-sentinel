# Log Sentinel 🔍
### Log Analysis Dashboard with Anomaly Detection

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-3.1-green)
![Status](https://img.shields.io/badge/Status-In%20Progress-orange)

A cybersecurity tool that parses server access logs, detects suspicious patterns, scores threats by risk level, and displays everything on an interactive dashboard.

Built by **Atena Hosseinifar** · Toronto Metropolitan University · CS 

---

## What it detects

- 🔴 **Brute force attacks** — repeated failed login attempts from the same IP
- 🟠 **Directory scanning** — IPs probing for hidden pages like `/admin`, `/.env`, `/config.php`
- 🟡 **Error spikes** — unusual surges in 404 or 500 errors
- 🔵 **Off-hours traffic** — suspicious requests at 2am–4am from unknown IPs

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Flask 3.1, pandas, scikit-learn |
| Frontend | HTML/CSS/JS, Chart.js, Tailwind CSS |
| Data | Apache access log format |
| Deployment | Render (backend), GitHub Pages (frontend) |

---

## Project Structure
```
log-sentinel/
├── backend/
│   ├── parser.py      # Parses raw log files into structured data
│   ├── detector.py    # Anomaly detection logic
│   ├── scorer.py      # Risk scoring system
│   ├── report.py      # Report generation
│   └── app.py         # Flask API
├── frontend/          # Dashboard (HTML/CSS/JS)
├── tests/             # Unit tests
└── data/              # Log files (gitignored)
```

## How to run locally

```bash
git clone https://github.com/atenahfr/log-sentinel.git
cd log-sentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 backend/app.py
```

---

## Progress Log

| Day | What I built |
|-----|-------------|
| 1 | Dev environment, project structure, GitHub setup |
| 2 | Studied Apache log format, created sample log file |
| 3 | Log parser with regex — extracts IP, timestamp, method, path, status, bytes |
| 4 | Loaded logs into pandas DataFrame, exploratory data analysis |
| 5 | Clean README, requirements.txt, documentation habits |



## Live Demo
Coming soon...

---

## Future improvements
- ML-based anomaly detection with Isolation Forest
- Real-time log streaming with WebSockets
- SQLite database for analysis history
- SSH auth.log support