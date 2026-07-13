# Log Sentinel 
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
---

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


## API Endpoints

Base URL (local): `http://127.0.0.1:5000`

### GET /api/health
Verify the server is running.

**Response:**
```json
{
  "status": "ok",
  "message": "Log Sentinel API is running"
}
```

### POST /api/analyze
Upload a log file and run the full analysis pipeline.

**Request:** multipart/form-data with field `file` (.log or .txt, max 16MB)

**Response:** complete analysis report including summary, anomalies, timeline, and scores.

**Errors:**
- `400` — missing file, empty file, or wrong file type
- `413` — file exceeds 16MB
- `422` — file is correct type but not valid log format
- `500` — unexpected server error

### GET /api/summary
Returns summary stats from the last analysis.

**Response:**
```json
{
  "total_requests": 360,
  "unique_ips": 6,
  "total_anomalies": 5,
  "overall_risk": 240,
  "time_range_start": "2024-05-15 02:00:00+00:00",
  "time_range_end": "2024-05-15 17:58:23+00:00"
}
```

### GET /api/anomalies
Returns all flagged anomalies sorted by risk score.

**Response:** anomaly_counts, all_scores, top_offenders

### GET /api/timeline
Returns requests-per-hour data for the timeline chart.

**Response:**
```json
{
  "timeline": [
    {"hour": 2, "count": 40},
    {"hour": 3, "count": 25}
  ]
}
```


## Live Demo

🌐 **Frontend:** https://atenahfr.github.io/log-sentinel/frontend/index.html  
⚙️ **Backend API:** https://log-sentinel-bgd7.onrender.com/api/health

---

## Future improvements
- ML-based anomaly detection with Isolation Forest
- Real-time log streaming with WebSockets
- SQLite database for analysis history
- SSH auth.log support