# Log Sentinel 🔍

A cybersecurity log analysis dashboard with anomaly detection.

Built by Atena Hosseinifar · Toronto Metropolitan University · CS

## What it does

Log Sentinel parses server access logs, detects suspicious patterns (brute force attacks,
error spikes, off-hours traffic), scores threats by risk level, and displays everything
on an interactive dashboard.

## Tech Stack

- **Backend:** Python · Flask · pandas · scikit-learn
- **Frontend:** HTML/CSS/JS · Chart.js · Tailwind CSS
- **Data:** Apache/Nginx access logs (EDGAR dataset)

## Project Status

🔨 Day 1 of 38 — Environment setup complete

## Progress Log

| Day | What I built |
|-----|-------------|
| 1   | Dev environment, project structure, GitHub setup |

## How to run locally

```bash
git clone https://github.com/atenahfr/log-sentinel.git
cd log-sentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Live Demo

Coming soon.