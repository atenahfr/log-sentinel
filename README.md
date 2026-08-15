# Log Sentinel 🔍

> A cybersecurity log analysis dashboard that detects brute force attacks, directory scanning, error spikes, and off-hours traffic — with plain-English explanations for every threat.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.1-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Live-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

**[🚀 Live Demo](https://atenahfr.github.io/log-sentinel/frontend/index.html)** · **[⚙️ API](https://log-sentinel-bgd7.onrender.com/api/health)** · Built by [Atena Hosseinifar](https://github.com/atenahfr) · TMU CS Year 3

---

## What it does

Log Sentinel parses Apache/Nginx server access logs and automatically detects four categories of suspicious behavior:

| Threat Type | Detection Logic | Risk Score |
|-------------|----------------|------------|
| 🔴 Brute Force | Same IP with 10+ failed logins | 80 pts |
| 🟠 Directory Scanning | Same IP with 10+ 404 errors | 40 pts |
| 🟡 Server Error Spike | Same IP causing 5+ 500 errors | 60 pts |
| 🔵 Off-Hours Traffic | Any activity between midnight–6am | 30 pts |

Every flagged event gets a **risk score**, a **severity label** (Critical/High/Medium/Low), and a **plain-English explanation** — making it readable by non-technical stakeholders, not just security engineers.

---

## What makes it different

Most log analysis tools tell you *what* was flagged. Log Sentinel tells you *why* in plain English:

> *"This IP made 40 failed login attempts on /login. Normal users fail 1-2 times at most. This volume strongly suggests an automated brute force attack."*

This explainability layer is what separates Log Sentinel from a basic data project and pushes it toward real SIEM territory.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Flask 3.1, pandas, scikit-learn |
| Frontend | HTML/CSS/JS, Tailwind CSS, Chart.js |
| Detection | Rule-based anomaly detection with statistical thresholds |
| Deployment | Render (backend), GitHub Pages (frontend) |

---

## Project Structure
```
log-sentinel/
├── backend/
│   ├── parser.py      # Regex-based Apache log parser
│   ├── detector.py    # Four anomaly detectors with auto-generated explanations
│   ├── scorer.py      # Risk scoring and severity labeling
│   ├── report.py      # Unified analysis pipeline
│   └── app.py         # Flask REST API (5 endpoints)
├── frontend/
│   └── index.html     # Single-page dashboard with terminal aesthetic
├── tests/
│   └── test_detector.py  # 7 unit tests
└── data/              # Log files (gitignored)
```
---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Server status check |
| POST | `/api/analyze` | Upload and analyze a log file |
| GET | `/api/summary` | Summary stats from last analysis |
| GET | `/api/anomalies` | All flagged events sorted by risk score |
| GET | `/api/timeline` | Requests-per-hour data |
| GET | `/api/demo` | Run analysis on built-in sample data |

---

## How to run locally

```bash
git clone https://github.com/atenahfr/log-sentinel.git
cd log-sentinel

# Backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 backend/app.py

# Frontend (in a new terminal)
python3 -m http.server 8080
# Open http://localhost:8080/frontend/index.html
```

---

## Running tests

```bash
python3 -m unittest tests/test_detector.py -v
# 7 tests, all passing
```

---

## What I learned

- How Apache access logs are structured and what each field means
- How to build rule-based anomaly detectors with configurable thresholds
- How to design a risk scoring system that stacks across multiple anomaly types
- How pandas DataFrames enable fast log analysis without loops
- How to build and deploy a Flask REST API with proper error handling
- How CORS works and why it matters for frontend/backend separation
- What makes a security tool explainable vs just functional

---

## Blog Posts

📝 [How I Built a Log Analysis Tool to Detect Network Anomalies](https://dev.to/atenahfr/how-i-built-a-log-analysis-tool-to-detect-network-anomalies-45ed) — dev.to · Phase 1

📝 [I Added ML Anomaly Detection to My Cybersecurity Tool — Here's What the Numbers Actually Showed](https://dev.to/atenahfr/i-added-ml-anamoly-detection-to-my-cybersecurity-tool-heres-what-the-numbers-actually-showed-4jpp) — dev.to · Phase 2

---

## ML Upgrade — Isolation Forest Detection

Log Sentinel's second phase adds a machine learning layer on top of the rule-based detectors.

### Model
- **Algorithm:** Isolation Forest (scikit-learn)
- **Type:** Unsupervised anomaly detection
- **Parameters:** `n_estimators=100`, `contamination=0.15`, `random_state=42`

### Feature Engineering
Each IP address is transformed into a 5-feature behavioral vector before being passed to the model:

| Feature | Description |
|---------|-------------|
| `request_count` | Total number of requests made |
| `error_rate` | Fraction of requests returning 4xx or 5xx status codes |
| `unique_paths` | Number of distinct URLs visited |
| `night_traffic_ratio` | Fraction of requests made between midnight and 6am |
| `avg_bytes` | Average response size in bytes |

All features are normalized using `StandardScaler` (mean=0, std=1) before model training.

### Evaluation Results
Evaluated on a labeled dataset of 230 IPs (200 normal, 30 attackers):

| Metric | Rule-Based | Isolation Forest |
|--------|-----------|-----------------|
| Precision | **1.0000** | 0.8571 |
| Recall | **1.0000** | **1.0000** |
| F1 Score | **1.0000** | 0.9231 |
| True Positives | 30 | 30 |
| False Positives | 0 | 5 |
| False Negatives | 0 | 0 |

### Key Finding
Rule-based detectors achieved perfect scores because the dataset contains well-defined, structured attack patterns that exactly match the detection rules. The Isolation Forest caught all 30 attackers (recall=1.0) but generated 5 false positives (precision=0.857), resulting in F1=0.923.

This is a known tradeoff: **rule-based systems excel on known attack signatures; ML generalizes better to unknown patterns**. In production, both layers running in parallel provides the strongest coverage.

### New Files
- `backend/features.py` — feature engineering (5 behavioral features per IP)
- `backend/ml_detector.py` — Isolation Forest model with explanation generation
- `backend/labeled_generator.py` — synthetic labeled dataset generator
- `backend/evaluate.py` — precision/recall/F1 evaluation framework
- `backend/plot_confusion.py` — confusion matrix visualization

---

## Future improvements

- [ ] Real-time log streaming with WebSockets
- [ ] SQLite database for analysis history across sessions
- [ ] SSH auth.log format support
- [ ] IP geolocation enrichment on flagged addresses

---

## Live Demo

🌐 **Frontend:** https://atenahfr.github.io/log-sentinel/frontend/index.html
⚙️ **Backend API:** https://log-sentinel-bgd7.onrender.com/api/health

*Note: The free Render instance spins down after inactivity — first request may take 30 seconds to wake up.*