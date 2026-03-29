# Cyber Threat Visualization Dashboard
### Modules 1 & 2 — Data Acquisition, Normalization & Core Visualizations

---

## Project Structure

```
cyber-threat-dashboard/
├── config/
│   ├── schema.py          # Pydantic models — ThreatEvent, CVEEvent, GeoLocation
│   ├── settings.py        # All env vars and constants
│   └── database.py        # MongoDB connection + all query helpers
│
├── ingestion/
│   ├── fetch_nvd.py        # Module 1 — NVD CVE feed (free, no key needed)
│   ├── fetch_otx.py        # Module 1 — AlienVault OTX threat pulses
│   ├── fetch_abuseipdb.py  # Module 1 — AbuseIPDB blacklist + GeoIP enrichment
│   ├── simulate_data.py    # Realistic simulated data (for dev/demo)
│   └── fetch_all.py        # Master orchestrator — runs all sources
│
├── visualizations/
│   ├── charts.py           # Module 2 — Time-series, bar, donut, heatmap
│   └── geo_charts.py       # Module 3 — Choropleth, scatter geo, treemap, sunburst
│
├── dashboard/
│   └── app.py              # Module 4 — Full Plotly/Dash dashboard
│
├── .github/workflows/
│   └── ingest.yml          # Free GitHub Actions cron (every 15 min)
│
├── requirements.txt
├── .env.example
└── README.md
```

---

## Quick Start (Local Dev — No API Keys Needed)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Set up environment
```bash
cp .env.example .env
# Edit .env — minimum needed for local dev:
#   MONGO_URI = your MongoDB Atlas connection string
#   Leave API keys blank — simulated data will be used
```

### 3. Generate simulated data (works without any API keys)
```bash
python ingestion/fetch_all.py --sim-only --sim-count 500
```

### 4. Launch dashboard
```bash
python dashboard/app.py
# Open http://localhost:8050
```

---

## With Real API Keys

### Get free API keys:
| Service | URL | Free Tier |
|---|---|---|
| AlienVault OTX | otx.alienvault.com | Unlimited reads |
| AbuseIPDB | abuseipdb.com | 1000 checks/day |
| NVD (optional) | nvd.nist.gov/developers | Removes rate limits |

### Run full ingestion:
```bash
python ingestion/fetch_all.py --sources nvd otx abuseipdb sim
```

### Run a specific source only:
```bash
python ingestion/fetch_nvd.py          # NVD CVEs only
python ingestion/fetch_otx.py          # OTX only
python ingestion/fetch_abuseipdb.py    # AbuseIPDB only
```

---

## Deploy to Render (Free)

### Step 1: Push to GitHub
```bash
git init && git add . && git commit -m "initial"
git remote add origin https://github.com/yourname/cyber-threat-dashboard
git push -u origin main
```

### Step 2: Deploy on Render
1. Go to render.com → New → Web Service
2. Connect your GitHub repo
3. Settings:
   - **Root Directory**: `dashboard/`
   - **Build Command**: `pip install -r ../requirements.txt`
   - **Start Command**: `gunicorn app:server -b 0.0.0.0:$PORT`
4. Add all env vars from `.env.example`

### Step 3: Set up GitHub Actions cron
1. Go to GitHub repo → Settings → Secrets → Actions
2. Add: `MONGO_URI`, `OTX_API_KEY`, `ABUSEIPDB_KEY`
3. The `.github/workflows/ingest.yml` runs automatically every 15 minutes ✓

---

## Architecture

```
[NVD API] [OTX API] [AbuseIPDB]
      ↓         ↓         ↓
   fetch_nvd  fetch_otx  fetch_abuseipdb
      ↓         ↓         ↓
   CVEEvent  ThreatEvent ThreatEvent
         ↓         ↓
       GeoEnricher (ip-api.com, free)
              ↓
       MongoDB Atlas (free M0)
              ↓
         database.py
    (aggregate queries for dashboard)
              ↓
    charts.py + geo_charts.py
    (Plotly figures, Module 2 + 3)
              ↓
          app.py (Dash)
       Module 4 Dashboard
```

---

## Key Design Decisions

**Why one ThreatEvent schema for all sources?**
Every API returns different fields. Normalizing into one Pydantic model means charts never need to know which source data came from — they just read `attack_type`, `severity_score`, `source_geo` etc. consistently.

**Why MongoDB over SQL?**
Threat events are JSON documents with nested geo objects. MongoDB stores and queries these natively. The aggregation pipeline handles all the groupby/count operations charts need.

**Why GitHub Actions for scheduling?**
Free, reliable, no extra server needed. 2000 minutes/month on free tier — running every 15 min uses ~1400 minutes/month.

**Why simulated data?**
Lets the whole team develop and demo the dashboard without needing API keys. The simulator generates statistically realistic attack distributions that exercise all chart types properly.
