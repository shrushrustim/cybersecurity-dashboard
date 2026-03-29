# Cloud Setup Guide
## Cyber Threat Visualization Dashboard

---

## What's Cloud vs What's Local

| File | Runs Where | Cloud Service |
|---|---|---|
| `ingestion/fetch_all.py` | GitHub Actions (cloud) | GitHub — free cron |
| `dashboard/app.py` | Render Service 1 (cloud) | Render — free PaaS |
| `ml_service/main.py` | Render Service 2 (cloud) | Render — free PaaS |
| `config/database.py` | Calls MongoDB Atlas (cloud) | MongoDB — free DBaaS |
| `config/cloud_client.py` | Runtime calls to Redis | Upstash — free Redis |
| `config/data_loader.py` | Used by dashboard | Cache layer for Redis |

---

## Step 1 — MongoDB Atlas (Free Database)

1. Go to **cloud.mongodb.com** → Create account
2. Create a **Free Shared Cluster** (M0 — 512MB)
3. Choose AWS → region closest to you
4. Create a database user (username + password)
5. Whitelist IP: `0.0.0.0/0` (allow all — needed for Render)
6. Get connection string:
   `mongodb+srv://<user>:<pass>@<cluster>.mongodb.net/cyber_threats`
7. Save this as `MONGO_URI`

---

## Step 2 — Upstash Redis (Free Cache)

1. Go to **upstash.com** → Create account
2. Create Database → Redis → Free tier
3. Copy the **Redis URL** (format: `redis://default:pass@host.upstash.io:6379`)
4. Save this as `REDIS_URL`

---

## Step 3 — Deploy to Render

### Connect your repo
1. Push your project to GitHub
2. Go to **render.com** → New → Blueprint
3. Connect your GitHub repo → it reads `render.yaml` automatically

### This deploys 2 services:
- `cyber-threat-ml-api` → your ML microservice
- `cyber-threat-dashboard` → your Dash app

### Set environment variables on Render
For EACH service, go to: Service → Environment → Add

```
MONGO_URI          = mongodb+srv://...   (your Atlas URI)
REDIS_URL          = redis://...          (your Upstash URL)
OTX_API_KEY        = ...                  (your OTX key)
ABUSEIPDB_KEY      = ...                  (your AbuseIPDB key)
ML_SERVICE_URL     = https://cyber-threat-ml-api.onrender.com
```

---

## Step 4 — GitHub Actions (Free Cron)

1. In your GitHub repo → Settings → Secrets → Actions
2. Add these secrets:
   - `MONGO_URI`
   - `OTX_API_KEY`
   - `ABUSEIPDB_KEY`
3. The file `.github/workflows/ingest.yml` runs automatically every 15 min ✓

---

## Step 5 — First Run Sequence

```bash
# 1. Seed your database with simulated data first (no API keys needed)
python ingestion/fetch_all.py --sim-only --sim-count 500

# 2. Check dashboard works locally
python dashboard/app.py
# open http://localhost:8050

# 3. Train ML models from the seeded data
python ml_service/trainer.py

# 4. Start the ML service locally to test it
uvicorn ml_service.main:app --port 8001
# test: http://localhost:8001/health
# test: http://localhost:8001/docs  (auto-generated Swagger UI)

# 5. Deploy everything to Render (just push to GitHub)
git add . && git commit -m "ready for cloud" && git push

# 6. On Render, after ML service is deployed, train models via API:
# POST https://cyber-threat-ml-api.onrender.com/model/train
```

---

## How Cloud Is Used in Each Module

### Module 1 — Data Acquisition
- **GitHub Actions** runs `fetch_all.py` every 15 minutes
- Data is written to **MongoDB Atlas** (cloud DB)
- GeoIP enrichment calls **ip-api.com** (external free API)

### Module 2 — Core Visualizations
- Dashboard callbacks call `data_loader.py`
- `data_loader.py` checks **Upstash Redis** first (cache)
- On cache miss → queries **MongoDB Atlas**
- Cache TTL: 25s for live events, 60s for aggregations

### Module 3 — Geospatial & Hierarchical
- Same cache layer as Module 2
- Geo coordinates already stored in MongoDB from enrichment step
- Choropleth/scatter maps rendered client-side by Plotly (no extra cloud needed)

### Module 4 — Dashboard + ML
- **Render Service 1**: hosts the Dash app (publicly accessible URL)
- **Render Service 2**: hosts the ML microservice
- Dashboard calls ML service via `cloud_client.ml_detect_anomalies()`
- Anomaly results are also cached in **Redis** for 120 seconds
- Trained model files stored in `ml_service/models/` on Render disk

---

## Architecture Diagram (Text)

```
[GitHub Actions — free cron]
         |
         | every 15 min
         ↓
[ingestion/fetch_all.py]
    ↓            ↓           ↓
[NVD API]  [OTX API]  [AbuseIPDB]
         \      |      /
          \     |     /
           ↓   ↓   ↓
         [GeoIP enrichment]
              ip-api.com
                 ↓
         [MongoDB Atlas]  ← DBaaS (free M0)
                 ↓
     ┌───────────────────────┐
     ↓                       ↓
[Upstash Redis]       [ML Microservice]
  cache layer           Render Service 2
  25–300s TTL         /predict /anomaly
     ↓                       ↓
     └───────────────────────┘
                 ↓
      [Plotly/Dash Dashboard]
         Render Service 1
      publicly accessible URL
```

---

## Free Tier Limits (Know These)

| Service | Free Limit | Your Usage |
|---|---|---|
| MongoDB Atlas M0 | 512MB storage | ~50MB for 50K events ✓ |
| Upstash Redis | 10K cmds/day, 30MB | ~500 cmds/day ✓ |
| Render Web Service | Sleeps after 15min inactivity | Wake time ~30s |
| GitHub Actions | 2000 min/month | ~1440 min/month ✓ |
| ip-api.com GeoIP | 45 req/min | Batched, stays under ✓ |
| AbuseIPDB | 1000 checks/day | Used for blacklist only ✓ |

---

## Viva Answer — "How is cloud computing used?"

> "Our system uses a cloud-native microservices architecture deployed entirely on free-tier PaaS providers.
> MongoDB Atlas serves as our managed DBaaS for storing normalized threat events.
> Upstash Redis provides a distributed cache layer that reduces dashboard latency by serving aggregated query results with TTLs between 25 and 300 seconds.
> The ML inference engine — serving anomaly detection and attack classification — is deployed as a separate FastAPI microservice on Render, following the microservices pattern.
> The main Plotly/Dash dashboard is a second independent service on Render, calling the ML service via REST.
> Data ingestion is fully automated using GitHub Actions as a serverless cron pipeline, fetching from NVD, AlienVault OTX, and AbuseIPDB every 15 minutes at zero infrastructure cost."
