# NetScan — Metadata-Only Network Intrusion Detection System

A **near real-time, metadata-only NIDS** for campus / corporate networks on **Linux (Debian/Kali/Ubuntu)**.  
Captures flows every 5–10 s, extracts per-device features, runs **rule-based + unsupervised ML anomaly detection**, optionally escalates to **Google Gemini** for semantic classification, and surfaces results through a **web dashboard + notifications**.

> **Privacy first:** Only packet headers (IPs, ports, timestamps, sizes) are analysed — **no payload data is captured or stored**.

---

## Architecture

```
Capture Layer ──► Feature Extraction ──► Hybrid Detection ──► AI Reasoner (Gemini)
     │                                        │                      │
     └────────── Database ◄───────────────────┴──────────────────────┘
                    │
              Admin Dashboard  ◄──  Alerts  ──►  Email / Telegram
```

| Component | Location | Purpose |
|-----------|----------|---------|
| **Capture** | `app/capture/` | Scapy + libpcap, groups packets into flows |
| **Features** | `app/features/` | Per-device feature vectors (sliding window) |
| **Detection** | `app/detection/` | Rule engine + IsolationForest ML, hybrid scoring |
| **AI Reasoner** | `app/ai_reasoner/` | Gemini API integration for uncertain detections |
| **Alerts** | `app/alerts/` | Persistence, console / email / Telegram notifications |
| **API & Dashboard** | `app/api/` + `templates/` | FastAPI + Bootstrap/Chart.js admin UI |
| **Database** | `app/db/` | SQLAlchemy models (SQLite dev / Postgres prod) |
| **Blocking** | `app/blocking/` | nftables/iptables IP blocking + /etc/hosts domain blocking |
| **Config** | `config/` | YAML configs for rules, thresholds, Gemini, logging |

---

## Quick Start (Linux / Debian / Kali)

### 1. Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev nftables iproute2
```

### 2. Automated Setup

```bash
git clone https://github.com/Desapphire/netscan.git
cd netscan
bash install_linux.sh
```

The script will:
- Install system packages (`libpcap-dev`, `nftables`)
- Create a Python virtual environment
- Install all Python dependencies
- Initialise the SQLite database
- Print the detected default network interface

### 3. Start the Dashboard Only

```bash
source venv/bin/activate
python3 cli.py api
```

Open **http://localhost:8000** in your browser.

### 4. Start Live Capture + Dashboard (requires root)

```bash
# Auto-detects your physical interface (eth0, enp3s0, wlan0, etc.)
sudo venv/bin/python3 cli.py live

# Or specify interface explicitly:
sudo venv/bin/python3 cli.py live --interface eth0
```

Every ~5 s a window of traffic is analysed and alerts appear in the console and dashboard.

### 5. Non-Root Capture (capability grant)

If you prefer not to run the full process as root, grant raw socket capabilities to Python:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(pwd)/venv/bin/python3
# Then run without sudo:
venv/bin/python3 cli.py live --interface eth0
```

> **Note:** `setcap` is reset when Python is updated. Re-run after upgrades.  
> IP blocking (iptables/nftables) still requires root or `CAP_NET_ADMIN`.

### 6. Capture Only (no dashboard)

```bash
sudo venv/bin/python3 cli.py capture --interface eth0
```

---

## Run as a systemd Service

```bash
# Copy service file and adjust path
sudo cp netscan.service /etc/systemd/system/
sudo sed -i "s|/opt/netscan|$(pwd)|g" /etc/systemd/system/netscan.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now netscan

# View logs
sudo journalctl -u netscan -f
```

---

## Configuration

All tunable parameters are in `config/app_config.yaml`:

| Key | Default | Description |
|-----|---------|-------------|
| `app.window_seconds` | 5 | Analysis window length |
| `app.slide_seconds` | 3 | Window slide interval |
| `app.default_interface` | `eth0` | Default capture interface |
| `detection.rule_weight` | 0.70 | Weight of rule score in hybrid |
| `detection.ml_weight` | 0.30 | Weight of ML score in hybrid |
| `detection.block_threshold` | 0.75 | Risk ≥ this → block decision |
| `detection.alert_threshold` | 0.40 | Risk ≥ this → alert decision |
| `detection.ai_review_low/high` | 0.40 / 0.74 | Gray-zone → escalate to Gemini |
| `gemini.enabled` | false | Enable Gemini AI reasoning |
| `gemini.model` | gemini-2.0-flash | Gemini model to call |

### Enable Gemini

1. Set `gemini.enabled: true` in `config/app_config.yaml`.
2. Export your API key: `export GEMINI_API_KEY=<your-key>`.

### Rules

Edit `config/rules.yaml` to add/modify VPN ports, torrent ports, restricted domain keywords, and fan-out thresholds.

---

## Firewall / IP Blocking

NetScan automatically blocks high-risk IPs and domains:

| Backend | Used when |
|---------|-----------|
| **nftables** | `nft` binary found (Debian 12+, Kali) — preferred |
| **iptables** | fallback on older kernels |
| **/etc/hosts** | domain-level blocking (CDN-backed sites like gambling, VPN portals) |

Blocking requires **root** or `CAP_NET_ADMIN`. Detection and alerting work without root.

View blocked IPs in the dashboard at `/blocked` or via the API at `/blocked-ips`.

---

## ML Model Training

1. Capture several hours of **normal** traffic.
2. Run the training command:
   ```bash
   sudo venv/bin/python3 cli.py train
   ```
3. The script trains an `IsolationForest` and saves it to `models/isolation_forest.pkl`.
4. The pipeline will automatically load the new model on restart.

Alternatively, explore data using the notebook at `models/train_notebook.ipynb`.

See `models/ml_config.yaml` for hyperparameters.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard (HTML) |
| `GET` | `/health` | System health check |
| `GET` | `/alerts` | List alerts (JSON), filterable by `status`, `severity`, `src_ip` |
| `GET` | `/alerts/stats` | Aggregate alert statistics |
| `GET` | `/alerts/{id}` | Alert detail with detection scores + AI assessment |
| `PATCH` | `/alerts/{id}` | Update alert status (`open` → `acknowledged` → `resolved`) |
| `GET` | `/alert/{id}` | Alert detail page (HTML) |
| `GET` | `/devices` | List tracked devices |
| `GET` | `/devices/{ip}` | Device detail with recent detections & alerts |
| `GET` | `/devices/summary/all` | Per-device risk summary |
| `GET` | `/blocked-ips` | List of currently blocked IPs |
| `POST` | `/unblock/{ip}` | Manually unblock an IP |

---

## Testing

```bash
source venv/bin/activate
pytest tests/ -v
```

Tests cover capture parsing, feature extraction, rule engine, ML scoring, AI reasoner (mocked), and API endpoints.

---

## Database Schema

| Table | Purpose |
|-------|---------|
| `devices` | Known IPs, MACs, hostnames, owners |
| `network_features` | Per-device per-window feature snapshots |
| `detections` | Rule + ML scores, decisions |
| `ai_assessments` | Gemini responses (threat type, severity, explanation) |
| `alerts` | Admin-facing alerts with status lifecycle |
| `blocked_ips` | IP blocking history (auto + manual) |

See `app/db/schema.sql` for the full DDL.

---

## Project Structure

```
netscan/
  app/
    config.py                   # AppConfig loader
    capture/                    # Packet capture & flow aggregation (Scapy/libpcap)
    features/                   # Feature extraction & sliding window
    detection/                  # Rules + ML + hybrid detector
    ai_reasoner/                # Gemini API client & prompt builder
    alerts/                     # Alert manager & notifier
    api/                        # FastAPI routes & dashboard
    blocking/                   # nftables/iptables IP blocking + hosts file domain blocking
    db/                         # SQLAlchemy models & session
    utils/                      # Logging, time, IP, config helpers
  templates/                    # Jinja2 HTML templates
  static/                       # CSS / JS assets
  models/                       # Trained ML models & notebook
  tests/                        # pytest test suite
  config/                       # YAML configuration files
  install_linux.sh              # One-shot Debian/Kali setup script
  netscan.service               # systemd service unit
  requirements.txt
  README.md
```

---

## Windows Support

NetScan is now Linux-first. Windows is **not officially supported**.

If you need to run on Windows:
- Install [Npcap](https://npcap.com/) for raw packet capture.
- Firewall blocking via PowerShell/`netsh` is not implemented — alerts and detection still work.
- Run in a WSL2 environment for best compatibility.

---

## License

MIT — see individual file headers for details.