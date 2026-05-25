# PILA Suite — Installation Guide

> **© 2026 ByTE X Bit Technologies LLC — Patent Pending**
> Community Edition · Apache 2.0

---

## Requirements

| Component | Minimum Version | Notes |
|-----------|----------------|-------|
| Python | 3.11+ | Required |
| Elasticsearch | 8.x | With HTTPS enabled |
| Filebeat | 8.x | Shipping Suricata alerts to ES |
| Suricata | 6.x+ | Running in IDS mode, writing eve.json |
| Linux OS | Ubuntu 22.04 / 24.04 or Debian 12 | Bare metal, VM, or LXC |
| RAM | 1GB minimum | 2GB recommended |
| Disk | 4GB minimum | For platform files and engagement data |

**Optional but recommended:**
- Zeek 5.x+ — adds network connection-level visibility
- Wazuh 4.x — adds HIDS endpoint alerts
- Winlogbeat 8.x+ — adds Windows Event Log data
- Elastic Security — adds pre-built ATT&CK-mapped detection rules

---

## Network Placement

PILA Suite is a **central server component** — not an endpoint agent. Deploy it on one Linux host with network access to your Elasticsearch instance.

```
Your network
├── Endpoints (Windows/Linux hosts)
│   └── Wazuh agents + Winlogbeat → ship data to Elasticsearch
├── Network monitoring
│   └── Suricata + Zeek → ship via Filebeat → Elasticsearch
├── Elasticsearch (your existing instance)
│   └── Stores all telemetry from all sources
└── PILA Suite (this installation)
    └── Queries Elasticsearch
    └── Runs emulation against scoped targets
    └── Scores and documents the detection program
```

PILA Suite does NOT need to be installed on the same host as Elasticsearch. It communicates via HTTPS on port 9200.

---

## Step 1 — Clone the repository

```bash
git clone https://github.com/nonducorduco311-cyber/pila-suite.git
cd pila-suite
```

---

## Step 2 — Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Step 3 — Configure pila.conf

Copy the example configuration and edit it with your Elasticsearch credentials:

```bash
cp integrations/pila.conf.example integrations/pila.conf
nano integrations/pila.conf
```

Minimum required configuration (Community Edition):

```ini
[elasticsearch]
host       = YOUR_ELASTICSEARCH_IP
port       = 9200
username   = elastic
password   = YOUR_ELASTIC_PASSWORD
verify_ssl = false
```

See `integrations/pila.conf.example` for the full reference with all optional sections (Wazuh, Winlogbeat, Elastic Security).

---

## Step 4 — Verify Elasticsearch connectivity

```bash
python3 -c "
import sys
sys.path.insert(0, '.')
from integrations.config import ESConfig
from integrations.elastic_client import ESClient
try:
    c = ESClient()
    r = c.ping()
    print('Connected:', r)
except Exception as e:
    print('Failed:', e)
"
```

Expected output:
```
Connected: {'connected': True, 'cluster_name': 'your-cluster', 'status': 'green'}
```

---

## Step 5 — Start PILA Suite

```bash
./start.sh
```

PILA Suite starts on port 8000. Verify it is running:

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected output:
```json
{
    "status": "ok",
    "suite": "PILA Suite v1.0.0 — Community Edition",
    "edition": "community"
}
```

---

## Step 6 — Open the dashboard

```
http://YOUR_SERVER_IP:8000/
```

Or for API documentation:

```
http://YOUR_SERVER_IP:8000/docs
```

---

## Stopping PILA Suite

```bash
./stop.sh
```

---

## Running as a systemd service (optional)

To have PILA Suite start automatically on boot:

```bash
sudo tee /etc/systemd/system/pila-suite.service << 'EOF'
[Unit]
Description=PILA Suite — Purple Team Platform
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/path/to/pila-suite
ExecStart=/path/to/pila-suite/venv/bin/python -m uvicorn api.server:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable pila-suite
sudo systemctl start pila-suite
```

---

## Upgrading

```bash
cd pila-suite
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
./stop.sh && ./start.sh
```

---

## Professional Edition

Community Edition includes the PSIL SDK, open connectors, and the REST API.

Professional Edition adds LMEP emulation, IRV validation, AESP scoring, and the ATT&CK heatmap. To activate a Professional license:

```bash
python3 activate.py PILA-XXXX-XXXX-XXXX-XXXX
```

License keys available at **byte-x-bit.com**

---

*© 2026 ByTE X Bit Technologies LLC — Patent Pending*
