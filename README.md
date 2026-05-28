# ByTE X Bit Platform

> **Integrated purple-team & blue-team security automation —
> proof your defenses actually work.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Status: Patent Pending](https://img.shields.io/badge/Status-Patent_Pending-orange.svg)](#patents--intellectual-property)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-brightgreen.svg)](https://www.python.org/)

The **ByTE X Bit Platform** is an integrated security automation platform from
[ByTE X Bit Technologies LLC](https://byte-x-bit.com). It emulates attacks,
watches and contains them, tracks detection coverage as it drifts over time,
and rolls every result into a single cryptographically-attested security
posture score.

This is the **Community Edition** — fully open source under Apache 2.0.

🌐 **Website:** [byte-x-bit.com](https://byte-x-bit.com)
📬 **Contact:** bryant@byte-x-bit.com

---

## Why this exists

Most security tools generate more data. This one generates **evidence**.

In a real SOC you end up asking the same question every quarter: *can we
actually prove our defenses work?* This platform exists to answer that with
signed, defensible artifacts instead of dashboards and assertions. It was
designed and built in a production-grade home lab running real Elasticsearch,
Suricata, Zeek, Wazuh, and Sysmon telemetry — and dogfooded against live
attack emulation before it shipped.

## The four products

The platform is one bundle made of four engines that share a common data
backbone:

| Product | Lane | What it does |
|---|---|---|
| **PILA** | Purple Team | Run, emulate, and **score** purple-team exercises against your live detection stack — quantifies effectiveness on a 0–100 scale and a Defense Maturity Tier |
| **CODE** | Blue Team | Monitors detection-rule health hourly, enriches every alert with threat intel, ranks containment actions, and seals IR evidence into a SHA-256 chain |
| **GHOST** | Coverage | Tracks ATT&CK detection coverage as it drifts over time, computes a Detection Debt Score and Coverage Maturity Level |
| **SENTINEL** | Risk & Trust | Turns validation evidence into a cryptographically-attested trust score with letter-grade ratings — built on append-only, signed evidence |

Inside each product:

- **PILA**: PSIL (engagement docs), LMEP (lateral movement emulation),
  IRV (incident remediation validator), AESP (attack effectiveness scoring)
- **CODE**: DRIFT (rule health), OBSERVER (alert enrichment),
  CHAIN (containment scoring), EVIDENCE (chain-of-custody ledger)
- **GHOST**: Coverage states, regression alerts, DDS / CML scoring
- **SENTINEL**: Sentinel Score, evidence ledger, decay model, trust ratings

For the full product story with screenshots and pricing, see
[byte-x-bit.com](https://byte-x-bit.com).

## What it is *not*

- **Not a SIEM.** It works alongside yours (Elastic, Splunk, Wazuh).
- **Not an EDR or antivirus.**
- **Not a firewall.**
- **Not a vulnerability scanner.** It measures whether *detections fire*,
  not what's unpatched.
- **Not an attack tool for unauthorized use.** Emulation runs against
  systems you own or have explicit authorization to test.

---

## Requirements

Minimum, to start the platform and explore the dashboards:

- **Linux** (tested on Ubuntu 22.04 / 24.04, Debian 12)
- **Python 3.11+**
- ~500 MB disk, ~1 GB RAM for the platform itself

To produce *live* scores against real telemetry, you also need a detection
stack to point it at. The platform integrates with:

- **Elasticsearch** 8.x or 9.x (primary backend for live correlation)
- **Suricata** 7.x (IDS rule telemetry)
- **Zeek** 6.x (network connection logs)
- **Wazuh** 4.x (endpoint events)
- **Sysmon** (Windows endpoint events, via Wazuh or Winlogbeat)
- **Splunk Enterprise** (optional — alternate backend)

If none of those are present, you can still run the platform in
**community/local mode** — engagements, basic scoring, and read-only
dashboards work entirely from local JSON files (no external dependencies).

---

## Quickstart

> **⚠ Known issue (v1.0.0):** `start.sh` currently calls `python3` directly
> instead of activating the project's `venv/`. This causes
> `ModuleNotFoundError` on a fresh clone if dependencies were installed
> into a venv. See [Workaround](#known-issues) below. A fix is planned for
> v1.0.1.

### 1. Clone and set up

```bash
git clone https://github.com/nonducorduco311-cyber/pila-suite.git
cd pila-suite

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the platform

```bash
# Workaround for the known start.sh issue — run uvicorn directly from the venv:
python -m uvicorn api.server:app --host 0.0.0.0 --port 8000
```

(Once the v1.0.1 fix lands, this becomes simply `./start.sh`.)

### 3. Open the dashboard

In your browser:

- **Dashboard:** http://localhost:8000/
- **API docs:** http://localhost:8000/docs
- **Health check:** http://localhost:8000/health

On first start, dashboards will be empty until you either:
- Run a purple-team exercise (PILA), **or**
- Wire up an Elasticsearch / Suricata / Wazuh data source (see
  [Integrations](#integrations))

### 4. Stop the platform

```bash
./stop.sh
```

---

## Integrations

The platform reads from your existing detection stack — it does not replace
it. Configuration lives in `integrations/pila.conf` (copy
`integrations/pila.conf.example` and edit).

| Source | What it provides | Config section |
|---|---|---|
| Elasticsearch | Live correlation backbone | `[elasticsearch]` |
| Suricata | IDS rule fires & metadata | (read via Elasticsearch) |
| Zeek | Connection / protocol logs | (read via Elasticsearch) |
| Wazuh | Endpoint events | (read via Elasticsearch / Wazuh API) |
| Sysmon | Windows process/file/network events | (read via Wazuh) |
| Splunk | Alternate backend (optional) | `[splunk]` |
| AbuseIPDB | IP reputation enrichment (OBSERVER) | `[threat_intel]` |
| VirusTotal | File / domain enrichment (OBSERVER) | `[threat_intel]` |

API keys for third-party services go in `pila.conf`; this file is
`.gitignore`'d and **must never be committed**.

---

## Project layout

```
pila-suite/
├── api/                    # FastAPI server (Professional / Community)
├── modules/
│   ├── code/               # CODE products (DRIFT, OBSERVER, CHAIN, EVIDENCE)
│   ├── ghost/              # GHOST coverage tracking
│   └── sentinel/           # SENTINEL scoring
├── integrations/           # External-system connectors
│   ├── elastic_client.py
│   ├── splunk_connector.py
│   └── pila.conf.example
├── data/                   # Persisted state (JSON files — gitignored)
├── start.sh / stop.sh      # Lifecycle scripts
├── requirements.txt
└── README.md               # this file
```

---

## Open Core model

This repository contains the **Community Edition** of the platform — fully
open source under Apache 2.0. The Community Edition includes:

- ✓ PSIL engagement documentation
- ✓ Basic AESP effectiveness scoring
- ✓ GHOST & SENTINEL read-only dashboards
- ✓ Full API read access
- ✓ Self-hosted, no license key required

The **Professional Edition** ($149 / month) adds the full automation and
live-correlation engines — full PILA modules, CODE blue-team operations,
GHOST sync & regression detection, SENTINEL evidence submission, the live
ATT&CK heatmap, API write access, and ES integration. See
[pricing](https://byte-x-bit.com/#pricing) for the full plan comparison
(Community / Professional / Team / Enterprise).

The proprietary scoring algorithms and detection engines are not in this
repository.

---

## Known issues

### `start.sh` does not activate the venv (v1.0.0)

`start.sh` invokes `python3` directly. If you installed dependencies into
a virtual environment (recommended), startup will fail with
`ModuleNotFoundError: No module named 'elasticsearch'` or similar.

**Workaround** (until v1.0.1):
```bash
source venv/bin/activate
python -m uvicorn api.server:app --host 0.0.0.0 --port 8000
```

### Empty dashboards on first start

This is expected. The platform reads persisted state from `data/*.json` and
those files don't exist until you've run an engagement or wired up an
Elasticsearch source. The dashboards will populate as you use the platform.

---

## Patents & intellectual property

Multiple provisional patent applications have been filed covering the
platform's scoring methods, evidence-decay model, and integrated
purple/blue-team architecture. The proprietary algorithms are not included
in this repository.

This Community Edition is licensed under **Apache 2.0** — you may use,
modify, and redistribute it under the terms of that license.
"ByTE X Bit Technologies" and the BX mark are trademarks of
ByTE X Bit Technologies LLC.

ATT&CK® is a registered trademark of The MITRE Corporation.

---

## Support & contact

This is an early-stage independent project. Support is best-effort.

- **Bug reports / feature requests:** open a GitHub issue
- **Security disclosures:** bryant@byte-x-bit.com (do **not** open a public
  issue for vulnerabilities)
- **Commercial / Professional inquiries:** bryant@byte-x-bit.com
- **Website:** [byte-x-bit.com](https://byte-x-bit.com)

---

© 2026 ByTE X Bit Technologies LLC. All rights reserved.
Open-source components licensed under Apache 2.0.
