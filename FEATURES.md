# PILA Suite — Community vs Professional

> **© 2026 ByTE X Bit Technologies LLC — Patent Pending**
> Full platform details at [pilasuit.com](https://pilasuit.com)

---

## What PILA Suite Is

PILA Suite is a purple team automation platform that measures, documents, and improves detection capability across a security stack. It connects to your live Elasticsearch environment and provides a unified workflow for running adversary simulations, validating incident remediations, and scoring your detection program — all from a single dashboard.

The platform is built around four integrated modules. Each module handles a distinct phase of the purple team engagement lifecycle:

```
PSIL → document the engagement
LMEP → emulate the adversary
IRV  → validate the remediation
AESP → score the defense
```

---

## Edition Comparison

### Community Edition — Free

The Community Edition is open source (Apache 2.0) and provides the foundational layer of the PILA Suite platform. It is designed for security engineers and researchers who want to structure and document their purple team work using an open, machine-readable format.

**What you get:**

#### PSIL — Purple Structured Intelligence Language
The full PSIL SDK is open source and freely available.

PSIL is an open data format for purple team engagement documentation. Instead of writing findings in Word documents or PowerPoint slides, PSIL captures every scenario in a structured, machine-readable format with:

- ATT&CK technique IDs and tactic mappings
- TLP classification (WHITE / GREEN / AMBER / RED)
- Detection outcomes per scenario (detected, not detected, prevented, detected late)
- Gap identification and remediation notes
- Tool and credential context per technique
- JSON export for version control and automation

PSIL engagements are the input that feeds every other PILA module. They are also designed to be shared, version-controlled, and imported by third-party tools.

**Community PSIL endpoints:**
| Endpoint | Description |
|----------|-------------|
| `POST /psil/engagements` | Create a new engagement document |
| `GET /psil/engagements` | List all engagements |
| `GET /psil/engagements/{id}` | Retrieve a specific engagement |
| `POST /psil/engagements/{id}/scenarios` | Add a scenario to an engagement |
| `POST /psil/validate/{id}` | Validate a PSIL document for completeness |

#### Platform Endpoints
| Endpoint | Description |
|----------|-------------|
| `GET /health` | Platform health and ES connectivity status |
| `GET /license` | Current license tier and enabled features |
| `GET /integrations/status` | Elasticsearch and Filebeat connectivity check |
| `GET /irv/incident-types` | List of supported incident types |
| `GET /lmep/techniques` | List of available emulation techniques |
| `GET /docs` | Interactive OpenAPI documentation |

**What Community does NOT include:**
- Technique emulation (LMEP engine is proprietary)
- Live Elasticsearch alert correlation
- Incident remediation validation (IRV engine is proprietary)
- Quantitative scoring (AESP engine is proprietary)
- ATT&CK coverage heatmap
- Evidence bundle generation

---

### Professional Edition — $149/month

The Professional Edition delivers the full PILA Suite platform. It includes all Community features plus the four proprietary engines that power the platform's core value: automated emulation, live detection correlation, remediation validation, and quantitative scoring.

**What you get — everything in Community, plus:**

---

#### LMEP — Lateral Movement Emulation Proxy *(Professional)*

LMEP executes behavioral technique simulations against scoped targets and correlates the results against live detection data in Elasticsearch.

**How it works:**
1. You create an emulation session with a target scope and credential mode
2. LMEP executes a behavioral traffic shape for the selected ATT&CK technique against the target
3. After emulation, LMEP waits for the detection pipeline to process events
4. LMEP queries your live Elasticsearch instance and checks whether the technique was detected
5. Results are returned with alert counts, detection sources, and top Suricata signatures

**Key capabilities:**
- **SYNTHETIC credential mode** — emulates technique behavior without requiring real credentials. No live credential exposure, no real authentication attempts. The traffic shape reflects the behavioral signature of the technique, not a functional attack.
- **PASSIVE deployment mode** — generates detection-relevant network signatures without active exploitation. Safe for production-adjacent environments.
- **Live ES correlation** — automatically queries your Suricata, Zeek, and Packetbeat indices after each emulation run to determine whether the technique was detected by your current ruleset
- **PSIL export** — emulation results export directly into a PSIL engagement document, closing the loop between emulation and documentation

**Supported techniques (v1.0):**
| Technique ID | Name |
|-------------|------|
| T1021.001 | Remote Services: RDP |
| T1021.002 | SMB/Windows Admin Shares |
| T1021.003 | DCOM Lateral Movement |
| T1021.004 | Remote Services: SSH |
| T1021.006 | Windows Remote Management |
| T1135 | Network Share Discovery |
| T1534 | Internal Spearphishing |
| T1550.002 | Pass-the-Hash (traffic shape) |

**LMEP Safety Guarantees:**
- No payload execution — behavioral signatures only, no real attack payloads
- Passive by default — no packet injection without explicit SEMI_ACTIVE mode authorization
- Credential isolation — SYNTHETIC mode requires no real credentials
- Full audit trail — all emulation actions logged with timestamps, scope, and technique ID

**Professional LMEP endpoints:**
| Endpoint | Description |
|----------|-------------|
| `POST /lmep/sessions` | Create an emulation session with scope and mode |
| `GET /lmep/sessions` | List all sessions |
| `GET /lmep/sessions/{id}` | Get session detail and results |
| `POST /lmep/sessions/{id}/run` | Execute a technique and correlate against live ES |
| `POST /lmep/sessions/{id}/abort` | Abort an active session |
| `POST /lmep/sessions/{id}/export-psil/{eng_id}` | Export results to a PSIL engagement |

---

#### IRV — Incident Remediation Validator *(Professional)*

IRV validates whether a remediation action actually eradicated a threat — using live Elasticsearch data, not self-reported status.

**How it works:**
1. After remediating an incident, you trigger an IRV validation job with the incident ID, incident type, and affected host scope
2. IRV runs a structured playbook of validation checks against live Elasticsearch data for the affected hosts
3. IRV checks for the absence of active Suricata alerts, malicious connection patterns, and known indicator signatures in the configured time window
4. IRV produces a timestamped, cryptographically signed evidence bundle documenting the validation result

**Key capabilities:**
- **7 incident type playbooks** — malware, credential compromise, ransomware, lateral movement, data exfiltration, phishing, insider threat. Each playbook runs checks specific to that incident category.
- **Live ES host cleanliness check** — queries Elasticsearch in real time to confirm a host shows no active alert indicators in the configured lookback window
- **Cryptographic evidence bundle** — each validation produces a signed bundle with a unique hash that serves as documented sign-off for compliance and audit purposes
- **Job queue** — multiple IRV validations can run concurrently across different hosts and incident types

**Professional IRV endpoints:**
| Endpoint | Description |
|----------|-------------|
| `POST /irv/validate` | Trigger a validation job |
| `GET /irv/jobs` | List all validation jobs |
| `GET /irv/jobs/{id}` | Get job detail and evidence bundle |
| `POST /integrations/irv/host-check` | Live host cleanliness check via ES |

---

#### AESP — Attack Effectiveness Scoring Platform *(Professional)*

AESP translates purple team engagement outcomes into a quantitative Effectiveness Score (ES, 0–100) and Defense Maturity Tier (DMT-1 through DMT-5).

**How it works:**
1. You run a PSIL engagement and add scenarios with their detection outcomes
2. AESP reads the engagement data and calculates a composite score across five dimensions of detection and response capability
3. AESP produces an ES score, a DMT tier classification, and a sub-score breakdown
4. Historical scores are tracked across engagements, allowing you to measure whether detection maturity is improving over time

**Key capabilities:**
- **Effectiveness Score (ES)** — a single 0–100 number representing the overall detection and response effectiveness of the security stack as measured by the purple team exercise
- **Defense Maturity Tier (DMT)** — a five-tier classification (DMT-1 Reactive through DMT-5 Optimized) that maps the ES score to a maturity level for executive and board reporting
- **Five-dimension scoring** — the ES is derived from five sub-scores covering detection efficacy, response speed, prevention rate, coverage breadth, and remediation quality. The specific formula and weights are proprietary (Patent Pending).
- **Historical trending** — ES scores are tracked across engagements. As gaps are closed and detection rules are added, the score improves — providing a measurable, defensible record of security program improvement over time
- **Incident type baselines** — response speed scoring is calibrated against industry baselines for specific incident types (malware, lateral movement, credential compromise, etc.)

**Professional AESP endpoints:**
| Endpoint | Description |
|----------|-------------|
| `POST /aesp/score` | Score a PSIL engagement |
| `GET /aesp/score/{id}` | Get the latest score for an engagement |
| `GET /aesp/history/{id}` | Get historical ES scores for trend tracking |

---

#### Live Elasticsearch Integration *(Professional)*

The live ES integration layer connects PILA Suite to your Suricata, Zeek, and Filebeat indices and powers real-time detection correlation across LMEP and IRV.

**Capabilities:**
- **Suricata alert queries** — query recent alerts by source IP, destination IP, and time window. Returns signature names, severity, and endpoint pairs.
- **Zeek connection queries** — query connection logs by IP, port, and protocol. Used for network-level detection correlation.
- **LMEP technique correlation** — after emulation, automatically queries ES for alerts that match the technique's behavioral signature within the correlation window
- **IRV host cleanliness** — queries ES to determine whether a host has active alert indicators following a remediation action

**Professional integration endpoints:**
| Endpoint | Description |
|----------|-------------|
| `GET /integrations/suricata/alerts` | Query Suricata alerts from ES |
| `GET /integrations/zeek/connections` | Query Zeek connection logs from ES |
| `POST /integrations/lmep/correlate` | Manual technique correlation against ES |
| `POST /integrations/irv/host-check` | Live host cleanliness check |

---

#### ATT&CK Coverage Heatmap *(Professional)*

The dashboard includes a live ATT&CK coverage heatmap that visualizes detection status across all tested techniques in real time.

**Capabilities:**
- Color-coded cells: green (detected), red (gap identified), blue (emulated, awaiting result), grey (untested)
- Grouped by ATT&CK tactic column
- Filter by status — view only gaps, only detected, only untested
- Click any technique for detail: last outcome, detection source, PSIL scenario count, LMEP run count, last tested timestamp
- Auto-refreshes from live API data on tab open
- Coverage percentage and counts shown in stats bar

---

## Summary Table

| Feature | Community | Professional |
|---------|:---------:|:------------:|
| PSIL engagement creation | ✓ | ✓ |
| PSIL scenario management | ✓ | ✓ |
| PSIL document validation | ✓ | ✓ |
| Platform health + ES status | ✓ | ✓ |
| Technique library (view) | ✓ | ✓ |
| Incident type list | ✓ | ✓ |
| Interactive API docs | ✓ | ✓ |
| **LMEP technique emulation** | — | ✓ |
| **LMEP live ES correlation** | — | ✓ |
| **LMEP PSIL export** | — | ✓ |
| **IRV incident validation** | — | ✓ |
| **IRV evidence bundles** | — | ✓ |
| **IRV live host cleanliness** | — | ✓ |
| **AESP effectiveness scoring** | — | ✓ |
| **AESP DMT tier classification** | — | ✓ |
| **AESP historical trending** | — | ✓ |
| **Live Suricata alert queries** | — | ✓ |
| **Live Zeek connection queries** | — | ✓ |
| **ATT&CK coverage heatmap** | — | ✓ |
| **Report generation** | — | ✓ |

---

## Licensing

**Community Edition** — Apache 2.0
The PSIL SDK, community API server, and open interfaces are licensed under Apache 2.0 and free to use, modify, and distribute.

**Professional Edition** — Commercial License
The AESP scoring engine, LMEP emulation engine, IRV orchestration engine, and live ES correlation layer are proprietary and Patent Pending. A Professional license is required to use these features.

**Activating Professional:**
```bash
python3 activate.py PILA-XXXX-XXXX-XXXX-XXXX
```

The activation script validates your key, writes it to `pila.conf`, and restarts PILA Suite automatically.

Purchase a license at **[pilasuit.com](https://pilasuit.com)**

---

*© 2026 ByTE X Bit Technologies LLC — Patent Pending*
*PILA Suite, PSIL, LMEP, IRV, and AESP are trademarks of ByTE X Bit Technologies LLC*
