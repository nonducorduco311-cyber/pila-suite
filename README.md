# PILA Suite v1.0.0

**Purple Team Intelligence Platform**

PSIL · IRV · LMEP · AESP — built as a unified monorepo.

---

## Products

| Product | Full Name | Role |
|---------|-----------|------|
| **PSIL** | Purple Structured Intelligence Language | Open data format + SDK for purple team engagements |
| **LMEP** | Lateral Movement Emulation Proxy | Safe production lateral movement emulation |
| **IRV** | Incident Remediation Validator | Post-remediation forensic validation |
| **AESP** | Attack Effectiveness Scoring Platform | Quantitative defense scoring (ES + DMT) |

---

## Requirements

- Python 3.11+
- pip3

---

## Quick Start

```bash
# Install and start
./start.sh

# Open dashboard
open http://localhost:8000/

# Interactive API docs
open http://localhost:8000/docs

# Stop
./stop.sh
```

---

## Project Structure

```
pila-suite/
├── psil/
│   └── psil_sdk/
│       ├── __init__.py      # SDK exports
│       ├── models.py        # Engagement, Scenario, Attack, Defense, Outcome, Metrics...
│       ├── validator.py     # PSIL document validator
│       └── serializer.py    # JSON/YAML serialization
├── aesp/
│   └── aesp_score/
│       └── __init__.py      # Scoring engine: ES formula, DMT classification
├── irv/
│   └── irv_core/
│       └── __init__.py      # Orchestration engine, playbook library, evidence packaging
├── lmep/
│   └── lmep_core/
│       └── __init__.py      # Technique library, session management, safety framework
├── platform/
│   └── server.py            # Unified FastAPI server + dashboard
├── start.sh                 # Startup script
├── stop.sh                  # Stop script
└── README.md
```

---

## API Endpoints

### PSIL
| Method | Path | Description |
|--------|------|-------------|
| POST | `/psil/engagements` | Create engagement |
| GET | `/psil/engagements` | List all engagements |
| GET | `/psil/engagements/{id}` | Get engagement |
| POST | `/psil/engagements/{id}/scenarios` | Add scenario |
| POST | `/psil/validate/{id}` | Validate PSIL document |

### AESP
| Method | Path | Description |
|--------|------|-------------|
| POST | `/aesp/score` | Score a PSIL engagement |
| GET | `/aesp/score/{id}` | Get latest score |
| GET | `/aesp/history/{id}` | ES score history |

### IRV
| Method | Path | Description |
|--------|------|-------------|
| POST | `/irv/validate` | Trigger validation job |
| GET | `/irv/jobs` | List all jobs |
| GET | `/irv/jobs/{id}` | Get job + evidence bundle |
| GET | `/irv/incident-types` | List valid incident types |

### LMEP
| Method | Path | Description |
|--------|------|-------------|
| POST | `/lmep/sessions` | Create emulation session |
| POST | `/lmep/sessions/{id}/run` | Run technique |
| POST | `/lmep/sessions/{id}/abort` | Abort session (kill switch) |
| POST | `/lmep/sessions/{id}/export-psil/{eng_id}` | Export to PSIL |
| GET | `/lmep/techniques` | List techniques |

---

## AESP Scoring Formula

```
ES = (DE × 0.30) + (RS × 0.20) + (PR × 0.20) + (CB × 0.15) + (RQ × 0.15)
```

| Sub-Score | Weight | Measures |
|-----------|--------|---------|
| DE — Detection Efficacy | 30% | Weighted detection rate by severity |
| RS — Response Speed | 20% | MTTR vs. industry baseline |
| PR — Prevention Rate | 20% | Fraction fully prevented/blocked |
| CB — Coverage Breadth | 15% | ATT&CK tactic + technique coverage |
| RQ — Remediation Quality | 15% | Verification status of gap closures |

| DMT Tier | ES Range | Label |
|----------|----------|-------|
| DMT-5 | 85–100 | Optimized |
| DMT-4 | 70–84 | Advanced |
| DMT-3 | 55–69 | Defined |
| DMT-2 | 40–54 | Developing |
| DMT-1 | 0–39 | Reactive |

---

## LMEP Safety Guarantees

1. **No Payload Execution** — behavioral signatures only; no real attack payloads
2. **Traffic Mirroring** — passive by default; no packet injection without explicit Active mode authorization
3. **Credential Isolation** — SYNTHETIC mode by default; real credentials require explicit authorization
4. **Full Audit Trail** — all actions logged to tamper-evident append-only store

---

## License

Apache 2.0 — OSS core (PSIL SDK, AESP scoring engine, IRV core playbooks, LMEP OSS technique library)

© PILA Suite — Draft v1.0
