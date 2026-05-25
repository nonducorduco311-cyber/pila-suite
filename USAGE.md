# PILA Suite — Usage Guide (Community Edition)

> **© 2026 ByTE X Bit Technologies LLC — Patent Pending**
> Community Edition · Apache 2.0

---

## Overview

PILA Suite Community Edition gives you the PSIL engagement documentation framework and the detection connector library. This guide covers everything available without a Professional license.

For Professional Edition features (LMEP emulation, IRV validation, AESP scoring, ATT&CK heatmap), see the Professional Setup Guide available with your license at **byte-x-bit.com**.

---

## The PILA Workflow

```
1. Create engagement (PSIL)
   └── Document what you're testing, scope, TLP marking

2. Add scenarios
   └── Each scenario = one ATT&CK technique + detection outcome

3. Validate the document
   └── PSIL validator checks completeness and ATT&CK mapping

4. Check integration status
   └── Confirm your detection sources are connected

5. (Professional) Run emulation, score, validate remediation
```

---

## PSIL — Creating an Engagement

### Create a new engagement

```bash
curl -s -X POST http://localhost:8000/psil/engagements \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q3 Purple Team Exercise",
    "organization": "Your Org",
    "scope": ["192.168.10.0/24"],
    "tlp_marking": "TLP:AMBER",
    "frameworks": ["MITRE ATT&CK"],
    "tags": ["lateral-movement", "q3-2026"]
  }' | python3 -m json.tool
```

The response includes an `engagement_id` — save this for subsequent calls.

### Add a scenario

```bash
curl -s -X POST http://localhost:8000/psil/engagements/YOUR_ENGAGEMENT_ID/scenarios \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SSH Lateral Movement Test",
    "technique_id": "T1021.004",
    "tactic": "Lateral Movement",
    "tool": "custom-ssh",
    "detected": true,
    "outcome": "detected",
    "severity": "HIGH",
    "gap_identified": false,
    "detection_source": "Suricata",
    "response_action": "Alert generated — no blocking"
  }' | python3 -m json.tool
```

**Outcome values:** `detected` | `not_detected` | `prevented` | `detected_late`

**Severity values:** `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`

### List all engagements

```bash
curl -s http://localhost:8000/psil/engagements | python3 -m json.tool
```

### Get a specific engagement

```bash
curl -s http://localhost:8000/psil/engagements/YOUR_ENGAGEMENT_ID | python3 -m json.tool
```

### Validate a PSIL document

```bash
curl -s -X POST http://localhost:8000/psil/validate/YOUR_ENGAGEMENT_ID \
  | python3 -m json.tool
```

The validator checks:
- Required fields are present
- ATT&CK technique IDs are correctly formatted (T####.###)
- Outcome values are valid
- TLP marking is set

---

## Integration Status

### Check overall connectivity

```bash
curl -s http://localhost:8000/integrations/status | python3 -m json.tool
```

### Check available ATT&CK techniques

```bash
curl -s http://localhost:8000/lmep/techniques | python3 -m json.tool
```

This lists the techniques available for emulation. Running them requires Professional Edition.

### Check supported incident types

```bash
curl -s http://localhost:8000/irv/incident-types | python3 -m json.tool
```

---

## Platform Endpoints

### Health check

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

### License status

```bash
curl -s http://localhost:8000/license | python3 -m json.tool
```

### Interactive API documentation

Open in browser: `http://YOUR_SERVER_IP:8000/docs`

The Swagger UI lists every endpoint with request/response schemas and a try-it interface.

---

## Community vs Professional

| Feature | Community | Professional |
|---------|:---------:|:------------:|
| PSIL engagement creation | ✓ | ✓ |
| PSIL scenario management | ✓ | ✓ |
| PSIL document validation | ✓ | ✓ |
| Platform health + ES status | ✓ | ✓ |
| Technique library (view) | ✓ | ✓ |
| Incident type list | ✓ | ✓ |
| Interactive API docs | ✓ | ✓ |
| LMEP technique emulation | — | ✓ |
| Live ES correlation | — | ✓ |
| AESP effectiveness scoring | — | ✓ |
| AESP DMT tier classification | — | ✓ |
| AESP historical trending | — | ✓ |
| IRV incident validation | — | ✓ |
| IRV evidence bundles | — | ✓ |
| Suricata alert queries | — | ✓ |
| Zeek connection queries | — | ✓ |
| Wazuh alert queries | — | ✓ |
| Elastic Security queries | — | ✓ |
| Winlogbeat event queries | — | ✓ |
| ATT&CK coverage heatmap | — | ✓ |
| Report generation | — | ✓ |

Professional Edition: **$99/month** — license at **byte-x-bit.com**

---

## PSIL Data Format Reference

Every PSIL engagement is stored as structured JSON. Key fields:

| Field | Type | Description |
|-------|------|-------------|
| `engagement_id` | UUID | Unique identifier |
| `name` | string | Engagement name |
| `organization` | string | Target organization |
| `scope` | array | IP ranges or hostnames in scope |
| `tlp_marking` | enum | TLP:WHITE / GREEN / AMBER / RED |
| `scenarios` | array | List of tested scenarios |
| `created_at` | ISO 8601 | Creation timestamp |

Each scenario within an engagement:

| Field | Type | Description |
|-------|------|-------------|
| `scenario_id` | UUID | Unique identifier |
| `name` | string | Scenario description |
| `technique_id` | ATT&CK ID | e.g. T1021.004 |
| `tactic` | string | ATT&CK tactic name |
| `detected` | boolean | Whether technique was detected |
| `outcome` | enum | detected / not_detected / prevented / detected_late |
| `severity` | enum | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `gap_identified` | boolean | Whether a detection gap was found |
| `gap_detail` | string | Description of the gap |
| `detection_source` | string | Which tool detected it |
| `response_action` | string | What response was taken |

---

## Tips for Getting Started

1. **Start with a real exercise** — create an engagement for something you actually tested, even manually. PSIL is most valuable when it captures real outcomes.

2. **Use TLP:AMBER by default** — appropriate for most internal purple team work. Switch to TLP:WHITE only for content you intend to share externally.

3. **Map every scenario to an ATT&CK technique** — even if the technique is approximate. This is what makes the data useful for coverage tracking over time.

4. **Mark gaps honestly** — set `gap_identified: true` and describe the gap when a technique was not detected. This is the most valuable output of a purple team exercise.

5. **Version control your engagements** — export engagement JSON and commit it to a git repo alongside your detection rules. Over time this becomes a historical record of your detection program's evolution.

---

*© 2026 ByTE X Bit Technologies LLC — Patent Pending*
*Full feature documentation available with Professional license at byte-x-bit.com*
