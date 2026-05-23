"""
PILA Suite - Unified Platform API
Serves PSIL, IRV, LMEP, AESP, and Live Network Integrations.
"""
import sys
import os
import json
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, ".."))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List
import uvicorn

from psil.psil_sdk.models import (
    Engagement, Scenario, Attack, Defense, Outcome, Severity,
    Metrics, LessonLearned, Remediation, TeamMember, TLPMarking
)
from psil.psil_sdk.validator import PSILValidator
from aesp.aesp_score import AESPScoringEngine
from irv.irv_core import IRVOrchestrationEngine, IncidentType
from lmep.lmep_core import LMEPControlPlane, CredentialMode, DeploymentMode

# ── Integration layer (graceful fallback if ES unreachable) ──────────────────
try:
    from integrations.elastic_client import ESClient
    from integrations.config import ESConfig, LMEPConfig, IRVConfig
    _es = ESClient()
    _lmep_cfg = LMEPConfig()
    _irv_cfg  = IRVConfig()
    INTEGRATIONS_AVAILABLE = True
except Exception as _ie:
    INTEGRATIONS_AVAILABLE = False
    _es = None
    print(f"[WARN] Live integrations not loaded: {_ie}")

app = FastAPI(
    title="PILA Suite API",
    description="PSIL · IRV · LMEP · AESP — Unified Purple Team Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Singletons ───────────────────────────────────────────────────────────────
psil_store:    dict[str, dict]       = {}
aesp_engine  = AESPScoringEngine()
aesp_history: dict[str, list[float]] = {}
irv_engine   = IRVOrchestrationEngine(demo_mode=False if INTEGRATIONS_AVAILABLE else True)
lmep_plane   = LMEPControlPlane()
validator    = PSILValidator()


# ═══════════════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    es_status = "unconfigured"
    if _es:
        try:
            info = _es.ping()
            es_status = f"online — cluster:{info['cluster_name']} v{info['version']} [{info['status']}]"
        except Exception as e:
            es_status = f"unreachable: {e}"
    return {
        "status": "ok",
        "suite": "PILA Suite v1.0.0",
        "components": {
            "psil": "online", "aesp": "online",
            "irv": "online",  "lmep": "online",
        },
        "integrations": {
            "elasticsearch": es_status,
            "available": INTEGRATIONS_AVAILABLE,
        }
    }


# ═══════════════════════════════════════════════════════════════════════════
# PSIL
# ═══════════════════════════════════════════════════════════════════════════

class CreateEngagementRequest(BaseModel):
    name: str
    organization: str
    scope: List[str]
    tlp_marking: str = "TLP:AMBER"
    frameworks: List[str] = []
    tags: List[str] = []

class AddScenarioRequest(BaseModel):
    name: str
    technique_id: str
    tactic: str
    tool: Optional[str] = None
    detected: bool
    outcome: str
    severity: str = "MEDIUM"
    gap_identified: bool = False
    gap_detail: Optional[str] = None
    detection_source: Optional[str] = None
    response_action: Optional[str] = None

@app.post("/psil/engagements")
def create_engagement(req: CreateEngagementRequest):
    eng = Engagement(
        name=req.name, organization=req.organization, scope=req.scope,
        tlp_marking=TLPMarking(req.tlp_marking),
        frameworks=req.frameworks, tags=req.tags,
    )
    d = eng.to_dict()
    psil_store[eng.engagement_id] = d
    return d

@app.get("/psil/engagements")
def list_engagements():
    return list(psil_store.values())

@app.get("/psil/engagements/{engagement_id}")
def get_engagement(engagement_id: str):
    if engagement_id not in psil_store:
        raise HTTPException(404, f"Engagement {engagement_id} not found")
    return psil_store[engagement_id]

@app.post("/psil/engagements/{engagement_id}/scenarios")
def add_scenario(engagement_id: str, req: AddScenarioRequest):
    if engagement_id not in psil_store:
        raise HTTPException(404, f"Engagement {engagement_id} not found")
    eng = Engagement.from_dict(psil_store[engagement_id])
    scenario = Scenario(
        name=req.name,
        attack=Attack(technique_id=req.technique_id, tactic=req.tactic, tool=req.tool),
        defense=Defense(detected=req.detected, detection_source=req.detection_source,
                        response_action=req.response_action),
        outcome=Outcome(req.outcome), severity=Severity(req.severity),
        gap_identified=req.gap_identified, gap_detail=req.gap_detail,
    )
    eng.add_scenario(scenario)
    psil_store[engagement_id] = eng.to_dict()
    return scenario.to_dict()

@app.post("/psil/validate/{engagement_id}")
def validate_engagement(engagement_id: str):
    if engagement_id not in psil_store:
        raise HTTPException(404, f"Engagement {engagement_id} not found")
    result = validator.validate(psil_store[engagement_id])
    return {"valid": result.valid, "errors": result.errors, "warnings": result.warnings}


# ═══════════════════════════════════════════════════════════════════════════
# AESP
# ═══════════════════════════════════════════════════════════════════════════

class ScoreRequest(BaseModel):
    engagement_id: str
    incident_type: str = "default"

@app.post("/aesp/score")
def score_engagement(req: ScoreRequest):
    if req.engagement_id not in psil_store:
        raise HTTPException(404, f"Engagement {req.engagement_id} not found")
    eng = Engagement.from_dict(psil_store[req.engagement_id])
    if not eng.scenarios:
        raise HTTPException(400, "Engagement has no scenarios to score")
    history  = aesp_history.get(req.engagement_id, [])
    prev_es  = history[-1] if history else None
    result   = aesp_engine.score(eng, previous_es=prev_es, history_es=history,
                                  incident_type=req.incident_type)
    aesp_history.setdefault(req.engagement_id, []).append(result.es)
    psil_store[req.engagement_id]["extensions"]["aesp_score"] = result.to_dict()
    return result.to_dict()

@app.get("/aesp/score/{engagement_id}")
def get_score(engagement_id: str):
    doc   = psil_store.get(engagement_id)
    if not doc:
        raise HTTPException(404, "Engagement not found")
    score = doc.get("extensions", {}).get("aesp_score")
    if not score:
        raise HTTPException(404, "No score yet. POST to /aesp/score first.")
    return score

@app.get("/aesp/history/{engagement_id}")
def get_score_history(engagement_id: str):
    return {"engagement_id": engagement_id, "es_history": aesp_history.get(engagement_id, [])}


# ═══════════════════════════════════════════════════════════════════════════
# IRV
# ═══════════════════════════════════════════════════════════════════════════

class IRVTriggerRequest(BaseModel):
    incident_id: str
    incident_type: str
    affected_scope: List[str]
    metadata: Optional[dict] = None

@app.post("/irv/validate")
def trigger_irv(req: IRVTriggerRequest):
    valid_types = [t.value for t in IncidentType]
    if req.incident_type not in valid_types:
        raise HTTPException(400, f"Invalid incident_type. Valid: {valid_types}")
    job_id = irv_engine.trigger_validation(
        incident_id=req.incident_id, incident_type=req.incident_type,
        affected_scope=req.affected_scope, metadata=req.metadata,
    )
    return irv_engine.get_job(job_id)

@app.get("/irv/jobs")
def list_irv_jobs():
    return irv_engine.get_all_jobs()

@app.get("/irv/jobs/{job_id}")
def get_irv_job(job_id: str):
    job = irv_engine.get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")
    return job

@app.get("/irv/incident-types")
def get_incident_types():
    return [t.value for t in IncidentType]


# ═══════════════════════════════════════════════════════════════════════════
# LMEP
# ═══════════════════════════════════════════════════════════════════════════

class LMEPSessionRequest(BaseModel):
    name: str
    scope: List[str]
    credential_mode: str = "SYNTHETIC"
    deployment_mode: str = "PASSIVE"

class LMEPRunRequest(BaseModel):
    technique_id: str
    target: str

@app.post("/lmep/sessions")
def create_lmep_session(req: LMEPSessionRequest):
    try:
        session = lmep_plane.create_session(
            name=req.name, scope=req.scope,
            credential_mode=req.credential_mode, deployment_mode=req.deployment_mode,
        )
        return session.to_dict()
    except PermissionError as e:
        raise HTTPException(403, str(e))

@app.get("/lmep/sessions")
def list_lmep_sessions():
    return lmep_plane.list_sessions()

@app.get("/lmep/sessions/{session_id}")
def get_lmep_session(session_id: str):
    s = lmep_plane.get_session(session_id)
    if not s:
        raise HTTPException(404, f"Session {session_id} not found")
    return s.to_dict()

@app.post("/lmep/sessions/{session_id}/run")
def run_technique(session_id: str, req: LMEPRunRequest):
    session = lmep_plane.get_session(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")
    try:
        from datetime import datetime, timezone
        emulation_time = datetime.now(timezone.utc)
        result = session.run_technique(req.technique_id, req.target)
        result_dict = result.to_dict()

        # ── Live ES correlation ──────────────────────────────────────────
        if _es and INTEGRATIONS_AVAILABLE:
            wait = _lmep_cfg.post_emulation_wait
            result_dict["live_detection_status"] = f"Waiting {wait}s for detection pipeline..."
            time.sleep(wait)
            try:
                correlation = _es.correlate_lmep_technique(
                    technique_id=req.technique_id,
                    target_ip=req.target,
                    emulation_time=emulation_time,
                    window_seconds=120,
                )
                result_dict["live_detection"] = correlation
                # Override the simulated detected flag with real ES result
                result_dict["detected_by_defense"]  = correlation["detected"]
                result_dict["detection_source"]      = ", ".join(correlation["detection_sources"]) or None
                result_dict["live_detection_status"] = "Live ES correlation complete"
            except Exception as e:
                result_dict["live_detection_status"] = f"ES correlation error: {e}"
        else:
            result_dict["live_detection_status"] = "ES integration not available — using simulated result"

        return result_dict
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(403, str(e))

@app.post("/lmep/sessions/{session_id}/abort")
def abort_session(session_id: str):
    lmep_plane.abort_session(session_id)
    return {"status": "aborted", "session_id": session_id}

@app.post("/lmep/sessions/{session_id}/export-psil/{engagement_id}")
def export_to_psil(session_id: str, engagement_id: str):
    session = lmep_plane.get_session(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")
    if engagement_id not in psil_store:
        raise HTTPException(404, f"Engagement {engagement_id} not found")
    eng = Engagement.from_dict(psil_store[engagement_id])
    new_scenarios = session.export_psil_scenarios()
    for scen in new_scenarios:
        eng.add_scenario(scen)
    psil_store[engagement_id] = eng.to_dict()
    return {"exported_scenarios": len(new_scenarios), "engagement_id": engagement_id}

@app.get("/lmep/techniques")
def list_techniques():
    return lmep_plane.list_techniques()


# ═══════════════════════════════════════════════════════════════════════════
# INTEGRATION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/integrations/status")
def integration_status():
    """Check connectivity to all live network tools."""
    result = {"elasticsearch": {}, "filebeat_modules": {}}
    if not _es:
        result["elasticsearch"] = {"connected": False, "error": "Client not initialized"}
        return result
    try:
        result["elasticsearch"] = _es.ping()
    except Exception as e:
        result["elasticsearch"] = {"connected": False, "error": str(e)}
    try:
        result["filebeat_modules"] = _es.get_filebeat_stats()
    except Exception as e:
        result["filebeat_modules"] = {"error": str(e)}
    return result

@app.get("/integrations/indices")
def list_es_indices():
    """List all non-system Elasticsearch indices."""
    if not _es:
        raise HTTPException(503, "Elasticsearch integration not available")
    try:
        return {"indices": _es.list_indices()}
    except Exception as e:
        raise HTTPException(502, str(e))

@app.get("/integrations/suricata/alerts")
def get_suricata_alerts(src_ip: Optional[str] = None, dst_ip: Optional[str] = None,
                         window: int = 300):
    """Query recent Suricata alerts from Elasticsearch."""
    if not _es:
        raise HTTPException(503, "Elasticsearch integration not available")
    try:
        alerts = _es.query_suricata_alerts(src_ip=src_ip, dst_ip=dst_ip, window_seconds=window)
        return {"count": len(alerts), "alerts": alerts}
    except Exception as e:
        raise HTTPException(502, str(e))

@app.get("/integrations/zeek/connections")
def get_zeek_connections(src_ip: Optional[str] = None, dst_ip: Optional[str] = None,
                          dst_port: Optional[int] = None, window: int = 300):
    """Query recent Zeek connection logs from Elasticsearch."""
    if not _es:
        raise HTTPException(503, "Elasticsearch integration not available")
    try:
        conns = _es.query_zeek_connections(src_ip=src_ip, dst_ip=dst_ip,
                                            dst_port=dst_port, window_seconds=window)
        return {"count": len(conns), "connections": conns}
    except Exception as e:
        raise HTTPException(502, str(e))

@app.post("/integrations/irv/host-check")
def live_host_check(body: dict):
    """
    Live IRV host cleanliness check via Elasticsearch.
    Body: { "host_ip": "x.x.x.x", "incident_type": "malware", "window_minutes": 10 }
    """
    if not _es:
        raise HTTPException(503, "Elasticsearch integration not available")
    host_ip       = body.get("host_ip")
    incident_type = body.get("incident_type", "malware")
    window        = int(body.get("window_minutes", 10))
    if not host_ip:
        raise HTTPException(400, "host_ip is required")
    try:
        return _es.check_host_clean(host_ip, incident_type, window)
    except Exception as e:
        raise HTTPException(502, str(e))

@app.post("/integrations/lmep/correlate")
def correlate_technique(body: dict):
    """
    Manually correlate an already-run technique against live ES data.
    Body: { "technique_id": "T1021.002", "target_ip": "x.x.x.x",
            "emulation_time": "2025-04-24T12:00:00Z", "window_seconds": 120 }
    """
    if not _es:
        raise HTTPException(503, "Elasticsearch integration not available")
    from datetime import datetime
    try:
        et = datetime.fromisoformat(body["emulation_time"].replace("Z", "+00:00"))
        return _es.correlate_lmep_technique(
            technique_id=body["technique_id"],
            target_ip=body["target_ip"],
            emulation_time=et,
            window_seconds=int(body.get("window_seconds", 120)),
        )
    except Exception as e:
        raise HTTPException(502, str(e))


# ═══════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PILA Suite — Dashboard</title>
<style>
  :root {
    --bg:#0d1117;--surface:#161b22;--border:#30363d;--accent:#58a6ff;
    --green:#3fb950;--red:#f85149;--yellow:#d29922;--text:#e6edf3;--muted:#8b949e;
    --font:'Segoe UI',system-ui,sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:16px}
  header h1{font-size:20px;font-weight:700;color:var(--accent)}
  header span{color:var(--muted);font-size:12px}
  nav{display:flex;gap:4px;padding:12px 24px;background:var(--surface);border-bottom:1px solid var(--border)}
  nav button{background:none;border:1px solid transparent;color:var(--muted);padding:6px 14px;border-radius:6px;cursor:pointer;font-size:13px}
  nav button.active,nav button:hover{background:var(--border);color:var(--text);border-color:var(--border)}
  main{padding:24px;max-width:1200px;margin:0 auto}
  .tab{display:none}.tab.active{display:block}
  h2{font-size:16px;font-weight:600;margin-bottom:16px}
  h3{font-size:14px;font-weight:600;margin-bottom:10px;color:var(--accent)}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
  label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px;margin-top:10px}
  input,select,textarea{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:6px;font-size:13px;font-family:var(--font)}
  input:focus,select:focus{outline:none;border-color:var(--accent)}
  button.btn{background:var(--accent);color:#0d1117;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;margin-top:12px}
  button.btn:hover{opacity:.85}
  button.btn.danger{background:var(--red);color:white}
  button.btn.secondary{background:var(--border);color:var(--text)}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
  .badge.green{background:rgba(63,185,80,.15);color:var(--green)}
  .badge.red{background:rgba(248,81,73,.15);color:var(--red)}
  .badge.yellow{background:rgba(210,153,34,.15);color:var(--yellow)}
  .badge.blue{background:rgba(88,166,255,.15);color:var(--accent)}
  .score-big{font-size:48px;font-weight:700;color:var(--accent);line-height:1}
  .bar-wrap{background:var(--border);border-radius:4px;height:8px;margin:4px 0 12px}
  .bar{height:8px;border-radius:4px;background:var(--accent);transition:width .5s}
  pre{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-size:12px;overflow:auto;max-height:400px;white-space:pre-wrap;color:var(--muted)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;color:var(--muted);font-weight:500;padding:8px 10px;border-bottom:1px solid var(--border)}
  td{padding:8px 10px;border-bottom:1px solid rgba(48,54,61,.5)}
  tr:hover td{background:rgba(255,255,255,.02)}
  .stat{text-align:center}
  .stat .val{font-size:28px;font-weight:700;color:var(--accent)}
  .stat .lbl{font-size:11px;color:var(--muted);margin-top:2px}
  .alert{padding:10px 14px;border-radius:6px;margin-bottom:12px;font-size:13px}
  .alert.success{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.3);color:var(--green)}
  .alert.error{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);color:var(--red)}
  .alert.info{background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.3);color:var(--accent)}
  .alert.warn{background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.3);color:var(--yellow)}
  #msg{position:fixed;top:20px;right:20px;z-index:999;min-width:240px}
  .live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);display:inline-block;margin-right:6px;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
  .offline-dot{width:8px;height:8px;border-radius:50%;background:var(--red);display:inline-block;margin-right:6px}
</style>
</head>
<body>
<header>
  <h1>⚔ PILA Suite</h1>
  <span>Purple Intelligence & Lifecycle Automation · v1.0.0</span>
  <span style="margin-left:auto" id="es-status-header">
    <span class="offline-dot" id="es-dot"></span>
    <span id="es-label" style="color:var(--muted);font-size:12px">Checking ES...</span>
  </span>
</header>
<nav>
  <button class="active" onclick="showTab('overview',this)">Overview</button>
  <button onclick="showTab('psil',this)">PSIL</button>
  <button onclick="showTab('lmep',this)">LMEP</button>
  <button onclick="showTab('irv',this)">IRV</button>
  <button onclick="showTab('aesp',this)">AESP</button>
  <button onclick="showTab('live',this)">⚡ Live Network</button>
  <button onclick="showTab('api',this)">API</button>
</nav>
<main>
<div id="msg"></div>

<!-- OVERVIEW -->
<div id="tab-overview" class="tab active">
  <h2>Platform Overview</h2>
  <div class="grid2">
    <div class="card">
      <h3>PSIL — Purple Structured Intelligence Language</h3>
      <p style="color:var(--muted);font-size:13px;line-height:1.6">Open data format for purple team engagements. Machine-readable scenario capture with ATT&CK, STIX, and D3FEND mappings.</p>
      <div style="margin-top:12px" id="psil-stat"><span class="badge blue">0 Engagements</span></div>
    </div>
    <div class="card">
      <h3>LMEP — Lateral Movement Emulation Proxy</h3>
      <p style="color:var(--muted);font-size:13px;line-height:1.6">Safe production lateral movement emulation. Behavioral signatures only. Results auto-correlated against your live Suricata/Zeek/Packetbeat data.</p>
      <div style="margin-top:12px" id="lmep-stat"><span class="badge blue">0 Sessions</span></div>
    </div>
    <div class="card">
      <h3>IRV — Incident Remediation Validator</h3>
      <p style="color:var(--muted);font-size:13px;line-height:1.6">Automated post-remediation validation. Checks live Elasticsearch data to confirm hosts are clean before issuing signed evidence bundles.</p>
      <div style="margin-top:12px" id="irv-stat"><span class="badge blue">0 Validations</span></div>
    </div>
    <div class="card">
      <h3>AESP — Attack Effectiveness Scoring Platform</h3>
      <p style="color:var(--muted);font-size:13px;line-height:1.6">Quantitative defense scoring. ES (0-100) + Defense Maturity Tier (DMT-1 to DMT-5). Driven by real detection results from your live stack.</p>
      <div style="margin-top:12px" id="aesp-stat"><span class="badge blue">No scores yet</span></div>
    </div>
  </div>
  <div class="card">
    <h3>Live Integration Status</h3>
    <div id="integration-status-panel"><em style="color:var(--muted)">Checking...</em></div>
    <button class="btn secondary" onclick="refreshIntegrationStatus()" style="margin-top:8px">↻ Refresh</button>
  </div>
</div>

<!-- PSIL -->
<div id="tab-psil" class="tab">
  <h2>PSIL — Create Engagement</h2>
  <div class="grid2">
    <div class="card">
      <h3>New Engagement</h3>
      <label>Engagement Name</label><input id="p-name" value="Q2 Purple Team Assessment"/>
      <label>Organization</label><input id="p-org" value="Home Lab"/>
      <label>Scope (comma-separated)</label><input id="p-scope" value="192.168.10.0/24"/>
      <label>TLP Marking</label>
      <select id="p-tlp"><option>TLP:AMBER</option><option>TLP:GREEN</option><option>TLP:RED</option><option>TLP:WHITE</option></select>
      <button class="btn" onclick="createEngagement()">Create Engagement</button>
    </div>
    <div class="card">
      <h3>Engagements</h3>
      <div id="psil-list"><em style="color:var(--muted)">No engagements yet.</em></div>
    </div>
  </div>
  <div class="card" id="add-scenario-card" style="display:none">
    <h3>Add Scenario to Selected Engagement</h3>
    <div class="grid2">
      <div>
        <label>Scenario Name</label><input id="s-name" value="LSASS Credential Dump"/>
        <label>ATT&CK Technique ID</label><input id="s-techid" value="T1003.001"/>
        <label>Tactic</label><input id="s-tactic" value="Credential Access"/>
        <label>Tool</label><input id="s-tool" value="Mimikatz"/>
      </div>
      <div>
        <label>Outcome</label>
        <select id="s-outcome">
          <option value="detected_not_blocked">detected_not_blocked</option>
          <option value="not_detected">not_detected</option>
          <option value="prevented">prevented</option>
          <option value="detected_and_blocked">detected_and_blocked</option>
          <option value="detected_late">detected_late</option>
        </select>
        <label>Severity</label>
        <select id="s-severity"><option>HIGH</option><option>CRITICAL</option><option>MEDIUM</option><option>LOW</option></select>
        <label>Detected?</label>
        <select id="s-detected"><option value="true">Yes</option><option value="false">No</option></select>
        <label>Gap Identified?</label>
        <select id="s-gap"><option value="false">No</option><option value="true">Yes</option></select>
      </div>
    </div>
    <button class="btn" onclick="addScenario()">Add Scenario</button>
  </div>
</div>

<!-- LMEP -->
<div id="tab-lmep" class="tab">
  <h2>LMEP — Lateral Movement Emulation</h2>
  <div class="alert info">⚡ Live mode: after each emulation, PILA waits 15s then queries your Suricata, Zeek, and Packetbeat indices in Elasticsearch to check for real detections.</div>
  <div class="grid2">
    <div class="card">
      <h3>Create Session</h3>
      <label>Session Name</label><input id="l-name" value="Home Lab Lateral Movement Test"/>
      <label>Scope — target IPs (comma-separated)</label><input id="l-scope" value="192.168.10.100"/>
      <label>Credential Mode</label>
      <select id="l-cred"><option>SYNTHETIC</option></select>
      <label>Deployment Mode</label>
      <select id="l-deploy"><option>PASSIVE</option><option>SEMI_ACTIVE</option></select>
      <button class="btn" onclick="createSession()">Create Session</button>
    </div>
    <div class="card">
      <h3>Available Techniques</h3>
      <div id="technique-list"><em style="color:var(--muted)">Loading...</em></div>
    </div>
  </div>
  <div class="card" id="lmep-run-card" style="display:none">
    <h3>Run Technique</h3>
    <div class="grid2">
      <div>
        <label>Technique</label><select id="l-techid"></select>
        <label>Target IP (must be in scope)</label><input id="l-target"/>
      </div>
      <div>
        <label>Export results to PSIL Engagement</label>
        <select id="l-export-eng"><option value="">— none —</option></select>
      </div>
    </div>
    <button class="btn" onclick="runTechnique()">▶ Emulate + Correlate Live</button>
    <button class="btn danger" onclick="abortSession()" style="margin-left:8px">■ Abort Session</button>
    <div id="lmep-result"></div>
  </div>
</div>

<!-- IRV -->
<div id="tab-irv" class="tab">
  <h2>IRV — Incident Remediation Validator</h2>
  <div class="grid2">
    <div class="card">
      <h3>Trigger Validation</h3>
      <label>Incident ID</label><input id="i-id" value="INC-2025-001"/>
      <label>Incident Type</label>
      <select id="i-type">
        <option value="malware">malware</option>
        <option value="credential_compromise">credential_compromise</option>
        <option value="ransomware">ransomware</option>
        <option value="lateral_movement">lateral_movement</option>
        <option value="data_exfiltration">data_exfiltration</option>
        <option value="phishing">phishing</option>
        <option value="insider_threat">insider_threat</option>
      </select>
      <label>Affected Host IPs (comma-separated)</label>
      <input id="i-scope" value="192.168.10.100"/>
      <button class="btn" onclick="triggerIRV()">Trigger Validation</button>
    </div>
    <div class="card">
      <h3>Live Host Cleanliness Check</h3>
      <p style="color:var(--muted);font-size:12px;margin-bottom:8px">Query Elasticsearch directly to check if a host has active Suricata alerts right now.</p>
      <label>Host IP</label><input id="hc-ip" value="192.168.10.100"/>
      <label>Incident Type</label>
      <select id="hc-type">
        <option value="malware">malware</option><option value="credential_compromise">credential_compromise</option>
        <option value="lateral_movement">lateral_movement</option>
      </select>
      <label>Lookback Window (minutes)</label><input id="hc-window" value="10" type="number"/>
      <button class="btn secondary" onclick="liveHostCheck()">Check Host Now</button>
      <div id="hc-result" style="margin-top:10px"></div>
    </div>
  </div>
  <div class="card">
    <h3>Validation Jobs</h3>
    <div id="irv-jobs"><em style="color:var(--muted)">No jobs yet.</em></div>
  </div>
  <div class="card" id="irv-detail" style="display:none">
    <h3>Job Detail</h3><pre id="irv-detail-content"></pre>
  </div>
</div>

<!-- AESP -->
<div id="tab-aesp" class="tab">
  <h2>AESP — Attack Effectiveness Scoring</h2>
  <div class="grid2">
    <div class="card">
      <h3>Score Engagement</h3>
      <label>Select Engagement</label>
      <select id="a-eng"><option value="">— select —</option></select>
      <label>Incident Type (RS baseline)</label>
      <select id="a-type">
        <option value="default">default</option>
        <option value="malware">malware</option>
        <option value="lateral_movement">lateral_movement</option>
        <option value="credential_compromise">credential_compromise</option>
      </select>
      <button class="btn" onclick="scoreEngagement()">Calculate Score</button>
    </div>
    <div class="card" id="aesp-score-card">
      <h3>Score Result</h3>
      <div id="aesp-result"><em style="color:var(--muted)">Score an engagement to see results.</em></div>
    </div>
  </div>
  <div class="card" id="aesp-sub-card" style="display:none">
    <h3>Sub-Score Breakdown</h3>
    <div id="aesp-subs"></div>
  </div>
</div>

<!-- LIVE NETWORK -->
<div id="tab-live" class="tab">
  <h2>⚡ Live Network — Elasticsearch</h2>
  <div class="grid2">
    <div class="card">
      <h3>Recent Suricata Alerts</h3>
      <label>Source IP (optional)</label><input id="sur-src" placeholder="e.g. 192.168.10.50"/>
      <label>Dest IP (optional)</label><input id="sur-dst" placeholder="leave blank for all"/>
      <label>Window (seconds)</label><input id="sur-win" value="300" type="number"/>
      <button class="btn secondary" onclick="fetchSuricata()">Fetch Alerts</button>
      <div id="sur-results" style="margin-top:10px"></div>
    </div>
    <div class="card">
      <h3>Recent Zeek Connections</h3>
      <label>Source IP (optional)</label><input id="zeek-src" placeholder="e.g. 192.168.10.50"/>
      <label>Dest IP (optional)</label><input id="zeek-dst" placeholder="leave blank for all"/>
      <label>Dest Port (optional)</label><input id="zeek-port" placeholder="e.g. 445" type="number"/>
      <label>Window (seconds)</label><input id="zeek-win" value="300" type="number"/>
      <button class="btn secondary" onclick="fetchZeek()">Fetch Connections</button>
      <div id="zeek-results" style="margin-top:10px"></div>
    </div>
  </div>
  <div class="card">
    <h3>Elasticsearch Indices</h3>
    <button class="btn secondary" onclick="fetchIndices()">List Indices</button>
    <div id="indices-list" style="margin-top:10px"></div>
  </div>
  <div class="card">
    <h3>Filebeat Module Activity (last 1h)</h3>
    <div id="filebeat-stats"><em style="color:var(--muted)">Click Refresh Integration Status on Overview to load.</em></div>
  </div>
</div>

<!-- API -->
<div id="tab-api" class="tab">
  <h2>API Reference</h2>
  <div class="card">
    <table>
      <tr><th>Method</th><th>Path</th><th>Description</th></tr>
      <tr><td><span class="badge green">GET</span></td><td>/health</td><td>Platform health + ES status</td></tr>
      <tr><td><span class="badge blue">POST</span></td><td>/psil/engagements</td><td>Create PSIL engagement</td></tr>
      <tr><td><span class="badge blue">POST</span></td><td>/psil/engagements/{id}/scenarios</td><td>Add scenario</td></tr>
      <tr><td><span class="badge blue">POST</span></td><td>/aesp/score</td><td>Score engagement</td></tr>
      <tr><td><span class="badge blue">POST</span></td><td>/irv/validate</td><td>Trigger IRV validation</td></tr>
      <tr><td><span class="badge blue">POST</span></td><td>/lmep/sessions</td><td>Create LMEP session</td></tr>
      <tr><td><span class="badge blue">POST</span></td><td>/lmep/sessions/{id}/run</td><td>Run technique + live ES correlation</td></tr>
      <tr><td><span class="badge green">GET</span></td><td>/integrations/status</td><td>ES + Filebeat connectivity</td></tr>
      <tr><td><span class="badge green">GET</span></td><td>/integrations/indices</td><td>List ES indices</td></tr>
      <tr><td><span class="badge green">GET</span></td><td>/integrations/suricata/alerts</td><td>Query Suricata alerts</td></tr>
      <tr><td><span class="badge green">GET</span></td><td>/integrations/zeek/connections</td><td>Query Zeek connections</td></tr>
      <tr><td><span class="badge blue">POST</span></td><td>/integrations/irv/host-check</td><td>Live host cleanliness check</td></tr>
      <tr><td><span class="badge blue">POST</span></td><td>/integrations/lmep/correlate</td><td>Manual technique correlation</td></tr>
      <tr><td><span class="badge green">GET</span></td><td>/docs</td><td>Interactive OpenAPI (Swagger)</td></tr>
    </table>
    <p style="margin-top:12px;color:var(--muted);font-size:12px">Interactive docs: <a href="/docs" style="color:var(--accent)">/docs</a></p>
  </div>
</div>

</main>
<script>
const API='';
let currentEngId=null,currentSessionId=null;

function showTab(name,btn){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  if(btn) btn.classList.add('active');
  if(name==='lmep') loadTechniques();
  if(name==='aesp') refreshAespEngList();
  if(name==='psil') refreshPsilList();
}

function toast(msg,type='info'){
  const d=document.getElementById('msg');
  d.innerHTML=`<div class="alert ${type}">${msg}</div>`;
  setTimeout(()=>d.innerHTML='',4000);
}

async function api(method,path,body){
  const opts={method,headers:{'Content-Type':'application/json'}};
  if(body) opts.body=JSON.stringify(body);
  const r=await fetch(API+path,opts);
  const data=await r.json();
  if(!r.ok) throw new Error(data.detail||JSON.stringify(data));
  return data;
}

async function refreshIntegrationStatus(){
  try{
    const s=await api('GET','/integrations/status');
    const es=s.elasticsearch;
    const connected=es.connected!==false && !es.error;
    document.getElementById('es-dot').className=connected?'live-dot':'offline-dot';
    document.getElementById('es-label').textContent=connected
      ?`ES ${es.version||''} · ${es.cluster_name||''} · ${es.status||''}`
      :`ES offline: ${es.error||'unknown'}`;
    document.getElementById('es-label').style.color=connected?'var(--green)':'var(--red)';

    let html='<table><tr><th>Source</th><th>Events (last 1h)</th><th>Status</th></tr>';
    const mods=s.filebeat_modules||{};
    if(mods.error){
      html+=`<tr><td colspan="3" style="color:var(--red)">${mods.error}</td></tr>`;
    } else {
      for(const [mod,count] of Object.entries(mods)){
        html+=`<tr><td>${mod}</td><td>${count.toLocaleString()}</td><td><span class="badge green">active</span></td></tr>`;
      }
      if(!Object.keys(mods).length) html+='<tr><td colspan="3" style="color:var(--muted)">No events in last 1h — check Filebeat is running</td></tr>';
    }
    html+='</table>';
    document.getElementById('integration-status-panel').innerHTML=html;
    document.getElementById('filebeat-stats').innerHTML=html;
  }catch(e){
    document.getElementById('integration-status-panel').innerHTML=`<div class="alert error">Cannot reach PILA API: ${e.message}</div>`;
  }
}

async function refreshOverview(){
  try{
    const engs=await api('GET','/psil/engagements');
    document.getElementById('psil-stat').innerHTML=`<span class="badge blue">${engs.length} Engagement${engs.length!==1?'s':''}</span>`;
    const sessions=await api('GET','/lmep/sessions');
    document.getElementById('lmep-stat').innerHTML=`<span class="badge blue">${sessions.length} Session${sessions.length!==1?'s':''}</span>`;
    const jobs=await api('GET','/irv/jobs');
    const passed=jobs.filter(j=>j.status==='passed').length;
    document.getElementById('irv-stat').innerHTML=`<span class="badge blue">${jobs.length} Job${jobs.length!==1?'s':''}</span> <span class="badge green">${passed} Passed</span>`;
  }catch(e){}
}

async function refreshPsilList(){
  const engs=await api('GET','/psil/engagements');
  const el=document.getElementById('psil-list');
  if(!engs.length){el.innerHTML='<em style="color:var(--muted)">No engagements yet.</em>';return;}
  el.innerHTML=engs.map(e=>`
    <div style="padding:8px 0;border-bottom:1px solid var(--border)">
      <strong style="cursor:pointer;color:var(--accent)" onclick="selectEng('${e.engagement.engagement_id}','${e.engagement.name}')">${e.engagement.name}</strong>
      <span class="badge blue" style="margin-left:8px">${e.scenarios.length} scenarios</span>
    </div>`).join('');
}

function selectEng(id,name){
  currentEngId=id;
  document.getElementById('add-scenario-card').style.display='block';
  toast(`Selected: ${name}`,'info');
}

async function createEngagement(){
  try{
    const scope=document.getElementById('p-scope').value.split(',').map(s=>s.trim());
    const data=await api('POST','/psil/engagements',{
      name:document.getElementById('p-name').value,
      organization:document.getElementById('p-org').value,
      scope,tlp_marking:document.getElementById('p-tlp').value
    });
    currentEngId=data.engagement.engagement_id;
    toast(`Engagement created`,'success');
    refreshPsilList();
    document.getElementById('add-scenario-card').style.display='block';
  }catch(e){toast(e.message,'error');}
}

async function addScenario(){
  if(!currentEngId){toast('Select an engagement first','error');return;}
  try{
    await api('POST',`/psil/engagements/${currentEngId}/scenarios`,{
      name:document.getElementById('s-name').value,
      technique_id:document.getElementById('s-techid').value,
      tactic:document.getElementById('s-tactic').value,
      tool:document.getElementById('s-tool').value,
      detected:document.getElementById('s-detected').value==='true',
      outcome:document.getElementById('s-outcome').value,
      severity:document.getElementById('s-severity').value,
      gap_identified:document.getElementById('s-gap').value==='true',
    });
    toast('Scenario added!','success');
    refreshPsilList();
  }catch(e){toast(e.message,'error');}
}

async function loadTechniques(){
  const techs=await api('GET','/lmep/techniques');
  document.getElementById('technique-list').innerHTML=`<table>${techs.map(t=>`
    <tr><td><code style="color:var(--accent)">${t.technique_id}</code></td><td>${t.name}</td><td><span class="badge green">${t.tier}</span></td></tr>`).join('')}</table>`;
  const sel=document.getElementById('l-techid');
  sel.innerHTML=techs.map(t=>`<option value="${t.technique_id}">${t.technique_id} — ${t.name}</option>`).join('');
}

async function createSession(){
  try{
    const scope=document.getElementById('l-scope').value.split(',').map(s=>s.trim());
    const data=await api('POST','/lmep/sessions',{
      name:document.getElementById('l-name').value,
      scope,credential_mode:document.getElementById('l-cred').value,
      deployment_mode:document.getElementById('l-deploy').value,
    });
    currentSessionId=data.session_id;
    document.getElementById('l-target').value=scope[0]||'';
    document.getElementById('lmep-run-card').style.display='block';
    toast(`Session created`,'success');
    refreshEngDropdown();
  }catch(e){toast(e.message,'error');}
}

async function refreshEngDropdown(){
  const engs=await api('GET','/psil/engagements');
  const sel=document.getElementById('l-export-eng');
  sel.innerHTML='<option value="">— none —</option>'+
    engs.map(e=>`<option value="${e.engagement.engagement_id}">${e.engagement.name}</option>`).join('');
}

async function runTechnique(){
  if(!currentSessionId){toast('Create a session first','error');return;}
  const tid=document.getElementById('l-techid').value;
  const target=document.getElementById('l-target').value.trim();
  const resultEl=document.getElementById('lmep-result');
  resultEl.innerHTML=`<div class="alert info" style="margin-top:12px">⏳ Emulating ${tid} on ${target}... waiting for detection pipeline (15s)...</div>`;
  try{
    const result=await api('POST',`/lmep/sessions/${currentSessionId}/run`,{technique_id:tid,target});
    const exportEngId=document.getElementById('l-export-eng').value;
    if(exportEngId){
      await api('POST',`/lmep/sessions/${currentSessionId}/export-psil/${exportEngId}`);
    }
    const ld=result.live_detection||{};
    const detected=result.detected_by_defense;
    const sources=ld.detection_sources||[];
    resultEl.innerHTML=`
      <div class="card" style="margin-top:12px">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
          <strong>${result.technique_name||tid}</strong> → <code>${target}</code>
          <span class="badge ${detected?'green':'red'}">${detected?'✓ DETECTED':'✗ NOT DETECTED'}</span>
          ${sources.length?`<span style="color:var(--muted);font-size:12px">via ${sources.join(', ')}</span>`:''}
        </div>
        ${ld.suricata_alerts!==undefined?`
        <div style="display:flex;gap:20px;margin-bottom:10px">
          <div class="stat"><div class="val" style="font-size:20px;color:${ld.suricata_alerts>0?'var(--red)':'var(--green)'}">
            ${ld.suricata_alerts}</div><div class="lbl">Suricata Alerts</div></div>
          <div class="stat"><div class="val" style="font-size:20px">${ld.zeek_connections}</div><div class="lbl">Zeek Connections</div></div>
          <div class="stat"><div class="val" style="font-size:20px">${ld.packetbeat_flows}</div><div class="lbl">Packetbeat Flows</div></div>
        </div>`:''}
        <div style="color:var(--muted);font-size:12px">${result.telemetry_generated?result.telemetry_generated.join('<br>'):''}
        </div>
        <div style="color:var(--yellow);font-size:11px;margin-top:6px">
          ${result.safety_events?result.safety_events.join(' | '):''}
        </div>
        ${ld.top_alerts&&ld.top_alerts.length?`
        <div style="margin-top:10px"><strong style="font-size:12px">Top Suricata Alerts:</strong>
          ${ld.top_alerts.map(a=>`<div style="font-size:11px;color:var(--red);margin-top:4px">
            ⚠ ${a.alert_sig||'Unknown'} | ${a.src_ip}→${a.dst_ip}:${a.dst_port} [sev:${a.severity}]
          </div>`).join('')}
        </div>`:''}
      </div>`;
    toast(`${tid}: ${detected?'DETECTED by '+sources.join(', '):'NOT DETECTED'}`,detected?'success':'error');
    refreshOverview();
  }catch(e){
    resultEl.innerHTML=`<div class="alert error" style="margin-top:12px">${e.message}</div>`;
    toast(e.message,'error');
  }
}

async function abortSession(){
  if(!currentSessionId)return;
  await api('POST',`/lmep/sessions/${currentSessionId}/abort`);
  toast('Session aborted','info');
  currentSessionId=null;
  document.getElementById('lmep-run-card').style.display='none';
}

async function triggerIRV(){
  try{
    const scope=document.getElementById('i-scope').value.split(',').map(s=>s.trim());
    const job=await api('POST','/irv/validate',{
      incident_id:document.getElementById('i-id').value,
      incident_type:document.getElementById('i-type').value,
      affected_scope:scope,
    });
    toast(`Validation: ${job.status.toUpperCase()}`,job.status==='passed'?'success':'warn');
    refreshIRVJobs();
    showIRVDetail(job);
  }catch(e){toast(e.message,'error');}
}

async function liveHostCheck(){
  try{
    const result=await api('POST','/integrations/irv/host-check',{
      host_ip:document.getElementById('hc-ip').value,
      incident_type:document.getElementById('hc-type').value,
      window_minutes:parseInt(document.getElementById('hc-window').value),
    });
    document.getElementById('hc-result').innerHTML=`
      <div class="alert ${result.clean?'success':'error'}">
        ${result.summary}<br>
        <span style="font-size:12px">Suricata: ${result.suricata_alerts} alert(s) | Zeek: ${result.zeek_connections} conn(s)</span>
      </div>`;
  }catch(e){document.getElementById('hc-result').innerHTML=`<div class="alert error">${e.message}</div>`;}
}

async function refreshIRVJobs(){
  const jobs=await api('GET','/irv/jobs');
  const el=document.getElementById('irv-jobs');
  if(!jobs.length){el.innerHTML='<em style="color:var(--muted)">No jobs yet.</em>';return;}
  el.innerHTML=`<table><tr><th>Incident ID</th><th>Type</th><th>Status</th><th>Scope</th></tr>`+
    jobs.map(j=>`<tr>
      <td style="cursor:pointer;color:var(--accent)" onclick='showIRVDetail(${JSON.stringify(j)})'>${j.incident_id}</td>
      <td>${j.incident_type}</td>
      <td><span class="badge ${j.status==='passed'?'green':j.status==='failed'?'red':'yellow'}">${j.status.toUpperCase()}</span></td>
      <td style="color:var(--muted);font-size:12px">${(j.affected_scope||[]).join(', ')}</td>
    </tr>`).join('')+'</table>';
}

function showIRVDetail(job){
  document.getElementById('irv-detail').style.display='block';
  document.getElementById('irv-detail-content').textContent=JSON.stringify(job,null,2);
}

async function refreshAespEngList(){
  const engs=await api('GET','/psil/engagements');
  const sel=document.getElementById('a-eng');
  sel.innerHTML='<option value="">— select —</option>'+
    engs.map(e=>`<option value="${e.engagement.engagement_id}">${e.engagement.name} (${e.scenarios.length} scenarios)</option>`).join('');
}

async function scoreEngagement(){
  const engId=document.getElementById('a-eng').value;
  if(!engId){toast('Select an engagement','error');return;}
  try{
    const score=await api('POST','/aesp/score',{engagement_id:engId,incident_type:document.getElementById('a-type').value});
    const dmt=score.dmt,es=score.effectiveness_score;
    const color=es>=70?'var(--green)':es>=55?'var(--yellow)':'var(--red)';
    document.getElementById('aesp-result').innerHTML=`
      <div style="display:flex;align-items:center;gap:24px;margin-bottom:12px">
        <div class="stat"><div class="val" style="color:${color}">${es}</div><div class="lbl">Effectiveness Score</div></div>
        <div class="stat"><div class="val" style="font-size:22px;color:${color}">${dmt.tier}</div><div class="lbl">${dmt.label}</div></div>
      </div>
      <p style="color:var(--muted);font-size:12px">${dmt.description}</p>`;
    const subs=score.sub_scores;
    document.getElementById('aesp-sub-card').style.display='block';
    document.getElementById('aesp-subs').innerHTML=Object.entries(subs).map(([k,v])=>`
      <div style="margin-bottom:8px">
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--muted);font-size:12px">${k.replace(/_/g,' ').toUpperCase()}</span><strong>${v}</strong>
        </div>
        <div class="bar-wrap"><div class="bar" style="width:${v}%;background:${v>=70?'var(--green)':v>=40?'var(--yellow)':'var(--red)'}"></div></div>
      </div>`).join('');
    document.getElementById('aesp-stat').innerHTML=`<span class="badge blue">Last ES: ${es}</span> <span class="badge ${es>=70?'green':es>=40?'yellow':'red'}">${dmt.tier}</span>`;
    toast(`Scored: ES=${es} ${dmt.tier}`,'success');
  }catch(e){toast(e.message,'error');}
}

async function fetchSuricata(){
  try{
    const params=new URLSearchParams();
    const src=document.getElementById('sur-src').value.trim();
    const dst=document.getElementById('sur-dst').value.trim();
    const win=document.getElementById('sur-win').value;
    if(src) params.append('src_ip',src);
    if(dst) params.append('dst_ip',dst);
    params.append('window',win);
    const data=await api('GET',`/integrations/suricata/alerts?${params}`);
    const el=document.getElementById('sur-results');
    if(!data.alerts.length){el.innerHTML='<div class="alert info">No alerts found in this window.</div>';return;}
    el.innerHTML=`<div class="badge blue" style="margin-bottom:8px">${data.count} alert(s)</div>
      <table><tr><th>Time</th><th>Signature</th><th>Src→Dst</th><th>Sev</th></tr>`+
      data.alerts.map(a=>`<tr>
        <td style="font-size:11px;color:var(--muted)">${(a.timestamp||'').slice(11,19)}</td>
        <td style="color:var(--red)">${a.alert_sig||'—'}</td>
        <td style="font-size:11px">${a.src_ip||'?'}→${a.dst_ip||'?'}:${a.dst_port||'?'}</td>
        <td>${a.severity||'?'}</td>
      </tr>`).join('')+'</table>';
  }catch(e){document.getElementById('sur-results').innerHTML=`<div class="alert error">${e.message}</div>`;}
}

async function fetchZeek(){
  try{
    const params=new URLSearchParams();
    const src=document.getElementById('zeek-src').value.trim();
    const dst=document.getElementById('zeek-dst').value.trim();
    const port=document.getElementById('zeek-port').value.trim();
    const win=document.getElementById('zeek-win').value;
    if(src) params.append('src_ip',src);
    if(dst) params.append('dst_ip',dst);
    if(port) params.append('dst_port',port);
    params.append('window',win);
    const data=await api('GET',`/integrations/zeek/connections?${params}`);
    const el=document.getElementById('zeek-results');
    if(!data.connections.length){el.innerHTML='<div class="alert info">No connections found.</div>';return;}
    el.innerHTML=`<div class="badge blue" style="margin-bottom:8px">${data.count} connection(s)</div>
      <table><tr><th>Time</th><th>Src→Dst</th><th>Port</th><th>Proto</th><th>Bytes</th></tr>`+
      data.connections.map(c=>`<tr>
        <td style="font-size:11px;color:var(--muted)">${(c.timestamp||'').slice(11,19)}</td>
        <td style="font-size:11px">${c.src_ip||'?'}→${c.dst_ip||'?'}</td>
        <td>${c.dst_port||'?'}</td>
        <td>${c.proto||'?'}</td>
        <td style="font-size:11px">${c.bytes_out||0}↑/${c.bytes_in||0}↓</td>
      </tr>`).join('')+'</table>';
  }catch(e){document.getElementById('zeek-results').innerHTML=`<div class="alert error">${e.message}</div>`;}
}

async function fetchIndices(){
  try{
    const data=await api('GET','/integrations/indices');
    document.getElementById('indices-list').innerHTML=`
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">
        ${data.indices.map(i=>`<span class="badge blue">${i}</span>`).join('')}
      </div>`;
  }catch(e){document.getElementById('indices-list').innerHTML=`<div class="alert error">${e.message}</div>`;}
}

// Init
refreshOverview();
refreshIntegrationStatus();
</script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
