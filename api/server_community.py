"""
PILA Suite — Community Edition Server
Purple Intelligence & Lifecycle Automation

This is the open-source community server. It provides:
- Full PSIL engagement documentation framework
- Basic AESP scoring
- GHOST coverage state read-only access
- SENTINEL SCORE read-only access
- Clean upgrade paths to Professional Edition

Professional Edition adds: LMEP emulation, IRV validation, live ES
correlation, CODE Suite (DRIFT/OBSERVER/CHAIN/EVIDENCE), GHOST sync,
SENTINEL evidence submission, report generation, and more.

License: Apache 2.0
© 2026 ByTE X Bit Technologies LLC — Patent Pending
"""
import os
import json
import configparser
import hashlib
import math
import shutil
from datetime import datetime, timezone
from uuid import uuid4
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title="ByTE X Bit Platform — Community Edition",
    description="Integrated Purple & Blue Team Security Automation",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Config ────────────────────────────────────────────────────
_BASE    = Path(__file__).parent.parent
_CONF    = _BASE / "integrations" / "pila.conf"
_DATA    = _BASE / "data"
_DATA.mkdir(exist_ok=True)

_cfg = configparser.ConfigParser()
_cfg.read(_CONF)

_API_KEY      = _cfg.get("api", "api_key", fallback="")
_REQUIRE_AUTH = _cfg.get("api", "require_auth", fallback="false").lower() == "true"
_LICENSE_URL  = _cfg.get("license", "api_url", fallback="http://127.0.0.1:8001")

# ── Community feature set ─────────────────────────────────────
COMMUNITY_FEATURES = {
    "psil_basic", "aesp_basic", "api_read",
}

PROFESSIONAL_FEATURES = {
    "psil_advanced", "aesp_full", "lmep_full", "irv_full",
    "report_generation", "attck_heatmap", "api_write",
    "es_integration", "code_observer", "code_drift",
    "code_chain", "code_evidence",
}

# ── Exempt routes (no auth required) ─────────────────────────
_EXEMPT = {"/health", "/", "/pila", "/docs", "/openapi.json",
           "/redoc", "/ghost", "/sentinel"}

# ── License validation ────────────────────────────────────────
import contextvars as _cv
_request_features = _cv.ContextVar("request_features",
                                    default=COMMUNITY_FEATURES)

def _validate_key(key: str) -> dict:
    """Validate API key — master key or license key."""
    if key == _API_KEY and _API_KEY:
        return {"valid": True, "tier": "professional",
                "features": COMMUNITY_FEATURES | PROFESSIONAL_FEATURES,
                "is_master": True}
    # Try license API
    try:
        import urllib.request as _ur
        payload = json.dumps(
            {"key": key, "product": "pila_suite"}).encode()
        req = _ur.Request(
            f"{_LICENSE_URL}/license/validate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST")
        resp = json.loads(_ur.urlopen(req, timeout=2).read())
        if resp.get("valid"):
            features = set(resp.get("features", []))
            return {"valid": True, "tier": resp["tier"],
                    "features": features, "is_master": False}
    except Exception:
        pass
    return {"valid": False, "tier": "none",
            "features": set(), "is_master": False}

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path in _EXEMPT or \
       request.url.path.startswith("/static"):
        _request_features.set(COMMUNITY_FEATURES)
        return await call_next(request)
    if _REQUIRE_AUTH and _API_KEY:
        key = request.headers.get("X-API-Key", "")
        if not key:
            return JSONResponse(status_code=401,
                content={"detail": "Missing X-API-Key header."})
        info = _validate_key(key)
        if not info["valid"]:
            return JSONResponse(status_code=401,
                content={"detail": "Invalid API key."})
        _request_features.set(info["features"])
    else:
        # No auth configured — community access
        _request_features.set(COMMUNITY_FEATURES)
    return await call_next(request)

def _gate(feature: str, label: str):
    """Block access if feature not in current request's feature set."""
    features = _request_features.get(COMMUNITY_FEATURES)
    if feature not in features:
        raise HTTPException(status_code=403, detail={
            "error": "license_required",
            "message": f"'{label}' requires Professional Edition.",
            "upgrade_url": "https://byte-x-bit.com",
            "current_tier": "community",
        })

# ── PSIL Store ────────────────────────────────────────────────
_PSIL_PATH = _DATA / "engagements.json"

def _psil_load() -> dict:
    if not _PSIL_PATH.exists():
        return {}
    try:
        data = json.loads(_PSIL_PATH.read_text())
        return {d["engagement"]["engagement_id"]: d for d in data}
    except Exception:
        return {}

def _psil_save(store: dict):
    _PSIL_PATH.parent.mkdir(parents=True, exist_ok=True)
    _PSIL_PATH.write_text(
        json.dumps(list(store.values()), indent=2))

def _bootstrap_demo_data_if_empty():
    """If data/engagements.json does not exist, populate from demo/sample_data/.
    Creates a marker file so the dashboard knows demo mode is active.
    No-op if engagements.json already exists (user has real or prior data)."""
    if _PSIL_PATH.exists():
        return
    demo_src = _BASE / "demo" / "sample_data" / "engagements.json"
    if not demo_src.exists():
        return
    _PSIL_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(demo_src, _PSIL_PATH)
    marker = _DATA / ".demo_loaded"
    marker.write_text(datetime.now(timezone.utc).isoformat() + "\n")
_bootstrap_demo_data_if_empty()
def _is_demo_mode() -> bool:
    """True iff data/.demo_loaded marker exists. Used by route handlers
    to inject the Demo Mode banner."""
    return (_DATA / ".demo_loaded").exists()

DEMO_BANNER_HTML = (
    '<div class="demo-mode-bar">'
      '<span class="badge yellow">DEMO MODE</span>'
      '<span style="color:var(--muted)">Showing synthetic data from a fictional SOC — '
      'useful for evaluation, not real engagements.</span>'
      '<a href="#" onclick="clearDemoData();return false;" '
        'style="margin-left:auto;color:var(--yellow);font-size:12px">'
        'Clear and start fresh \u2192</a>'
    '</div>'
    '<script>'
    'async function clearDemoData(){'
    'if(!confirm("Clear all demo data? You will start with an empty platform."))return;'
    'try{'
    'const r=await fetch("/demo/clear",{method:"POST"});'
    'if(r.ok){location.reload();}else{alert("Failed to clear demo data: "+r.status);}'
    '}catch(e){alert("Network error: "+e.message);}'
    '}'
    '</script>'
)

@app.post("/demo/clear")
def clear_demo_data():
    """Clear demo data and exit demo mode. Refuses if not currently in
    demo mode (protects against accidentally deleting real user data)."""
    if not _is_demo_mode():
        raise HTTPException(status_code=400, detail="Not in demo mode")
    # Delete the engagements file and marker; reset in-memory store
    if _PSIL_PATH.exists():
        _PSIL_PATH.unlink()
    marker = _DATA / ".demo_loaded"
    if marker.exists():
        marker.unlink()
    global psil_store
    psil_store = {}
    return {"status": "cleared", "message": "Demo data cleared."}
psil_store = _psil_load()

# ── Health ────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "suite": "ByTE X Bit Platform v1.0.0 — Community Edition",
        "edition": "community",
        "components": {
            "psil": "online",
            "aesp": "basic",
            "irv": "professional_only",
            "lmep": "professional_only",
        },
        "upgrade_url": "https://byte-x-bit.com",
    }

@app.get("/license")
def license_info():
    key = ""
    if _CONF.exists():
        c = configparser.ConfigParser()
        c.read(_CONF)
        key = c.get("api", "api_key", fallback="")
    info = _validate_key(key) if key else {
        "valid": False, "tier": "community", "features": list(COMMUNITY_FEATURES)}
    return {
        "valid": info["valid"],
        "tier": info.get("tier", "community"),
        "features": list(info.get("features", COMMUNITY_FEATURES)),
        "edition": "community",
        "upgrade_url": "https://byte-x-bit.com",
    }

# ── PSIL ──────────────────────────────────────────────────────
@app.post("/psil/engagements")
def create_engagement(payload: dict):
    _gate("psil_basic", "PSIL Engagement Creation")
    now = datetime.now(timezone.utc).isoformat()
    eid = f"eng-{uuid4()}"
    doc = {
        "psil_version": "1.0.0",
        "document_id":  f"psil-{uuid4()}",
        "created":      now,
        "modified":     now,
        "classification": payload.get("tlp_marking", "TLP:AMBER"),
        "engagement": {
            "engagement_id": eid,
            "name":          payload.get("name", ""),
            "organization":  payload.get("organization", ""),
            "start_date":    payload.get("start_date"),
            "end_date":      payload.get("end_date"),
            "scope":         payload.get("scope", []),
            "team":          payload.get("team", []),
            "frameworks":    payload.get("frameworks", []),
            "tags":          payload.get("tags", []),
            "tlp_marking":   payload.get("tlp_marking", "TLP:AMBER"),
        },
        "scenarios":       [],
        "metrics": {
            "total_scenarios": 0,
            "detection_rate":  0.0,
            "prevention_rate": 0.0,
            "gaps_identified": 0,
        },
        "lessons_learned": [],
        "extensions":      {},
    }
    psil_store[eid] = doc
    _psil_save(psil_store)
    return doc

@app.get("/psil/engagements")
def list_engagements():
    _gate("psil_basic", "PSIL Engagement List")
    return list(psil_store.values())

@app.get("/psil/engagements/{engagement_id}")
def get_engagement(engagement_id: str):
    _gate("psil_basic", "PSIL Engagement")
    if engagement_id not in psil_store:
        raise HTTPException(404, "Engagement not found")
    return psil_store[engagement_id]

@app.post("/psil/engagements/{engagement_id}/scenarios")
def add_scenario(engagement_id: str, payload: dict):
    _gate("psil_basic", "PSIL Scenario")
    if engagement_id not in psil_store:
        raise HTTPException(404, "Engagement not found")
    doc = psil_store[engagement_id]
    scenario = {
        "scenario_id":       f"scen-{uuid4()}",
        "name":              payload.get("name", ""),
        "attack": {
            "technique_id":  payload.get("technique_id", ""),
            "tactic":        payload.get("tactic", ""),
        },
        "defense": {
            "detected":      payload.get("detected", False),
        },
        "outcome":           payload.get("outcome", "not_detected"),
        "severity":          payload.get("severity", "MEDIUM"),
        "tools":             payload.get("tools", []),
        "detection_sources": payload.get("detection_sources", []),
        "notes":             payload.get("notes", ""),
        "created_at":        datetime.now(timezone.utc).isoformat(),
    }
    doc["scenarios"].append(scenario)
    doc["metrics"]["total_scenarios"] = len(doc["scenarios"])
    psil_store[engagement_id] = doc
    _psil_save(psil_store)
    return scenario

@app.post("/psil/validate/{engagement_id}")
def validate_engagement(engagement_id: str):
    _gate("psil_basic", "PSIL Validation")
    if engagement_id not in psil_store:
        raise HTTPException(404, "Engagement not found")
    doc  = psil_store[engagement_id]
    eng  = doc["engagement"]
    errs = []
    if not eng.get("name"):
        errs.append("engagement.name is required")
    if not eng.get("organization"):
        errs.append("engagement.organization is required")
    if not eng.get("scope"):
        errs.append("engagement.scope must have at least one entry")
    for s in doc.get("scenarios", []):
        tid = s.get("attack", {}).get("technique_id", "")
        if tid and not (tid.startswith("T") and len(tid) >= 5):
            errs.append(f"Invalid technique_id: {tid}")
    return {
        "valid":      len(errs) == 0,
        "errors":     errs,
        "engagement": eng["name"],
        "scenarios":  len(doc.get("scenarios", [])),
    }

# ── AESP Basic ────────────────────────────────────────────────
@app.post("/aesp/score")
def score_engagement(payload: dict):
    _gate("aesp_basic", "AESP Basic Scoring")
    eid = payload.get("engagement_id", "")
    if eid not in psil_store:
        raise HTTPException(404, f"Engagement {eid} not found")
    doc       = psil_store[eid]
    scenarios = doc.get("scenarios", [])
    if not scenarios:
        raise HTTPException(400, "No scenarios to score")
    total     = len(scenarios)
    detected  = sum(1 for s in scenarios
                    if s.get("defense", {}).get("detected"))
    prevented = sum(1 for s in scenarios
                    if s.get("outcome") in
                    ("prevented", "detected_and_blocked"))
    de  = round(detected  / total * 100, 1) if total else 0
    pr  = round(prevented / total * 100, 1) if total else 0
    es  = round((de * 0.4) + (pr * 0.2) + 50, 1)
    es  = min(100.0, max(0.0, es))
    if es >= 85:
        dmt = {"tier": "DMT-5", "label": "Optimized"}
    elif es >= 70:
        dmt = {"tier": "DMT-4", "label": "Advanced"}
    elif es >= 55:
        dmt = {"tier": "DMT-3", "label": "Developing"}
    elif es >= 40:
        dmt = {"tier": "DMT-2", "label": "Basic"}
    else:
        dmt = {"tier": "DMT-1", "label": "Initial"}
    result = {
        "engagement_id":      eid,
        "engagement_name":    doc["engagement"]["name"],
        "effectiveness_score": es,
        "dmt":                dmt,
        "sub_scores": {
            "detection_efficacy": de,
            "prevention_rate":    pr,
        },
        "scenario_count":     total,
        "note": "Basic scoring — upgrade to Professional for full AESP with Coverage Breadth, Response Speed, Remediation Quality, and historical trending.",
        "upgrade_url": "https://byte-x-bit.com",
    }
    doc["extensions"]["aesp_score"] = result
    psil_store[eid] = doc
    _psil_save(psil_store)
    return result

@app.get("/aesp/score/{engagement_id}")
def get_score(engagement_id: str):
    _gate("aesp_basic", "AESP Score")
    if engagement_id not in psil_store:
        raise HTTPException(404, "Engagement not found")
    score = psil_store[engagement_id].get(
        "extensions", {}).get("aesp_score")
    if not score:
        raise HTTPException(404, "No score yet. POST to /aesp/score first.")
    return score

# ── Professional gates ────────────────────────────────────────
@app.get("/lmep/techniques")
def lmep_techniques():
    # Technique list is free — execution requires Professional
    return {
        "available_techniques": [
            {"id": "T1046",     "name": "Network Service Discovery"},
            {"id": "T1021.004", "name": "Remote Services: SSH"},
            {"id": "T1021.001", "name": "Remote Services: RDP"},
            {"id": "T1021.002", "name": "Remote Services: SMB"},
            {"id": "T1110",     "name": "Brute Force"},
            {"id": "T1078",     "name": "Valid Accounts"},
            {"id": "T1021.006", "name": "Windows Remote Management"},
            {"id": "T1550.002", "name": "Pass the Hash"},
        ],
        "note": "Technique execution requires Professional Edition.",
        "upgrade_url": "https://byte-x-bit.com",
    }

@app.post("/lmep/sessions")
def lmep_sessions():
    _gate("lmep_full", "LMEP Emulation")
    return {}

@app.get("/irv/incident-types")
def irv_incident_types():
    return {
        "incident_types": [
            "credential_compromise", "lateral_movement",
            "data_exfiltration", "malware_infection",
            "ransomware", "insider_threat", "phishing",
        ],
        "note": "IRV validation requires Professional Edition.",
        "upgrade_url": "https://byte-x-bit.com",
    }

@app.post("/irv/jobs")
def irv_jobs():
    _gate("irv_full", "IRV Validation")
    return {}

# ── GHOST read-only ───────────────────────────────────────────
_GHOST_PATH = _DATA / "ghost" / "coverage_states.json"
_GHOST_ALERTS = _DATA / "ghost" / "regression_alerts.json"

def _ghost_stats():
    if not _GHOST_PATH.exists():
        return {"total_techniques": 0, "covered": 0, "partial": 0,
                "not_covered": 0, "coverage_percentage": 0.0,
                "validated": 0, "asserted": 0}
    states = json.loads(_GHOST_PATH.read_text())
    current = {}
    for s in states:
        if not s.get("superseded"):
            current[s["technique_id"]] = s
    total   = len(current)
    covered = sum(1 for s in current.values()
                  if s.get("coverage_status") == "covered")
    partial = sum(1 for s in current.values()
                  if s.get("coverage_status") == "partial")
    not_cov = sum(1 for s in current.values()
                  if s.get("coverage_status") == "not_covered")
    valid   = sum(1 for s in current.values()
                  if s.get("confidence") == "validated")
    assert_ = sum(1 for s in current.values()
                  if s.get("confidence") == "asserted")
    pct     = round((covered + partial) / total * 100, 1) if total else 0.0
    return {"total_techniques": total, "covered": covered,
            "partial": partial, "not_covered": not_cov,
            "coverage_percentage": pct, "validated": valid,
            "asserted": assert_}

def _ghost_dds(stats):
    total = stats["total_techniques"]
    if not total:
        return 0.0
    debt = (stats["not_covered"] * 1.0 +
            stats["partial"] * 0.5 +
            (stats["asserted"] * 0.2))
    return round(max(0, min(100, 100 - debt / total * 100)), 1)

def _ghost_cml(dds):
    if dds >= 85: return {"level": "CML-5", "label": "Optimized"}
    if dds >= 70: return {"level": "CML-4", "label": "Proactive"}
    if dds >= 55: return {"level": "CML-3", "label": "Defined"}
    if dds >= 40: return {"level": "CML-2", "label": "Reactive"}
    return           {"level": "CML-1", "label": "Ad Hoc"}

@app.get("/ghost/dashboard")
def ghost_dashboard():
    stats  = _ghost_stats()
    dds    = _ghost_dds(stats)
    cml    = _ghost_cml(dds)
    alerts = []
    if _GHOST_ALERTS.exists():
        all_alerts = json.loads(_GHOST_ALERTS.read_text())
        alerts = [a for a in all_alerts if not a.get("resolved")][-20:]
    return {
        "dds": dds, "cml": cml,
        "coverage_stats": stats,
        "open_alerts": len(alerts),
        "alerts": alerts,
        "note": "Read-only. GHOST sync and regression detection require Professional Edition.",
        "upgrade_url": "https://byte-x-bit.com",
    }

@app.get("/ghost/stats")
def ghost_stats():
    stats = _ghost_stats()
    dds   = _ghost_dds(stats)
    return {**stats, "dds": dds, "cml": _ghost_cml(dds)}

@app.post("/ghost/sync")
def ghost_sync():
    _gate("code_drift", "GHOST Sync")
    return {}

@app.post("/ghost/regression/check")
def ghost_regression():
    _gate("code_drift", "GHOST Regression Check")
    return {}

# ── SENTINEL read-only ────────────────────────────────────────
_SENTINEL_SCORES = _DATA / "sentinel" / "scores.json"
_SENTINEL_LEDGER = _DATA / "sentinel" / "evidence_ledger.json"

def _sentinel_latest():
    if not _SENTINEL_SCORES.exists():
        return None
    history = json.loads(_SENTINEL_SCORES.read_text())
    return history[-1] if history else None

@app.get("/sentinel/score/latest")
def sentinel_latest():
    score = _sentinel_latest()
    if not score:
        return {
            "sentinel_score": 0,
            "trust_rating": {"rating": "SS-F", "label": "Insufficient"},
            "sub_scores": {},
            "note": "No evidence submitted yet.",
            "upgrade_url": "https://byte-x-bit.com",
        }
    score["note"] = "Read-only. Evidence submission requires Professional Edition."
    score["upgrade_url"] = "https://byte-x-bit.com"
    return score

@app.post("/sentinel/sync")
def sentinel_sync():
    _gate("code_evidence", "SENTINEL Sync")
    return {}

@app.post("/sentinel/evidence/submit")
def sentinel_submit():
    _gate("code_evidence", "SENTINEL Evidence Submission")
    return {}

@app.post("/sentinel/score")
def sentinel_score():
    _gate("code_evidence", "SENTINEL Score Computation")
    return {}

# ── Dashboard pages ───────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
@app.get("/pila", response_class=HTMLResponse)
def dashboard():
    key = _cfg.get("api", "api_key", fallback="") if _CONF.exists() else ""
    html = _PILA_HTML.replace("const API='';", f"const API='{key}';")
    html = html.replace("<!-- DEMO_BANNER -->", DEMO_BANNER_HTML if _is_demo_mode() else "")
    return html

@app.get("/ghost", response_class=HTMLResponse)
def ghost_page():
    key = _cfg.get("api", "api_key", fallback="") if _CONF.exists() else ""
    html = _GHOST_HTML.replace("const API='';", f"const API='{key}';")
    html = html.replace("<!-- DEMO_BANNER -->", DEMO_BANNER_HTML if _is_demo_mode() else "")
    return html

@app.get("/sentinel", response_class=HTMLResponse)
def sentinel_page():
    key = _cfg.get("api", "api_key", fallback="") if _CONF.exists() else ""
    html = _SENTINEL_HTML.replace("const API='';", f"const API='{key}';")
    html = html.replace("<!-- DEMO_BANNER -->", DEMO_BANNER_HTML if _is_demo_mode() else "")
    return html

# ── Minimal dashboard HTML ────────────────────────────────────
_PILA_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ByTE X Bit Platform — Community Edition</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--accent:#2e86ab;
    --green:#3fb950;--red:#f85149;--yellow:#d29922;--text:#e6edf3;--muted:#8b949e}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:16px}
  header h1{font-size:20px;font-weight:700;color:var(--accent)}
  .demo-mode-bar{background:rgba(210,153,34,.15);border-bottom:1px solid rgba(210,153,34,.5);padding:8px 24px;font-size:12px;display:flex;align-items:center;gap:12px}
  .community-bar{background:rgba(210,153,34,.08);border-bottom:1px solid rgba(210,153,34,.3);padding:8px 24px;font-size:12px;display:flex;align-items:center;gap:12px}
  main{padding:24px;max-width:1200px;margin:0 auto}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
  h2{font-size:16px;font-weight:600;margin-bottom:12px}
  h3{font-size:13px;font-weight:600;color:var(--accent);margin-bottom:8px}
  label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px;margin-top:8px}
  input,select,textarea{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:6px;font-size:13px}
  button.btn{background:var(--accent);color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;margin-top:8px}
  button.btn.secondary{background:var(--border);color:var(--text)}
  button.btn.pro{background:var(--yellow);color:#0d1117}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
  .badge.green{background:rgba(63,185,80,.15);color:var(--green)}
  .badge.yellow{background:rgba(210,153,34,.15);color:var(--yellow)}
  .badge.gray{background:rgba(139,148,158,.15);color:var(--muted)}
  .badge.blue{background:rgba(46,134,171,.2);color:var(--accent)}
  .lock{opacity:.5;pointer-events:none;position:relative}
  .lock-label{font-size:11px;color:var(--yellow);margin-left:8px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;color:var(--muted);padding:8px;border-bottom:1px solid var(--border)}
  td{padding:8px;border-bottom:1px solid rgba(48,54,61,.5)}
  .alert{padding:10px 14px;border-radius:6px;margin-bottom:8px;font-size:13px}
  .alert.success{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.3);color:var(--green)}
  .alert.error{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);color:var(--red)}
  .alert.info{background:rgba(46,134,171,.1);border:1px solid rgba(46,134,171,.3);color:var(--accent)}
  #msg{position:fixed;top:20px;right:20px;z-index:999;min-width:240px}
  .suite-link{color:var(--muted);font-size:12px;text-decoration:none;padding:4px 10px;border:1px solid var(--border);border-radius:4px}
  .suite-link:hover{color:var(--text)}
  .pro-gate{background:rgba(210,153,34,.05);border:1px dashed rgba(210,153,34,.3);border-radius:8px;padding:16px;text-align:center}
</style>
</head>
<body>
<header>
  <h1>⚔ PILA Suite</h1>
  <span style="color:var(--muted);font-size:12px">Purple Intelligence &amp; Lifecycle Automation · Community Edition</span>
  <span style="margin-left:auto;display:flex;gap:12px">
    <a href="/ghost" class="suite-link">👻 GHOST</a>
    <a href="/sentinel" class="suite-link">🔒 SENTINEL</a>
  </span>
</header>
<!-- DEMO_BANNER -->
<div class="community-bar">
  <span class="badge yellow">COMMUNITY</span>
  <span style="color:var(--muted)">Free tier — PSIL + basic AESP included</span>
  <a href="https://byte-x-bit.com" style="margin-left:auto;color:var(--yellow);font-size:12px">Upgrade to Professional →</a>
</div>
<main>
<div id="msg"></div>
<div class="grid3" style="margin-bottom:16px">
  <div class="card" style="text-align:center">
    <div style="font-size:28px;font-weight:700;color:var(--accent)" id="eng-count">-</div>
    <div style="font-size:11px;color:var(--muted);margin-top:4px">Engagements</div>
  </div>
  <div class="card" style="text-align:center">
    <div style="font-size:28px;font-weight:700;color:var(--green)" id="scen-count">-</div>
    <div style="font-size:11px;color:var(--muted);margin-top:4px">Scenarios</div>
  </div>
  <div class="card" style="text-align:center">
    <div style="font-size:28px;font-weight:700;color:var(--yellow)" id="es-avg">-</div>
    <div style="font-size:11px;color:var(--muted);margin-top:4px">Avg ES Score</div>
  </div>
</div>
<div class="grid2">
  <div class="card">
    <h2>Create Engagement</h2>
    <label>Name</label>
    <input id="eng-name" placeholder="Q3 Purple Team Exercise">
    <label>Organization</label>
    <input id="eng-org" placeholder="Your Organization">
    <label>Scope (comma separated IPs/ranges)</label>
    <input id="eng-scope" placeholder="192.168.1.0/24, 10.0.0.0/8">
    <label>TLP Marking</label>
    <select id="eng-tlp">
      <option value="TLP:AMBER">TLP:AMBER (default)</option>
      <option value="TLP:WHITE">TLP:WHITE</option>
      <option value="TLP:GREEN">TLP:GREEN</option>
      <option value="TLP:RED">TLP:RED</option>
    </select>
    <button class="btn" onclick="createEngagement()">Create Engagement</button>
  </div>
  <div class="card">
    <h2>Add Scenario</h2>
    <label>Engagement</label>
    <select id="scen-eng"><option value="">— select engagement —</option></select>
    <label>Name</label>
    <input id="scen-name" placeholder="SSH Lateral Movement Test">
    <label>ATT&CK Technique ID</label>
    <input id="scen-tech" placeholder="T1021.004">
    <label>Tactic</label>
    <select id="scen-tactic">
      <option>Discovery</option><option>Lateral Movement</option>
      <option>Credential Access</option><option>Execution</option>
      <option>Persistence</option><option>Defense Evasion</option>
      <option>Collection</option><option>Exfiltration</option>
      <option>Impact</option><option>Initial Access</option>
    </select>
    <label>Outcome</label>
    <select id="scen-outcome">
      <option value="detected_not_blocked">Detected (not blocked)</option>
      <option value="detected_and_blocked">Detected and blocked</option>
      <option value="not_detected">Not detected</option>
      <option value="detected_late">Detected late</option>
      <option value="partial_detection">Partial detection</option>
      <option value="prevented">Prevented</option>
    </select>
    <label>Severity</label>
    <select id="scen-sev">
      <option value="HIGH">HIGH</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="MEDIUM" selected>MEDIUM</option>
      <option value="LOW">LOW</option>
    </select>
    <button class="btn" onclick="addScenario()">Add Scenario</button>
  </div>
</div>
<div class="card">
  <h2>Engagements</h2>
  <table>
    <thead><tr><th>Name</th><th>Org</th><th>Scenarios</th><th>ES</th><th>DMT</th><th>Actions</th></tr></thead>
    <tbody id="eng-table"></tbody>
  </table>
</div>
<div class="card pro-gate">
  <div style="font-size:32px;margin-bottom:8px">🔒</div>
  <h3 style="color:var(--yellow);font-size:14px">Professional Edition Features</h3>
  <p style="color:var(--muted);font-size:13px;margin:8px 0">LMEP adversary emulation · IRV incident validation · Live Elasticsearch correlation · CODE Suite (DRIFT/OBSERVER/CHAIN/EVIDENCE) · GHOST coverage tracking · SENTINEL vendor scoring · Full AESP with historical trending · ATT&CK heatmap · Report generation</p>
  <a href="https://byte-x-bit.com"><button class="btn pro" style="margin-top:12px">Upgrade to Professional — $149/month</button></a>
</div>
</main>
<script>
const API='';
function h(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function toast(msg,type='info'){
  const d=document.createElement('div');
  d.className='alert '+type;d.textContent=msg;
  document.getElementById('msg').appendChild(d);
  setTimeout(()=>d.remove(),4000);
}
const hdrs=()=>({'X-API-Key':API,'Content-Type':'application/json'});

async function loadEngagements(){
  try{
    const r=await fetch('/psil/engagements',{headers:{'X-API-Key':API}});
    const engs=await r.json();
    document.getElementById('eng-count').textContent=engs.length;
    let totalScen=0,totalES=0,esCount=0;
    const sel=document.getElementById('scen-eng');
    sel.innerHTML='<option value="">— select engagement —</option>';
    document.getElementById('eng-table').innerHTML=engs.map(e=>{
      const eng=e.engagement;
      const scens=e.scenarios||[];
      totalScen+=scens.length;
      const score=e.extensions?.aesp_score;
      if(score){totalES+=score.effectiveness_score;esCount++;}
      sel.innerHTML+=`<option value="${eng.engagement_id}">${h(eng.name)}</option>`;
      return `<tr>
        <td><strong>${h(eng.name)}</strong></td>
        <td style="color:var(--muted);font-size:12px">${h(eng.organization)}</td>
        <td>${scens.length}</td>
        <td style="color:${score?'var(--green)':'var(--muted)'}">${score?score.effectiveness_score:'—'}</td>
        <td>${score?`<span class="badge blue">${score.dmt?.tier||'?'}</span>`:'—'}</td>
        <td>
          <button class="btn secondary" style="padding:4px 8px;font-size:11px;margin:0"
            onclick="scoreEngagement('${eng.engagement_id}')">Score</button>
        </td>
      </tr>`;
    }).join('');
    document.getElementById('scen-count').textContent=totalScen;
    document.getElementById('es-avg').textContent=esCount?round1(totalES/esCount):'—';
  }catch(e){console.error(e);}
}

function round1(n){return Math.round(n*10)/10}

async function createEngagement(){
  const name=document.getElementById('eng-name').value.trim();
  const org=document.getElementById('eng-org').value.trim();
  const scope=document.getElementById('eng-scope').value.split(',').map(s=>s.trim()).filter(Boolean);
  const tlp=document.getElementById('eng-tlp').value;
  if(!name||!org){toast('Name and organization required','error');return;}
  const r=await fetch('/psil/engagements',{method:'POST',headers:hdrs(),
    body:JSON.stringify({name,organization:org,scope,tlp_marking:tlp})});
  const d=await r.json();
  toast(`Engagement created: ${d.engagement.name}`,'success');
  document.getElementById('eng-name').value='';
  document.getElementById('eng-org').value='';
  loadEngagements();
}

async function addScenario(){
  const eid=document.getElementById('scen-eng').value;
  const name=document.getElementById('scen-name').value.trim();
  const tech=document.getElementById('scen-tech').value.trim();
  const tactic=document.getElementById('scen-tactic').value;
  const outcome=document.getElementById('scen-outcome').value;
  const sev=document.getElementById('scen-sev').value;
  if(!eid||!name||!tech){toast('Engagement, name and technique required','error');return;}
  const detected=!['not_detected'].includes(outcome);
  const r=await fetch(`/psil/engagements/${eid}/scenarios`,{method:'POST',headers:hdrs(),
    body:JSON.stringify({name,technique_id:tech,tactic,detected,outcome,severity:sev})});
  const d=await r.json();
  toast(`Scenario added: ${d.name}`,'success');
  document.getElementById('scen-name').value='';
  document.getElementById('scen-tech').value='';
  loadEngagements();
}

async function scoreEngagement(eid){
  const r=await fetch('/aesp/score',{method:'POST',headers:hdrs(),
    body:JSON.stringify({engagement_id:eid})});
  const d=await r.json();
  if(d.error){toast(d.error,'error');return;}
  toast(`Scored: ES ${d.effectiveness_score} ${d.dmt?.tier}`,'success');
  loadEngagements();
}

loadEngagements();
setInterval(loadEngagements,30000);
</script>
</body>
</html>"""

_GHOST_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>GHOST — Community</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--accent:#8b5cf6;
    --green:#3fb950;--red:#f85149;--yellow:#d29922;--text:#e6edf3;--muted:#8b949e}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:16px}
  header h1{font-size:20px;font-weight:700;color:var(--accent)}
  .demo-mode-bar{background:rgba(210,153,34,.15);border-bottom:1px solid rgba(210,153,34,.5);padding:8px 24px;font-size:12px;display:flex;align-items:center;gap:12px}
  .community-bar{background:rgba(210,153,34,.08);border-bottom:1px solid rgba(210,153,34,.3);padding:8px 24px;font-size:12px;display:flex;align-items:center;gap:12px}
  main{padding:24px;max-width:1200px;margin:0 auto}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}
  .grid4{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:16px}
  h2{font-size:16px;font-weight:600;margin-bottom:12px}
  .stat{text-align:center}
  .stat .val{font-size:32px;font-weight:700}
  .stat .lbl{font-size:11px;color:var(--muted);margin-top:4px}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
  .badge.yellow{background:rgba(210,153,34,.15);color:var(--yellow)}
  .badge.green{background:rgba(63,185,80,.15);color:var(--green)}
  .pro-gate{background:rgba(139,92,246,.05);border:1px dashed rgba(139,92,246,.3);border-radius:8px;padding:16px;text-align:center;margin-top:16px}
  .suite-link{color:var(--muted);font-size:12px;text-decoration:none;padding:4px 10px;border:1px solid var(--border);border-radius:4px}
</style>
</head>
<body>
<header>
  <h1>👻 GHOST</h1>
  <span style="color:var(--muted);font-size:12px">Gap Heatmap &amp; Operational Simulation Tracker · Community</span>
  <span style="margin-left:auto;display:flex;gap:12px">
    <a href="/pila" class="suite-link">⚔ PILA</a>
    <a href="/sentinel" class="suite-link">🔒 SENTINEL</a>
  </span>
</header>
<!-- DEMO_BANNER -->
<div class="community-bar">
  <span class="badge yellow">COMMUNITY</span>
  <span style="color:var(--muted)">Read-only coverage view</span>
  <a href="https://byte-x-bit.com" style="margin-left:auto;color:var(--yellow);font-size:12px">Upgrade for full GHOST →</a>
</div>
<main>
<div class="grid4" style="margin-bottom:16px">
  <div class="card stat"><div class="val" id="dds" style="color:var(--accent)">-</div><div class="lbl">Detection Debt Score</div></div>
  <div class="card stat"><div class="val" id="cml">-</div><div class="lbl">Coverage Maturity</div></div>
  <div class="card stat"><div class="val" id="techniques" style="color:var(--green)">-</div><div class="lbl">Techniques Tracked</div></div>
  <div class="card stat"><div class="val" id="coverage" style="color:var(--green)">-</div><div class="lbl">Coverage %</div></div>
</div>
<div class="card">
  <h2>Coverage Summary</h2>
  <div id="summary" style="color:var(--muted)">Loading...</div>
</div>
<div class="pro-gate">
  <div style="font-size:32px;margin-bottom:8px">🔒</div>
  <p style="color:var(--muted);font-size:13px">GHOST sync from PSIL + DRIFT, regression detection, coverage timeline, and alert management require Professional Edition.</p>
  <a href="https://byte-x-bit.com"><button style="background:var(--accent);color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;margin-top:8px">Upgrade to Professional</button></a>
</div>
</main>
<script>
const API='';
async function load(){
  try{
    const r=await fetch('/ghost/dashboard',{headers:{'X-API-Key':API}});
    const d=await r.json();
    document.getElementById('dds').textContent=d.dds||0;
    document.getElementById('cml').textContent=d.cml?.level||'?';
    document.getElementById('techniques').textContent=d.coverage_stats?.total_techniques||0;
    document.getElementById('coverage').textContent=(d.coverage_stats?.coverage_percentage||0)+'%';
    const s=d.coverage_stats||{};
    document.getElementById('summary').innerHTML=`
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:8px">
        <div>Covered: <strong style="color:var(--green)">${s.covered||0}</strong></div>
        <div>Partial: <strong style="color:var(--yellow)">${s.partial||0}</strong></div>
        <div>Not Covered: <strong style="color:var(--red)">${s.not_covered||0}</strong></div>
        <div>Validated: <strong>${s.validated||0}</strong></div>
        <div>Asserted: <strong>${s.asserted||0}</strong></div>
        <div>Open Alerts: <strong style="color:var(--red)">${d.open_alerts||0}</strong></div>
      </div>`;
  }catch(e){document.getElementById('summary').textContent='No coverage data yet.';}
}
load();
</script>
</body>
</html>"""

_SENTINEL_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>SENTINEL SCORE — Community</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--accent:#e36d2e;
    --green:#3fb950;--red:#f85149;--yellow:#d29922;--text:#e6edf3;--muted:#8b949e}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:16px}
  header h1{font-size:20px;font-weight:700;color:var(--accent)}
  .demo-mode-bar{background:rgba(210,153,34,.15);border-bottom:1px solid rgba(210,153,34,.5);padding:8px 24px;font-size:12px;display:flex;align-items:center;gap:12px}
  .community-bar{background:rgba(210,153,34,.08);border-bottom:1px solid rgba(210,153,34,.3);padding:8px 24px;font-size:12px;display:flex;align-items:center;gap:12px}
  main{padding:24px;max-width:1200px;margin:0 auto}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}
  h2{font-size:16px;font-weight:600;margin-bottom:12px}
  .ss-score{font-size:72px;font-weight:700;text-align:center}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
  .badge.yellow{background:rgba(210,153,34,.15);color:var(--yellow)}
  .pro-gate{background:rgba(227,109,46,.05);border:1px dashed rgba(227,109,46,.3);border-radius:8px;padding:16px;text-align:center;margin-top:16px}
  .suite-link{color:var(--muted);font-size:12px;text-decoration:none;padding:4px 10px;border:1px solid var(--border);border-radius:4px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;color:var(--muted);padding:8px;border-bottom:1px solid var(--border)}
  td{padding:8px;border-bottom:1px solid rgba(48,54,61,.5)}
</style>
</head>
<body>
<header>
  <h1>🔒 SENTINEL SCORE</h1>
  <span style="color:var(--muted);font-size:12px">Security Evidence &amp; Network Threat Intelligence · Community</span>
  <span style="margin-left:auto;display:flex;gap:12px">
    <a href="/pila" class="suite-link">⚔ PILA</a>
    <a href="/ghost" class="suite-link">👻 GHOST</a>
  </span>
</header>
<!-- DEMO_BANNER -->
<div class="community-bar">
  <span class="badge yellow">COMMUNITY</span>
  <span style="color:var(--muted)">Read-only score view</span>
  <a href="https://byte-x-bit.com" style="margin-left:auto;color:var(--yellow);font-size:12px">Upgrade for full SENTINEL →</a>
</div>
<main>
<div class="card" style="text-align:center;padding:32px">
  <div id="ss-val" class="ss-score" style="color:var(--accent)">-</div>
  <div id="ss-rating" style="font-size:20px;color:var(--muted);margin-top:8px">Loading...</div>
</div>
<div class="card">
  <h2>Sub-Score Breakdown</h2>
  <table>
    <thead><tr><th>Sub-Score</th><th>Weight</th><th>Score</th></tr></thead>
    <tbody id="sub-table"></tbody>
  </table>
</div>
<div class="pro-gate">
  <div style="font-size:32px;margin-bottom:8px">🔒</div>
  <p style="color:var(--muted);font-size:13px">Evidence submission, score computation, evidence ledger, and score history require Professional Edition.</p>
  <a href="https://byte-x-bit.com"><button style="background:var(--accent);color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;margin-top:8px">Upgrade to Professional</button></a>
</div>
</main>
<script>
const API='';
async function load(){
  try{
    const r=await fetch('/sentinel/score/latest',{headers:{'X-API-Key':API}});
    const d=await r.json();
    const ss=d.sentinel_score||0;
    document.getElementById('ss-val').textContent=ss;
    const tr=d.trust_rating||{};
    document.getElementById('ss-rating').textContent=`${tr.rating||'?'} — ${tr.label||''}`;
    const subs=d.sub_scores||{};
    document.getElementById('sub-table').innerHTML=
      Object.entries(subs).map(([k,v])=>
        `<tr><td><strong>${k}</strong> ${v.label||''}</td>
         <td>${(v.weight*100).toFixed(0)}%</td>
         <td style="color:${v.score>=70?'var(--green)':v.score>=40?'var(--yellow)':'var(--red)'}">${v.score}</td></tr>`
      ).join('');
  }catch(e){document.getElementById('ss-rating').textContent='No data yet.';}
}
load();
</script>
</body>
</html>"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.server_community:app",
                host="0.0.0.0", port=8000, reload=False)
