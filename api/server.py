"""
PILA Suite — Community Edition API
© 2026 ByTE X Bit Technologies LLC — Patent Pending

This is the Community Edition server. It provides:
  - PSIL engagement creation and management
  - Basic AESP scoring interface
  - License status endpoint

Professional Edition adds:
  - LMEP lateral movement emulation
  - IRV incident remediation validation
  - Live Elasticsearch correlation
  - ATT&CK coverage heatmap
  - Full AESP scoring engine

Visit pilasuit.com to upgrade.
"""
import sys
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, ".."))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List
import uvicorn

from shared.license_check import check_license, get_license, has_feature
LICENSE = check_license()

from psil.psil_sdk.models import (
    Engagement, Scenario, Attack, Defense, Outcome, Severity,
    TLPMarking
)
from psil.psil_sdk.validator import PSILValidator
from aesp.aesp_score import AESPScoringEngine

app = FastAPI(
    title="PILA Suite API — Community Edition",
    description="PSIL · AESP — Community Edition. Upgrade at pilasuit.com for full platform access.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

psil_store: dict[str, dict] = {}
aesp_engine = AESPScoringEngine()
validator = PSILValidator()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "suite": "PILA Suite v1.0.0 — Community Edition",
        "edition": "community",
        "upgrade_url": "https://pilasuit.com",
    }


@app.get("/license")
def license_status():
    return get_license().summary()


# ── PSIL ─────────────────────────────────────────────────────────────────────

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


# ── AESP (basic — Professional required for full scoring) ─────────────────────

class ScoreRequest(BaseModel):
    engagement_id: str
    incident_type: str = "default"

@app.post("/aesp/score")
def score_engagement(req: ScoreRequest):
    raise HTTPException(
        status_code=403,
        detail={
            "error": "professional_required",
            "message": "AESP scoring engine requires PILA Suite Professional.",
            "upgrade_url": "https://pilasuit.com",
        }
    )

@app.get("/aesp/score/{engagement_id}")
def get_score(engagement_id: str):
    raise HTTPException(
        status_code=403,
        detail={"error": "professional_required", "upgrade_url": "https://pilasuit.com"}
    )


# ── Professional feature stubs ────────────────────────────────────────────────

def _pro_required():
    raise HTTPException(
        status_code=403,
        detail={
            "error": "professional_required",
            "message": "This feature requires PILA Suite Professional.",
            "upgrade_url": "https://pilasuit.com",
        }
    )

@app.post("/lmep/sessions")
def create_lmep_session(req: dict): _pro_required()

@app.get("/lmep/sessions")
def list_lmep_sessions(): return []

@app.get("/lmep/techniques")
def list_techniques():
    return [
        {"technique_id": "T1021.001", "name": "Remote Services: RDP",          "tier": "professional"},
        {"technique_id": "T1021.002", "name": "SMB/Windows Admin Shares",      "tier": "professional"},
        {"technique_id": "T1021.003", "name": "DCOM Lateral Movement",         "tier": "professional"},
        {"technique_id": "T1021.004", "name": "Remote Services: SSH",          "tier": "professional"},
        {"technique_id": "T1021.006", "name": "Windows Remote Management",     "tier": "professional"},
        {"technique_id": "T1135",     "name": "Network Share Discovery",       "tier": "professional"},
        {"technique_id": "T1534",     "name": "Internal Spearphishing",        "tier": "professional"},
        {"technique_id": "T1550.002", "name": "Pass-the-Hash (traffic shape)", "tier": "professional"},
    ]

@app.post("/irv/validate")
def trigger_irv(req: dict): _pro_required()

@app.get("/irv/jobs")
def list_irv_jobs(): _pro_required()

@app.get("/irv/incident-types")
def get_incident_types():
    return ["malware","credential_compromise","ransomware","lateral_movement",
            "data_exfiltration","phishing","insider_threat"]

@app.get("/integrations/status")
def integration_status():
    return {"message": "Live ES integration requires PILA Suite Professional.",
            "upgrade_url": "https://pilasuit.com"}

@app.get("/integrations/suricata/alerts")
def get_suricata_alerts(): _pro_required()

@app.get("/integrations/zeek/connections")
def get_zeek_connections(): _pro_required()

@app.post("/integrations/irv/host-check")
def live_host_check(body: dict): _pro_required()

@app.post("/integrations/lmep/correlate")
def correlate_technique(body: dict): _pro_required()

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """<!DOCTYPE html>
<html><head><title>PILA Suite — Community Edition</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .box{text-align:center;max-width:480px;padding:40px}
  h1{color:#58a6ff;font-size:28px;margin-bottom:8px}
  p{color:#8b949e;line-height:1.6}
  .badge{background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.3);
         color:#58a6ff;padding:4px 12px;border-radius:20px;font-size:13px;
         display:inline-block;margin-bottom:24px}
  a.btn{background:#58a6ff;color:#0d1117;padding:12px 28px;border-radius:8px;
        text-decoration:none;font-weight:700;display:inline-block;margin-top:16px}
  .api{margin-top:24px;font-size:13px;color:#58a6ff}
  .api a{color:#58a6ff}
</style></head>
<body><div class="box">
  <h1>⚔ PILA Suite</h1>
  <div class="badge">Community Edition</div>
  <p>Purple Intelligence & Lifecycle Automation</p>
  <p style="margin-top:16px">PSIL engagement creation and management are available in the Community edition.
  Upgrade to Professional for LMEP emulation, IRV validation, live ES correlation,
  ATT&CK heatmap, and AESP scoring.</p>
  <a class="btn" href="https://pilasuit.com">Upgrade to Professional →</a>
  <div class="api"><a href="/docs">API Documentation</a></div>
</div></body></html>"""

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
