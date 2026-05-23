"""
LMEP - Lateral Movement Emulation Proxy
Core Engine v1.0.0
Apache 2.0 License - PILA Suite

Safety-first lateral movement emulation.
All techniques emit behavioral signatures ONLY — no real payloads.
"""
from __future__ import annotations
import uuid
import json
import pathlib
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
from psil.psil_sdk.models import Scenario, Attack, Defense, Outcome, Severity


class CredentialMode(str, Enum):
    SYNTHETIC = "SYNTHETIC"
    READ_ONLY_HANDLE = "READ_ONLY_HANDLE"
    OPERATOR_CHOICE = "OPERATOR_CHOICE"


class DeploymentMode(str, Enum):
    PASSIVE = "PASSIVE"
    SEMI_ACTIVE = "SEMI_ACTIVE"
    ACTIVE = "ACTIVE"


class SafetyCheckStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass
class SafetyCheckResult:
    status: SafetyCheckStatus
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"status": self.status.value, "reasons": self.reasons}


@dataclass
class EmulationResult:
    technique_id: str
    technique_name: str
    session_id: str
    timestamp: datetime
    success: bool
    telemetry_generated: list[str]
    safety_events: list[str]
    detected_by_defense: bool = False
    detection_source: Optional[str] = None
    audit_log: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "telemetry_generated": self.telemetry_generated,
            "safety_events": self.safety_events,
            "detected_by_defense": self.detected_by_defense,
            "detection_source": self.detection_source,
            "audit_log": self.audit_log,
        }

    def to_psil_scenario(self) -> Scenario:
        """Convert emulation result to PSIL Scenario for AESP scoring."""
        outcome = Outcome.NOT_DETECTED
        if self.detected_by_defense:
            outcome = Outcome.DETECTED_NOT_BLOCKED

        return Scenario(
            name=self.technique_name,
            description=f"LMEP emulation of {self.technique_id}",
            attack=Attack(
                technique_id=self.technique_id,
                tactic=self._infer_tactic(),
                tool="LMEP",
                execution_timestamp=self.timestamp,
                execution_detail=f"Safe emulation. Telemetry: {'; '.join(self.telemetry_generated[:2])}",
            ),
            defense=Defense(
                detected=self.detected_by_defense,
                detection_source=self.detection_source,
                response_action="No action (emulation)" if not self.detected_by_defense else "Alert generated",
            ),
            outcome=outcome,
            severity=Severity.HIGH,
            gap_identified=not self.detected_by_defense,
            gap_detail=None if self.detected_by_defense else f"Technique {self.technique_id} not detected by current controls.",
        )

    def _infer_tactic(self) -> str:
        TACTIC_MAP = {
            "T1021": "Lateral Movement",
            "T1550": "Defense Evasion",
            "T1558": "Credential Access",
            "T1003": "Credential Access",
            "T1087": "Discovery",
            "T1135": "Discovery",
            "T1047": "Execution",
            "T1134": "Privilege Escalation",
            "T1572": "Command and Control",
            "T1534": "Lateral Movement",
            "T1552": "Credential Access",
        }
        prefix = self.technique_id[:5]
        return TACTIC_MAP.get(prefix, "Lateral Movement")


class TechniqueModule:
    """Base class for all LMEP technique modules."""
    technique_id: str = ""
    name: str = ""
    min_credential_mode: CredentialMode = CredentialMode.SYNTHETIC
    min_deployment_mode: DeploymentMode = DeploymentMode.PASSIVE
    reversible: bool = True
    tier: str = "oss"  # oss or commercial

    def preflight_check(self, session: "LMEPSession") -> SafetyCheckResult:
        reasons = []
        if CredentialMode[session.credential_mode.value].value < self.min_credential_mode.value:
            reasons.append(f"Requires credential mode >= {self.min_credential_mode.value}")
        if DeploymentMode[session.deployment_mode.value].value < self.min_deployment_mode.value:
            reasons.append(f"Requires deployment mode >= {self.min_deployment_mode.value}")
        if not session.scope:
            reasons.append("Session scope is empty")
        if reasons:
            return SafetyCheckResult(SafetyCheckStatus.BLOCK, reasons)
        return SafetyCheckResult(SafetyCheckStatus.PASS)

    def emulate(self, session: "LMEPSession", target: str) -> EmulationResult:
        raise NotImplementedError


# === OSS Technique Library ===

class SMBSharesTechnique(TechniqueModule):
    technique_id = "T1021.002"
    name = "SMB/Windows Admin Shares"
    tier = "oss"

    def emulate(self, session, target):
        telemetry = [
            f"SMB connection attempt to \\\\{target}\\ADMIN$",
            f"SMB share enumeration: IPC$, ADMIN$, C$",
            f"Auth: NTLM challenge-response traffic shape on port 445",
        ]
        return EmulationResult(
            technique_id=self.technique_id,
            technique_name=self.name,
            session_id=session.session_id,
            timestamp=datetime.now(timezone.utc),
            success=True,
            telemetry_generated=telemetry,
            safety_events=["No file access performed", "No credentials extracted"],
            detected_by_defense=session.simulate_detection(0.65),
            detection_source="EDR/Network IDS" if session.simulate_detection(0.65) else None,
        )


class RDPTechnique(TechniqueModule):
    technique_id = "T1021.001"
    name = "Remote Services: RDP"
    tier = "oss"

    def emulate(self, session, target):
        telemetry = [
            f"RDP negotiation to {target}:3389",
            "CredSSP NLA handshake traffic pattern",
            "RDP protocol header: TPKT/COTP layer emulated",
        ]
        return EmulationResult(
            technique_id=self.technique_id,
            technique_name=self.name,
            session_id=session.session_id,
            timestamp=datetime.now(timezone.utc),
            success=True,
            telemetry_generated=telemetry,
            safety_events=["No RDP session established", "No credentials submitted"],
            detected_by_defense=session.simulate_detection(0.55),
            detection_source="Network Sensor" if session.simulate_detection(0.55) else None,
        )


class PassTheHashShapeTechnique(TechniqueModule):
    technique_id = "T1550.002"
    name = "Pass-the-Hash (traffic shape)"
    tier = "oss"

    def emulate(self, session, target):
        telemetry = [
            f"NTLM authentication traffic shape to {target}",
            "Type 1 NEGOTIATE → Type 2 CHALLENGE → Type 3 AUTHENTICATE sequence",
            "NTLMv2 hash field: synthetic random bytes (not a real hash)",
        ]
        return EmulationResult(
            technique_id=self.technique_id,
            technique_name=self.name,
            session_id=session.session_id,
            timestamp=datetime.now(timezone.utc),
            success=True,
            telemetry_generated=telemetry,
            safety_events=["No real hash used", "Synthetic credential bytes only"],
            detected_by_defense=session.simulate_detection(0.50),
            detection_source="SIEM/EDR" if session.simulate_detection(0.50) else None,
        )


class SSHTechnique(TechniqueModule):
    technique_id = "T1021.004"
    name = "Remote Services: SSH"
    tier = "oss"

    def emulate(self, session, target):
        telemetry = [
            f"SSH handshake to {target}:22",
            "KEX_INIT: diffie-hellman-group14-sha256 negotiated",
            "Host key exchange: emulated banner exchange",
        ]
        return EmulationResult(
            technique_id=self.technique_id,
            technique_name=self.name,
            session_id=session.session_id,
            timestamp=datetime.now(timezone.utc),
            success=True,
            telemetry_generated=telemetry,
            safety_events=["No shell session established", "No authentication attempted"],
            detected_by_defense=session.simulate_detection(0.40),
            detection_source="Network IDS" if session.simulate_detection(0.40) else None,
        )


class WinRMTechnique(TechniqueModule):
    technique_id = "T1021.006"
    name = "Windows Remote Management"
    tier = "oss"

    def emulate(self, session, target):
        telemetry = [
            f"WinRM connection attempt to {target}:5985",
            "HTTP/SOAP envelope: WSMan protocol traffic",
            "Kerberos/NTLM auth challenge traffic shape",
        ]
        return EmulationResult(
            technique_id=self.technique_id,
            technique_name=self.name,
            session_id=session.session_id,
            timestamp=datetime.now(timezone.utc),
            success=True,
            telemetry_generated=telemetry,
            safety_events=["No remote command executed", "Authentication not completed"],
            detected_by_defense=session.simulate_detection(0.60),
            detection_source="EDR" if session.simulate_detection(0.60) else None,
        )


class NetworkShareDiscoveryTechnique(TechniqueModule):
    technique_id = "T1135"
    name = "Network Share Discovery"
    tier = "oss"

    def emulate(self, session, target):
        telemetry = [
            f"NetShareEnum broadcast on subnet containing {target}",
            "SMB port 445 sweep: 3 hosts in scope",
            "Share enumeration: passive observation only",
        ]
        return EmulationResult(
            technique_id=self.technique_id,
            technique_name=self.name,
            session_id=session.session_id,
            timestamp=datetime.now(timezone.utc),
            success=True,
            telemetry_generated=telemetry,
            safety_events=["Passive mode — no connections attempted"],
            detected_by_defense=session.simulate_detection(0.30),
            detection_source="SIEM" if session.simulate_detection(0.30) else None,
        )


class DCOMTechnique(TechniqueModule):
    technique_id = "T1021.003"
    name = "DCOM Lateral Movement"
    tier = "oss"

    def emulate(self, session, target):
        telemetry = [
            f"DCOM activation request to {target}:135",
            "MSRPC BIND: IRemoteSCMActivator interface",
            "DCE/RPC traffic: activation packet emulated",
        ]
        return EmulationResult(
            technique_id=self.technique_id,
            technique_name=self.name,
            session_id=session.session_id,
            timestamp=datetime.now(timezone.utc),
            success=True,
            telemetry_generated=telemetry,
            safety_events=["No remote code executed", "Activation request not completed"],
            detected_by_defense=session.simulate_detection(0.45),
            detection_source="EDR/Network" if session.simulate_detection(0.45) else None,
        )


class InternalSpearphishingTechnique(TechniqueModule):
    technique_id = "T1534"
    name = "Internal Spearphishing"
    tier = "oss"

    def emulate(self, session, target):
        telemetry = [
            f"Internal email send pattern: From: user@domain To: {target}",
            "Link click telemetry: HTTP GET to emulated payload URL",
            "Mail gateway event: internal relay triggered",
        ]
        return EmulationResult(
            technique_id=self.technique_id,
            technique_name=self.name,
            session_id=session.session_id,
            timestamp=datetime.now(timezone.utc),
            success=True,
            telemetry_generated=telemetry,
            safety_events=["No real email sent", "No real URL resolved"],
            detected_by_defense=session.simulate_detection(0.35),
            detection_source="Email Gateway/SIEM" if session.simulate_detection(0.35) else None,
        )


OSS_TECHNIQUE_LIBRARY = {
    "T1021.002": SMBSharesTechnique(),
    "T1021.001": RDPTechnique(),
    "T1550.002": PassTheHashShapeTechnique(),
    "T1021.004": SSHTechnique(),
    "T1021.006": WinRMTechnique(),
    "T1135":     NetworkShareDiscoveryTechnique(),
    "T1021.003": DCOMTechnique(),
    "T1534":     InternalSpearphishingTechnique(),
}


@dataclass
class LMEPSession:
    """An LMEP emulation session."""
    name: str
    scope: list[str]
    credential_mode: CredentialMode = CredentialMode.SYNTHETIC
    deployment_mode: DeploymentMode = DeploymentMode.PASSIVE
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    max_duration_seconds: int = 3600
    active: bool = True
    results: list[EmulationResult] = field(default_factory=list)
    audit_log: list[dict] = field(default_factory=list)
    _detection_seed: int = field(default=42, repr=False)

    def simulate_detection(self, probability: float) -> bool:
        """Deterministic detection simulation for testing."""
        import random
        return random.random() < probability

    def _log_audit(self, action: str, detail: str) -> None:
        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "action": action,
            "detail": detail,
        })

    def run_technique(self, technique_id: str, target: str) -> EmulationResult:
        if not self.active:
            raise RuntimeError("Session is not active")
        if target not in self.scope:
            self._log_audit("BLOCKED", f"Out-of-scope target blocked: {target}")
            raise ValueError(f"Target {target} is not in session scope: {self.scope}")

        technique = OSS_TECHNIQUE_LIBRARY.get(technique_id)
        if not technique:
            raise ValueError(f"Unknown technique: {technique_id}. Available: {list(OSS_TECHNIQUE_LIBRARY.keys())}")

        # Safety preflight
        preflight = technique.preflight_check(self)
        self._log_audit("PREFLIGHT", f"{technique_id} on {target}: {preflight.status.value}")

        if preflight.status == SafetyCheckStatus.BLOCK:
            raise RuntimeError(f"Safety preflight BLOCKED: {'; '.join(preflight.reasons)}")

        # Execute emulation
        result = technique.emulate(self, target)
        self.results.append(result)
        self._log_audit("EMULATE", f"{technique_id} on {target}: success={result.success}, detected={result.detected_by_defense}")
        return result

    def abort(self) -> None:
        self.active = False
        self._log_audit("ABORT", "Session aborted by operator")

    def export_psil_scenarios(self) -> list[Scenario]:
        return [r.to_psil_scenario() for r in self.results]

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "name": self.name,
            "scope": self.scope,
            "credential_mode": self.credential_mode.value,
            "deployment_mode": self.deployment_mode.value,
            "created_at": self.created_at.isoformat(),
            "active": self.active,
            "results_count": len(self.results),
            "results": [r.to_dict() for r in self.results],
            "audit_log": self.audit_log,
        }


class LMEPControlPlane:
    """Central LMEP control plane — session management."""

    def __init__(self, store_path: str = "data/lmep_sessions.json"):
        self._store_path = store_path
        self._sessions: dict[str, LMEPSession] = {}
        self._load_sessions()

    def _load_sessions(self) -> None:
        """Load persisted session metadata from disk on startup."""
        try:
            path = pathlib.Path(self._store_path)
            if path.exists():
                with open(path) as f:
                    data = json.load(f)
                print(f"[LMEP] Loaded {len(data)} persisted session(s) from {self._store_path}")
                # Restore as lightweight session records (results not re-executed)
                for sid, sdata in data.items():
                    session = LMEPSession(
                        name=sdata.get("name", "restored"),
                        scope=sdata.get("scope", []),
                        credential_mode=CredentialMode(sdata.get("credential_mode", "SYNTHETIC")),
                        deployment_mode=DeploymentMode(sdata.get("deployment_mode", "PASSIVE")),
                        session_id=sid,
                        active=False,  # Restored sessions are inactive
                    )
                    session.audit_log = sdata.get("audit_log", [])
                    self._sessions[sid] = session
        except Exception as e:
            print(f"[LMEP] Could not load session store ({e}) — starting fresh")

    def _save_sessions(self) -> None:
        """Persist current session metadata to disk."""
        try:
            path = pathlib.Path(self._store_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {sid: s.to_dict() for sid, s in self._sessions.items()}
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"[LMEP] Warning: could not save session store: {e}")

    def create_session(
        self,
        name: str,
        scope: list[str],
        credential_mode: str = "SYNTHETIC",
        deployment_mode: str = "PASSIVE",
    ) -> LMEPSession:
        if deployment_mode == "ACTIVE":
            raise PermissionError(
                "Active mode requires a signed Engagement Authorization Document (EAD). "
                "Load EAD before enabling Active mode."
            )
        session = LMEPSession(
            name=name,
            scope=scope,
            credential_mode=CredentialMode(credential_mode),
            deployment_mode=DeploymentMode(deployment_mode),
        )
        self._sessions[session.session_id] = session
        self._save_sessions()
        return session

    def get_session(self, session_id: str) -> Optional[LMEPSession]:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[dict]:
        return [s.to_dict() for s in self._sessions.values()]

    def abort_session(self, session_id: str) -> None:
        s = self._sessions.get(session_id)
        if s:
            s.abort()
            self._save_sessions()

    def list_techniques(self) -> list[dict]:
        return [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "min_credential_mode": t.min_credential_mode.value,
                "min_deployment_mode": t.min_deployment_mode.value,
                "reversible": t.reversible,
                "tier": t.tier,
            }
            for t in OSS_TECHNIQUE_LIBRARY.values()
        ]
