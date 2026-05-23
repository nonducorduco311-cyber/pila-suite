"""
IRV - Incident Remediation Validator
Core Engine v1.0.0
Apache 2.0 License - PILA Suite
"""
from __future__ import annotations
import uuid
import hashlib
import json
import hmac
import os
import pathlib
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class IncidentType(str, Enum):
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PHISHING = "phishing"
    INSIDER_THREAT = "insider_threat"


class ValidationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    ABORTED = "aborted"


class CheckResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


@dataclass
class ValidationCheck:
    name: str
    description: str
    result: CheckResult = CheckResult.SKIP
    detail: Optional[str] = None
    timestamp: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "result": self.result.value,
            "detail": self.detail,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class PlaybookResult:
    incident_type: IncidentType
    checks: list[ValidationCheck] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    warnings: int = 0

    @property
    def overall_pass(self) -> bool:
        return self.failed == 0

    def to_dict(self) -> dict:
        return {
            "incident_type": self.incident_type.value,
            "checks": [c.to_dict() for c in self.checks],
            "summary": {
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "overall": "PASS" if self.overall_pass else "FAIL",
            }
        }


class PlaybookLibrary:
    """Validation playbook library - YAML-definable, OSS core."""

    def get_playbook(self, incident_type: IncidentType) -> list[ValidationCheck]:
        playbooks = {
            IncidentType.MALWARE: self._malware_playbook(),
            IncidentType.RANSOMWARE: self._ransomware_playbook(),
            IncidentType.CREDENTIAL_COMPROMISE: self._credential_playbook(),
            IncidentType.LATERAL_MOVEMENT: self._lateral_movement_playbook(),
            IncidentType.DATA_EXFILTRATION: self._exfiltration_playbook(),
            IncidentType.PHISHING: self._phishing_playbook(),
            IncidentType.INSIDER_THREAT: self._insider_threat_playbook(),
        }
        return playbooks.get(incident_type, self._generic_playbook())

    def _malware_playbook(self) -> list[ValidationCheck]:
        return [
            ValidationCheck("persistence_check", "Verify no persistence mechanisms (startup keys, scheduled tasks, services)"),
            ValidationCheck("process_scan", "Confirm malicious processes are terminated"),
            ValidationCheck("file_hash_validation", "Validate known malicious file hashes are absent"),
            ValidationCheck("registry_sweep", "Check registry for known malware indicators"),
            ValidationCheck("network_ioc_check", "Verify C2 communication indicators are blocked"),
            ValidationCheck("patch_applied", "Confirm relevant security patches are applied"),
        ]

    def _ransomware_playbook(self) -> list[ValidationCheck]:
        return [
            ValidationCheck("encryption_key_destroyed", "Verify ransomware encryption keys are destroyed"),
            ValidationCheck("backup_integrity", "Validate backup integrity and restoration feasibility"),
            ValidationCheck("persistence_check", "Confirm ransomware persistence mechanisms removed"),
            ValidationCheck("lateral_spread_check", "Verify ransomware has not spread to additional systems"),
            ValidationCheck("decryption_verified", "Confirm affected files are accessible/restored"),
            ValidationCheck("initial_access_vector_patched", "Verify initial access vulnerability is remediated"),
        ]

    def _credential_playbook(self) -> list[ValidationCheck]:
        return [
            ValidationCheck("password_reset_confirmed", "Verify affected account passwords are reset"),
            ValidationCheck("session_tokens_revoked", "Confirm all active session tokens are invalidated"),
            ValidationCheck("mfa_reenrolled", "Verify MFA is re-enrolled on affected accounts"),
            ValidationCheck("login_history_reviewed", "Check post-reset login activity for anomalies"),
            ValidationCheck("privileged_access_audited", "Confirm no unauthorized privilege escalation persists"),
            ValidationCheck("api_keys_rotated", "Verify API keys and service credentials are rotated"),
        ]

    def _lateral_movement_playbook(self) -> list[ValidationCheck]:
        return [
            ValidationCheck("account_privilege_audit", "Audit account privileges for unauthorized changes"),
            ValidationCheck("trust_relationship_delta", "Map and verify trust relationship changes"),
            ValidationCheck("network_segmentation_check", "Validate network segmentation controls are restored"),
            ValidationCheck("compromised_hosts_reimaged", "Confirm compromised hosts are reimaged or restored"),
            ValidationCheck("lateral_path_blocked", "Verify the lateral movement path is blocked"),
        ]

    def _exfiltration_playbook(self) -> list[ValidationCheck]:
        return [
            ValidationCheck("dlp_rules_validated", "Confirm DLP rules are active and correctly configured"),
            ValidationCheck("egress_rules_verified", "Verify outbound network rules block exfiltration paths"),
            ValidationCheck("affected_data_classified", "Classify and document data potentially exfiltrated"),
            ValidationCheck("egress_log_clean", "Confirm no ongoing exfiltration in post-remediation logs"),
            ValidationCheck("data_access_audited", "Audit access to affected data stores post-remediation"),
        ]

    def _phishing_playbook(self) -> list[ValidationCheck]:
        return [
            ValidationCheck("mail_rules_audited", "Audit email rules for malicious forwarding or deletion rules"),
            ValidationCheck("forwarding_rules_removed", "Confirm unauthorized forwarding rules are removed"),
            ValidationCheck("delegated_access_reviewed", "Review and revoke unauthorized delegated mailbox access"),
            ValidationCheck("sender_blocked", "Verify malicious sender/domain is blocked in mail gateway"),
            ValidationCheck("affected_accounts_secured", "Confirm all accounts that interacted with phishing are secured"),
        ]

    def _insider_threat_playbook(self) -> list[ValidationCheck]:
        return [
            ValidationCheck("access_revoked", "Verify all system access for the subject is revoked"),
            ValidationCheck("data_transfer_scan", "Scan for unauthorized data transfers or exfiltration"),
            ValidationCheck("endpoint_wiped", "Confirm corporate endpoints are wiped and reconfigured"),
            ValidationCheck("audit_logs_preserved", "Ensure audit logs are preserved for investigation"),
            ValidationCheck("access_review_complete", "Complete access review for shared accounts"),
        ]

    def _generic_playbook(self) -> list[ValidationCheck]:
        return [
            ValidationCheck("containment_verified", "Verify incident containment actions are complete"),
            ValidationCheck("eradication_confirmed", "Confirm eradication of threat artifacts"),
            ValidationCheck("systems_restored", "Validate affected systems are restored to known-good state"),
            ValidationCheck("monitoring_enhanced", "Confirm enhanced monitoring is active on affected systems"),
        ]


@dataclass
class EvidenceBundle:
    """Cryptographically signed proof-of-eradication artifact bundle."""
    validation_id: str
    incident_id: str
    incident_type: str
    timestamp: datetime
    playbook_result: PlaybookResult
    affected_scope: list[str]
    bundle_hash: str = ""
    signature: str = ""

    def to_dict(self) -> dict:
        return {
            "validation_id": self.validation_id,
            "incident_id": self.incident_id,
            "incident_type": self.incident_type,
            "timestamp": self.timestamp.isoformat(),
            "playbook_result": self.playbook_result.to_dict(),
            "affected_scope": self.affected_scope,
            "bundle_hash": self.bundle_hash,
            "signature": self.signature,
            "status": "ERADICATED" if self.playbook_result.overall_pass else "INCOMPLETE",
        }

    def compute_hash(self) -> str:
        content = json.dumps({
            "validation_id": self.validation_id,
            "incident_id": self.incident_id,
            "timestamp": self.timestamp.isoformat(),
            "playbook_result": self.playbook_result.to_dict(),
        }, sort_keys=True).encode()
        return hashlib.sha256(content).hexdigest()

    def sign(self, key: bytes = b"irv-demo-key") -> str:
        """HMAC-SHA256 signature over bundle hash."""
        return hmac.new(key, self.bundle_hash.encode(), hashlib.sha256).hexdigest()


class IRVOrchestrationEngine:
    """
    Core IRV orchestration engine.
    In production: dispatches to real scan agents.
    In demo/test mode: simulates scan results based on incident metadata.
    """

    def __init__(self, demo_mode: bool = True,
                 store_path: str = "data/irv_jobs.json"):
        self.demo_mode = demo_mode
        self.playbook_library = PlaybookLibrary()
        self._store_path = store_path
        self._jobs: dict[str, dict] = self._load_jobs()

    def _load_jobs(self) -> dict[str, dict]:
        """Load persisted IRV jobs from disk on startup."""
        try:
            path = pathlib.Path(self._store_path)
            if path.exists():
                with open(path) as f:
                    data = json.load(f)
                print(f"[IRV] Loaded {len(data)} persisted job(s) from {self._store_path}")
                return data
        except Exception as e:
            print(f"[IRV] Could not load job store ({e}) — starting fresh")
        return {}

    def _save_jobs(self) -> None:
        """Persist current IRV jobs to disk."""
        try:
            path = pathlib.Path(self._store_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as f:
                json.dump(self._jobs, f, indent=2, default=str)
        except Exception as e:
            print(f"[IRV] Warning: could not save job store: {e}")

    def trigger_validation(
        self,
        incident_id: str,
        incident_type: str,
        affected_scope: list[str],
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Trigger a validation job. Returns job_id.
        In production: async; here we run synchronously for simplicity.
        """
        job_id = str(uuid.uuid4())
        self._jobs[job_id] = {
            "job_id": job_id,
            "incident_id": incident_id,
            "incident_type": incident_type,
            "affected_scope": affected_scope,
            "metadata": metadata or {},
            "status": ValidationStatus.PENDING.value,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "evidence_bundle": None,
        }
        # Run synchronously
        self._run_validation(job_id)
        self._save_jobs()
        return job_id

    def get_job(self, job_id: str) -> Optional[dict]:
        return self._jobs.get(job_id)

    def get_all_jobs(self) -> list[dict]:
        return list(self._jobs.values())

    def _run_validation(self, job_id: str) -> None:
        job = self._jobs[job_id]
        job["status"] = ValidationStatus.RUNNING.value

        try:
            incident_type_enum = IncidentType(job["incident_type"])
        except ValueError:
            incident_type_enum = IncidentType.MALWARE

        checks = self.playbook_library.get_playbook(incident_type_enum)

        # Execute checks (demo mode: simulate results)
        executed_checks = []
        for check in checks:
            result = self._execute_check(check, job)
            executed_checks.append(result)

        passed = sum(1 for c in executed_checks if c.result == CheckResult.PASS)
        failed = sum(1 for c in executed_checks if c.result == CheckResult.FAIL)
        warnings = sum(1 for c in executed_checks if c.result == CheckResult.WARN)

        playbook_result = PlaybookResult(
            incident_type=incident_type_enum,
            checks=executed_checks,
            passed=passed,
            failed=failed,
            warnings=warnings,
        )

        # Build evidence bundle
        bundle = EvidenceBundle(
            validation_id=str(uuid.uuid4()),
            incident_id=job["incident_id"],
            incident_type=job["incident_type"],
            timestamp=datetime.now(timezone.utc),
            playbook_result=playbook_result,
            affected_scope=job["affected_scope"],
        )
        bundle.bundle_hash = bundle.compute_hash()
        bundle.signature = bundle.sign()

        job["status"] = ValidationStatus.PASSED.value if playbook_result.overall_pass else ValidationStatus.FAILED.value
        job["evidence_bundle"] = bundle.to_dict()
        job["completed_at"] = datetime.now(timezone.utc).isoformat()

    def _execute_check(self, check: ValidationCheck, job: dict) -> ValidationCheck:
        """
        In demo mode: simulate check results.
        In production: dispatch to real scan agents.
        """
        import random
        check.timestamp = datetime.now(timezone.utc)

        if self.demo_mode:
            # Simulate realistic but varied results
            rand = random.random()
            if rand < 0.80:
                check.result = CheckResult.PASS
                check.detail = f"[DEMO] {check.description} — verified clean."
            elif rand < 0.90:
                check.result = CheckResult.WARN
                check.detail = f"[DEMO] {check.description} — minor anomaly detected, manual review recommended."
            else:
                check.result = CheckResult.FAIL
                check.detail = f"[DEMO] {check.description} — FAILED. Residual indicator detected."
        else:
            # Production: would call real scan agents here
            check.result = CheckResult.SKIP
            check.detail = "Real agent dispatch not configured in this environment."

        return check
