"""
PSIL Core Data Models
Implements the PSIL v1.0.0 specification.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from dataclasses import dataclass, field


class Outcome(str, Enum):
    PREVENTED = "prevented"
    DETECTED_AND_BLOCKED = "detected_and_blocked"
    DETECTED_NOT_BLOCKED = "detected_not_blocked"
    DETECTED_LATE = "detected_late"
    NOT_DETECTED = "not_detected"
    PARTIAL_DETECTION = "partial_detection"
    FALSE_POSITIVE_GENERATED = "false_positive_generated"


class TLPMarking(str, Enum):
    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class LessonCategory(str, Enum):
    DETECTION_GAP = "detection_gap"
    RESPONSE_GAP = "response_gap"
    PROCESS_GAP = "process_gap"
    TOOL_MISCONFIGURATION = "tool_misconfiguration"
    COVERAGE_GAP = "coverage_gap"
    POSITIVE_FINDING = "positive_finding"


class RemediationStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED_UNVERIFIED = "closed_unverified"
    VERIFIED = "verified"


@dataclass
class IOC:
    type: str  # process, file, network, registry, account
    value: str
    description: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"type": self.type, "value": self.value}
        if self.description:
            d["description"] = self.description
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "IOC":
        return cls(**d)


@dataclass
class Attack:
    technique_id: str
    tactic: str
    tool: Optional[str] = None
    stix_attack_pattern_id: Optional[str] = None
    execution_timestamp: Optional[datetime] = None
    execution_detail: Optional[str] = None
    iocs: list[IOC] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "technique_id": self.technique_id,
            "tactic": self.tactic,
        }
        if self.tool:
            d["tool"] = self.tool
        if self.stix_attack_pattern_id:
            d["stix_attack_pattern_id"] = self.stix_attack_pattern_id
        if self.execution_timestamp:
            d["execution_timestamp"] = self.execution_timestamp.isoformat()
        if self.execution_detail:
            d["execution_detail"] = self.execution_detail
        if self.iocs:
            d["iocs"] = [i.to_dict() for i in self.iocs]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Attack":
        ts = d.get("execution_timestamp")
        return cls(
            technique_id=d["technique_id"],
            tactic=d["tactic"],
            tool=d.get("tool"),
            stix_attack_pattern_id=d.get("stix_attack_pattern_id"),
            execution_timestamp=datetime.fromisoformat(ts) if ts else None,
            execution_detail=d.get("execution_detail"),
            iocs=[IOC.from_dict(i) for i in d.get("iocs", [])],
        )


@dataclass
class Defense:
    detected: bool
    detection_time: Optional[datetime] = None
    detection_source: Optional[str] = None
    response_action: Optional[str] = None
    response_time: Optional[datetime] = None
    d3fend_mitigations: list[str] = field(default_factory=list)
    analyst_notes: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"detected": self.detected}
        if self.detection_time:
            d["detection_time"] = self.detection_time.isoformat()
        if self.detection_source:
            d["detection_source"] = self.detection_source
        if self.response_action:
            d["response_action"] = self.response_action
        if self.response_time:
            d["response_time"] = self.response_time.isoformat()
        if self.d3fend_mitigations:
            d["d3fend_mitigations"] = self.d3fend_mitigations
        if self.analyst_notes:
            d["analyst_notes"] = self.analyst_notes
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Defense":
        dt = d.get("detection_time")
        rt = d.get("response_time")
        return cls(
            detected=d["detected"],
            detection_time=datetime.fromisoformat(dt) if dt else None,
            detection_source=d.get("detection_source"),
            response_action=d.get("response_action"),
            response_time=datetime.fromisoformat(rt) if rt else None,
            d3fend_mitigations=d.get("d3fend_mitigations", []),
            analyst_notes=d.get("analyst_notes"),
        )


@dataclass
class Remediation:
    recommended_actions: list[str] = field(default_factory=list)
    owner: Optional[str] = None
    due_date: Optional[str] = None
    status: RemediationStatus = RemediationStatus.OPEN
    verified: bool = False
    irv_validation_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "recommended_actions": self.recommended_actions,
            "owner": self.owner,
            "due_date": self.due_date,
            "status": self.status.value,
            "verified": self.verified,
            "irv_validation_id": self.irv_validation_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Remediation":
        return cls(
            recommended_actions=d.get("recommended_actions", []),
            owner=d.get("owner"),
            due_date=d.get("due_date"),
            status=RemediationStatus(d.get("status", "open")),
            verified=d.get("verified", False),
            irv_validation_id=d.get("irv_validation_id"),
        )


@dataclass
class Scenario:
    name: str
    attack: Attack
    defense: Defense
    outcome: Outcome
    scenario_id: str = field(default_factory=lambda: f"scen-{uuid.uuid4()}")
    description: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    gap_identified: bool = False
    gap_detail: Optional[str] = None
    remediation: Optional[Remediation] = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "attack": self.attack.to_dict(),
            "defense": self.defense.to_dict(),
            "outcome": self.outcome.value,
            "severity": self.severity.value,
            "gap_identified": self.gap_identified,
        }
        if self.description:
            d["description"] = self.description
        if self.gap_detail:
            d["gap_detail"] = self.gap_detail
        if self.remediation:
            d["remediation"] = self.remediation.to_dict()
        if self.tags:
            d["tags"] = self.tags
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Scenario":
        rem = d.get("remediation")
        return cls(
            scenario_id=d.get("scenario_id", f"scen-{uuid.uuid4()}"),
            name=d["name"],
            description=d.get("description"),
            attack=Attack.from_dict(d["attack"]),
            defense=Defense.from_dict(d["defense"]),
            outcome=Outcome(d["outcome"]),
            severity=Severity(d.get("severity", "MEDIUM")),
            gap_identified=d.get("gap_identified", False),
            gap_detail=d.get("gap_detail"),
            remediation=Remediation.from_dict(rem) if rem else None,
            tags=d.get("tags", []),
        )


@dataclass
class Metrics:
    total_scenarios: int = 0
    detection_rate: float = 0.0
    prevention_rate: float = 0.0
    mean_time_to_detect_seconds: Optional[float] = None
    mean_time_to_respond_seconds: Optional[float] = None
    gaps_identified: int = 0
    remediations_verified: int = 0
    coverage_by_tactic: dict[str, float] = field(default_factory=dict)
    tool_effectiveness: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_scenarios": self.total_scenarios,
            "detection_rate": self.detection_rate,
            "prevention_rate": self.prevention_rate,
            "mean_time_to_detect_seconds": self.mean_time_to_detect_seconds,
            "mean_time_to_respond_seconds": self.mean_time_to_respond_seconds,
            "gaps_identified": self.gaps_identified,
            "remediations_verified": self.remediations_verified,
            "coverage_by_tactic": self.coverage_by_tactic,
            "tool_effectiveness": self.tool_effectiveness,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Metrics":
        return cls(**d)

    @classmethod
    def compute_from_scenarios(cls, scenarios: list[Scenario]) -> "Metrics":
        if not scenarios:
            return cls()
        total = len(scenarios)
        detected = sum(
            1 for s in scenarios
            if s.defense.detected or s.outcome in (
                Outcome.DETECTED_AND_BLOCKED, Outcome.DETECTED_NOT_BLOCKED,
                Outcome.DETECTED_LATE, Outcome.PARTIAL_DETECTION
            )
        )
        prevented = sum(
            1 for s in scenarios
            if s.outcome in (Outcome.PREVENTED, Outcome.DETECTED_AND_BLOCKED)
        )
        gaps = sum(1 for s in scenarios if s.gap_identified)
        verified = sum(
            1 for s in scenarios
            if s.remediation and s.remediation.verified
        )

        # MTTx calculations
        detect_times = []
        respond_times = []
        for s in scenarios:
            if (s.defense.detected and s.attack.execution_timestamp
                    and s.defense.detection_time):
                dt = (s.defense.detection_time - s.attack.execution_timestamp).total_seconds()
                if dt >= 0:
                    detect_times.append(dt)
            if (s.attack.execution_timestamp and s.defense.response_time):
                rt = (s.defense.response_time - s.attack.execution_timestamp).total_seconds()
                if rt >= 0:
                    respond_times.append(rt)

        # Coverage by tactic
        tactic_counts: dict[str, int] = {}
        tactic_detected: dict[str, int] = {}
        for s in scenarios:
            t = s.attack.tactic
            tactic_counts[t] = tactic_counts.get(t, 0) + 1
            if s.defense.detected:
                tactic_detected[t] = tactic_detected.get(t, 0) + 1
        coverage = {
            t: round(tactic_detected.get(t, 0) / tactic_counts[t], 2)
            for t in tactic_counts
        }

        return cls(
            total_scenarios=total,
            detection_rate=round(detected / total, 4),
            prevention_rate=round(prevented / total, 4),
            mean_time_to_detect_seconds=round(sum(detect_times) / len(detect_times), 1) if detect_times else None,
            mean_time_to_respond_seconds=round(sum(respond_times) / len(respond_times), 1) if respond_times else None,
            gaps_identified=gaps,
            remediations_verified=verified,
            coverage_by_tactic=coverage,
        )


@dataclass
class LessonLearned:
    title: str
    category: LessonCategory
    detail: str
    recommendation: str
    id: str = field(default_factory=lambda: f"LL-{uuid.uuid4().hex[:6].upper()}")
    priority: Severity = Severity.MEDIUM
    affected_scenarios: list[str] = field(default_factory=list)
    owner: Optional[str] = None
    status: str = "open"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category.value,
            "title": self.title,
            "detail": self.detail,
            "priority": self.priority.value,
            "affected_scenarios": self.affected_scenarios,
            "recommendation": self.recommendation,
            "owner": self.owner,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "LessonLearned":
        return cls(
            id=d.get("id", f"LL-{uuid.uuid4().hex[:6].upper()}"),
            title=d["title"],
            category=LessonCategory(d["category"]),
            detail=d["detail"],
            recommendation=d["recommendation"],
            priority=Severity(d.get("priority", "MEDIUM")),
            affected_scenarios=d.get("affected_scenarios", []),
            owner=d.get("owner"),
            status=d.get("status", "open"),
        )


@dataclass
class TeamMember:
    role: str  # red, blue, purple
    handle: Optional[str] = None

    def to_dict(self) -> dict:
        return {"role": self.role, "handle": self.handle}

    @classmethod
    def from_dict(cls, d: dict) -> "TeamMember":
        return cls(**d)


@dataclass
class Engagement:
    name: str
    organization: str
    scope: list[str]
    tlp_marking: TLPMarking = TLPMarking.AMBER
    engagement_id: str = field(default_factory=lambda: f"eng-{uuid.uuid4()}")
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    team: list[TeamMember] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    scenarios: list[Scenario] = field(default_factory=list)
    lessons_learned: list[LessonLearned] = field(default_factory=list)
    metrics: Optional[Metrics] = None
    aesp_score: Optional[dict] = None  # populated by AESP after scoring

    def add_scenario(self, scenario: Scenario) -> None:
        self.scenarios.append(scenario)
        self.metrics = Metrics.compute_from_scenarios(self.scenarios)

    def to_dict(self) -> dict:
        return {
            "psil_version": "1.0.0",
            "document_id": f"psil-{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "classification": self.tlp_marking.value,
            "engagement": {
                "engagement_id": self.engagement_id,
                "name": self.name,
                "organization": self.organization,
                "start_date": self.start_date.isoformat() if self.start_date else None,
                "end_date": self.end_date.isoformat() if self.end_date else None,
                "scope": self.scope,
                "team": [m.to_dict() for m in self.team],
                "frameworks": self.frameworks,
                "tags": self.tags,
                "tlp_marking": self.tlp_marking.value,
            },
            "scenarios": [s.to_dict() for s in self.scenarios],
            "metrics": self.metrics.to_dict() if self.metrics else Metrics().to_dict(),
            "lessons_learned": [ll.to_dict() for ll in self.lessons_learned],
            "extensions": {"aesp_score": self.aesp_score} if self.aesp_score else {},
        }

    def save(self, path: str) -> None:
        import json
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "Engagement":
        eng = d["engagement"]
        sd = eng.get("start_date")
        ed = eng.get("end_date")
        obj = cls(
            engagement_id=eng.get("engagement_id", f"eng-{uuid.uuid4()}"),
            name=eng["name"],
            organization=eng["organization"],
            scope=eng.get("scope", []),
            tlp_marking=TLPMarking(eng.get("tlp_marking", "TLP:AMBER")),
            start_date=datetime.fromisoformat(sd) if sd else None,
            end_date=datetime.fromisoformat(ed) if ed else None,
            team=[TeamMember.from_dict(m) for m in eng.get("team", [])],
            frameworks=eng.get("frameworks", []),
            tags=eng.get("tags", []),
            scenarios=[Scenario.from_dict(s) for s in d.get("scenarios", [])],
            lessons_learned=[LessonLearned.from_dict(ll) for ll in d.get("lessons_learned", [])],
        )
        metrics_data = d.get("metrics")
        obj.metrics = Metrics.from_dict(metrics_data) if metrics_data else None
        ext = d.get("extensions", {})
        obj.aesp_score = ext.get("aesp_score")
        return obj

    @classmethod
    def load(cls, path: str) -> "Engagement":
        import json
        with open(path) as f:
            return cls.from_dict(json.load(f))
