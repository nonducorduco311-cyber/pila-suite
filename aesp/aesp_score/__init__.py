"""
AESP Scoring Engine v2.0
Drop-in replacement for /home/bryant/pila-suite/aesp/aesp_score/__init__.py

Changes from v1.0:
  - CB split into CB_source (30%) + CB_technique (70%)
  - PR mode-aware: PASSIVE=50 neutral, weight 5%; ACTIVE=actual, weight 10%
  - RS adjusted: RS_adj = RS_raw * (1 - FPR * 0.50)
  - Weights redistributed: DE=35/40%, RS=15%, PR=5/10%, CB=20%, RQ=20%
  - Delta ES added to AESPResult
  - DMT bands rebalanced: 0-34/35-49/50-64/65-79/80-100
  - formula_version field added to AESPResult
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
from psil.psil_sdk.models import Engagement, Outcome, Severity, RemediationStatus


MTTR_BASELINES = {
    "malware":               3600,
    "ransomware":            1800,
    "credential_compromise": 2700,
    "lateral_movement":      5400,
    "data_exfiltration":     7200,
    "phishing":              1800,
    "insider_threat":        10800,
    "default":               3600,
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFORMATIONAL": 0.5,
}

# Known active data sources PILA Suite can integrate with
ALL_DATA_SOURCES = ["suricata", "zeek", "packetbeat", "wazuh", "auditbeat"]


@dataclass
class SubScores:
    de:         float   # Detection Efficacy (0-100)
    rs:         float   # Response Speed raw (0-100)
    rs_adj:     float   # Response Speed adjusted for FPR (0-100)
    pr:         float   # Prevention Rate adjusted (0-100)
    cb:         float   # Coverage Breadth adjusted (0-100)
    cb_source:  float   # CB sub-component: source coverage (0-100)
    cb_technique: float # CB sub-component: technique coverage (0-100)
    rq:         float   # Remediation Quality (0-100)
    fpr:        float   # False Positive Rate (0.0 - 1.0)
    lmep_mode:  str     # PASSIVE or ACTIVE

    def to_dict(self) -> dict:
        return {
            "detection_efficacy":    round(self.de, 1),
            "response_speed_raw":    round(self.rs, 1),
            "response_speed_adj":    round(self.rs_adj, 1),
            "prevention_rate":       round(self.pr, 1),
            "coverage_breadth":      round(self.cb, 1),
            "coverage_breadth_source":    round(self.cb_source, 1),
            "coverage_breadth_technique": round(self.cb_technique, 1),
            "remediation_quality":   round(self.rq, 1),
            "false_positive_rate":   round(self.fpr, 3),
            "lmep_mode":             self.lmep_mode,
        }


class DMTTier:
    # v2.0 bands — rebalanced for realistic score distribution
    TIERS = [
        (80, 100, "DMT-5", "Optimized",
         "Near-complete validated coverage. Automated regression detection. Minimal false positives. Continuous improvement demonstrated by Delta ES."),
        (65,  79, "DMT-4", "Advanced",
         "Comprehensive detection. Custom rules for environment-specific techniques. Active gap identification. IRV validation in use."),
        (50,  64, "DMT-3", "Defined",
         "Structured detection program. Most common techniques covered. Regular exercise cadence. Response processes documented."),
        (35,  49, "DMT-2", "Developing",
         "Basic detection in place for key techniques. No automated response. First purple team exercises completed."),
        (0,   34, "DMT-1", "Foundational",
         "No structured detection program. Individual rules only. No correlation or scoring history. Response ad hoc."),
    ]

    @classmethod
    def from_es(cls, es: float) -> tuple[str, str, str]:
        for lo, hi, tier_id, label, desc in cls.TIERS:
            if lo <= es <= hi:
                return tier_id, label, desc
        return "DMT-1", "Foundational", cls.TIERS[-1][4]


@dataclass
class AESPResult:
    engagement_id:    str
    engagement_name:  str
    es:               float
    dmt_tier:         str
    dmt_label:        str
    dmt_description:  str
    sub_scores:       SubScores
    modifiers_applied: list[str]
    scenario_count:   int
    coverage_by_tactic: dict[str, float]
    previous_es:      Optional[float] = None
    delta_es:         Optional[float] = None   # NEW v2.0
    formula_version:  str = "2.0"              # NEW v2.0

    def to_dict(self) -> dict:
        return {
            "engagement_id":      self.engagement_id,
            "engagement_name":    self.engagement_name,
            "effectiveness_score": self.es,
            "formula_version":    self.formula_version,
            "dmt": {
                "tier":        self.dmt_tier,
                "label":       self.dmt_label,
                "description": self.dmt_description,
            },
            "sub_scores":         self.sub_scores.to_dict(),
            "modifiers_applied":  self.modifiers_applied,
            "scenario_count":     self.scenario_count,
            "coverage_by_tactic": self.coverage_by_tactic,
            "previous_es":        self.previous_es,
            "delta_es":           self.delta_es,
        }

    def summary(self) -> str:
        delta_str = ""
        if self.delta_es is not None:
            arrow = "▲" if self.delta_es >= 0 else "▼"
            delta_str = f"  ({arrow}{abs(self.delta_es):.1f} vs previous)"

        lines = [
            f"AESP Score v{self.formula_version} — {self.engagement_name}",
            "=" * 55,
            f"  Effectiveness Score (ES):  {self.es:.1f} / 100{delta_str}",
            f"  Defense Maturity Tier:     {self.dmt_tier} — {self.dmt_label}",
            f"  {self.dmt_description}",
            "",
            "Sub-Scores:",
            f"  Detection Efficacy   (DE):  {self.sub_scores.de:.1f}",
            f"  Response Speed       (RS):  {self.sub_scores.rs:.1f} raw → {self.sub_scores.rs_adj:.1f} adj (FPR={self.sub_scores.fpr:.1%})",
            f"  Prevention Rate      (PR):  {self.sub_scores.pr:.1f}  [mode: {self.sub_scores.lmep_mode}]",
            f"  Coverage Breadth     (CB):  {self.sub_scores.cb:.1f}  [source={self.sub_scores.cb_source:.1f} technique={self.sub_scores.cb_technique:.1f}]",
            f"  Remediation Quality  (RQ):  {self.sub_scores.rq:.1f}",
            "",
            f"Scenarios scored: {self.scenario_count}",
        ]
        if self.modifiers_applied:
            lines.append(f"Modifiers: {', '.join(self.modifiers_applied)}")
        if self.coverage_by_tactic:
            lines.append("\nATT&CK Tactic Coverage:")
            for tactic, cov in self.coverage_by_tactic.items():
                lines.append(f"  {tactic:<30} {cov*100:.0f}%")
        return "\n".join(lines)


class AESPScoringEngine:
    """
    AESP Scoring Engine v2.0
    Deterministic — same inputs always produce the same output.
    """

    def score(self,
              engagement: Engagement,
              previous_es: Optional[float] = None,
              history_es: Optional[list[float]] = None,
              incident_type: str = "default",
              lmep_mode: str = "PASSIVE",
              active_sources: Optional[list[str]] = None,
              false_positive_rate: float = 0.0) -> AESPResult:

        scenarios = engagement.scenarios
        if not scenarios:
            raise ValueError("Cannot score an engagement with no scenarios")

        # ── Calculate all sub-scores ──────────────────────────────
        de         = self._calculate_de(scenarios)
        rs_raw     = self._calculate_rs_raw(scenarios, incident_type)
        rs_adj     = self._calculate_rs_adj(rs_raw, false_positive_rate)
        pr_adj     = self._calculate_pr_adj(scenarios, lmep_mode)
        cb_source  = self._calculate_cb_source(active_sources)
        cb_tech    = self._calculate_cb_technique(scenarios)
        cb_adj     = (cb_source * 0.30) + (cb_tech * 0.70)
        rq         = self._calculate_rq(scenarios)

        sub_scores = SubScores(
            de=de,
            rs=rs_raw,
            rs_adj=rs_adj,
            pr=pr_adj,
            cb=cb_adj,
            cb_source=cb_source,
            cb_technique=cb_tech,
            rq=rq,
            fpr=false_positive_rate,
            lmep_mode=lmep_mode,
        )

        # ── Weights — mode-aware ──────────────────────────────────
        # In PASSIVE mode: PR weight reduced, redistributed to DE
        if lmep_mode.upper() == "PASSIVE":
            w_de, w_rs, w_pr, w_cb, w_rq = 0.40, 0.15, 0.05, 0.20, 0.20
        else:  # ACTIVE
            w_de, w_rs, w_pr, w_cb, w_rq = 0.35, 0.15, 0.10, 0.20, 0.20

        # ── Composite ES ──────────────────────────────────────────
        es_raw = (
            de      * w_de +
            rs_adj  * w_rs +
            pr_adj  * w_pr +
            cb_adj  * w_cb +
            rq      * w_rq
        )
        es = round(min(100.0, max(0.0, es_raw)), 1)

        # ── Delta ES ──────────────────────────────────────────────
        delta_es = None
        if previous_es is not None:
            delta_es = round(es - previous_es, 1)

        # ── DMT classification ────────────────────────────────────
        dmt_tier, dmt_label, dmt_desc = DMTTier.from_es(es)

        # ── Modifiers ─────────────────────────────────────────────
        modifiers = []
        dmt_num = int(dmt_tier.split("-")[1])

        # Consistency bonus
        if history_es and len(history_es) >= 2:
            recent = history_es[-2:] + [es]
            if max(recent) - min(recent) <= 10:
                if dmt_num < 5:
                    dmt_num += 1
                    modifiers.append("Consistency Bonus (+1 tier): low ES variance over last 3 engagements")

        # Coverage gap penalty: CB < 40
        if cb_adj < 40:
            if dmt_num > 1:
                dmt_num -= 1
            modifiers.append(f"Coverage Gap Penalty (-1 tier): CB={cb_adj:.1f} < 40")

        # Regression penalty
        if previous_es is not None and (previous_es - es) > 15:
            if dmt_num > 1:
                dmt_num -= 1
            modifiers.append(f"Regression Penalty (-1 tier): ES dropped {previous_es - es:.1f} pts from {previous_es}")

        # High FPR warning modifier
        if false_positive_rate > 0.30:
            modifiers.append(f"High False Positive Rate warning: FPR={false_positive_rate:.1%} — tune detection rules")

        # Recalculate tier after modifiers
        dmt_num = max(1, min(5, dmt_num))
        final_tier = f"DMT-{dmt_num}"
        _, final_label, final_desc = DMTTier.from_es(
            [80, 65, 50, 35, 0][5 - dmt_num]
        )

        metrics  = engagement.metrics
        coverage = metrics.coverage_by_tactic if metrics else {}

        return AESPResult(
            engagement_id=engagement.engagement_id,
            engagement_name=engagement.name,
            es=es,
            dmt_tier=final_tier,
            dmt_label=final_label,
            dmt_description=final_desc,
            sub_scores=sub_scores,
            modifiers_applied=modifiers,
            scenario_count=len(scenarios),
            coverage_by_tactic=coverage,
            previous_es=previous_es,
            delta_es=delta_es,
            formula_version="2.0",
        )

    # ── Sub-score calculators ─────────────────────────────────────────────────

    def _calculate_de(self, scenarios) -> float:
        """Detection Efficacy: severity-weighted detection rate."""
        if not scenarios:
            return 0.0
        total_weight    = 0.0
        detected_weight = 0.0
        for s in scenarios:
            w = SEVERITY_WEIGHTS.get(s.severity.value, 2)
            total_weight += w
            if s.outcome == Outcome.PARTIAL_DETECTION:
                detected_weight += 0.5 * w
            elif s.defense.detected or s.outcome in (
                Outcome.DETECTED_AND_BLOCKED,
                Outcome.DETECTED_NOT_BLOCKED,
                Outcome.DETECTED_LATE,
            ):
                detected_weight += 1.0 * w
        if total_weight == 0:
            return 0.0
        return min(100.0, (detected_weight / total_weight) * 100)

    def _calculate_rs_raw(self, scenarios, incident_type: str = "default") -> float:
        """Response Speed raw: MTTR normalized against baseline. Unchanged from v1.0."""
        mttr_vals = []
        baseline  = MTTR_BASELINES.get(incident_type, MTTR_BASELINES["default"])
        for s in scenarios:
            if (s.attack.execution_timestamp and s.defense.response_time
                    and s.defense.detected):
                delta = (s.defense.response_time - s.attack.execution_timestamp).total_seconds()
                if delta >= 0:
                    mttr_vals.append(delta)
        if not mttr_vals:
            return 50.0  # No timing data — neutral default
        mttr_actual = sum(mttr_vals) / len(mttr_vals)
        rs = max(0.0, 100.0 - ((mttr_actual / baseline) - 1.0) * 50.0)
        return min(100.0, rs)

    def _calculate_rs_adj(self, rs_raw: float, false_positive_rate: float) -> float:
        """
        Response Speed adjusted: apply false positive penalty.
        RS_adj = RS_raw * (1 - FPR * 0.50)
        A 20% FPR reduces RS by 10%. A 50% FPR reduces RS by 25%.
        """
        FP_PENALTY_WEIGHT = 0.50
        fp_modifier = 1.0 - (false_positive_rate * FP_PENALTY_WEIGHT)
        fp_modifier  = max(0.0, min(1.0, fp_modifier))
        return round(min(100.0, rs_raw * fp_modifier), 1)

    def _calculate_pr_adj(self, scenarios, lmep_mode: str) -> float:
        """
        Prevention Rate mode-aware.
        PASSIVE: return neutral baseline (50) — prevention structurally disabled.
        ACTIVE:  calculate actual prevention rate from scenario outcomes.
        """
        if lmep_mode.upper() == "PASSIVE":
            return 50.0  # Neutral — neither penalized nor rewarded
        # ACTIVE mode — calculate actual prevention
        if not scenarios:
            return 0.0
        prevented = sum(
            1 for s in scenarios
            if s.outcome in (Outcome.PREVENTED, Outcome.DETECTED_AND_BLOCKED)
        )
        return (prevented / len(scenarios)) * 100

    def _calculate_cb_source(self, active_sources: Optional[list[str]]) -> float:
        """
        Coverage Breadth — Source component.
        Measures what fraction of supported data sources are active.
        Suricata only = 1/5 = 20%. Suricata + Zeek = 2/5 = 40%.
        """
        if not active_sources:
            # Default: assume Suricata only (minimum viable deployment)
            active = ["suricata"]
        else:
            active = [s.lower() for s in active_sources]
        connected = sum(1 for s in ALL_DATA_SOURCES if s in active)
        return round((connected / len(ALL_DATA_SOURCES)) * 100, 1)

    def _calculate_cb_technique(self, scenarios) -> float:
        """
        Coverage Breadth — Technique component.
        Measures what fraction of scoped techniques have detection coverage.
        Detected techniques / total techniques in scope.
        This is the primary CB signal (70% weight in CB_adj).
        """
        if not scenarios:
            return 0.0
        total     = len(scenarios)
        covered   = sum(
            1 for s in scenarios
            if s.defense.detected or s.outcome in (
                Outcome.DETECTED_AND_BLOCKED,
                Outcome.DETECTED_NOT_BLOCKED,
                Outcome.DETECTED_LATE,
                Outcome.PARTIAL_DETECTION,
            )
        )
        return round((covered / total) * 100, 1)

    def _calculate_rq(self, scenarios) -> float:
        """Remediation Quality: unchanged from v1.0, weight increased."""
        remediation_scenarios = [s for s in scenarios if s.gap_identified]
        if not remediation_scenarios:
            return 100.0  # No gaps = full marks
        total = len(remediation_scenarios)
        score = 0.0
        for s in remediation_scenarios:
            if s.remediation is None:
                score += 0.0
            elif s.remediation.status == RemediationStatus.VERIFIED:
                score += 1.0
            elif s.remediation.status == RemediationStatus.CLOSED_UNVERIFIED:
                score += 0.5
            elif s.remediation.status == RemediationStatus.IN_PROGRESS:
                score += 0.2
            else:
                score += 0.0
        return (score / total) * 100

    # ── Backward compatibility ────────────────────────────────────────────────

    def _calculate_rs(self, scenarios, incident_type: str = "default") -> float:
        """Alias for v1.0 callers — returns RS_raw."""
        return self._calculate_rs_raw(scenarios, incident_type)

    def _calculate_pr(self, scenarios) -> float:
        """Alias for v1.0 callers — returns ACTIVE mode PR."""
        return self._calculate_pr_adj(scenarios, "ACTIVE")

    def _calculate_cb(self, scenarios, engagement) -> float:
        """Alias for v1.0 callers — returns CB_adj with default source (Suricata only)."""
        cb_source = self._calculate_cb_source(["suricata"])
        cb_tech   = self._calculate_cb_technique(scenarios)
        return round((cb_source * 0.30) + (cb_tech * 0.70), 1)

