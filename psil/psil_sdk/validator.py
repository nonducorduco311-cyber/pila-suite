"""PSIL Document Validator"""
from typing import Optional
from dataclasses import dataclass


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str]
    warnings: list[str]

    def __str__(self) -> str:
        if self.valid:
            s = "✓ Valid PSIL document"
            if self.warnings:
                s += f"\n  Warnings: {'; '.join(self.warnings)}"
        else:
            s = "✗ Invalid PSIL document\n"
            s += "\n".join(f"  ERROR: {e}" for e in self.errors)
            if self.warnings:
                s += "\n" + "\n".join(f"  WARN: {w}" for w in self.warnings)
        return s


class PSILValidator:
    REQUIRED_TOP_LEVEL = {"psil_version", "document_id", "engagement", "scenarios", "metrics"}
    REQUIRED_ENGAGEMENT = {"engagement_id", "name", "organization", "scope", "tlp_marking"}
    REQUIRED_SCENARIO = {"scenario_id", "name", "attack", "defense", "outcome"}
    REQUIRED_ATTACK = {"technique_id", "tactic"}
    REQUIRED_DEFENSE = {"detected"}
    VALID_OUTCOMES = {
        "prevented", "detected_and_blocked", "detected_not_blocked",
        "detected_late", "not_detected", "partial_detection", "false_positive_generated"
    }
    VALID_TLP = {"TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"}

    def validate(self, doc: dict) -> ValidationResult:
        errors = []
        warnings = []

        # Top-level fields
        missing_top = self.REQUIRED_TOP_LEVEL - set(doc.keys())
        if missing_top:
            errors.append(f"Missing required top-level fields: {missing_top}")

        # Version check
        version = doc.get("psil_version", "")
        if not version.startswith("1."):
            errors.append(f"Unsupported PSIL version: {version}")

        # Engagement object
        eng = doc.get("engagement", {})
        missing_eng = self.REQUIRED_ENGAGEMENT - set(eng.keys())
        if missing_eng:
            errors.append(f"Missing required engagement fields: {missing_eng}")

        tlp = eng.get("tlp_marking", "")
        if tlp and tlp not in self.VALID_TLP:
            errors.append(f"Invalid TLP marking: {tlp}")

        scope = eng.get("scope", [])
        if not scope:
            warnings.append("Engagement scope is empty")

        # Scenarios
        scenarios = doc.get("scenarios", [])
        if not scenarios:
            warnings.append("Document contains no scenarios")

        for i, scen in enumerate(scenarios):
            prefix = f"scenarios[{i}]"
            missing_scen = self.REQUIRED_SCENARIO - set(scen.keys())
            if missing_scen:
                errors.append(f"{prefix}: Missing fields: {missing_scen}")

            outcome = scen.get("outcome", "")
            if outcome and outcome not in self.VALID_OUTCOMES:
                errors.append(f"{prefix}: Invalid outcome: {outcome}")

            attack = scen.get("attack", {})
            missing_atk = self.REQUIRED_ATTACK - set(attack.keys())
            if missing_atk:
                errors.append(f"{prefix}.attack: Missing fields: {missing_atk}")

            defense = scen.get("defense", {})
            if "detected" not in defense:
                errors.append(f"{prefix}.defense: Missing required field 'detected'")

            # ATT&CK technique ID format check
            tech_id = attack.get("technique_id", "")
            if tech_id and not (tech_id.startswith("T") and len(tech_id) >= 5):
                warnings.append(f"{prefix}: technique_id '{tech_id}' may not be a valid ATT&CK ID")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def validate_file(self, path: str) -> ValidationResult:
        import json
        try:
            with open(path) as f:
                doc = json.load(f)
            return self.validate(doc)
        except json.JSONDecodeError as e:
            return ValidationResult(valid=False, errors=[f"JSON parse error: {e}"], warnings=[])
        except FileNotFoundError:
            return ValidationResult(valid=False, errors=[f"File not found: {path}"], warnings=[])
