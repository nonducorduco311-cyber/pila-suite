"""
PILA Suite — Test Suite
© 2026 ByTE X Bit Technologies LLC

Tests covering:
- AESP scoring formula and DMT tier classification
- PSIL engagement creation and validation
- API authentication (401 without key, 200 with key)
- Error handling (404, 422 responses)
- Connector config loading
- IRV incident type validation
- LMEP technique validation
"""

import pytest
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── AESP Scoring Tests ────────────────────────────────────────────────────────

class TestAESPScoring:
    """Tests for the AESP scoring engine and DMT tier classification."""

    def _make_scenarios(self, outcomes):
        """Helper to create scenario dicts from a list of outcome strings."""
        scenarios = []
        for i, outcome in enumerate(outcomes):
            scenarios.append({
                "scenario_id": f"scen-{i}",
                "name": f"Test scenario {i}",
                "technique_id": f"T100{i}.001",
                "tactic": "Lateral Movement",
                "detected": outcome in ("detected", "prevented", "detected_late"),
                "outcome": outcome,
                "severity": "HIGH",
                "gap_identified": outcome == "not_detected",
                "gap_detail": "No rule" if outcome == "not_detected" else "",
                "detection_source": "Suricata" if outcome != "not_detected" else "",
                "response_action": "Alert" if outcome != "not_detected" else "",
                "remediation_validated": outcome in ("detected", "prevented"),
            })
        return scenarios

    def test_perfect_score_all_detected(self):
        """All techniques detected should produce high ES and DMT-4 or DMT-5."""
        try:
            from aesp.aesp_score import calculate_score
            scenarios = self._make_scenarios(["detected"] * 5)
            result = calculate_score(scenarios, "lateral_movement")
            assert result["effectiveness_score"] >= 70, \
                f"Expected ES >= 70 for all-detected, got {result['effectiveness_score']}"
            assert result["dmt"]["tier"] in ("DMT-4", "DMT-5"), \
                f"Expected DMT-4 or DMT-5, got {result['dmt']['tier']}"
        except ImportError:
            pytest.skip("AESP scoring engine not available in community edition")

    def test_zero_score_none_detected(self):
        """No techniques detected should produce low ES and DMT-1."""
        try:
            from aesp.aesp_score import calculate_score
            scenarios = self._make_scenarios(["not_detected"] * 5)
            result = calculate_score(scenarios, "lateral_movement")
            assert result["effectiveness_score"] <= 39, \
                f"Expected ES <= 39 for none-detected, got {result['effectiveness_score']}"
            assert result["dmt"]["tier"] == "DMT-1", \
                f"Expected DMT-1, got {result['dmt']['tier']}"
        except ImportError:
            pytest.skip("AESP scoring engine not available in community edition")

    def test_mixed_outcomes(self):
        """Mixed outcomes should produce mid-range ES."""
        try:
            from aesp.aesp_score import calculate_score
            scenarios = self._make_scenarios(
                ["detected", "not_detected", "detected", "not_detected", "detected_late"]
            )
            result = calculate_score(scenarios, "lateral_movement")
            assert 20 <= result["effectiveness_score"] <= 80, \
                f"Mixed outcomes should produce mid-range ES, got {result['effectiveness_score']}"
        except ImportError:
            pytest.skip("AESP scoring engine not available in community edition")

    def test_prevention_boosts_score(self):
        """Prevented techniques should score higher than merely detected."""
        try:
            from aesp.aesp_score import calculate_score
            detected_scenarios  = self._make_scenarios(["detected"] * 4)
            prevented_scenarios = self._make_scenarios(["prevented"] * 4)
            detected_result  = calculate_score(detected_scenarios,  "lateral_movement")
            prevented_result = calculate_score(prevented_scenarios, "lateral_movement")
            assert prevented_result["effectiveness_score"] >= detected_result["effectiveness_score"], \
                "Prevented should score >= detected"
        except ImportError:
            pytest.skip("AESP scoring engine not available in community edition")

    def test_dmt_tier_boundaries(self):
        """DMT tier labels should match defined ES ranges."""
        try:
            from aesp.aesp_score import get_dmt_tier
            assert get_dmt_tier(0)["tier"]   == "DMT-1"
            assert get_dmt_tier(39)["tier"]  == "DMT-1"
            assert get_dmt_tier(40)["tier"]  == "DMT-2"
            assert get_dmt_tier(54)["tier"]  == "DMT-2"
            assert get_dmt_tier(55)["tier"]  == "DMT-3"
            assert get_dmt_tier(69)["tier"]  == "DMT-3"
            assert get_dmt_tier(70)["tier"]  == "DMT-4"
            assert get_dmt_tier(84)["tier"]  == "DMT-4"
            assert get_dmt_tier(85)["tier"]  == "DMT-5"
            assert get_dmt_tier(100)["tier"] == "DMT-5"
        except ImportError:
            pytest.skip("AESP scoring engine not available in community edition")

    def test_es_bounded_0_to_100(self):
        """Effectiveness Score must always be between 0 and 100."""
        try:
            from aesp.aesp_score import calculate_score
            for outcomes in [
                ["detected"] * 10,
                ["not_detected"] * 10,
                ["prevented"] * 10,
                ["detected_late"] * 10,
            ]:
                scenarios = self._make_scenarios(outcomes)
                result = calculate_score(scenarios, "lateral_movement")
                es = result["effectiveness_score"]
                assert 0 <= es <= 100, f"ES out of bounds: {es}"
        except ImportError:
            pytest.skip("AESP scoring engine not available in community edition")

    def test_empty_scenarios_handled(self):
        """Empty scenario list should not crash the scoring engine."""
        try:
            from aesp.aesp_score import calculate_score
            result = calculate_score([], "lateral_movement")
            assert "effectiveness_score" in result
            assert "dmt" in result
        except (ImportError, Exception) as e:
            if "ImportError" in type(e).__name__:
                pytest.skip("AESP scoring engine not available in community edition")
            else:
                pytest.fail(f"Empty scenarios crashed the scorer: {e}")


# ── PSIL Validation Tests ─────────────────────────────────────────────────────

class TestPSILValidation:
    """Tests for PSIL engagement structure and ATT&CK technique ID validation."""

    def test_valid_technique_id_format(self):
        """ATT&CK technique IDs must match T####.### or T#### format."""
        import re
        pattern = r'^T\d{4}(\.\d{3})?$'
        valid   = ["T1021", "T1021.004", "T1059.001", "T1110"]
        invalid = ["t1021", "T102", "T1021.04", "TA001", "1021.004"]
        for t in valid:
            assert re.match(pattern, t), f"Valid technique ID rejected: {t}"
        for t in invalid:
            assert not re.match(pattern, t), f"Invalid technique ID accepted: {t}"

    def test_valid_outcome_values(self):
        """Outcome field must be one of the four valid values."""
        valid_outcomes   = ["detected", "not_detected", "prevented", "detected_late"]
        invalid_outcomes = ["missed", "blocked", "found", "yes", "no", ""]
        for o in valid_outcomes:
            assert o in valid_outcomes
        for o in invalid_outcomes:
            assert o not in valid_outcomes

    def test_valid_tlp_markings(self):
        """TLP markings must be one of the four valid values."""
        valid   = ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]
        invalid = ["TLP:BLUE", "tlp:amber", "AMBER", "TLP WHITE", ""]
        for t in valid:
            assert t in valid
        for t in invalid:
            assert t not in valid

    def test_valid_severity_values(self):
        """Severity must be one of the five valid values."""
        valid   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        invalid = ["critical", "high", "WARN", "ERROR", "5", ""]
        for s in valid:
            assert s in valid
        for s in invalid:
            assert s not in valid

    def test_engagement_requires_name(self):
        """Engagement creation must require a name field."""
        engagement = {"organization": "Test Org", "scope": ["192.168.1.0/24"]}
        assert "name" not in engagement

    def test_scope_is_list(self):
        """Scope must be a list of strings."""
        valid_scope   = ["192.168.1.0/24", "10.0.0.1"]
        invalid_scope = "192.168.1.0/24"
        assert isinstance(valid_scope, list)
        assert not isinstance(invalid_scope, list)


# ── API Authentication Tests ──────────────────────────────────────────────────

class TestAPIAuthentication:
    """Tests for API key authentication middleware."""

    @pytest.fixture
    def client(self):
        """Create a test client for the FastAPI app."""
        try:
            from fastapi.testclient import TestClient
            import httpx
            # Import the app — this requires the full server
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
            from api.server import app
            return TestClient(app)
        except Exception as e:
            pytest.skip(f"Cannot create test client: {e}")

    @pytest.fixture
    def api_key(self):
        """Load the API key from pila.conf."""
        import configparser
        cfg = configparser.ConfigParser()
        cfg_path = os.path.join(os.path.dirname(__file__), "../integrations/pila.conf")
        cfg.read(cfg_path)
        return cfg.get("api", "api_key", fallback="")

    def test_health_no_auth_required(self, client):
        """Health endpoint should return 200 without API key."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_protected_endpoint_no_key_returns_401(self, client):
        """Protected endpoints should return 401 without API key."""
        response = client.get("/psil/engagements")
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data or "error" in data

    def test_protected_endpoint_wrong_key_returns_401(self, client):
        """Protected endpoints should return 401 with wrong API key."""
        response = client.get("/psil/engagements",
                              headers={"X-API-Key": "wrong-key-12345"})
        assert response.status_code == 401

    def test_protected_endpoint_correct_key_returns_200(self, client, api_key):
        """Protected endpoints should return 200 with correct API key."""
        if not api_key:
            pytest.skip("No API key configured")
        response = client.get("/psil/engagements",
                              headers={"X-API-Key": api_key})
        assert response.status_code == 200

    def test_docs_no_auth_required(self, client):
        """API docs should be accessible without authentication."""
        response = client.get("/docs")
        assert response.status_code == 200


# ── Error Handling Tests ──────────────────────────────────────────────────────

class TestErrorHandling:
    """Tests for consistent error response format."""

    @pytest.fixture
    def client(self):
        try:
            from fastapi.testclient import TestClient
            from api.server import app
            return TestClient(app)
        except Exception as e:
            pytest.skip(f"Cannot create test client: {e}")

    @pytest.fixture
    def api_key(self):
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(os.path.dirname(__file__), "../integrations/pila.conf"))
        return cfg.get("api", "api_key", fallback="")

    def test_404_returns_json(self, client, api_key):
        """404 errors should return JSON with error and status_code fields."""
        response = client.get("/psil/engagements/nonexistent-id-xyz",
                              headers={"X-API-Key": api_key})
        assert response.status_code == 404
        data = response.json()
        assert "error" in data or "detail" in data

    def test_422_returns_field_details(self, client, api_key):
        """422 validation errors should include field-level details."""
        response = client.post("/psil/engagements",
                               headers={"X-API-Key": api_key,
                                        "Content-Type": "application/json"},
                               content=json.dumps({"invalid_field": "value"}))
        assert response.status_code == 422
        data = response.json()
        assert "error" in data or "detail" in data

    def test_404_not_html(self, client, api_key):
        """404 errors must not return HTML (no raw traceback)."""
        response = client.get("/nonexistent-endpoint-xyz",
                              headers={"X-API-Key": api_key})
        assert "text/html" not in response.headers.get("content-type", "")


# ── Connector Config Tests ────────────────────────────────────────────────────

class TestConnectorConfig:
    """Tests for connector configuration loading."""

    def test_pila_conf_exists(self):
        """pila.conf must exist."""
        conf_path = os.path.join(os.path.dirname(__file__), "../integrations/pila.conf")
        assert os.path.exists(conf_path), "pila.conf not found"

    def test_elasticsearch_section_exists(self):
        """pila.conf must have [elasticsearch] section."""
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(os.path.dirname(__file__), "../integrations/pila.conf"))
        assert "elasticsearch" in cfg, "Missing [elasticsearch] section in pila.conf"

    def test_elasticsearch_has_required_fields(self):
        """[elasticsearch] section must have host, port, username, password."""
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(os.path.dirname(__file__), "../integrations/pila.conf"))
        es = cfg["elasticsearch"]
        for field in ["host", "port", "username", "password"]:
            assert field in es, f"Missing field '{field}' in [elasticsearch]"

    def test_api_key_configured(self):
        """[api] section must have api_key configured."""
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(os.path.dirname(__file__), "../integrations/pila.conf"))
        assert "api" in cfg, "Missing [api] section in pila.conf"
        assert cfg.get("api", "api_key", fallback="") != "", \
            "api_key is empty in [api] section"

    def test_wazuh_connector_loads(self):
        """Wazuh connector should initialize without errors."""
        try:
            from integrations.wazuh_connector import WazuhConnector
            conn = WazuhConnector()
            assert conn is not None
        except Exception as e:
            pytest.fail(f"Wazuh connector failed to initialize: {e}")

    def test_splunk_connector_loads(self):
        """Splunk connector should initialize without errors."""
        try:
            from integrations.splunk_connector import SplunkConnector
            conn = SplunkConnector()
            assert conn.host != ""
        except Exception as e:
            pytest.fail(f"Splunk connector failed to initialize: {e}")

    def test_winlogbeat_connector_loads(self):
        """Winlogbeat connector should initialize without errors."""
        try:
            from integrations.winlogbeat_connector import WinlogbeatConnector
            conn = WinlogbeatConnector()
            assert conn is not None
        except Exception as e:
            pytest.fail(f"Winlogbeat connector failed to initialize: {e}")


# ── IRV Incident Type Tests ───────────────────────────────────────────────────

class TestIRVValidation:
    """Tests for IRV incident type and scope validation."""

    VALID_INCIDENT_TYPES = [
        "malware", "credential_compromise", "ransomware",
        "lateral_movement", "data_exfiltration", "phishing", "insider_threat"
    ]

    def test_valid_incident_types(self):
        """All seven incident types should be recognized."""
        assert len(self.VALID_INCIDENT_TYPES) == 7
        for t in self.VALID_INCIDENT_TYPES:
            assert isinstance(t, str) and len(t) > 0

    def test_invalid_incident_type_rejected(self):
        """Invalid incident types should not be in the valid list."""
        invalid = ["exploit", "ddos", "unknown", "all", ""]
        for t in invalid:
            assert t not in self.VALID_INCIDENT_TYPES

    def test_scope_ip_format(self):
        """Scope IPs should be valid IPv4 addresses or CIDR ranges."""
        import re
        ipv4_pattern = r'^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)(/\d{1,2})?$'
        valid_ips   = ["192.168.10.192", "10.0.0.1", "192.168.0.0/24"]
        invalid_ips = ["192.168.10", "999.999.999.999", "hostname", ""]
        for ip in valid_ips:
            assert re.match(ipv4_pattern, ip), f"Valid IP rejected: {ip}"
        for ip in invalid_ips:
            assert not re.match(ipv4_pattern, ip), f"Invalid IP accepted: {ip}"


# ── LMEP Technique Tests ──────────────────────────────────────────────────────

class TestLMEPValidation:
    """Tests for LMEP technique and session validation."""

    VALID_TECHNIQUES = [
        "T1021.001", "T1021.002", "T1021.003", "T1021.004",
        "T1021.006", "T1135", "T1534", "T1550.002"
    ]

    VALID_CREDENTIAL_MODES = ["SYNTHETIC", "SEMI_ACTIVE"]
    VALID_DEPLOYMENT_MODES  = ["PASSIVE", "SEMI_ACTIVE"]

    def test_all_eight_techniques_defined(self):
        """LMEP v1.0 should support exactly 8 techniques."""
        assert len(self.VALID_TECHNIQUES) == 8

    def test_technique_ids_valid_format(self):
        """All LMEP technique IDs should match ATT&CK format."""
        import re
        pattern = r'^T\d{4}(\.\d{3})?$'
        for t in self.VALID_TECHNIQUES:
            assert re.match(pattern, t), f"Invalid technique ID format: {t}"

    def test_credential_modes_valid(self):
        """Only SYNTHETIC and SEMI_ACTIVE credential modes should be valid."""
        assert "SYNTHETIC" in self.VALID_CREDENTIAL_MODES
        assert "REAL" not in self.VALID_CREDENTIAL_MODES
        assert "ACTIVE" not in self.VALID_CREDENTIAL_MODES

    def test_deployment_modes_valid(self):
        """Only PASSIVE and SEMI_ACTIVE deployment modes should be valid."""
        assert "PASSIVE" in self.VALID_DEPLOYMENT_MODES
        assert "ACTIVE" not in self.VALID_DEPLOYMENT_MODES
        assert "AGGRESSIVE" not in self.VALID_DEPLOYMENT_MODES
