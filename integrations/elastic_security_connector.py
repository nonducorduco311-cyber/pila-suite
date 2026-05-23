"""
PILA Suite — Elastic Security Connector
Queries Elastic Security detection alerts from Elasticsearch.

Elastic Security adds pre-built ATT&CK-mapped detection rules that
complement Suricata's custom rules and Wazuh's HIDS alerts:
  - Network reconnaissance detection (port scans, service discovery)
  - Threat intelligence matches
  - Anomaly detection (ML-based)
  - Pre-built MITRE ATT&CK rule library (thousands of rules)
  - Full ATT&CK tactic + technique mapping on every alert

The key advantage over Suricata: Elastic Security alerts come with
ATT&CK technique IDs built in — PILA can use these directly for
technique-level correlation without regex matching.

© 2026 ByTE X Bit Technologies LLC — Patent Pending
"""

import json
import ssl
import urllib.request
import urllib.error
import base64
import configparser
import os
from datetime import datetime, timezone, timedelta
from typing import Optional


# ── Config ────────────────────────────────────────────────────────────────────

class ElasticSecurityConfig:
    def __init__(self, conf_path: Optional[str] = None):
        cfg = configparser.ConfigParser()
        candidates = [
            conf_path or "",
            os.path.join(os.path.dirname(__file__), "pila.conf"),
            os.path.join(os.path.dirname(__file__), "..", "integrations", "pila.conf"),
        ]
        for p in candidates:
            if p and os.path.exists(p):
                cfg.read(p)
                break

        # Fall back to elasticsearch section if no elastic_security section
        src = "elastic_security" if cfg.has_section("elastic_security") else "elasticsearch"

        if not cfg.has_section(src):
            self.host       = "192.168.10.172"
            self.port       = 9200
            self.username   = "elastic"
            self.password   = ""
            self.verify_ssl = False
            self.index      = ".alerts-security*"
            self.enabled    = False
            return

        s = cfg[src]
        self.host       = s.get("host",       "192.168.10.172")
        self.port       = int(s.get("port",   "9200"))
        self.username   = s.get("username",   "elastic")
        self.password   = s.get("password",   "")
        self.verify_ssl = s.getboolean("verify_ssl", False)
        self.index      = ".alerts-security*"
        self.enabled    = True

    @property
    def url(self) -> str:
        return f"https://{self.host}:{self.port}"

    @property
    def auth_header(self) -> str:
        creds = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()
        return f"Basic {creds}"


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _ssl_ctx(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def _search(cfg: ElasticSecurityConfig, query: dict, size: int = 50) -> list[dict]:
    url     = f"{cfg.url}/{cfg.index}/_search"
    payload = json.dumps({
        "size": size,
        "query": query,
        "sort": [{"kibana.alert.start": "desc"}],
    }).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": cfg.auth_header,
                 "X-Elastic-Product-Origin": "kibana"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(cfg.verify_ssl),
                                    timeout=10) as r:
            data = json.loads(r.read())
            return [h["_source"] for h in data.get("hits", {}).get("hits", [])]
    except Exception as e:
        raise ConnectionError(f"Elastic Security unreachable: {e}")


# ── Normalisation ─────────────────────────────────────────────────────────────

def _extract_attck(h: dict) -> list[dict]:
    """Extract ATT&CK mappings from an Elastic Security alert."""
    threat = h.get("kibana.alert.rule.parameters", {}).get("threat", [])
    mappings = []
    for t in threat:
        tactic = t.get("tactic", {})
        for tech in t.get("technique", []):
            mappings.append({
                "tactic_id":    tactic.get("id"),
                "tactic_name":  tactic.get("name"),
                "technique_id": tech.get("id"),
                "technique":    tech.get("name"),
            })
            # Include subtechniques
            for sub in tech.get("subtechnique", []):
                mappings.append({
                    "tactic_id":    tactic.get("id"),
                    "tactic_name":  tactic.get("name"),
                    "technique_id": sub.get("id"),
                    "technique":    sub.get("name"),
                })
    return mappings


def _norm_alert(h: dict) -> dict:
    """Normalize an Elastic Security alert into PILA's common alert schema."""
    params = h.get("kibana.alert.rule.parameters", {})

    return {
        "timestamp":      h.get("kibana.alert.start") or h.get("@timestamp"),
        "alert_sig":      h.get("kibana.alert.rule.name"),
        "rule_id":        params.get("rule_id") or h.get("kibana.alert.rule.uuid"),
        "severity":       h.get("kibana.alert.severity"),
        "risk_score":     h.get("kibana.alert.risk_score") or params.get("risk_score"),
        "status":         h.get("kibana.alert.workflow_status", "open"),
        "src_ip":         h.get("source", {}).get("ip") if isinstance(h.get("source"), dict) else None,
        "dst_ip":         h.get("destination", {}).get("ip") if isinstance(h.get("destination"), dict) else None,
        "host":           h.get("host", {}).get("name") if isinstance(h.get("host"), dict) else None,
        "attck_mappings": _extract_attck(h),
        "description":    params.get("description", "")[:200] if params.get("description") else None,
        "source":         "elastic_security",
    }


# ── Public connector API ──────────────────────────────────────────────────────

class ElasticSecurityConnector:
    """
    PILA Suite connector for Elastic Security detection alerts.

    Queries .alerts-security* indices for:
      - Detection rule alerts with full ATT&CK mappings
      - Technique-level correlation (ATT&CK IDs built into every alert)
      - Host cleanliness checks using Elastic Security signal data
      - Severity and risk score filtering

    Uses the existing Elasticsearch credentials from pila.conf [elasticsearch].
    No additional configuration required if ES is already connected.
    """

    def __init__(self, conf_path: Optional[str] = None):
        self.cfg = ElasticSecurityConfig(conf_path)

    def ping(self) -> dict:
        """Test connectivity and count available alerts."""
        url = f"{self.cfg.url}/{self.cfg.index}/_count"
        req = urllib.request.Request(
            url,
            headers={"Authorization": self.cfg.auth_header,
                     "X-Elastic-Product-Origin": "kibana"},
        )
        try:
            with urllib.request.urlopen(req, context=_ssl_ctx(self.cfg.verify_ssl),
                                        timeout=5) as r:
                data = json.loads(r.read())
                return {
                    "connected":     True,
                    "total_alerts":  data.get("count", 0),
                    "index_pattern": self.cfg.index,
                    "source":        "elastic_security",
                }
        except Exception as e:
            raise ConnectionError(f"Elastic Security unreachable: {e}")

    def query_alerts(
        self,
        technique_id:   Optional[str] = None,
        severity:       Optional[str] = None,
        host:           Optional[str] = None,
        src_ip:         Optional[str] = None,
        window_seconds: int = 300,
        after:          Optional[datetime] = None,
        status:         str = "open",
    ) -> list[dict]:
        """
        Query Elastic Security detection alerts.

        Args:
            technique_id:   Filter by ATT&CK technique ID (e.g. 'T1046')
            severity:       Filter by severity ('low', 'medium', 'high', 'critical')
            host:           Filter by hostname
            src_ip:         Filter by source IP
            window_seconds: How far back to look
            after:          Explicit start time
            status:         Alert workflow status ('open', 'acknowledged', 'closed')
        """
        after = after or (
            datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        )

        must = [
            {"range": {"kibana.alert.start": {"gte": after.isoformat()}}},
        ]

        if status:
            must.append({"term": {"kibana.alert.workflow_status": status}})
        if severity:
            must.append({"term": {"kibana.alert.severity": severity}})
        if host:
            must.append({"term": {"host.name": host}})
        if src_ip:
            must.append({"term": {"source.ip": src_ip}})
        if technique_id:
            # Search in the nested threat array for the technique ID
            must.append({
                "nested": {
                    "path": "kibana.alert.rule.parameters.threat",
                    "query": {
                        "bool": {
                            "should": [
                                {"term": {"kibana.alert.rule.parameters.threat.technique.id": technique_id}},
                                {"term": {"kibana.alert.rule.parameters.threat.technique.subtechnique.id": technique_id}},
                            ]
                        }
                    }
                }
            })

        hits = _search(self.cfg, {"bool": {"must": must}}, size=50)
        return [_norm_alert(h) for h in hits]

    def query_by_technique(
        self,
        technique_id:   str,
        window_seconds: int = 300,
        after:          Optional[datetime] = None,
    ) -> list[dict]:
        """
        Query alerts that match a specific ATT&CK technique.
        Used by LMEP correlation to check if Elastic Security detected a technique.
        Falls back to keyword search if nested query fails.
        """
        after = after or (
            datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        )
        must = [
            {"range": {"kibana.alert.start": {"gte": after.isoformat()}}},
            {"multi_match": {
                "query": technique_id,
                "fields": [
                    "kibana.alert.rule.name",
                    "kibana.alert.rule.parameters.threat.technique.id",
                    "kibana.alert.rule.parameters.threat.technique.subtechnique.id",
                ]
            }},
        ]
        hits = _search(self.cfg, {"bool": {"must": must}}, size=20)
        return [_norm_alert(h) for h in hits]

    def check_host_clean(
        self,
        host:           str,
        incident_type:  str = "malware",
        window_minutes: int = 10,
    ) -> dict:
        """
        Check if a host has active Elastic Security alerts.
        Complements Suricata (network) and Wazuh (HIDS) host checks.
        """
        after = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        # Map incident type to relevant severities
        min_severity = {
            "malware":               "high",
            "ransomware":            "high",
            "credential_compromise": "medium",
            "lateral_movement":      "medium",
            "data_exfiltration":     "medium",
            "phishing":              "low",
            "insider_threat":        "low",
        }.get(incident_type, "medium")

        severity_order = ["low", "medium", "high", "critical"]
        min_idx = severity_order.index(min_severity)
        severities = severity_order[min_idx:]

        all_alerts = []
        for sev in severities:
            alerts = self.query_alerts(
                host=host,
                severity=sev,
                after=after,
                window_seconds=window_minutes * 60,
            )
            all_alerts.extend(alerts)

        clean = len(all_alerts) == 0
        return {
            "host":           host,
            "incident_type":  incident_type,
            "window_minutes": window_minutes,
            "clean":          clean,
            "elastic_alerts": len(all_alerts),
            "source":         "elastic_security",
            "summary": (
                f"CLEAN (Elastic Security) — no alerts on {host} "
                f"in last {window_minutes}m"
                if clean else
                f"NOT CLEAN (Elastic Security) — {len(all_alerts)} alert(s) on {host} "
                f"in last {window_minutes}m"
            ),
            "alerts": all_alerts[:10],
        }

    def correlate_technique(
        self,
        technique_id:   str,
        target_ip:      Optional[str] = None,
        emulation_time: Optional[datetime] = None,
        window_seconds: int = 120,
    ) -> dict:
        """
        Correlate an LMEP technique against Elastic Security alerts.
        Elastic Security's ATT&CK-native alerts make this highly accurate —
        if a detection rule for the technique exists and fired, it will appear here.
        """
        after = emulation_time or (
            datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        )

        alerts = self.query_by_technique(
            technique_id=technique_id,
            after=after,
            window_seconds=window_seconds,
        )

        # Filter by target IP if provided
        if target_ip and alerts:
            alerts = [
                a for a in alerts
                if a.get("src_ip") == target_ip
                or a.get("dst_ip") == target_ip
                or a.get("host") == target_ip
            ] or alerts  # Fall back to all if IP filter removes everything

        detected = len(alerts) > 0
        return {
            "technique_id":      technique_id,
            "target_ip":         target_ip,
            "emulation_time":    after.isoformat(),
            "detected":          detected,
            "detection_sources": ["Elastic Security"] if detected else [],
            "elastic_alerts":    len(alerts),
            "source":            "elastic_security",
            "top_alerts": [
                {
                    "alert_sig":      a["alert_sig"],
                    "severity":       a["severity"],
                    "risk_score":     a["risk_score"],
                    "attck_mappings": a["attck_mappings"],
                    "timestamp":      a["timestamp"],
                }
                for a in alerts[:5]
            ],
        }
