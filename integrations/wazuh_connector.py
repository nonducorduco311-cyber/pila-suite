"""
PILA Suite — Wazuh Connector
Queries the Wazuh Indexer directly for HIDS alerts, agent status,
and host cleanliness checks.

Wazuh adds endpoint-level visibility that Suricata/Zeek cannot provide:
  - Windows Event Log alerts (authentication, process execution, registry)
  - File integrity monitoring (FIM) violations
  - Vulnerability detection
  - Agent-based host cleanliness checks (no network dependency)

© 2026 ByTE X Bit Technologies LLC — Patent Pending
"""

import json
import ssl
import urllib.request
import urllib.error
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional

import configparser
import os


# ── Config ────────────────────────────────────────────────────────────────────

class WazuhConfig:
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

        if not cfg.has_section("wazuh"):
            # Defaults
            self.host       = ""
            self.port       = 9200
            self.username   = "admin"
            self.password   = ""
            self.verify_ssl = False
            self.index      = "wazuh-alerts-4.x-*"
            self.min_level  = 3
            self.enabled    = False
            return

        w = cfg["wazuh"]
        self.host       = w.get("host",       "")
        self.port       = int(w.get("port",   "9200"))
        self.username   = w.get("username",   "admin")
        self.password   = w.get("password",   "")
        self.verify_ssl = w.getboolean("verify_ssl", False)
        self.index      = w.get("index",      "wazuh-alerts-4.x-*")
        self.min_level  = int(w.get("min_level", "3"))
        self.enabled    = w.getboolean("enabled", True)

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


def _search(cfg: WazuhConfig, index: str, query: dict, size: int = 50) -> list[dict]:
    """Run an ES-compatible search against the Wazuh indexer."""
    url     = f"{cfg.url}/{index}/_search"
    payload = json.dumps({"size": size, "query": query,
                          "sort": [{"@timestamp": "desc"}]}).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": cfg.auth_header},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(cfg.verify_ssl),
                                    timeout=10) as r:
            data = json.loads(r.read())
            return [h["_source"] for h in data.get("hits", {}).get("hits", [])]
    except Exception as e:
        raise ConnectionError(f"Wazuh indexer unreachable: {e}")


# ── Normalisation ─────────────────────────────────────────────────────────────

def _norm_alert(h: dict) -> dict:
    """Normalize a raw Wazuh alert into PILA's common alert schema."""
    rule    = h.get("rule", {})
    agent   = h.get("agent", {})
    data    = h.get("data", {})

    # Try to extract source IP from various Wazuh data structures
    src_ip = (
        data.get("srcip") or
        data.get("src_ip") or
        data.get("win", {}).get("eventdata", {}).get("ipAddress") or
        agent.get("ip") or
        None
    )

    return {
        "timestamp":     h.get("@timestamp"),
        "alert_sig":     rule.get("description"),
        "rule_id":       rule.get("id"),
        "rule_level":    rule.get("level"),
        "rule_groups":   rule.get("groups", []),
        "agent_name":    agent.get("name"),
        "agent_ip":      agent.get("ip"),
        "src_ip":        src_ip,
        "location":      h.get("location"),
        "decoder":       h.get("decoder", {}).get("name"),
        "source":        "wazuh",
    }


# ── Public connector API ──────────────────────────────────────────────────────

class WazuhConnector:
    """
    PILA Suite connector for Wazuh HIDS.

    Queries the Wazuh Indexer (OpenSearch-compatible) for:
      - HIDS alerts by agent IP, rule group, severity level, and time window
      - Host cleanliness checks (no active high-severity alerts on a host)
      - Authentication failure detection
      - File integrity monitoring violations

    Configuration in pila.conf [wazuh] section.
    """

    def __init__(self, conf_path: Optional[str] = None):
        self.cfg = WazuhConfig(conf_path)

    def ping(self) -> dict:
        """Test connectivity to the Wazuh indexer."""
        url = f"{self.cfg.url}/_cluster/health"
        req = urllib.request.Request(
            url, headers={"Authorization": self.cfg.auth_header}
        )
        try:
            with urllib.request.urlopen(req, context=_ssl_ctx(self.cfg.verify_ssl),
                                        timeout=5) as r:
                data = json.loads(r.read())
                return {
                    "connected":    True,
                    "cluster_name": data.get("cluster_name"),
                    "status":       data.get("status"),
                    "source":       "wazuh",
                }
        except Exception as e:
            raise ConnectionError(f"Wazuh indexer unreachable: {e}")

    def get_agents(self) -> list[dict]:
        """List all Wazuh agents seen in recent alerts."""
        try:
            # Query recent alerts and extract unique agents
            hits = _search(self.cfg, self.cfg.index,
                          {"match_all": {}}, size=200)
            seen = {}
            for h in hits:
                agent = h.get("agent", {})
                aid   = agent.get("id", agent.get("name", "unknown"))
                if aid and aid not in seen:
                    seen[aid] = {
                        "id":     aid,
                        "name":   agent.get("name"),
                        "ip":     agent.get("ip"),
                        "status": "active",
                    }
            return list(seen.values())
        except Exception:
            return []

    def query_alerts(
        self,
        agent_ip:       Optional[str] = None,
        agent_name:     Optional[str] = None,
        rule_group:     Optional[str] = None,
        min_level:      Optional[int] = None,
        window_seconds: int = 300,
        after:          Optional[datetime] = None,
    ) -> list[dict]:
        """
        Query Wazuh alerts with flexible filters.

        Args:
            agent_ip:       Filter by agent IP address
            agent_name:     Filter by agent hostname
            rule_group:     Filter by rule group (e.g. 'authentication_failed',
                            'attack', 'syscheck', 'vulnerability-detector')
            min_level:      Minimum Wazuh rule level (1-15). Default from config.
            window_seconds: How far back to look (seconds)
            after:          Explicit start time (overrides window_seconds)
        """
        after = after or (
            datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        )
        level = min_level if min_level is not None else self.cfg.min_level

        must = [
            {"range": {"@timestamp": {"gte": after.isoformat()}}},
            {"range": {"rule.level":  {"gte": level}}},
        ]

        if agent_ip:
            must.append({"term": {"agent.ip": agent_ip}})
        if agent_name:
            must.append({"match": {"agent.name": agent_name}})
        if rule_group:
            must.append({"term": {"rule.groups": rule_group}})

        hits = _search(self.cfg, self.cfg.index,
                       {"bool": {"must": must}}, size=50)
        return [_norm_alert(h) for h in hits]

    def check_host_clean(
        self,
        host_ip:        str,
        incident_type:  str = "malware",
        window_minutes: int = 10,
    ) -> dict:
        """
        Check if a host is clean — no active high-severity Wazuh alerts.
        Complements Suricata's network-level check with endpoint-level evidence.

        Returns a dict compatible with PILA's IRV host cleanliness schema.
        """
        after   = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        # Map incident type to relevant Wazuh rule groups
        GROUP_MAP = {
            "malware":              ["malware", "trojans", "rootcheck"],
            "credential_compromise":["authentication_failed", "authentication_failures"],
            "lateral_movement":     ["authentication_failed", "attack"],
            "ransomware":           ["malware", "syscheck"],
            "data_exfiltration":    ["attack", "network"],
            "phishing":             ["phishing", "attack"],
            "insider_threat":       ["syscheck", "audit"],
        }
        groups = GROUP_MAP.get(incident_type, ["attack"])

        all_alerts = []
        for group in groups:
            alerts = self.query_alerts(
                agent_ip=host_ip,
                rule_group=group,
                min_level=7,          # only high-severity for cleanliness check
                after=after,
                window_seconds=window_minutes * 60,
            )
            all_alerts.extend(alerts)

        # Deduplicate by rule_id + timestamp
        seen   = set()
        unique = []
        for a in all_alerts:
            k = f"{a['rule_id']}:{a['timestamp']}"
            if k not in seen:
                seen.add(k)
                unique.append(a)

        clean = len(unique) == 0
        return {
            "host_ip":        host_ip,
            "incident_type":  incident_type,
            "window_minutes": window_minutes,
            "clean":          clean,
            "wazuh_alerts":   len(unique),
            "source":         "wazuh",
            "summary": (
                f"CLEAN (Wazuh) — no high-severity alerts on {host_ip} "
                f"in last {window_minutes}m"
                if clean else
                f"NOT CLEAN (Wazuh) — {len(unique)} alert(s) on {host_ip} "
                f"in last {window_minutes}m"
            ),
            "alerts": unique[:10],  # top 10 for evidence bundle
        }

    def correlate_technique(
        self,
        technique_id:   str,
        target_ip:      str,
        emulation_time: datetime,
        window_seconds: int = 120,
    ) -> dict:
        """
        Correlate an LMEP technique execution against Wazuh HIDS alerts.
        Complements Suricata network detection with endpoint-level signals.

        Wazuh detects what Suricata cannot:
          - Process execution on the target host (T1059)
          - Authentication attempts in Windows Event Log (T1110, T1021)
          - File drops and modifications (T1105, syscheck)
          - Registry changes (T1547)
        """
        # Map ATT&CK technique to relevant Wazuh rule groups
        TECHNIQUE_GROUPS = {
            "T1021.001": ["authentication_failed", "windows"],      # RDP
            "T1021.002": ["authentication_failed", "windows"],      # SMB
            "T1021.003": ["windows", "attack"],                     # DCOM
            "T1021.004": ["authentication_failed", "sshd"],         # SSH
            "T1021.006": ["windows", "authentication_failed"],      # WinRM
            "T1110":     ["authentication_failures", "brute_force"],# Brute force
            "T1059":     ["windows", "attack"],                     # Script exec
            "T1105":     ["syscheck"],                              # File transfer
            "T1547":     ["windows", "registry"],                   # Persistence
            "T1550.002": ["authentication_failed", "windows"],      # Pass-the-Hash
            "T1135":     ["windows", "attack"],                     # Net share
            "T1534":     ["phishing", "attack"],                    # Spearphishing
        }
        groups = TECHNIQUE_GROUPS.get(technique_id, ["attack"])

        all_alerts = []
        for group in groups:
            alerts = self.query_alerts(
                agent_ip=target_ip,
                rule_group=group,
                min_level=self.cfg.min_level,
                after=emulation_time,
                window_seconds=window_seconds,
            )
            all_alerts.extend(alerts)

        # Deduplicate
        seen   = set()
        unique = []
        for a in all_alerts:
            k = f"{a['rule_id']}:{a['timestamp']}"
            if k not in seen:
                seen.add(k)
                unique.append(a)

        detected = len(unique) > 0
        return {
            "technique_id":      technique_id,
            "target_ip":         target_ip,
            "emulation_time":    emulation_time.isoformat(),
            "detected":          detected,
            "detection_sources": ["Wazuh"] if detected else [],
            "wazuh_alerts":      len(unique),
            "source":            "wazuh",
            "top_alerts": [
                {
                    "alert_sig":  a["alert_sig"],
                    "rule_id":    a["rule_id"],
                    "rule_level": a["rule_level"],
                    "agent_name": a["agent_name"],
                    "timestamp":  a["timestamp"],
                }
                for a in unique[:5]
            ],
        }
