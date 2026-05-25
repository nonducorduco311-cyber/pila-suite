"""
PILA Suite — Splunk Enterprise Connector
© 2026 ByTE X Bit Technologies LLC — Patent Pending

Queries Splunk Enterprise via REST API for security alerts,
correlates LMEP technique emulation results, and supports
IRV host cleanliness checks.

Supported Splunk versions: 8.x, 9.x, 10.x
Authentication: Username/password or API token
"""

import requests
import urllib3
import json
import time
from datetime import datetime, timezone
from typing import Optional
import configparser
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkConnector:
    """
    Connector for Splunk Enterprise REST API.
    Queries alerts, events, and performs host cleanliness checks.
    """

    def __init__(self, conf_path=None):
        import configparser, os
        if conf_path is None:
            conf_path = os.path.join(os.path.dirname(__file__), "pila.conf")
        cfg = configparser.ConfigParser()
        cfg.read(conf_path)
        s = cfg["splunk"] if "splunk" in cfg else {}
        self.host       = s.get("host", "192.168.10.122")
        self.port       = int(s.get("port", 8089))
        self.username   = s.get("username", "admin")
        self.password   = s.get("password", "")
        self.token      = s.get("token", "")
        self.verify_ssl = s.get("verify_ssl", "false").lower() == "true"
        self.index      = s.get("index", "main")
        self.hec_port   = int(s.get("hec_port", 8088))
        self.hec_token  = s.get("hec_token", "")
        self.base_url = f"https://{self.host}:{self.port}"
        self.hec_url  = f"https://{self.host}:{self.hec_port}"
        self.session  = requests.Session()
        self.session.verify = self.verify_ssl

        if self.token:
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        else:
            self.session.auth = (self.username, self.password)

    # ── Internal helpers ────────────────────────────────────────────────────

    def _run_search(self, spl: str, earliest: str = "-24h", latest: str = "now",
                    max_results: int = 1000) -> list:
        """Run a Splunk search and return results as a list of dicts."""
        try:
            # Submit search job
            resp = self.session.post(
                f"{self.base_url}/services/search/jobs",
                data={
                    "search":       f"search {spl}",
                    "earliest_time": earliest,
                    "latest_time":   latest,
                    "output_mode":  "json",
                },
                timeout=30
            )
            resp.raise_for_status()
            sid = resp.json()["sid"]

            # Poll until done
            for _ in range(30):
                status_resp = self.session.get(
                    f"{self.base_url}/services/search/jobs/{sid}",
                    params={"output_mode": "json"},
                    timeout=15
                )
                dispatch_state = status_resp.json()["entry"][0]["content"]["dispatchState"]
                if dispatch_state == "DONE":
                    break
                time.sleep(1)

            # Fetch results
            results_resp = self.session.get(
                f"{self.base_url}/services/search/jobs/{sid}/results",
                params={"output_mode": "json", "count": max_results},
                timeout=30
            )
            results_resp.raise_for_status()
            return results_resp.json().get("results", [])

        except Exception as e:
            return []

    def _spl_escape(self, value: str) -> str:
        """Escape a value for use in SPL queries."""
        return value.replace('"', '\\"').replace("'", "\\'")

    # ── Status and connectivity ──────────────────────────────────────────────

    def get_status(self) -> dict:
        """Check Splunk connectivity and return server info."""
        try:
            resp = self.session.get(
                f"{self.base_url}/services/server/info",
                params={"output_mode": "json"},
                timeout=10
            )
            resp.raise_for_status()
            info = resp.json()["entry"][0]["content"]

            # Get total event count
            results = self._run_search(
                f"index={self.index} | stats count",
                earliest="-7d"
            )
            total = int(results[0].get("count", 0)) if results else 0

            return {
                "connected":       True,
                "splunk_version":  info.get("version", "unknown"),
                "server_name":     info.get("serverName", "unknown"),
                "os_name":         info.get("os_name", "unknown"),
                "index":           self.index,
                "total_events_7d": total,
                "host":            self.host,
                "port":            self.port,
            }
        except Exception as e:
            return {
                "connected": False,
                "error":     str(e),
                "host":      self.host,
                "port":      self.port,
            }

    # ── Alert queries ────────────────────────────────────────────────────────

    def get_alerts(self, window_seconds: int = 86400, limit: int = 100) -> dict:
        """
        Query Splunk for security alerts.
        Returns alerts with technique mappings where available.
        """
        earliest = f"-{window_seconds}s"
        spl = (
            f"index={self.index} "
            f"| eval technique=coalesce(technique, event.technique, mitre_technique, \"-\") "
            f"| eval tactic=coalesce(tactic, event.tactic, mitre_tactic, \"-\") "
            f"| eval severity=coalesce(severity, event.severity, alert_severity, \"medium\") "
            f"| eval src_ip=coalesce(src_ip, event.src_ip, src, source_ip, \"-\") "
            f"| eval dest_ip=coalesce(dest_ip, event.dest_ip, dest, destination_ip, \"-\") "
            f"| eval signature=coalesce(signature, event.signature, alert_name, message, \"-\") "
            f"| eval msg=coalesce(message, event.message, _raw) "
            f"| table _time, msg, signature, technique, tactic, severity, src_ip, dest_ip "
            f"| head {limit}"
        )

        results = self._run_search(spl, earliest=earliest)

        alerts = []
        for r in results:
            alerts.append({
                "timestamp":  r.get("_time", ""),
                "message":    r.get("msg", ""),
                "signature":  r.get("signature", "-"),
                "technique":  r.get("technique", "-"),
                "tactic":     r.get("tactic", "-"),
                "severity":   r.get("severity", "medium"),
                "src_ip":     r.get("src_ip", "-"),
                "dest_ip":    r.get("dest_ip", "-"),
                "source":     "splunk",
            })

        return {
            "connected":    True,
            "alert_count":  len(alerts),
            "window_hours": round(window_seconds / 3600, 1),
            "index":        self.index,
            "alerts":       alerts,
            "source":       "splunk",
        }

    def get_alerts_by_technique(self, technique_id: str,
                                 window_seconds: int = 86400) -> dict:
        """
        Query Splunk for alerts matching a specific ATT&CK technique ID.
        Used by LMEP correlation after technique emulation.
        """
        earliest = f"-{window_seconds}s"
        escaped  = self._spl_escape(technique_id)

        spl = (
            f"index={self.index} "
            f"(technique=\"{escaped}\" OR event.technique=\"{escaped}\" "
            f" OR mitre_technique=\"{escaped}\" OR _raw=\"*{escaped}*\") "
            f"| eval severity=coalesce(severity, event.severity, \"medium\") "
            f"| eval signature=coalesce(signature, event.signature, message, \"-\") "
            f"| eval src_ip=coalesce(src_ip, event.src_ip, \"-\") "
            f"| eval dest_ip=coalesce(dest_ip, event.dest_ip, \"-\") "
            f"| table _time, signature, technique, tactic, severity, src_ip, dest_ip "
            f"| head 50"
        )

        results = self._run_search(spl, earliest=earliest)

        alerts = []
        for r in results:
            alerts.append({
                "timestamp": r.get("_time", ""),
                "signature": r.get("signature", "-"),
                "technique": r.get("technique", technique_id),
                "tactic":    r.get("tactic", "-"),
                "severity":  r.get("severity", "medium"),
                "src_ip":    r.get("src_ip", "-"),
                "dest_ip":   r.get("dest_ip", "-"),
                "source":    "splunk",
            })

        return {
            "technique_id":  technique_id,
            "detected":      len(alerts) > 0,
            "alert_count":   len(alerts),
            "window_seconds": window_seconds,
            "alerts":        alerts,
            "source":        "splunk",
        }

    # ── Host cleanliness check ───────────────────────────────────────────────

    def host_check(self, host_ip: str, incident_type: str = "malware",
                   window_minutes: int = 10) -> dict:
        """
        IRV host cleanliness check via Splunk.
        Returns whether the host shows active malicious indicators.
        """
        earliest   = f"-{window_minutes}m"
        escaped_ip = self._spl_escape(host_ip)

        # Build SPL based on incident type
        type_filters = {
            "malware": (
                f"index={self.index} "
                f"(src_ip=\"{escaped_ip}\" OR dest_ip=\"{escaped_ip}\" "
                f" OR event.src_ip=\"{escaped_ip}\" OR event.dest_ip=\"{escaped_ip}\") "
                f"(technique=\"T1071\" OR technique=\"T1059\" OR technique=\"T1055\" "
                f" OR signature=\"*malware*\" OR signature=\"*trojan*\" OR signature=\"*beacon*\")"
            ),
            "lateral_movement": (
                f"index={self.index} "
                f"(src_ip=\"{escaped_ip}\" OR dest_ip=\"{escaped_ip}\") "
                f"(technique=\"T1021*\" OR technique=\"T1550*\" OR technique=\"T1534\" "
                f" OR signature=\"*lateral*\" OR signature=\"*SMB*\" OR signature=\"*RDP*\")"
            ),
            "credential_compromise": (
                f"index={self.index} "
                f"(src_ip=\"{escaped_ip}\" OR dest_ip=\"{escaped_ip}\") "
                f"(technique=\"T1110\" OR technique=\"T1078\" OR technique=\"T1003\" "
                f" OR signature=\"*brute*\" OR signature=\"*credential*\" OR signature=\"*auth*fail*\")"
            ),
            "ransomware": (
                f"index={self.index} "
                f"(src_ip=\"{escaped_ip}\" OR dest_ip=\"{escaped_ip}\") "
                f"(technique=\"T1486\" OR technique=\"T1490\" "
                f" OR signature=\"*ransom*\" OR signature=\"*encrypt*\" OR signature=\"*C2*\")"
            ),
            "data_exfiltration": (
                f"index={self.index} "
                f"src_ip=\"{escaped_ip}\" "
                f"(technique=\"T1041\" OR technique=\"T1048\" "
                f" OR signature=\"*exfil*\" OR signature=\"*upload*\" OR dest_port=443)"
            ),
        }

        spl = type_filters.get(incident_type, type_filters["malware"])
        spl += " | table _time, signature, technique, severity, src_ip, dest_ip | head 20"

        results = self._run_search(spl, earliest=earliest)

        indicators = []
        for r in results:
            indicators.append({
                "timestamp": r.get("_time", ""),
                "signature": r.get("signature", "-"),
                "technique": r.get("technique", "-"),
                "severity":  r.get("severity", "medium"),
                "src_ip":    r.get("src_ip", "-"),
                "dest_ip":   r.get("dest_ip", "-"),
            })

        clean = len(indicators) == 0

        return {
            "host_ip":        host_ip,
            "incident_type":  incident_type,
            "clean":          clean,
            "indicator_count": len(indicators),
            "window_minutes": window_minutes,
            "indicators":     indicators,
            "checked_at":     datetime.now(timezone.utc).isoformat(),
            "source":         "splunk",
            "evidence_summary": (
                f"Host {host_ip} shows NO active {incident_type} indicators in Splunk "
                f"over the last {window_minutes} minutes."
                if clean else
                f"Host {host_ip} shows {len(indicators)} active {incident_type} "
                f"indicator(s) in Splunk over the last {window_minutes} minutes."
            ),
        }

    # ── Statistics ───────────────────────────────────────────────────────────

    def get_technique_stats(self, window_seconds: int = 86400) -> dict:
        """Get ATT&CK technique frequency statistics from Splunk."""
        earliest = f"-{window_seconds}s"
        spl = (
            f"index={self.index} "
            f"| eval technique=coalesce(technique, event.technique, mitre_technique) "
            f"| where isnotnull(technique) AND technique!=\"-\" "
            f"| stats count by technique "
            f"| sort -count "
            f"| head 20"
        )

        results = self._run_search(spl, earliest=earliest)

        techniques = []
        for r in results:
            techniques.append({
                "technique_id": r.get("technique", "unknown"),
                "count":        int(r.get("count", 0)),
            })

        return {
            "window_hours": round(window_seconds / 3600, 1),
            "technique_count": len(techniques),
            "techniques":   techniques,
            "source":       "splunk",
        }

    # ── HEC event submission ─────────────────────────────────────────────────

    def send_event(self, event_data: dict, sourcetype: str = "_json",
                   index: str = None) -> dict:
        """
        Send an event to Splunk via HEC.
        Used for testing and for PILA Suite audit logging.
        """
        if not self.hec_token:
            return {"success": False, "error": "No HEC token configured"}

        try:
            payload = {
                "event":      event_data,
                "sourcetype": sourcetype,
                "index":      index or self.index,
                "time":       time.time(),
            }

            resp = requests.post(
                f"{self.hec_url}/services/collector/event",
                headers={
                    "Authorization":  f"Splunk {self.hec_token}",
                    "Content-Type":   "application/json",
                },
                json=payload,
                verify=self.verify_ssl,
                timeout=10,
            )
            resp.raise_for_status()
            result = resp.json()
            return {
                "success": result.get("code") == 0,
                "response": result,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
