"""
PILA Suite — Winlogbeat / Sysmon Connector
Queries Windows Event Logs shipped via Winlogbeat to Elasticsearch.

Adds endpoint-level Windows visibility that network-based tools cannot provide:
  - Authentication events (4624 success, 4625 failure, 4648 explicit creds)
  - Process execution (4688 process create, Sysmon Event ID 1)
  - Network connections from processes (Sysmon Event ID 3)
  - Scheduled task creation (4698) — common persistence mechanism
  - Service installation (7045) — common persistence mechanism
  - Network share access (5140, 5145) — lateral movement indicator
  - File creation (Sysmon Event ID 11) — file drop detection
  - Registry modifications (Sysmon Event ID 13) — persistence detection
  - DNS queries (Sysmon Event ID 22) — C2 communication detection

ATT&CK technique mapping:
  T1021.001 (RDP)        → Event 4624 LogonType=10
  T1021.002 (SMB)        → Events 5140, 5145
  T1021.004 (SSH)        → Event 4624 + process sshd/putty
  T1059     (Scripting)  → Event 4688/Sysmon 1 (powershell, cmd, wscript)
  T1078     (Valid Accts)→ Events 4624, 4648, 4776
  T1110     (Brute Force)→ Event 4625 repeated
  T1547     (Persistence)→ Events 4698, 7045, Sysmon 13
  T1105     (File Drop)  → Sysmon Event 11
  T1135     (Net Share)  → Events 5140, 5145

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


# ── Event ID reference ────────────────────────────────────────────────────────

SECURITY_EVENTS = {
    # Authentication
    4624: ("Logon Success",              "T1078"),
    4625: ("Logon Failure",              "T1110"),
    4648: ("Logon with Explicit Creds",  "T1078"),
    4776: ("NTLM Auth Attempt",          "T1078"),
    4768: ("Kerberos TGT Request",       "T1558"),
    4769: ("Kerberos Service Ticket",    "T1558"),
    # Account management
    4720: ("User Account Created",       "T1136"),
    4726: ("User Account Deleted",       None),
    4732: ("User Added to Local Group",  "T1098"),
    4756: ("User Added to Global Group", "T1098"),
    # Process execution
    4688: ("Process Created",            "T1059"),
    4689: ("Process Exited",             None),
    # Persistence
    4698: ("Scheduled Task Created",     "T1053"),
    4702: ("Scheduled Task Modified",    "T1053"),
    7045: ("Service Installed",          "T1543"),
    # Lateral movement
    5140: ("Network Share Accessed",     "T1021.002"),
    5145: ("Network Share Object Check", "T1021.002"),
    # Privilege escalation
    4672: ("Special Privileges Assigned","T1078"),
}

SYSMON_EVENTS = {
    1:  ("Process Create",        "T1059"),
    2:  ("File Creation Time",    "T1070"),
    3:  ("Network Connection",    "T1021"),
    5:  ("Process Terminated",    None),
    7:  ("Image Loaded",          "T1574"),
    8:  ("CreateRemoteThread",    "T1055"),
    10: ("Process Access",        "T1055"),
    11: ("File Create",           "T1105"),
    12: ("Registry Create/Delete","T1547"),
    13: ("Registry Set Value",    "T1547"),
    15: ("File Create Stream",    "T1096"),
    17: ("Pipe Created",          "T1559"),
    22: ("DNS Query",             "T1071"),
    23: ("File Delete",           "T1070"),
    25: ("Process Tamper",        "T1562"),
}

# ATT&CK technique → relevant event IDs for LMEP correlation
TECHNIQUE_EVENTS = {
    "T1021.001": [4624],                        # RDP — LogonType 10
    "T1021.002": [5140, 5145],                  # SMB share access
    "T1021.004": [4624],                        # SSH — LogonType 3 + process
    "T1021.006": [4624],                        # WinRM — LogonType 3
    "T1059":     [4688, 1],                     # Script execution
    "T1078":     [4624, 4648, 4776],            # Valid accounts
    "T1110":     [4625],                        # Brute force
    "T1105":     [11],                          # File drop (Sysmon)
    "T1135":     [5140, 5145],                  # Network share discovery
    "T1136":     [4720],                        # Create account
    "T1547":     [4698, 7045, 12, 13],         # Persistence
    "T1550.002": [4624, 4648, 4776],           # Pass-the-Hash
    "T1534":     [4624, 1],                    # Internal spearphishing
    "T1021.003": [4688, 1],                    # DCOM
}


# ── Config ────────────────────────────────────────────────────────────────────

class WinlogbeatConfig:
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

        # Use winlogbeat section if present, else fall back to elasticsearch
        src = "winlogbeat" if cfg.has_section("winlogbeat") else "elasticsearch"
        s   = cfg[src] if cfg.has_section(src) else {}

        self.host       = s.get("host",       "")
        self.port       = int(s.get("port",   "9200"))
        self.username   = s.get("username",   "elastic")
        self.password   = s.get("password",   "")
        self.verify_ssl = cfg.getboolean(src, "verify_ssl", fallback=False)
        self.index      = s.get("index",      "winlogbeat-*")
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


def _search(cfg: WinlogbeatConfig, query: dict, size: int = 50) -> list[dict]:
    url     = f"{cfg.url}/{cfg.index}/_search"
    payload = json.dumps({
        "size": size,
        "query": query,
        "sort": [{"@timestamp": "desc"}],
    }).encode()
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
        raise ConnectionError(f"Winlogbeat unreachable: {e}")


# ── Normalisation ─────────────────────────────────────────────────────────────

def _norm_event(h: dict) -> dict:
    """Normalize a Winlogbeat event into PILA's common schema."""
    winlog   = h.get("winlog", {})
    event    = h.get("event",  {})
    ev_data  = winlog.get("event_data", {})
    event_id = winlog.get("event_id")

    # Determine source from event ID
    if event_id in SYSMON_EVENTS:
        desc, technique = SYSMON_EVENTS[event_id]
        source_type = "sysmon"
    elif event_id in SECURITY_EVENTS:
        desc, technique = SECURITY_EVENTS[event_id]
        source_type = "windows_security"
    else:
        desc, technique = event.get("action", "Unknown"), None
        source_type = "windows"

    return {
        "timestamp":    h.get("@timestamp"),
        "event_id":     event_id,
        "alert_sig":    desc,
        "technique_id": technique,
        "channel":      winlog.get("channel"),
        "host":         h.get("host", {}).get("name"),
        "outcome":      event.get("outcome"),
        "action":       event.get("action"),
        "process_name": ev_data.get("NewProcessName") or
                        ev_data.get("Image") or
                        ev_data.get("ProcessName"),
        "username":     ev_data.get("TargetUserName") or
                        ev_data.get("SubjectUserName"),
        "logon_type":   ev_data.get("LogonType"),
        "src_ip":       ev_data.get("IpAddress") or
                        ev_data.get("SourceAddress") or
                        h.get("source", {}).get("ip") if isinstance(h.get("source"), dict) else None,
        "dst_ip":       ev_data.get("DestinationIp"),
        "dst_port":     ev_data.get("DestinationPort"),
        "source_type":  source_type,
        "source":       "winlogbeat",
    }


# ── Public connector API ──────────────────────────────────────────────────────

class WinlogbeatConnector:
    """
    PILA Suite connector for Windows Event Logs via Winlogbeat.

    Supports both standard Windows Security events and Sysmon-enriched events.
    Sysmon events are automatically detected and labeled — no separate
    configuration required if Sysmon is installed on the monitored host.

    Uses existing Elasticsearch credentials from pila.conf [elasticsearch].
    Optional [winlogbeat] section for custom index patterns.
    """

    def __init__(self, conf_path: Optional[str] = None):
        self.cfg = WinlogbeatConfig(conf_path)

    def ping(self) -> dict:
        """Test connectivity and return event count."""
        url = f"{self.cfg.url}/{self.cfg.index}/_count"
        req = urllib.request.Request(
            url, headers={"Authorization": self.cfg.auth_header}
        )
        try:
            with urllib.request.urlopen(req, context=_ssl_ctx(self.cfg.verify_ssl),
                                        timeout=5) as r:
                data  = json.loads(r.read())
                count = data.get("count", 0)
                # Check if Sysmon data is present
                sysmon_query = json.dumps({
                    "query": {"term": {"winlog.channel.keyword": "Microsoft-Windows-Sysmon/Operational"}}
                }).encode()
                req2 = urllib.request.Request(
                    f"{self.cfg.url}/{self.cfg.index}/_count",
                    data=sysmon_query,
                    headers={"Content-Type": "application/json",
                             "Authorization": self.cfg.auth_header},
                    method="POST",
                )
                with urllib.request.urlopen(req2, context=_ssl_ctx(self.cfg.verify_ssl),
                                            timeout=5) as r2:
                    sysmon_count = json.loads(r2.read()).get("count", 0)
                return {
                    "connected":     True,
                    "total_events":  count,
                    "sysmon_events": sysmon_count,
                    "sysmon_active": sysmon_count > 0,
                    "index_pattern": self.cfg.index,
                    "source":        "winlogbeat",
                }
        except Exception as e:
            raise ConnectionError(f"Winlogbeat index unreachable: {e}")

    def query_events(
        self,
        event_ids:      Optional[list[int]] = None,
        host:           Optional[str] = None,
        username:       Optional[str] = None,
        channel:        Optional[str] = None,
        outcome:        Optional[str] = None,
        window_seconds: int = 300,
        after:          Optional[datetime] = None,
    ) -> list[dict]:
        """
        Query Windows events with flexible filters.

        Args:
            event_ids:      List of Windows Event IDs to filter by
            host:           Filter by hostname
            username:       Filter by target username
            channel:        Filter by event channel (Security, System, etc.)
            outcome:        Filter by outcome (success, failure)
            window_seconds: How far back to look
            after:          Explicit start time
        """
        after = after or (
            datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        )
        must = [{"range": {"@timestamp": {"gte": after.isoformat()}}}]

        if event_ids:
            must.append({"terms": {"winlog.event_id": event_ids}})
        if host:
            must.append({"term": {"host.name.keyword": host}})
        if username:
            must.append({"term": {"winlog.event_data.TargetUserName.keyword": username}})
        if channel:
            must.append({"term": {"winlog.channel.keyword": channel}})
        if outcome:
            must.append({"term": {"event.outcome": outcome}})

        hits = _search(self.cfg, {"bool": {"must": must}}, size=50)
        return [_norm_event(h) for h in hits]

    def query_auth_events(
        self,
        host:           Optional[str] = None,
        failures_only:  bool = False,
        window_seconds: int = 300,
        after:          Optional[datetime] = None,
    ) -> list[dict]:
        """Query authentication events — logon success, failure, explicit creds."""
        event_ids = [4625] if failures_only else [4624, 4625, 4648, 4776]
        return self.query_events(
            event_ids=event_ids,
            host=host,
            window_seconds=window_seconds,
            after=after,
        )

    def query_process_events(
        self,
        host:           Optional[str] = None,
        process_name:   Optional[str] = None,
        window_seconds: int = 300,
        after:          Optional[datetime] = None,
    ) -> list[dict]:
        """Query process creation events (4688 + Sysmon 1)."""
        events = self.query_events(
            event_ids=[4688, 1],
            host=host,
            window_seconds=window_seconds,
            after=after,
        )
        if process_name:
            events = [
                e for e in events
                if e.get("process_name") and
                   process_name.lower() in (e["process_name"] or "").lower()
            ]
        return events

    def check_host_clean(
        self,
        host:           str,
        incident_type:  str = "malware",
        window_minutes: int = 10,
    ) -> dict:
        """
        Check for suspicious Windows events on a host post-remediation.
        Complements Suricata (network) and Wazuh (HIDS) host checks.
        """
        after = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        # Map incident type to suspicious event IDs
        INCIDENT_EVENTS = {
            "malware":               [4688, 1, 7045, 11, 13],
            "credential_compromise": [4624, 4625, 4648, 4776],
            "lateral_movement":      [4624, 4648, 5140, 5145, 3],
            "ransomware":            [4688, 1, 11, 13, 7045],
            "data_exfiltration":     [4688, 3, 5140, 22],
            "phishing":              [4688, 1, 11],
            "insider_threat":        [4624, 4648, 5140, 4720],
        }
        event_ids = INCIDENT_EVENTS.get(incident_type, [4688, 4625, 7045])

        alerts = self.query_events(
            event_ids=event_ids,
            host=host,
            after=after,
            window_seconds=window_minutes * 60,
        )

        # Filter out expected baseline events (e.g. SYSTEM logons)
        suspicious = [
            a for a in alerts
            if not (
                a.get("event_id") == 4624 and
                a.get("username") in ("SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE")
            )
        ]

        clean = len(suspicious) == 0
        return {
            "host":            host,
            "incident_type":   incident_type,
            "window_minutes":  window_minutes,
            "clean":           clean,
            "windows_events":  len(suspicious),
            "source":          "winlogbeat",
            "summary": (
                f"CLEAN (Windows) — no suspicious events on {host} "
                f"in last {window_minutes}m"
                if clean else
                f"NOT CLEAN (Windows) — {len(suspicious)} suspicious event(s) on {host} "
                f"in last {window_minutes}m"
            ),
            "events": suspicious[:10],
        }

    def correlate_technique(
        self,
        technique_id:   str,
        target_host:    Optional[str] = None,
        emulation_time: Optional[datetime] = None,
        window_seconds: int = 120,
    ) -> dict:
        """
        Correlate an LMEP technique against Windows Event Logs.
        Maps ATT&CK technique IDs to relevant Windows event IDs.
        """
        after     = emulation_time or (
            datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        )
        event_ids = TECHNIQUE_EVENTS.get(technique_id, [4688, 4624])

        events = self.query_events(
            event_ids=event_ids,
            host=target_host,
            after=after,
            window_seconds=window_seconds,
        )

        detected = len(events) > 0
        return {
            "technique_id":      technique_id,
            "target_host":       target_host,
            "emulation_time":    after.isoformat(),
            "detected":          detected,
            "detection_sources": ["Winlogbeat"] if detected else [],
            "windows_events":    len(events),
            "event_ids_queried": event_ids,
            "source":            "winlogbeat",
            "top_events": [
                {
                    "event_id":    e["event_id"],
                    "alert_sig":   e["alert_sig"],
                    "host":        e["host"],
                    "username":    e["username"],
                    "process":     e["process_name"],
                    "timestamp":   e["timestamp"],
                }
                for e in events[:5]
            ],
        }
