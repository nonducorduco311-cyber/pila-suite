"""
PILA Suite — Elasticsearch Integration Client
Queries Suricata alerts, Zeek connections, Packetbeat flows,
and Filebeat events for detection correlation and IRV validation.
"""
from __future__ import annotations
import json
import urllib.request
import urllib.error
import base64
import ssl
from datetime import datetime, timezone, timedelta
from typing import Optional
from .config import ESConfig


class ESClient:
    """Lightweight ES client — stdlib only, no elasticsearch-py required."""

    def __init__(self, config: Optional[ESConfig] = None):
        self.cfg = config or ESConfig()
        token = base64.b64encode(
            f"{self.cfg.username}:{self.cfg.password}".encode()
        ).decode()
        self._headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
        }
        self._ctx = ssl.create_default_context()
        if not self.cfg.verify_ssl:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = f"{self.cfg.url}{path}"
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=data, headers=self._headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"ES {method} {path} HTTP {e.code}: {e.read().decode()}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"ES connection failed ({self.cfg.url}): {e.reason}")

    def ping(self) -> dict:
        info   = self._request("GET", "/")
        health = self._request("GET", "/_cluster/health")
        return {
            "cluster_name": info.get("cluster_name"),
            "version":      info.get("version", {}).get("number"),
            "status":       health.get("status"),
            "connected":    True,
        }

    def search(self, index: str, query: dict, size: int = 100) -> list[dict]:
        body   = {"query": query, "size": size, "sort": [{"@timestamp": {"order": "desc"}}]}
        result = self._request("POST", f"/{index}/_search", body)
        return [h["_source"] for h in result.get("hits", {}).get("hits", [])]

    def count(self, index: str, query: dict) -> int:
        result = self._request("POST", f"/{index}/_count", {"query": query})
        return result.get("count", 0)

    def list_indices(self, pattern: str = "*") -> list[str]:
        result = self._request("GET", f"/_cat/indices/{pattern}?format=json&h=index")
        return sorted([r["index"] for r in result if not r["index"].startswith(".")])

    def query_suricata_alerts(self, src_ip=None, dst_ip=None, after=None, window_seconds=120) -> list[dict]:
        after = after or (datetime.now(timezone.utc) - timedelta(seconds=window_seconds))
        must  = [
            {"term":  {"event.module":  "suricata"}},
            {"term":  {"event.dataset": "suricata.eve"}},
            {"term":  {"event.kind":    "alert"}},
            {"range": {"@timestamp":    {"gte": after.isoformat()}}},
        ]
        if src_ip: must.append({"term": {"source.ip": src_ip}})
        if dst_ip: must.append({"term": {"destination.ip": dst_ip}})
        hits = self.search(self.cfg.suricata_index, {"bool": {"must": must}}, size=50)
        return [self._norm_suricata(h) for h in hits]

    def query_zeek_connections(self, src_ip=None, dst_ip=None, dst_port=None, proto=None, after=None, window_seconds=120) -> list[dict]:
        after = after or (datetime.now(timezone.utc) - timedelta(seconds=window_seconds))
        must  = [
            {"term":  {"event.module": "zeek"}},
            {"range": {"@timestamp":   {"gte": after.isoformat()}}},
        ]
        if src_ip:   must.append({"term": {"source.ip": src_ip}})
        if dst_ip:   must.append({"term": {"destination.ip": dst_ip}})
        if dst_port: must.append({"term": {"destination.port": dst_port}})
        if proto:    must.append({"term": {"network.transport": proto.lower()}})
        hits = self.search(self.cfg.zeek_index, {"bool": {"must": must}}, size=50)
        return [self._norm_zeek(h) for h in hits]

    def query_packetbeat(self, src_ip=None, dst_ip=None, dst_port=None, after=None, window_seconds=120) -> list[dict]:
        after = after or (datetime.now(timezone.utc) - timedelta(seconds=window_seconds))
        must  = [{"range": {"@timestamp": {"gte": after.isoformat()}}}]
        if src_ip:   must.append({"term": {"source.ip": src_ip}})
        if dst_ip:   must.append({"term": {"destination.ip": dst_ip}})
        if dst_port: must.append({"term": {"destination.port": dst_port}})
        hits = self.search(self.cfg.packetbeat_index, {"bool": {"must": must}}, size=50)
        return hits

    def check_host_clean(self, host_ip: str, incident_type: str, window_minutes: int = 10) -> dict:
        after   = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        alerts  = self.query_suricata_alerts(src_ip=host_ip, after=after, window_seconds=window_minutes*60)
        conns   = self.query_zeek_connections(src_ip=host_ip, after=after, window_seconds=window_minutes*60)
        clean   = len(alerts) == 0
        return {
            "host": host_ip, "incident_type": incident_type,
            "window_minutes": window_minutes, "clean": clean,
            "suricata_alerts": len(alerts), "zeek_connections": len(conns),
            "alerts": alerts[:5],
            "summary": (f"CLEAN — no alerts in last {window_minutes}m" if clean
                        else f"NOT CLEAN — {len(alerts)} active Suricata alert(s)"),
        }

    def correlate_lmep_technique(self, technique_id: str, target_ip: str,
                                  emulation_time: datetime, window_seconds: int = 120) -> dict:
        PORTS = {
            "T1021.002": 445, "T1021.001": 3389, "T1021.004": 22,
            "T1021.006": 5985, "T1021.003": 135, "T1550.002": 445,
            "T1135": 445, "T1534": None,
        }
        dst_port   = PORTS.get(technique_id)
        suricata   = self.query_suricata_alerts(dst_ip=target_ip, after=emulation_time, window_seconds=window_seconds)
        zeek       = self.query_zeek_connections(dst_ip=target_ip, dst_port=dst_port, after=emulation_time, window_seconds=window_seconds)
        packetbeat = self.query_packetbeat(dst_ip=target_ip, dst_port=dst_port, after=emulation_time, window_seconds=window_seconds)
        sources    = ([("Suricata" if suricata else "")] + [("Zeek" if zeek else "")] + [("Packetbeat" if packetbeat else "")])
        sources    = [s for s in sources if s]
        return {
            "technique_id": technique_id, "target_ip": target_ip,
            "emulation_time": emulation_time.isoformat(),
            "detected": bool(sources), "detection_sources": sources,
            "suricata_alerts": len(suricata), "zeek_connections": len(zeek),
            "packetbeat_flows": len(packetbeat),
            "top_alerts": suricata[:3], "top_zeek": zeek[:3],
        }

    def get_filebeat_stats(self) -> dict:
        try:
            result = self._request("POST", f"/{','.join(self.cfg.alert_indices)}/_search", {
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": "now-1h"}}},
                "aggs": {"by_module": {"terms": {"field": "event.module", "size": 20}}}
            })
            buckets = result.get("aggregations", {}).get("by_module", {}).get("buckets", [])
            return {b["key"]: b["doc_count"] for b in buckets}
        except Exception as e:
            return {"error": str(e)}

    def _norm_suricata(self, h: dict) -> dict:
        return {
            "timestamp": h.get("@timestamp"),
            "alert_sig": (h.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature")
                          or h.get("rule", {}).get("name")),
            "severity":  (h.get("suricata", {}).get("eve", {}).get("alert", {}).get("severity")
                          or h.get("event", {}).get("severity")),
            "category":  h.get("suricata", {}).get("eve", {}).get("alert", {}).get("category"),
            "src_ip":    h.get("source", {}).get("ip"),
            "dst_ip":    h.get("destination", {}).get("ip"),
            "dst_port":  h.get("destination", {}).get("port"),
            "proto":     h.get("network", {}).get("transport"),
        }

    def _norm_zeek(self, h: dict) -> dict:
        return {
            "timestamp": h.get("@timestamp"),
            "log_type":  h.get("event", {}).get("dataset"),
            "src_ip":    h.get("source", {}).get("ip"),
            "dst_ip":    h.get("destination", {}).get("ip"),
            "dst_port":  h.get("destination", {}).get("port"),
            "proto":     h.get("network", {}).get("transport"),
            "bytes_out": h.get("source", {}).get("bytes"),
            "bytes_in":  h.get("destination", {}).get("bytes"),
        }
