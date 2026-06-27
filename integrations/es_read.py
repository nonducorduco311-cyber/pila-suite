"""
PILA Suite — Community Elasticsearch Read Client
© 2026 ByTE X Bit Technologies LLC

Read-only ES access for the Community (free) tier: connect to your existing
Elasticsearch and view correlated detections. Reading is free; emulation,
full scoring, and reporting are Professional. stdlib-only.
"""
import json
import ssl
import base64
import urllib.request
import urllib.error


class ESReadClient:
    def __init__(self, host, port=9200, username="elastic", password="",
                 scheme="https", verify_ssl=False, timeout=8):
        self.base = f"{scheme}://{host}:{port}"
        self.timeout = timeout
        tok = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {tok}",
            "Content-Type": "application/json",
        }
        if scheme == "https" and not verify_ssl:
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        else:
            self._ctx = None

    def _request(self, method, path, body=None):
        url = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self.headers,
                                     method=method)
        with urllib.request.urlopen(req, timeout=self.timeout,
                                    context=self._ctx) as r:
            return json.loads(r.read())

    def ping(self):
        try:
            h = self._request("GET", "/_cluster/health")
            return {"connected": True, "status": h.get("status"),
                    "cluster": h.get("cluster_name"),
                    "nodes": h.get("number_of_nodes")}
        except urllib.error.HTTPError as e:
            return {"connected": False, "error": f"HTTP {e.code}",
                    "hint": "check ES username/password in pila.conf"}
        except Exception as e:
            return {"connected": False, "error": str(e),
                    "hint": "check ES host/port and verify_ssl in pila.conf"}

    def list_indices(self):
        """Helper to discover real index names (for setting alert_indices)."""
        try:
            return self._request("GET", "/_cat/indices?format=json&h=index,docs.count")
        except Exception as e:
            return {"error": str(e)}

    def recent_detections(self, indices, window_seconds=3600, size=25):
        """Recent named detections (Suricata alerts + Zeek notices) — free aha.
        Filters to docs that carry a rule.name, so flow/connection noise is
        excluded and only real, named detections surface."""
        query = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp":
                                   {"gte": f"now-{window_seconds}s"}}},
                        {"exists": {"field": "rule.name"}},
                    ],
                }
            },
        }
        path = f"/{indices}/_search"
        try:
            resp = self._request("POST", path, query)
        except urllib.error.HTTPError as e:
            return {"ok": False, "error": f"HTTP {e.code}",
                    "detail": e.read().decode()[:200]}
        except Exception as e:
            return {"ok": False, "error": str(e)}

        hits = resp.get("hits", {}).get("hits", [])
        total = resp.get("hits", {}).get("total", {})
        total = total.get("value") if isinstance(total, dict) else total
        out = []
        for h in hits:
            s = h.get("_source", {})
            rule  = s.get("rule") or {}
            event = s.get("event") or {}
            src   = s.get("source") or {}
            dst   = s.get("destination") or {}
            cat = rule.get("category")
            if cat is None:
                ec = event.get("category")
                cat = ec[0] if isinstance(ec, list) and ec else ec
            out.append({
                "timestamp": s.get("@timestamp"),
                "signature": rule.get("name") or "(unnamed)",
                "severity":  event.get("severity"),
                "category":  cat,
                "engine":    event.get("module") or "suricata",
                "src_ip":    src.get("ip") or s.get("src_ip"),
                "dst_ip":    dst.get("ip") or s.get("dest_ip"),
                "dst_port":  dst.get("port"),
            })
        return {"ok": True, "total": total, "count": len(out),
                "detections": out}
