# PILA Suite — Frequently Asked Questions

> **© 2026 ByTE X Bit Technologies LLC — Patent Pending**

---

## General

**What is PILA Suite?**
PILA Suite is a purple team automation platform that measures, documents, and improves detection capability across a security stack. It connects to your existing Elasticsearch environment and automates the full engagement lifecycle: scenario planning (PSIL), adversary emulation (LMEP), incident validation (IRV), and quantitative scoring (AESP).

**Who is PILA Suite built for?**
Security operations teams, purple team practitioners, red/blue team consultants, and managed security service providers who run structured detection exercises and want to measure improvement over time.

**Is PILA Suite an endpoint agent?**
No. Nothing installs on monitored hosts. PILA Suite is a central server component that queries your existing Elasticsearch instance. Your detection sensors (Suricata, Zeek, Wazuh, Winlogbeat) continue operating independently.

**Does PILA Suite replace my SIEM?**
No. PILA Suite reads from your existing SIEM/Elasticsearch — it does not store logs or replace any detection tooling. It sits on top of your existing stack and measures what it catches.

**Does PILA Suite block traffic?**
No. PILA Suite is observation and measurement only. LMEP operates in behavioral emulation mode — it does not inject packets, exploit vulnerabilities, or take any action that would affect production systems without explicit authorization.

---

## Installation and Requirements

**What do I need before installing PILA Suite?**
- Python 3.11+ on a Linux host
- Elasticsearch 8.x with Filebeat shipping Suricata alerts
- Suricata 6.x+ writing eve.json
- Network access from the PILA Suite host to your Elasticsearch instance

Zeek, Wazuh, Winlogbeat, and Elastic Security are optional but add detection coverage.

**Can I run PILA Suite on Windows?**
PILA Suite is designed for Linux (Ubuntu 22.04/24.04 or Debian 12). It may work on WSL2 but this is not a supported configuration.

**Can I run PILA Suite on the same host as Elasticsearch?**
Yes. This is the simplest deployment. PILA Suite communicates with Elasticsearch over localhost:9200.

**Can PILA Suite connect to a remote Elasticsearch instance?**
Yes. Set `host` in pila.conf to the remote IP or hostname. PILA Suite communicates over HTTPS on port 9200.

**What if my Elasticsearch uses a self-signed certificate?**
Set `verify_ssl = false` in the `[elasticsearch]` section of pila.conf. This is the default for lab environments.

**How much RAM and CPU does PILA Suite need?**
Minimal. The FastAPI server uses roughly 150-300MB of RAM at rest. 1 CPU core and 512MB RAM is sufficient for most deployments.

---

## Community vs Professional

**What does Community Edition include?**
The PSIL SDK (engagement documentation and validation), the detection connector library (all 5 sources), the REST API, and the Swagger documentation interface. Community Edition is free and open source under Apache 2.0.

**What does Professional Edition add?**
LMEP adversary emulation, live Elasticsearch correlation, AESP quantitative scoring (Effectiveness Score 0-100 and Defense Maturity Tier DMT-1 through DMT-5), IRV incident remediation validation, the ATT&CK coverage heatmap, and report generation.

**How do I get a Professional license?**
Visit **byte-x-bit.com** or email **bryant@byte-x-bit.com**. Professional Edition is $99/month. Beta access is available at no cost in exchange for practitioner feedback.

**How do I activate a Professional license?**
```bash
python3 activate.py PILA-XXXX-XXXX-XXXX-XXXX
```
The activation script validates your key, writes it to pila.conf, and restarts PILA Suite automatically.

**What happens if my license expires?**
PILA Suite downgrades to Community Edition automatically. Your PSIL engagement data is preserved. Professional endpoints return 403 until the license is renewed.

---

## Detection and Connectors

**Which detection sources does PILA Suite support?**

| Source | Type | What it adds |
|--------|------|-------------|
| Suricata | Network IDS | Signature-based network alerts |
| Zeek | Network monitor | Connection-level visibility |
| Wazuh | HIDS | Endpoint alerts across Linux and Windows |
| Elastic Security | SIEM detection rules | ATT&CK-mapped pre-built rules |
| Winlogbeat | Windows Event Logs | Process execution, auth, persistence |

**Does PILA Suite work without Suricata?**
Yes, though some detection coverage will be lower. PILA Suite can operate with any subset of supported connectors. Configure only the sources you have in pila.conf.

**How does LMEP emulation work?** *(Professional)*
LMEP executes behavioral traffic shapes against scoped target hosts — not real exploits. After each emulation run, it waits for your detection pipeline to process events, then queries all connected Elasticsearch sources to determine whether the technique was detected. SYNTHETIC credential mode is used by default — no real credentials are required.

**What ATT&CK techniques does LMEP support?**
v1.0 supports: T1021.001 (RDP), T1021.002 (SMB), T1021.003 (DCOM), T1021.004 (SSH), T1021.006 (WinRM), T1135 (Network Share Discovery), T1534 (Internal Spearphishing), T1550.002 (Pass-the-Hash traffic shape). Additional techniques are planned for v1.2.

**What does "SYNTHETIC mode" mean?**
SYNTHETIC credential mode means LMEP generates the behavioral signature of a technique without requiring real credentials or completing a real authentication session. It tests whether your detection rules can identify the behavioral pattern, not whether the attack itself succeeds.

---

## AESP Scoring

**What is the Effectiveness Score?** *(Professional)*
The Effectiveness Score (ES) is a number from 0 to 100 representing the overall detection and response effectiveness of your security stack as measured by the purple team exercise. It is derived from five sub-dimensions: detection efficacy, response speed, prevention rate, coverage breadth, and remediation quality. The specific formula is proprietary (Patent Pending).

**What is the Defense Maturity Tier?** *(Professional)*
The DMT (Defense Maturity Tier) maps the ES score to a five-level classification:

| Tier | ES Range | Label |
|------|----------|-------|
| DMT-5 | 85–100 | Optimized |
| DMT-4 | 70–84 | Advanced |
| DMT-3 | 55–69 | Defined |
| DMT-2 | 40–54 | Developing |
| DMT-1 | 0–39 | Reactive |

**Why is my Coverage Breadth score lower than expected?**
Coverage Breadth reflects the percentage of ATT&CK tactics and techniques covered by your active detection sources. If Zeek, Winlogbeat, or Elastic Security are not fully configured, Coverage Breadth will be lower. Completing connector configuration typically raises this score.

---

## Troubleshooting

**PILA Suite starts but shows "community" tier even with a valid license key**
Check that the license API is running: `curl -s http://127.0.0.1:8001/health`
If it is not running, start it: `cd ~/pila-license && ./start.sh`
Then restart PILA Suite: `./stop.sh && ./start.sh`

**Elasticsearch connection fails with SSL error**
Set `verify_ssl = false` in pila.conf under `[elasticsearch]`. Most lab deployments use self-signed certificates.

**Suricata alerts return zero results**
Verify the correct index pattern. PILA Suite queries `filebeat-*` with `event.dataset: suricata.eve` and `event.kind: alert`. Check that Filebeat is running and the Suricata module is enabled:
```bash
sudo systemctl status filebeat
sudo filebeat modules list | grep suricata
```

**The dashboard shows a blank heatmap** *(Professional)*
The heatmap requires at least one LMEP session with a completed emulation run. Create a session, run a technique, and the heatmap will populate.

**Port 8000 is already in use**
Change the port in start.sh or kill the existing process:
```bash
lsof -i :8000
kill -9 PID
```

**How do I view logs?**
```bash
tail -f ~/pila-suite/pila.log
```

---

## Security and Privacy

**Is the PILA Suite API authenticated?**
Community Edition v1.0 does not require API authentication. It is designed for deployment on a trusted internal network. Do not expose port 8000 directly to the internet. API authentication is planned for v1.1.

**Does PILA Suite send any data externally?**
PILA Suite only makes outbound connections to your configured Elasticsearch instance and to the license validation API (127.0.0.1:8001 by default). No telemetry or usage data is sent to ByTE X Bit Technologies.

**Is engagement data stored securely?**
Engagement data is stored in `data/engagements.json` on the PILA Suite host. Protect this file with appropriate filesystem permissions. It contains your purple team exercise findings and detection gap details.

---

## Contributing and Support

**Where is the source code?**
Community Edition: https://github.com/nonducorduco311-cyber/pila-suite

**How do I report a bug?**
Open an issue on GitHub: https://github.com/nonducorduco311-cyber/pila-suite/issues

**How do I get Professional Edition support?**
Email **bryant@byte-x-bit.com** or open a GitHub issue tagged `[professional]`.

**Can I contribute a connector?**
Yes — connector contributions are welcome under Apache 2.0. See the connector architecture in `integrations/` and follow the existing connector pattern. Open a pull request on GitHub.

---

*© 2026 ByTE X Bit Technologies LLC — Patent Pending*
*PILA Suite, PSIL, LMEP, IRV, and AESP are trademarks of ByTE X Bit Technologies LLC*

---

**How do I configure my detection source connections?**

Open the PILA Suite dashboard and click the **⚙ Settings** tab. You can enter connection details for all supported connectors (Elasticsearch, Wazuh, Winlogbeat/Sysmon, Splunk, Suricata, Zeek) through the web interface without editing any config files. Click **Test** on each connector to verify connectivity before saving.

Settings are saved to `integrations/pila.conf` and take effect after restarting PILA Suite.

---

**How do I manage my API key?**

The Settings tab includes an API Key section showing your current key (masked). You can copy it to clipboard or regenerate a new key. If you regenerate, update any scripts or integrations using the old key — it stops working immediately.

---

**Why does the Zeek live view show question marks for IPs?**

This happens when Filebeat is watching the wrong Zeek log path. Zeek writes live logs to its spool directory (typically `/opt/zeek-install/spool/zeek/`) not `/var/log/zeek/`. Update your Filebeat Zeek module config to point to the correct path and restart Filebeat.

