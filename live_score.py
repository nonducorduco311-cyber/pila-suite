import sys, os, time, uuid
sys.path.insert(0, '/home/bryant/pila-suite')

from datetime import datetime, timezone, timedelta
from lmep.lmep_core import LMEPControlPlane
from integrations.elastic_client import ESClient
from psil.psil_sdk.models import Engagement, Scenario, Attack, Defense, Outcome, Severity
from aesp.aesp_score import AESPScoringEngine
import socket

print("=" * 60)
print("PILA Suite — Live Scoring Run")
print("=" * 60)

es = ESClient()
ping = es.ping()
print(f"\nES: {ping['cluster_name']} v{ping['version']} [{ping['status']}]\n")

def is_reachable(host, port, timeout=2):
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((host, port)); s.close(); return True
    except: return False

ALL_TECHNIQUES = {
    "T1021.002": ("192.168.10.192", "Lateral Movement", "SMB/Windows Admin Shares", Severity.HIGH,     [9000004,9000005,9000008,9000009,9000014], 445),
    "T1021.001": ("192.168.10.192", "Lateral Movement", "Remote Desktop Protocol",  Severity.HIGH,     [9000001,9000002,9000003],                3389),
    "T1550.002": ("192.168.10.192", "Lateral Movement", "Pass-the-Hash",            Severity.CRITICAL, [9000008,9000009],                        445),
    "T1021.004": ("192.168.10.148", "Lateral Movement", "SSH Lateral Movement",     Severity.HIGH,     [9000006,9000007],                        22),
    "T1021.006": ("192.168.10.192", "Lateral Movement", "WinRM Lateral Movement",   Severity.MEDIUM,   [9000010,9000011],                        5985),
    "T1135":     ("192.168.10.192", "Discovery",        "Network Share Discovery",  Severity.MEDIUM,   [9000014],                                445),
    "T1021.003": ("192.168.10.192", "Lateral Movement", "DCOM Lateral Movement",    Severity.HIGH,     [9000012,9000013],                        135),
}

# ── Preflight ─────────────────────────────────────────────────
print("Preflight reachability checks...")
reachable = {}
unreachable = {}
for tid, v in ALL_TECHNIQUES.items():
    target, tactic, name, sev, sids, port = v
    if is_reachable(target, port):
        reachable[tid] = v
        print(f"  {tid:<12} {target}:{port:<6} REACHABLE")
    else:
        unreachable[tid] = v
        print(f"  {tid:<12} {target}:{port:<6} UNREACHABLE — scored as detection gap")

print(f"\n{len(reachable)} active tests / {len(unreachable)} gap assumptions / {len(ALL_TECHNIQUES)} total\n")

# ── Generate traffic for reachable targets ────────────────────
print("Generating real traffic...")
emulation_time = datetime.now(timezone.utc) - timedelta(seconds=10)

# SSH
if "T1021.004" in reachable:
    for i in range(4):
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect(("192.168.10.148", 22)); s.recv(256); s.close()
        except: pass
        time.sleep(0.3)

# RDP
if "T1021.001" in reachable:
    for i in range(3):
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect(("192.168.10.192", 3389))
            s.send(bytes([0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,
                          0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x0b,0x00,0x00,0x00]))
            time.sleep(0.5); s.close()
        except: pass
        time.sleep(0.5)

# SMB/NTLM
if "T1021.002" in reachable or "T1550.002" in reachable or "T1135" in reachable:
    for i in range(5):
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect(("192.168.10.192", 445))
            # SMB negotiate + NTLMSSP
            s.send(bytes([
                0x00,0x00,0x00,0x54,0xff,0x53,0x4d,0x42,
                0x72,0x00,0x00,0x00,0x00,0x18,0x01,0x28,
                0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                0x01,0x00,0x00,0x00,0x07,0x82,0x08,0xa2,
            ]))
            time.sleep(0.5); s.close()
        except: pass
        time.sleep(0.5)

# DCOM/RPC
if "T1021.003" in reachable:
    for i in range(5):
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect(("192.168.10.192", 135))
            s.send(bytes([0x05,0x00,0x0b,0x03,0x10,0x00,0x00,0x00,
                          0x48,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
                          0xb8,0x10,0xb8,0x10,0x00,0x00,0x00,0x00,
                          0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00]))
            time.sleep(0.5); s.close()
        except: pass
        time.sleep(0.8)

print(f"Traffic generated at {emulation_time.isoformat()}\n")

# ── LMEP emulation ────────────────────────────────────────────
cp = LMEPControlPlane()
scope = list(set(v[0] for v in reachable.values()))
if scope:
    session = cp.create_session(
        name="live-score-run", scope=scope,
        credential_mode="SYNTHETIC", deployment_mode="SEMI_ACTIVE"
    )
    for tid in reachable:
        session.run_technique(tid, reachable[tid][0])

print("Waiting 60 seconds for ES indexing...")
time.sleep(60)

# ── Correlate ─────────────────────────────────────────────────
print("\nCorrelating with Elasticsearch...\n")

def query_alerts(sids, after, window=300):
    return es.search("filebeat-*", {"bool": {"must": [
        {"term":  {"event.dataset": "suricata.eve"}},
        {"term":  {"suricata.eve.event_type": "alert"}},
        {"range": {"@timestamp": {"gte": after.isoformat(),
                                  "lte": (after + timedelta(seconds=window)).isoformat()}}},
        {"terms": {"rule.id": [str(s) for s in sids]}},
    ]}}, size=20)

scenarios = []

# Reachable — score from real ES data
print("  --- Active tests (real detections) ---")
for tid, (target, tactic, name, sev, sids, port) in reachable.items():
    hits = query_alerts(sids, emulation_time)
    detected = bool(hits)
    outcome = Outcome.DETECTED_AND_BLOCKED if detected else Outcome.NOT_DETECTED
    sources = ["Suricata"] if detected else []
    sig = hits[0].get("suricata",{}).get("eve",{}).get("alert",{}).get("signature","?") if hits else ""
    status = "DETECTED" if detected else "MISSED"
    print(f"  {tid:<12} {status:<10} alerts:{len(hits):<4} {sig}")
    scenarios.append(Scenario(
        name=name,
        attack=Attack(technique_id=tid, tactic=tactic, tool="LMEP",
                     execution_timestamp=emulation_time, execution_detail=name),
        defense=Defense(detected=detected,
                       detection_source=", ".join(sources) if sources else None,
                       detection_time=datetime.now(timezone.utc) if detected else None,
                       response_time=datetime.now(timezone.utc) if detected else None),
        outcome=outcome, severity=sev,
        gap_identified=not detected,
        gap_detail=f"{tid} not detected on {target}" if not detected else None,
    ))

# Unreachable — score as undetected gaps
print("\n  --- Gap assumptions (unreachable targets) ---")
for tid, (target, tactic, name, sev, sids, port) in unreachable.items():
    print(f"  {tid:<12} GAP        {target}:{port} unreachable — counted as undetected")
    scenarios.append(Scenario(
        name=name,
        attack=Attack(technique_id=tid, tactic=tactic, tool="LMEP",
                     execution_timestamp=emulation_time, execution_detail=name),
        defense=Defense(detected=False),
        outcome=Outcome.NOT_DETECTED, severity=sev,
        gap_identified=True,
        gap_detail=f"{tid} target {target}:{port} unreachable — detection capability unknown",
    ))

# ── Score ─────────────────────────────────────────────────────
engagement = Engagement(
    engagement_id=str(uuid.uuid4()),
    name="Live Lab Score — May 2026",
    organization="Ghost Home Lab",
    scope=["192.168.10.0/24"],
    scenarios=scenarios,
)

engine = AESPScoringEngine()
result = engine.score(
        engagement,
        incident_type="lateral_movement",
        lmep_mode="PASSIVE",
        active_sources=["suricata"],
        false_positive_rate=0.0,
    )

print("\n" + "=" * 60)
print(result.summary())
print()
print(f"Active tests:      {len(reachable)}")
print(f"Gap assumptions:   {len(unreachable)} (unreachable targets = unverified detection)")
print(f"Total techniques:  {len(ALL_TECHNIQUES)}")
print("=" * 60)
