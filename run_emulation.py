import sys, os
sys.path.insert(0, '/home/bryant/pila-suite')
from lmep.lmep_core import LMEPControlPlane

cp = LMEPControlPlane()
session = cp.create_session(
    name="lateral-movement-test",
    scope=["192.168.10.89", "192.168.10.148", "192.168.10.192"],
    credential_mode="SYNTHETIC",
    deployment_mode="SEMI_ACTIVE"
)
print(f"Session: {session.session_id}\n")

targets = {
    "T1021.002": "192.168.10.89",
    "T1021.001": "192.168.10.192",
    "T1550.002": "192.168.10.89",
    "T1021.004": "192.168.10.148",
    "T1021.006": "192.168.10.148",
    "T1135":     "192.168.10.89",
    "T1021.003": "192.168.10.192",
}

detected = 0
missed   = 0

for tid, target in targets.items():
    print(f"Running {tid} -> {target}")
    try:
        result = session.run_technique(tid, target)
        r = result.to_dict()
        d = r.get('detected_by_defense', False)
        telemetry = r.get('telemetry_generated', [])
        safety    = r.get('safety_events', [])
        if d:
            detected += 1
        else:
            missed += 1
        print(f"  Success:          {r.get('success')}")
        print(f"  Detected:         {d}")
        print(f"  Detection source: {r.get('detection_source')}")
        print(f"  Telemetry:        {telemetry}")
        print(f"  Safety events:    {safety}")
    except Exception as e:
        print(f"  ERROR: {e}")
        missed += 1
    print()

print("=== Session Summary ===")
total = detected + missed
print(f"Techniques run: {total}")
print(f"Detected:       {detected} ({int(detected/total*100) if total else 0}%)")
print(f"Missed:         {missed}  ({int(missed/total*100) if total else 0}%)")
