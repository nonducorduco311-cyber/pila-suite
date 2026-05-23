#!/usr/bin/env python3
"""
PILA Suite — License Activation
Usage:
  python3 activate.py PILA-XXXX-XXXX-XXXX-XXXX

What it does:
  1. Validates the key against the license API
  2. Writes the key to pila.conf [license] section
  3. Optionally restarts PILA Suite

Run from anywhere — it finds pila.conf automatically.
"""

import sys
import os
import json
import urllib.request
import urllib.error
import configparser
import subprocess
import shutil
from pathlib import Path
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────

LICENSE_API     = "http://127.0.0.1:8001"
PRODUCT         = "pila_suite"
TIMEOUT         = 5

# Locate pila.conf — search from script location upward
def find_pila_conf() -> Path:
    candidates = [
        Path(__file__).parent / "integrations" / "pila.conf",
        Path(__file__).parent.parent / "integrations" / "pila.conf",
        Path.home() / "pila-suite" / "integrations" / "pila.conf",
        Path(os.environ.get("PILA_CONF", "")) if os.environ.get("PILA_CONF") else None,
    ]
    for p in candidates:
        if p and p.exists():
            return p
    return None

def find_pila_root() -> Path:
    conf = find_pila_conf()
    if conf:
        return conf.parent.parent
    return None

# ── Validation ────────────────────────────────────────────────────────────────

def validate_key_format(key: str) -> bool:
    parts = key.upper().split("-")
    return len(parts) == 5 and parts[0] == "PILA" and all(len(p) == 4 for p in parts[1:])

def validate_key_api(key: str) -> dict:
    payload = json.dumps({"key": key, "product": PRODUCT}).encode()
    req = urllib.request.Request(
        f"{LICENSE_API}/license/validate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        return {"valid": False, "reason": f"License API unreachable: {e}. Is pila-license running?"}
    except Exception as e:
        return {"valid": False, "reason": f"Unexpected error: {e}"}

# ── Config write ──────────────────────────────────────────────────────────────

def write_key_to_conf(conf_path: Path, key: str) -> None:
    """Write or update the [license] section in pila.conf."""
    # Backup first
    backup = conf_path.with_suffix(".conf.bak")
    shutil.copy2(conf_path, backup)

    cfg = configparser.ConfigParser()
    cfg.read(conf_path)

    if not cfg.has_section("license"):
        cfg.add_section("license")

    cfg.set("license", "api_url", LICENSE_API)
    cfg.set("license", "key",     key)
    cfg.set("license", "product", PRODUCT)

    with open(conf_path, "w") as f:
        # Write a comment header for the license section
        # configparser doesn't preserve comments, so we append manually
        pass

    # Read raw content to preserve existing comments
    raw = conf_path.read_text()

    # Write fresh with configparser (preserves all other sections)
    with open(conf_path, "w") as f:
        cfg.write(f)

    print(f"  Backup saved: {backup}")

def restart_pila(pila_root: Path) -> bool:
    """Attempt to restart PILA Suite using stop.sh / start.sh."""
    stop  = pila_root / "stop.sh"
    start = pila_root / "start.sh"
    if not stop.exists() or not start.exists():
        return False
    try:
        subprocess.run([str(stop)],  cwd=pila_root, timeout=10, check=False)
        subprocess.run([str(start)], cwd=pila_root, timeout=10, check=False)
        return True
    except Exception:
        return False

# ── Display helpers ───────────────────────────────────────────────────────────

def green(s): return f"\033[92m{s}\033[0m"
def red(s):   return f"\033[91m{s}\033[0m"
def bold(s):  return f"\033[1m{s}\033[0m"
def dim(s):   return f"\033[2m{s}\033[0m"

def print_banner():
    print()
    print(bold("  ╔══════════════════════════════════════════╗"))
    print(bold("  ║         PILA Suite Activation            ║"))
    print(bold("  ║  Purple Intelligence & Lifecycle Auto    ║"))
    print(bold("  ╚══════════════════════════════════════════╝"))
    print()

def print_license_info(data: dict):
    tier    = (data.get("tier") or "unknown").upper()
    expires = data.get("expires_at")
    feats   = data.get("features", [])
    exp_str = expires[:10] if expires else "Never"

    print(f"  {green('✓')} Tier:     {bold(tier)}")
    print(f"  {green('✓')} Expires:  {exp_str}")
    print(f"  {green('✓')} Features: {len(feats)} unlocked")
    print()
    print("  Unlocked features:")
    for f in feats:
        print(f"    {green('·')} {f}")
    print()

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    # ── Get key ──────────────────────────────────────────────────────────────
    if len(sys.argv) >= 2:
        key = sys.argv[1].strip().upper()
    else:
        print("  Enter your PILA Suite license key:")
        print(dim("  Format: PILA-XXXX-XXXX-XXXX-XXXX"))
        print()
        key = input("  Key: ").strip().upper()

    print()

    # ── Format check ─────────────────────────────────────────────────────────
    if not validate_key_format(key):
        print(red("  ✗ Invalid key format."))
        print(dim("  Expected: PILA-XXXX-XXXX-XXXX-XXXX"))
        print(dim("  Check your purchase confirmation email and try again."))
        sys.exit(1)

    print(f"  Key: {dim(key)}")
    print(f"  Validating against license server...")
    print()

    # ── API validation ────────────────────────────────────────────────────────
    result = validate_key_api(key)

    if not result.get("valid"):
        reason = result.get("reason", "Unknown error")
        print(red(f"  ✗ License validation failed: {reason}"))
        print()

        # Check if API is unreachable vs key is bad
        if "unreachable" in reason.lower():
            print("  The license server is not running. To start it:")
            print(dim("    cd ~/pila-license && ./start.sh"))
            print()
            print("  Once the license server is running, run this script again.")
        else:
            print("  If you believe this is an error, contact support.")
        sys.exit(1)

    print(green("  ✓ License validated successfully!"))
    print()
    print_license_info(result)

    # ── Find pila.conf ────────────────────────────────────────────────────────
    conf_path = find_pila_conf()
    pila_root = find_pila_root()

    if not conf_path:
        print(red("  ✗ Could not find pila.conf."))
        print()
        print("  Run this script from inside the pila-suite directory:")
        print(dim("    cd ~/pila-suite && python3 activate.py PILA-XXXX-XXXX-XXXX-XXXX"))
        print()
        print("  Or set the PILA_CONF environment variable:")
        print(dim("    PILA_CONF=/path/to/pila.conf python3 activate.py PILA-XXXX-XXXX-XXXX-XXXX"))
        sys.exit(1)

    print(f"  Writing license to: {dim(str(conf_path))}")
    write_key_to_conf(conf_path, key)
    print(green("  ✓ License key saved to pila.conf"))
    print()

    # ── Offer to restart ─────────────────────────────────────────────────────
    if pila_root:
        print("  Restart PILA Suite now to activate? [Y/n] ", end="", flush=True)
        try:
            answer = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        if answer in ("", "y", "yes"):
            print()
            print("  Restarting PILA Suite...")
            ok = restart_pila(pila_root)
            if ok:
                print(green("  ✓ PILA Suite restarted."))
                print(dim("  Open http://localhost:8000/ to confirm Professional tier is active."))
            else:
                print("  Could not auto-restart. Restart manually:")
                print(dim(f"    cd {pila_root} && ./stop.sh && ./start.sh"))
        else:
            print()
            print("  Restart PILA Suite to activate your license:")
            print(dim(f"    cd {pila_root} && ./stop.sh && ./start.sh"))

    print()
    print(bold("  Activation complete. Welcome to PILA Suite Professional."))
    print()


if __name__ == "__main__":
    main()
