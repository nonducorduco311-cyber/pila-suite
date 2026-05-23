"""
PILA Suite — License Check Module
~/pila-suite/shared/license_check.py

Called once at startup from api/server.py.
Reads the [license] section from pila.conf, calls the local
license validation API, and returns a LicenseState object that
the rest of the platform uses to gate features.

Design decisions:
  - NEVER hard-crashes PILA on license failure. Logs a clear warning
    and falls back to community tier. This keeps your lab running
    even if the license API is down.
  - Caches the result in memory for the lifetime of the process.
    No per-request license checks — startup-only.
  - Timeout is short (3s) so a dead license API doesn't slow startup.
  - All license logic stays in ~/pila-license/. This module is just
    the client that talks to it.
"""

import configparser
import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Defaults ─────────────────────────────────────────────────────────────────

DEFAULT_LICENSE_API   = "http://127.0.0.1:8001"
DEFAULT_PRODUCT       = "pila_suite"
COMMUNITY_FEATURES    = [
    "psil_basic",
    "aesp_basic",
    "api_read",
]
TIMEOUT_SECONDS       = 3

# ── License state (populated once at startup) ─────────────────────────────────

@dataclass
class LicenseState:
    valid:      bool          = False
    tier:       str           = "community"
    features:   list[str]     = field(default_factory=lambda: list(COMMUNITY_FEATURES))
    expires_at: Optional[str] = None
    key:        Optional[str] = None
    reason:     str           = "not_checked"
    api_reachable: bool       = False

    def has_feature(self, feature: str) -> bool:
        return feature in self.features

    def require_feature(self, feature: str, label: str = "") -> None:
        """Raise a clear error if a feature isn't licensed."""
        if not self.has_feature(feature):
            name = label or feature
            raise PermissionError(
                f"'{name}' requires a PILA Suite Professional license. "
                f"Current tier: {self.tier}. "
                f"Visit pilasuit.com to upgrade."
            )

    def summary(self) -> dict:
        return {
            "valid":        self.valid,
            "tier":         self.tier,
            "expires_at":   self.expires_at,
            "features":     self.features,
            "api_reachable": self.api_reachable,
            "reason":       self.reason,
        }


# ── Module-level singleton — set by check_license() at startup ───────────────

_state: LicenseState = LicenseState()


def get_license() -> LicenseState:
    """Return the cached license state. Always available after startup."""
    return _state


def has_feature(feature: str) -> bool:
    """Convenience shortcut for feature checks anywhere in the codebase."""
    return _state.has_feature(feature)


# ── Config reader ─────────────────────────────────────────────────────────────

def _read_config(conf_path: str) -> tuple[str, str, str]:
    """
    Read [license] section from pila.conf.
    Returns (api_url, key, product).
    Missing section = community mode (no key).
    """
    cfg = configparser.ConfigParser()
    cfg.read(conf_path)

    if not cfg.has_section("license"):
        return DEFAULT_LICENSE_API, "", DEFAULT_PRODUCT

    api_url = cfg.get("license", "api_url",  fallback=DEFAULT_LICENSE_API).rstrip("/")
    key     = cfg.get("license", "key",      fallback="").strip()
    product = cfg.get("license", "product",  fallback=DEFAULT_PRODUCT).strip()
    return api_url, key, product


# ── API call ──────────────────────────────────────────────────────────────────

def _call_validate(api_url: str, key: str, product: str) -> dict:
    """
    POST to /license/validate. Returns parsed JSON or raises.
    Uses stdlib urllib — no extra dependencies.
    """
    payload = json.dumps({"key": key, "product": product}).encode()
    req = urllib.request.Request(
        f"{api_url}/license/validate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read())


# ── Main entry point ──────────────────────────────────────────────────────────

def check_license(conf_path: Optional[str] = None) -> LicenseState:
    """
    Perform the startup license check. Call this once from api/server.py
    before the FastAPI app starts accepting requests.

    Updates and returns the module-level _state singleton.
    """
    global _state

    # Find pila.conf relative to this file if not specified
    if conf_path is None:
        here = Path(__file__).parent          # shared/
        conf_path = str(here.parent / "integrations" / "pila.conf")

    api_url, key, product = _read_config(conf_path)

    # No key configured — community mode, no API call needed
    if not key:
        _state = LicenseState(
            valid=False,
            tier="community",
            features=list(COMMUNITY_FEATURES),
            reason="no_key_configured",
            api_reachable=False,
        )
        _print_banner(_state)
        return _state

    # Try to reach the license API
    try:
        data = _call_validate(api_url, key, product)
        _state = LicenseState(
            valid=        data.get("valid", False),
            tier=         data.get("tier") or "community",
            features=     data.get("features") or list(COMMUNITY_FEATURES),
            expires_at=   data.get("expires_at"),
            key=          key,
            reason=       data.get("reason", "ok"),
            api_reachable=True,
        )

        # API reachable but key invalid — fall back to community, warn loudly
        if not _state.valid:
            _state.tier     = "community"
            _state.features = list(COMMUNITY_FEATURES)

    except urllib.error.URLError as e:
        # License API unreachable — warn and run as community
        # This means a dead pila-license service doesn't kill PILA
        print(f"[LICENSE] WARNING: License API unreachable ({api_url}): {e}")
        print(f"[LICENSE] Running in community mode. Start ~/pila-license/start.sh to restore.")
        _state = LicenseState(
            valid=False,
            tier="community",
            features=list(COMMUNITY_FEATURES),
            key=key,
            reason=f"api_unreachable: {e}",
            api_reachable=False,
        )

    except Exception as e:
        print(f"[LICENSE] Unexpected error during license check: {e}")
        _state = LicenseState(
            valid=False,
            tier="community",
            features=list(COMMUNITY_FEATURES),
            reason=f"error: {e}",
            api_reachable=False,
        )

    _print_banner(_state)
    return _state


def _print_banner(state: LicenseState) -> None:
    tier_label = state.tier.upper()
    if state.valid:
        exp = f"  Expires: {state.expires_at}" if state.expires_at else "  Expires: Never"
        print(f"[LICENSE] ✅ PILA Suite — {tier_label} tier activated.{exp}")
    elif state.reason == "no_key_configured":
        print(f"[LICENSE] ℹ️  PILA Suite — COMMUNITY tier (no license key in pila.conf)")
        print(f"[LICENSE]    Add a [license] key= entry to unlock Professional features.")
    else:
        print(f"[LICENSE] ⚠️  PILA Suite — COMMUNITY tier (license issue: {state.reason})")
