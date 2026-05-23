"""
PILA Suite — License Check
Community Edition

© 2026 ByTE X Bit Technologies LLC
"""

class LicenseState:
    def __init__(self):
        self.valid    = False
        self.tier     = "community"
        self.features = ["psil_basic", "aesp_basic", "api_read"]
        self.expires_at = None
        self.reason   = "community"
        self.api_reachable = False

    def has_feature(self, feature):
        return feature in self.features

    def require_feature(self, feature, label=""):
        if not self.has_feature(feature):
            raise PermissionError(
                f"'{label or feature}' requires PILA Suite Professional. "
                f"Visit pilasuit.com to upgrade."
            )

    def summary(self):
        return {
            "valid": self.valid,
            "tier": self.tier,
            "expires_at": self.expires_at,
            "features": self.features,
            "api_reachable": self.api_reachable,
            "reason": self.reason,
        }

_state = LicenseState()

def check_license(conf_path=None):
    print("[LICENSE] ℹ️  PILA Suite — COMMUNITY tier")
    print("[LICENSE]    Professional features require a license key.")
    print("[LICENSE]    Visit pilasuit.com to upgrade.")
    return _state

def get_license():
    return _state

def has_feature(feature):
    return _state.has_feature(feature)
