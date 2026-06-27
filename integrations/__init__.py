"""PILA Suite — Live Network Integrations"""

# Community (open-core) tree does NOT ship the proprietary ES client or the
# Pro config dataclasses. Import them optionally so the package loads in the
# Community build; the Professional build supplies these modules.
__all__ = []

try:
    from .elastic_client import ESClient  # Professional only
    __all__.append("ESClient")
except ImportError:
    ESClient = None

try:
    from .config import (ESConfig, SuricataConfig, ZeekConfig,
                         LMEPConfig, IRVConfig)  # Professional only
    __all__ += ["ESConfig", "SuricataConfig", "ZeekConfig",
                "LMEPConfig", "IRVConfig"]
except ImportError:
    ESConfig = SuricataConfig = ZeekConfig = LMEPConfig = IRVConfig = None

# Community read client — always available in the open build.
try:
    from .es_read import ESReadClient
    __all__.append("ESReadClient")
except ImportError:
    ESReadClient = None
