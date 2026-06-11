"""
MHDDoS - Core Engine Package
Refactored from start.py, gui.py, deathstar_modules.py, adaptive_plus.py
"""

from .utils import (
    bcolors,
    Methods,
    Tools,
    Counter,
    Minecraft,
    REQUESTS_SENT,
    BYTES_SEND,
    __version__,
    __dir__,
    __ip__,
    ctx,
    logger,
    WAF_BYPASS_VECTORS,
    waf_auto_select_bypass,
    waf_report_result,
    TrafficGraph,
    _traffic_graph,
)
from .proxy import ProxyManager, ProxyRotator, load_proxies
from .tls import TLSRandomizer
from .adaptive import (
    AdaptiveRPC,
    AdaptiveThrottle,
    EnhancedAdaptiveController,
    Aggressiveness,
)
from .engine import Layer4, HttpFlood
from .deathstar import (
    KeepalivePool,
    get_global_pool,
    ResponseSwapper,
    SlowlorisFlood,
    WAFFingerprint,
)
from .recon import ReconSuite
