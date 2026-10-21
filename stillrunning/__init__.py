"""
stillrunning - AI-powered supply chain security.
Blocks malicious packages at install AND import time.

Patent Pending - US Provisional Application filed April 12, 2026

Usage:
    stillrunning --setup          # 3-minute setup wizard
    stillrunning --install-hook   # Enable always-on import protection
    stillrunning --allow <pkg>    # Allow a blocked package
    stillrunning-scan <file>      # Static analysis scanner
    stillrunning-guard            # Always-on security daemon
    stillrunning-intercept        # npm/pip supply chain blocker
    pkl-inspector <file>          # Pickle file static analysis

Import Protection:
    import stillrunning.hook      # Activate for this session

Tiers (SESSION 93):
    Personal ($9/mo)   - process monitor, restart, Telegram alerts
    Basic ($29/mo)     - + file integrity, tripwire, honeypot
    AI ($49/mo)        - + AI package review, import hook, MCP integration
    Enterprise ($499)  - + unlimited scans, SIEM, SSO, compliance
"""

__version__ = "2.13.7"
__author__ = "johhnyg"
__license__ = "MIT"

# Re-export main components
from .cli import main_cli, load_config
from .scan import main as scan_main, analyze_python_file, analyze_pickle_file
from .guard import main_loop as guard_main
from .intercept import main as intercept_main
from .docker_agent import main as docker_main
from .pkl_inspector import PklInspector, main as pkl_main
from .features import validate_token, has_feature, require_feature, TIER_FEATURES
from . import hook

__all__ = [
    "__version__",
    "main_cli",
    "load_config",
    "scan_main",
    "analyze_python_file",
    "analyze_pickle_file",
    "guard_main",
    "intercept_main",
    "docker_main",
    "PklInspector",
    "pkl_main",
    "validate_token",
    "has_feature",
    "require_feature",
    "TIER_FEATURES",
    "hook",
]
