"""
Firewall parser family — public API.

    from firewall import parse, is_firewall, FirewallParseResult

parse(raw_log) -> FirewallParseResult | None
"""
from .engine import parse, FirewallParseResult
from .detector import is_firewall, detect_format

__all__ = ["parse", "is_firewall", "detect_format", "FirewallParseResult"]
