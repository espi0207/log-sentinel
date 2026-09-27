"""Detector de ataques contra SSH y servidores web a partir de sus logs."""

from .detectors import Analysis, Config, Finding, Severity, analyze
from .parser import AuthEvent, EventKind, parse_lines
from .webserver import WebAnalysis, WebEvent, analyze_web, parse_web_lines

__all__ = [
    "Analysis",
    "AuthEvent",
    "Config",
    "EventKind",
    "Finding",
    "Severity",
    "WebAnalysis",
    "WebEvent",
    "analyze",
    "analyze_web",
    "parse_lines",
    "parse_web_lines",
]
__version__ = "1.1.0"
