"""Sensitive Word Analyzer public API."""

from .models import FileReport, Finding, ScanReport, Severity
from .rules import RuleSet
from .scanner import ScanOptions, Scanner

__all__ = [
    "FileReport",
    "Finding",
    "RuleSet",
    "ScanOptions",
    "ScanReport",
    "Scanner",
    "Severity",
]

__version__ = "1.0.0"
