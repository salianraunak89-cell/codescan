"""Core functionality for CodeScan."""

from .scanner import CodeScanner
from .language_detector import LanguageDetector
from .config import Config
from .result import ScanResult, Issue

__all__ = ["CodeScanner", "LanguageDetector", "Config", "ScanResult", "Issue"]