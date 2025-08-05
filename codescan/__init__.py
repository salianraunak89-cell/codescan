"""
CodeScan - A comprehensive code analysis tool for multiple programming languages.

This package provides static code analysis, security scanning, and best practices
checking for various programming languages including Python, JavaScript, Java,
C/C++, Go, Rust, and more.
"""

__version__ = "1.0.0"
__author__ = "CodeScan Team"
__email__ = "info@codescan.dev"

from .core.scanner import CodeScanner
from .core.language_detector import LanguageDetector
from .core.config import Config

__all__ = ["CodeScanner", "LanguageDetector", "Config"]