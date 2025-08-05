"""Security and vulnerability scanners."""

from typing import Optional
from .security_scanner import SecurityScanner


def get_security_scanner() -> Optional[SecurityScanner]:
    """
    Get security scanner instance.
    
    Returns:
        SecurityScanner instance
    """
    return SecurityScanner()


__all__ = ["SecurityScanner", "get_security_scanner"]