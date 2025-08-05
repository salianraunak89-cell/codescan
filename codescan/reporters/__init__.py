"""Report generation and formatting."""

from .json_reporter import JsonReporter
from .html_reporter import HtmlReporter
from .text_reporter import TextReporter
from .sarif_reporter import SarifReporter


def get_reporter(format_type: str):
    """
    Get reporter instance for specified format.
    
    Args:
        format_type: Output format (json, html, text, sarif)
        
    Returns:
        Reporter instance
    """
    reporters = {
        'json': JsonReporter,
        'html': HtmlReporter,
        'text': TextReporter,
        'sarif': SarifReporter,
    }
    
    reporter_class = reporters.get(format_type.lower())
    if reporter_class:
        return reporter_class()
    else:
        raise ValueError(f"Unsupported report format: {format_type}")


__all__ = [
    "JsonReporter",
    "HtmlReporter", 
    "TextReporter",
    "SarifReporter",
    "get_reporter"
]