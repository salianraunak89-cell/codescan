"""Language-specific code analyzers."""

from typing import Optional, Dict, Type
from .base import BaseAnalyzer
from .python_analyzer import PythonAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from .java_analyzer import JavaAnalyzer
from .c_analyzer import CAnalyzer
from .cpp_analyzer import CppAnalyzer
from .go_analyzer import GoAnalyzer
from .rust_analyzer import RustAnalyzer


# Registry of analyzers by language
ANALYZERS: Dict[str, Type[BaseAnalyzer]] = {
    'python': PythonAnalyzer,
    'javascript': JavaScriptAnalyzer,
    'typescript': JavaScriptAnalyzer,  # Use JS analyzer for TypeScript
    'java': JavaAnalyzer,
    'c': CAnalyzer,
    'cpp': CppAnalyzer,
    'go': GoAnalyzer,
    'rust': RustAnalyzer,
}


def get_analyzer_for_language(language: str) -> Optional[BaseAnalyzer]:
    """
    Get analyzer instance for a specific language.
    
    Args:
        language: Programming language name
        
    Returns:
        Analyzer instance or None if not supported
    """
    analyzer_class = ANALYZERS.get(language)
    if analyzer_class:
        return analyzer_class()
    return None


def get_supported_languages() -> list[str]:
    """Get list of supported languages for analysis."""
    return list(ANALYZERS.keys())


__all__ = [
    'BaseAnalyzer',
    'get_analyzer_for_language',
    'get_supported_languages',
    'PythonAnalyzer',
    'JavaScriptAnalyzer',
    'JavaAnalyzer',
    'CAnalyzer',
    'CppAnalyzer',
    'GoAnalyzer',
    'RustAnalyzer',
]