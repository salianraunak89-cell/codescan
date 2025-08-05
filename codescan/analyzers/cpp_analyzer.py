"""C++-specific code analyzer."""

from typing import List
from .c_analyzer import CAnalyzer


class CppAnalyzer(CAnalyzer):
    """Analyzer for C++ code."""
    
    def _get_language(self) -> str:
        return "cpp"
    
    def _get_file_extensions(self) -> List[str]:
        return ['.cpp', '.cxx', '.cc', '.hpp', '.hxx', '.hh']