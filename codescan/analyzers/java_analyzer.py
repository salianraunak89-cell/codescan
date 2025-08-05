"""Java-specific code analyzer."""

import re
from typing import List

from .base import BaseAnalyzer
from ..core.result import Issue, Severity, IssueType
from ..core.config import AnalyzerConfig


class JavaAnalyzer(BaseAnalyzer):
    """Analyzer for Java code."""
    
    def _get_language(self) -> str:
        return "java"
    
    def _get_file_extensions(self) -> List[str]:
        return ['.java']
    
    def _analyze_syntax(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Analyze Java syntax issues."""
        issues = []
        
        # Basic syntax patterns
        syntax_patterns = {
            "missing_semicolon": {
                "pattern": re.compile(r'[^;{}\s]\s*\n\s*[a-zA-Z_$]'),
                "severity": "medium",
                "type": "bug",
                "title": "Missing Semicolon",
                "description": "Statement may be missing semicolon",
                "suggestion": "Add semicolon at end of statement"
            }
        }
        
        issues.extend(self._find_pattern_issues(file_path, content, syntax_patterns))
        return issues
    
    def _analyze_style(self, file_path: str, content: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Analyze Java style issues."""
        issues = []
        
        # Check naming conventions
        issues.extend(self._check_naming_conventions(file_path, content, config))
        
        return issues
    
    def _analyze_complexity(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Analyze Java complexity issues."""
        issues = []
        
        complexity = self._calculate_cyclomatic_complexity(content)
        max_complexity = config.rules.get('max_complexity', 15)
        
        if complexity > max_complexity:
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.MEDIUM,
                issue_type=IssueType.COMPLEXITY,
                rule_id="file_too_complex",
                title="File Too Complex",
                description=f"File has complexity {complexity}, exceeding limit of {max_complexity}",
                suggestion="Break down into smaller classes or methods"
            ))
        
        return issues
    
    def _analyze_best_practices(self, file_path: str, content: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Analyze Java best practices violations."""
        issues = []
        
        java_patterns = {
            "system_out_print": {
                "pattern": re.compile(r'System\.out\.print'),
                "severity": "low",
                "type": "best_practice",
                "title": "System.out.print Usage",
                "description": "Consider using proper logging instead of System.out.print",
                "suggestion": "Use a logging framework like SLF4J or java.util.logging"
            },
            "empty_catch": {
                "pattern": re.compile(r'catch\s*\([^)]*\)\s*{\s*}'),
                "severity": "high",
                "type": "best_practice",
                "title": "Empty Catch Block",
                "description": "Empty catch blocks hide exceptions",
                "suggestion": "Handle exceptions properly or at least log them"
            }
        }
        
        issues.extend(self._find_pattern_issues(file_path, content, java_patterns))
        return issues