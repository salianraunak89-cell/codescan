"""Base analyzer class for language-specific analysis."""

import re
import ast
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

from ..core.result import Issue, Severity, IssueType
from ..core.config import AnalyzerConfig


class BaseAnalyzer(ABC):
    """Base class for language-specific code analyzers."""
    
    def __init__(self):
        """Initialize the analyzer."""
        self.language = self._get_language()
        self.file_extensions = self._get_file_extensions()
        
    @abstractmethod
    def _get_language(self) -> str:
        """Get the language this analyzer handles."""
        pass
    
    @abstractmethod
    def _get_file_extensions(self) -> List[str]:
        """Get file extensions this analyzer handles."""
        pass
    
    def analyze(self, file_path: str, config: AnalyzerConfig) -> List[Issue]:
        """
        Analyze a file and return issues.
        
        Args:
            file_path: Path to file to analyze
            config: Analyzer configuration
            
        Returns:
            List of issues found
        """
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.splitlines()
            
            # Run basic checks
            issues.extend(self._check_line_length(file_path, lines, config))
            issues.extend(self._check_file_size(file_path, content, config))
            issues.extend(self._check_encoding(file_path, content, config))
            
            # Run language-specific checks
            issues.extend(self._analyze_syntax(file_path, content, config))
            issues.extend(self._analyze_style(file_path, content, lines, config))
            issues.extend(self._analyze_complexity(file_path, content, config))
            issues.extend(self._analyze_best_practices(file_path, content, lines, config))
            
        except Exception as e:
            # Create an issue for analysis failure
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.LOW,
                issue_type=IssueType.BUG,
                rule_id="analyzer_error",
                title="Analysis Error",
                description=f"Failed to analyze file: {str(e)}",
                suggestion="Check file encoding and syntax"
            ))
        
        return issues
    
    def _check_line_length(self, file_path: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Check for lines that are too long."""
        issues = []
        max_length = config.rules.get('max_line_length', 100)
        
        for line_num, line in enumerate(lines, 1):
            if len(line) > max_length:
                issues.append(Issue(
                    file_path=file_path,
                    line_number=line_num,
                    column=max_length + 1,
                    severity=Severity.LOW,
                    issue_type=IssueType.CODE_STYLE,
                    rule_id="line_too_long",
                    title="Line Too Long",
                    description=f"Line exceeds {max_length} characters ({len(line)} chars)",
                    suggestion=f"Break line into multiple lines or refactor",
                    code_snippet=line
                ))
        
        return issues
    
    def _check_file_size(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check if file is too large."""
        issues = []
        max_lines = config.rules.get('max_file_lines', 1000)
        lines = content.count('\n') + 1
        
        if lines > max_lines:
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.MEDIUM,
                issue_type=IssueType.MAINTAINABILITY,
                rule_id="file_too_large",
                title="File Too Large",
                description=f"File has {lines} lines, exceeding limit of {max_lines}",
                suggestion="Consider breaking this file into smaller modules"
            ))
        
        return issues
    
    def _check_encoding(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for encoding issues."""
        issues = []
        
        # Check for mixed line endings
        has_crlf = '\r\n' in content
        has_lf = '\n' in content.replace('\r\n', '')
        
        if has_crlf and has_lf:
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.LOW,
                issue_type=IssueType.CODE_STYLE,
                rule_id="mixed_line_endings",
                title="Mixed Line Endings",
                description="File contains mixed line endings (CRLF and LF)",
                suggestion="Use consistent line endings throughout the file"
            ))
        
        # Check for trailing whitespace
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            if line.endswith(' ') or line.endswith('\t'):
                issues.append(Issue(
                    file_path=file_path,
                    line_number=line_num,
                    column=len(line.rstrip()) + 1,
                    severity=Severity.LOW,
                    issue_type=IssueType.CODE_STYLE,
                    rule_id="trailing_whitespace",
                    title="Trailing Whitespace",
                    description="Line has trailing whitespace",
                    suggestion="Remove trailing whitespace",
                    code_snippet=line
                ))
        
        return issues
    
    @abstractmethod
    def _analyze_syntax(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Analyze syntax-specific issues."""
        pass
    
    @abstractmethod
    def _analyze_style(self, file_path: str, content: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Analyze code style issues."""
        pass
    
    @abstractmethod
    def _analyze_complexity(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Analyze code complexity issues."""
        pass
    
    @abstractmethod
    def _analyze_best_practices(self, file_path: str, content: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Analyze best practices violations."""
        pass
    
    def _find_pattern_issues(self, file_path: str, content: str, patterns: Dict[str, Dict[str, Any]]) -> List[Issue]:
        """
        Find issues based on regex patterns.
        
        Args:
            file_path: Path to file
            content: File content
            patterns: Dictionary of pattern configurations
            
        Returns:
            List of issues found
        """
        issues = []
        lines = content.splitlines()
        
        for rule_id, pattern_config in patterns.items():
            pattern = pattern_config['pattern']
            severity = Severity(pattern_config.get('severity', 'medium'))
            issue_type = IssueType(pattern_config.get('type', 'best_practice'))
            title = pattern_config['title']
            description = pattern_config['description']
            suggestion = pattern_config.get('suggestion', '')
            
            # Search in each line
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=severity,
                        issue_type=issue_type,
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        suggestion=suggestion,
                        code_snippet=line.strip()
                    ))
        
        return issues
    
    def _calculate_cyclomatic_complexity(self, content: str) -> int:
        """
        Calculate basic cyclomatic complexity.
        
        This is a simplified implementation that counts decision points.
        """
        # Keywords that increase complexity
        complexity_keywords = [
            r'\bif\b', r'\belse\b', r'\belif\b', r'\bwhile\b', r'\bfor\b',
            r'\bswitch\b', r'\bcase\b', r'\bcatch\b', r'\btry\b',
            r'\b\?\s*\w+\s*:', r'\&\&', r'\|\|'  # ternary operator, logical operators
        ]
        
        complexity = 1  # Base complexity
        
        for keyword_pattern in complexity_keywords:
            complexity += len(re.findall(keyword_pattern, content, re.IGNORECASE))
        
        return complexity
    
    def _extract_functions(self, content: str) -> List[Dict[str, Any]]:
        """
        Extract function information from code.
        
        This is a basic implementation that should be overridden by specific analyzers.
        """
        # Basic function pattern (works for many C-style languages)
        function_pattern = re.compile(
            r'^[\s]*(?:(?:public|private|protected|static|virtual|override|async)\s+)*'
            r'(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{',
            re.MULTILINE
        )
        
        functions = []
        lines = content.splitlines()
        
        for match in function_pattern.finditer(content):
            function_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            
            functions.append({
                'name': function_name,
                'line_number': line_num,
                'start_pos': match.start(),
                'end_pos': self._find_function_end(content, match.end())
            })
        
        return functions
    
    def _find_function_end(self, content: str, start_pos: int) -> int:
        """Find the end position of a function."""
        brace_count = 1
        pos = start_pos
        
        while pos < len(content) and brace_count > 0:
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
            pos += 1
        
        return pos
    
    def _count_function_lines(self, content: str, start_pos: int, end_pos: int) -> int:
        """Count lines in a function."""
        function_content = content[start_pos:end_pos]
        return function_content.count('\n')
    
    def _is_comment_line(self, line: str) -> bool:
        """Check if a line is a comment (basic implementation)."""
        stripped = line.strip()
        return (stripped.startswith('//') or 
                stripped.startswith('#') or 
                stripped.startswith('/*') or 
                stripped.startswith('*') or
                stripped.startswith('<!--'))
    
    def _check_naming_conventions(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check naming conventions (basic implementation)."""
        issues = []
        
        if not config.rules.get('check_naming_conventions', True):
            return issues
        
        # This is a basic implementation - should be overridden by specific analyzers
        # Check for snake_case vs camelCase consistency
        snake_case_pattern = re.compile(r'\b[a-z]+(_[a-z]+)+\b')
        camel_case_pattern = re.compile(r'\b[a-z]+([A-Z][a-z]*)+\b')
        
        snake_cases = snake_case_pattern.findall(content)
        camel_cases = camel_case_pattern.findall(content)
        
        # If both patterns are found, suggest consistency
        if snake_cases and camel_cases:
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.LOW,
                issue_type=IssueType.CODE_STYLE,
                rule_id="inconsistent_naming",
                title="Inconsistent Naming Convention",
                description="File contains both snake_case and camelCase naming",
                suggestion="Use consistent naming convention throughout the file"
            ))
        
        return issues