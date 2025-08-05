"""JavaScript/TypeScript-specific code analyzer."""

import re
from typing import List, Dict, Any

from .base import BaseAnalyzer
from ..core.result import Issue, Severity, IssueType
from ..core.config import AnalyzerConfig


class JavaScriptAnalyzer(BaseAnalyzer):
    """Analyzer for JavaScript and TypeScript code."""
    
    def _get_language(self) -> str:
        return "javascript"
    
    def _get_file_extensions(self) -> List[str]:
        return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']
    
    def _analyze_syntax(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Analyze JavaScript syntax issues."""
        issues = []
        
        # Basic syntax checks using regex patterns
        syntax_patterns = {
            "unclosed_brace": {
                "pattern": re.compile(r'\{[^}]*$', re.MULTILINE),
                "severity": "high",
                "type": "bug",
                "title": "Potential Unclosed Brace",
                "description": "Line may have unclosed brace",
                "suggestion": "Ensure all braces are properly closed"
            },
            "semicolon_missing": {
                "pattern": re.compile(r'[^;{}\s]\s*\n\s*[a-zA-Z_$]'),
                "severity": "low",
                "type": "code_style",
                "title": "Missing Semicolon",
                "description": "Statement may be missing semicolon",
                "suggestion": "Add semicolon at end of statement"
            }
        }
        
        issues.extend(self._find_pattern_issues(file_path, content, syntax_patterns))
        return issues
    
    def _analyze_style(self, file_path: str, content: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Analyze JavaScript style issues."""
        issues = []
        
        # Check for var vs let/const
        issues.extend(self._check_variable_declarations(file_path, content, config))
        
        # Check indentation and spacing
        issues.extend(self._check_javascript_spacing(file_path, lines, config))
        
        # Check for trailing commas
        issues.extend(self._check_trailing_commas(file_path, lines, config))
        
        return issues
    
    def _analyze_complexity(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Analyze JavaScript complexity issues."""
        issues = []
        
        # Extract functions and analyze complexity
        functions = self._extract_javascript_functions(content)
        max_complexity = config.rules.get('max_complexity', 15)
        
        for func in functions:
            complexity = self._calculate_function_complexity_js(func['content'])
            if complexity > max_complexity:
                issues.append(Issue(
                    file_path=file_path,
                    line_number=func['line_number'],
                    column=1,
                    severity=Severity.MEDIUM,
                    issue_type=IssueType.COMPLEXITY,
                    rule_id="function_too_complex",
                    title="Function Too Complex",
                    description=f"Function '{func['name']}' has complexity {complexity}, exceeding limit of {max_complexity}",
                    suggestion="Break function into smaller functions or simplify logic"
                ))
        
        # Check for deeply nested callbacks
        callback_depth = self._check_callback_depth(content)
        max_callback_depth = config.rules.get('max_callback_depth', 3)
        
        if callback_depth > max_callback_depth:
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.MEDIUM,
                issue_type=IssueType.COMPLEXITY,
                rule_id="callback_hell",
                title="Callback Hell Detected",
                description=f"Deeply nested callbacks detected (depth: {callback_depth})",
                suggestion="Consider using async/await or Promises to flatten callback structure"
            ))
        
        return issues
    
    def _analyze_best_practices(self, file_path: str, content: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Analyze JavaScript best practices violations."""
        issues = []
        
        # JavaScript-specific patterns
        js_patterns = {
            "console_log": {
                "pattern": re.compile(r'\bconsole\.(log|warn|error|info|debug)\s*\('),
                "severity": "low",
                "type": "best_practice",
                "title": "Console Statement Found",
                "description": "Console statements should be removed from production code",
                "suggestion": "Remove console statements or use proper logging"
            },
            "eval_usage": {
                "pattern": re.compile(r'\beval\s*\('),
                "severity": "critical",
                "type": "security",
                "title": "Dangerous eval() Usage",
                "description": "eval() can execute arbitrary code and is a security risk",
                "suggestion": "Avoid eval() or use safer alternatives like JSON.parse()"
            },
            "alert_usage": {
                "pattern": re.compile(r'\balert\s*\('),
                "severity": "medium",
                "type": "best_practice",
                "title": "Alert Usage",
                "description": "alert() should not be used in production code",
                "suggestion": "Use proper user notifications or modal dialogs"
            },
            "document_write": {
                "pattern": re.compile(r'\bdocument\.write\s*\('),
                "severity": "high",
                "type": "best_practice",
                "title": "document.write() Usage",
                "description": "document.write() can cause security issues and poor performance",
                "suggestion": "Use modern DOM manipulation methods"
            },
            "with_statement": {
                "pattern": re.compile(r'\bwith\s*\('),
                "severity": "high",
                "type": "best_practice",
                "title": "with Statement Usage",
                "description": "with statements are deprecated and can cause confusion",
                "suggestion": "Avoid with statements and use explicit object references"
            },
            "equality_operator": {
                "pattern": re.compile(r'[^=!]==[^=]|[^=!]!=[^=]'),
                "severity": "medium",
                "type": "best_practice",
                "title": "Non-strict Equality",
                "description": "Use strict equality (=== or !==) instead of == or !=",
                "suggestion": "Replace == with === and != with !=="
            },
            "var_declaration": {
                "pattern": re.compile(r'\bvar\s+\w+'),
                "severity": "low",
                "type": "best_practice",
                "title": "var Declaration",
                "description": "Use let or const instead of var",
                "suggestion": "Replace var with let or const for better scoping"
            },
            "function_in_loop": {
                "pattern": re.compile(r'for\s*\([^)]*\)\s*{[^}]*function\s*\('),
                "severity": "medium",
                "type": "performance",
                "title": "Function Declaration in Loop",
                "description": "Creating functions inside loops can impact performance",
                "suggestion": "Move function declaration outside the loop"
            }
        }
        
        issues.extend(self._find_pattern_issues(file_path, content, js_patterns))
        
        # Check for unused variables
        issues.extend(self._check_unused_variables(file_path, content, config))
        
        # Check for missing error handling
        issues.extend(self._check_error_handling(file_path, content, config))
        
        return issues
    
    def _check_variable_declarations(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check variable declaration best practices."""
        issues = []
        
        if not config.rules.get('prefer_const', True):
            return issues
        
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Check for let variables that could be const
            let_match = re.search(r'\blet\s+(\w+)\s*=\s*[^;]+;?', line)
            if let_match:
                var_name = let_match.group(1)
                
                # Simple heuristic: if variable is not reassigned in remaining lines
                remaining_content = '\n'.join(lines[line_num:])
                reassignment_pattern = rf'\b{var_name}\s*='
                
                if not re.search(reassignment_pattern, remaining_content):
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=let_match.start() + 1,
                        severity=Severity.LOW,
                        issue_type=IssueType.BEST_PRACTICE,
                        rule_id="prefer_const",
                        title="Prefer const Declaration",
                        description=f"Variable '{var_name}' is never reassigned and should be const",
                        suggestion="Change let to const for variables that are never reassigned",
                        code_snippet=line.strip()
                    ))
        
        return issues
    
    def _check_javascript_spacing(self, file_path: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Check JavaScript-specific spacing issues."""
        issues = []
        
        spacing_patterns = [
            (re.compile(r'function\('), "Missing space after function keyword"),
            (re.compile(r'\){\s*'), "Missing space before opening brace"),
            (re.compile(r'if\('), "Missing space after if keyword"),
            (re.compile(r'for\('), "Missing space after for keyword"),
            (re.compile(r'while\('), "Missing space after while keyword"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in spacing_patterns:
                if pattern.search(line):
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=1,
                        severity=Severity.LOW,
                        issue_type=IssueType.CODE_STYLE,
                        rule_id="spacing_style",
                        title="Spacing Style Issue",
                        description=message,
                        suggestion="Add appropriate spacing for better readability",
                        code_snippet=line.strip()
                    ))
        
        return issues
    
    def _check_trailing_commas(self, file_path: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Check for trailing commas in objects and arrays."""
        issues = []
        
        if not config.rules.get('check_trailing_commas', True):
            return issues
        
        for line_num, line in enumerate(lines, 1):
            # Check for missing trailing comma in multiline objects/arrays
            if re.search(r'[^\s,]\s*\n\s*[}\]]', line + '\n' + (lines[line_num] if line_num < len(lines) else '')):
                issues.append(Issue(
                    file_path=file_path,
                    line_number=line_num,
                    column=len(line),
                    severity=Severity.LOW,
                    issue_type=IssueType.CODE_STYLE,
                    rule_id="missing_trailing_comma",
                    title="Missing Trailing Comma",
                    description="Consider adding trailing comma for better diffs",
                    suggestion="Add trailing comma after the last element",
                    code_snippet=line.strip()
                ))
        
        return issues
    
    def _extract_javascript_functions(self, content: str) -> List[Dict[str, Any]]:
        """Extract JavaScript function information."""
        functions = []
        lines = content.splitlines()
        
        # Pattern for function declarations and expressions
        function_patterns = [
            re.compile(r'^[\s]*function\s+(\w+)\s*\([^)]*\)\s*{'),  # function declaration
            re.compile(r'^[\s]*(?:const|let|var)\s+(\w+)\s*=\s*function\s*\([^)]*\)\s*{'),  # function expression
            re.compile(r'^[\s]*(?:const|let|var)\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*{'),  # arrow function
            re.compile(r'^[\s]*(\w+)\s*:\s*function\s*\([^)]*\)\s*{'),  # object method
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in function_patterns:
                match = pattern.search(line)
                if match:
                    function_name = match.group(1)
                    
                    # Find function end (simple brace counting)
                    brace_count = 1
                    function_lines = [line]
                    current_line = line_num
                    
                    while current_line < len(lines) and brace_count > 0:
                        current_line += 1
                        if current_line <= len(lines):
                            next_line = lines[current_line - 1]
                            function_lines.append(next_line)
                            brace_count += next_line.count('{') - next_line.count('}')
                    
                    functions.append({
                        'name': function_name,
                        'line_number': line_num,
                        'content': '\n'.join(function_lines)
                    })
                    break
        
        return functions
    
    def _calculate_function_complexity_js(self, function_content: str) -> int:
        """Calculate cyclomatic complexity for JavaScript function."""
        complexity = 1  # Base complexity
        
        # JavaScript complexity keywords
        complexity_keywords = [
            r'\bif\b', r'\belse\b', r'\bwhile\b', r'\bfor\b', r'\bswitch\b',
            r'\bcase\b', r'\bcatch\b', r'\btry\b', r'\?[^?]', r'&&', r'\|\|'
        ]
        
        for keyword_pattern in complexity_keywords:
            complexity += len(re.findall(keyword_pattern, function_content))
        
        return complexity
    
    def _check_callback_depth(self, content: str) -> int:
        """Check for deeply nested callbacks."""
        max_depth = 0
        current_depth = 0
        
        # Simple pattern matching for function nesting
        for char in content:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        
        return max_depth
    
    def _check_unused_variables(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for unused variables (basic implementation)."""
        issues = []
        
        if not config.rules.get('check_unused_vars', True):
            return issues
        
        # Extract variable declarations
        var_declarations = re.findall(r'\b(?:var|let|const)\s+(\w+)', content)
        
        # Check if variables are used
        for var_name in var_declarations:
            # Count occurrences (declaration + usage)
            occurrences = len(re.findall(rf'\b{var_name}\b', content))
            
            # If only appears once, it's likely unused (just declared)
            if occurrences == 1:
                match = re.search(rf'\b(?:var|let|const)\s+{var_name}\b', content)
                if match:
                    line_num = content[:match.start()].count('\n') + 1
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=Severity.LOW,
                        issue_type=IssueType.BEST_PRACTICE,
                        rule_id="unused_variable",
                        title="Unused Variable",
                        description=f"Variable '{var_name}' is declared but never used",
                        suggestion="Remove unused variable or use it in the code"
                    ))
        
        return issues
    
    def _check_error_handling(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for proper error handling."""
        issues = []
        
        # Check for try blocks without catch
        try_blocks = re.findall(r'\btry\s*{[^}]*}', content)
        catch_blocks = re.findall(r'\bcatch\s*\([^)]*\)\s*{[^}]*}', content)
        
        if len(try_blocks) > len(catch_blocks):
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.MEDIUM,
                issue_type=IssueType.BEST_PRACTICE,
                rule_id="missing_catch_block",
                title="Missing Catch Block",
                description="Try block found without corresponding catch block",
                suggestion="Add catch block to handle potential errors"
            ))
        
        # Check for Promise usage without error handling
        promise_usage = re.findall(r'\.then\s*\([^)]*\)', content)
        promise_catch = re.findall(r'\.catch\s*\([^)]*\)', content)
        
        if len(promise_usage) > len(promise_catch):
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.MEDIUM,
                issue_type=IssueType.BEST_PRACTICE,
                rule_id="promise_without_catch",
                title="Promise Without Error Handling",
                description="Promise chain found without .catch() for error handling",
                suggestion="Add .catch() to handle Promise rejections"
            ))
        
        return issues