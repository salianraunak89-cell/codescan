"""Python-specific code analyzer."""

import ast
import re
from typing import List, Dict, Any, Set
import builtins

from .base import BaseAnalyzer
from ..core.result import Issue, Severity, IssueType
from ..core.config import AnalyzerConfig


class PythonAnalyzer(BaseAnalyzer):
    """Analyzer for Python code."""
    
    def _get_language(self) -> str:
        return "python"
    
    def _get_file_extensions(self) -> List[str]:
        return ['.py', '.pyw', '.pyi']
    
    def _analyze_syntax(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Analyze Python syntax issues."""
        issues = []
        
        try:
            # Parse AST to check for syntax errors
            ast.parse(content)
        except SyntaxError as e:
            issues.append(Issue(
                file_path=file_path,
                line_number=e.lineno or 1,
                column=e.offset or 1,
                severity=Severity.HIGH,
                issue_type=IssueType.BUG,
                rule_id="syntax_error",
                title="Syntax Error",
                description=f"Python syntax error: {e.msg}",
                suggestion="Fix syntax error"
            ))
        except Exception as e:
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.MEDIUM,
                issue_type=IssueType.BUG,
                rule_id="parse_error",
                title="Parse Error",
                description=f"Failed to parse Python code: {str(e)}",
                suggestion="Check for invalid Python syntax"
            ))
        
        return issues
    
    def _analyze_style(self, file_path: str, content: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Analyze Python style issues."""
        issues = []
        
        # PEP 8 style checks
        issues.extend(self._check_imports(file_path, content, config))
        issues.extend(self._check_indentation(file_path, lines, config))
        issues.extend(self._check_spacing(file_path, lines, config))
        issues.extend(self._check_line_endings(file_path, content, config))
        
        return issues
    
    def _analyze_complexity(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Analyze Python complexity issues."""
        issues = []
        
        try:
            tree = ast.parse(content)
            
            # Check function complexity
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    complexity = self._calculate_function_complexity(node)
                    max_complexity = config.rules.get('max_complexity', 10)
                    
                    if complexity > max_complexity:
                        issues.append(Issue(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset + 1,
                            severity=Severity.MEDIUM,
                            issue_type=IssueType.COMPLEXITY,
                            rule_id="function_too_complex",
                            title="Function Too Complex",
                            description=f"Function '{node.name}' has complexity {complexity}, exceeding limit of {max_complexity}",
                            suggestion="Break function into smaller functions or simplify logic"
                        ))
                
                # Check for deeply nested code
                if isinstance(node, (ast.If, ast.For, ast.While, ast.With)):
                    depth = self._calculate_nesting_depth(node)
                    max_depth = config.rules.get('max_nesting_depth', 4)
                    
                    if depth > max_depth:
                        issues.append(Issue(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset + 1,
                            severity=Severity.MEDIUM,
                            issue_type=IssueType.COMPLEXITY,
                            rule_id="code_too_nested",
                            title="Code Too Nested",
                            description=f"Code block has nesting depth {depth}, exceeding limit of {max_depth}",
                            suggestion="Extract nested logic into separate functions"
                        ))
        
        except Exception:
            pass  # Already handled in syntax analysis
        
        return issues
    
    def _analyze_best_practices(self, file_path: str, content: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Analyze Python best practices violations."""
        issues = []
        
        try:
            tree = ast.parse(content)
            
            # Check for various best practices
            issues.extend(self._check_docstrings(file_path, tree, config))
            issues.extend(self._check_type_hints(file_path, tree, config))
            issues.extend(self._check_exception_handling(file_path, tree, config))
            issues.extend(self._check_unused_imports(file_path, tree, content, config))
            issues.extend(self._check_dangerous_patterns(file_path, tree, config))
            
        except Exception:
            pass  # Already handled in syntax analysis
        
        # Pattern-based checks
        python_patterns = {
            "print_statement": {
                "pattern": re.compile(r'\bprint\s*\('),
                "severity": "low",
                "type": "best_practice",
                "title": "Print Statement Found",
                "description": "Consider using logging instead of print statements",
                "suggestion": "Use logging.info(), logging.debug(), etc. instead of print()"
            },
            "bare_except": {
                "pattern": re.compile(r'except\s*:'),
                "severity": "medium",
                "type": "best_practice",
                "title": "Bare Except Clause",
                "description": "Bare except clauses can hide errors",
                "suggestion": "Specify exception types: except SpecificException:"
            },
            "mutable_default": {
                "pattern": re.compile(r'def\s+\w+\([^)]*=\s*\[\s*\]'),
                "severity": "high",
                "type": "bug",
                "title": "Mutable Default Argument",
                "description": "Mutable default arguments can cause unexpected behavior",
                "suggestion": "Use None as default and initialize inside function"
            }
        }
        
        issues.extend(self._find_pattern_issues(file_path, content, python_patterns))
        
        return issues
    
    def _check_imports(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check import statements."""
        issues = []
        
        if not config.rules.get('check_imports', True):
            return issues
        
        lines = content.splitlines()
        import_lines = []
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                import_lines.append((line_num, stripped))
        
        # Check for imports not at top of file
        first_non_import_line = None
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if (stripped and 
                not stripped.startswith('#') and 
                not stripped.startswith('"""') and 
                not stripped.startswith("'''") and
                not stripped.startswith('import ') and
                not stripped.startswith('from ') and
                not stripped.startswith('__')):
                first_non_import_line = line_num
                break
        
        if first_non_import_line:
            for line_num, import_stmt in import_lines:
                if line_num > first_non_import_line:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=1,
                        severity=Severity.LOW,
                        issue_type=IssueType.CODE_STYLE,
                        rule_id="import_not_at_top",
                        title="Import Not at Top",
                        description="Import statements should be at the top of the file",
                        suggestion="Move import statements to the top of the file",
                        code_snippet=import_stmt
                    ))
        
        return issues
    
    def _check_indentation(self, file_path: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Check indentation consistency."""
        issues = []
        
        has_tabs = any('\t' in line for line in lines)
        has_spaces = any(line.startswith('    ') for line in lines)
        
        if has_tabs and has_spaces:
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.MEDIUM,
                issue_type=IssueType.CODE_STYLE,
                rule_id="mixed_indentation",
                title="Mixed Indentation",
                description="File contains both tabs and spaces for indentation",
                suggestion="Use consistent indentation (preferably 4 spaces per PEP 8)"
            ))
        
        return issues
    
    def _check_spacing(self, file_path: str, lines: List[str], config: AnalyzerConfig) -> List[Issue]:
        """Check spacing around operators."""
        issues = []
        
        # Check for missing spaces around operators
        operator_patterns = [
            (re.compile(r'\w+=[^=]'), "Missing space before ="),
            (re.compile(r'=[^=]\w'), "Missing space after ="),
            (re.compile(r'\w+\+[^=]'), "Missing space before +"),
            (re.compile(r'\+[^=]\w'), "Missing space after +"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in operator_patterns:
                if pattern.search(line):
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=1,
                        severity=Severity.LOW,
                        issue_type=IssueType.CODE_STYLE,
                        rule_id="spacing_around_operators",
                        title="Spacing Around Operators",
                        description=message,
                        suggestion="Add spaces around operators per PEP 8",
                        code_snippet=line.strip()
                    ))
        
        return issues
    
    def _check_docstrings(self, file_path: str, tree: ast.AST, config: AnalyzerConfig) -> List[Issue]:
        """Check for missing docstrings."""
        issues = []
        
        if not config.rules.get('check_docstrings', True):
            return issues
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                # Skip private methods and short functions
                if (node.name.startswith('_') and not node.name.startswith('__')) or \
                   (isinstance(node, ast.FunctionDef) and len(node.body) < 3):
                    continue
                
                # Check if function/class has docstring
                has_docstring = (
                    node.body and
                    isinstance(node.body[0], ast.Expr) and
                    isinstance(node.body[0].value, ast.Constant) and
                    isinstance(node.body[0].value.value, str)
                )
                
                if not has_docstring:
                    entity_type = "Function" if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else "Class"
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset + 1,
                        severity=Severity.LOW,
                        issue_type=IssueType.BEST_PRACTICE,
                        rule_id="missing_docstring",
                        title=f"Missing {entity_type} Docstring",
                        description=f"{entity_type} '{node.name}' is missing a docstring",
                        suggestion=f"Add a docstring explaining what this {entity_type.lower()} does"
                    ))
        
        return issues
    
    def _check_type_hints(self, file_path: str, tree: ast.AST, config: AnalyzerConfig) -> List[Issue]:
        """Check for missing type hints."""
        issues = []
        
        if not config.rules.get('check_type_hints', True):
            return issues
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Skip private methods and simple functions
                if node.name.startswith('_') or len(node.body) < 2:
                    continue
                
                # Check for missing return type annotation
                if node.returns is None and node.name != '__init__':
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset + 1,
                        severity=Severity.LOW,
                        issue_type=IssueType.BEST_PRACTICE,
                        rule_id="missing_return_type",
                        title="Missing Return Type Hint",
                        description=f"Function '{node.name}' is missing return type annotation",
                        suggestion="Add return type annotation: def func() -> ReturnType:"
                    ))
                
                # Check for missing parameter type annotations
                for arg in node.args.args:
                    if arg.annotation is None and arg.arg != 'self':
                        issues.append(Issue(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset + 1,
                            severity=Severity.LOW,
                            issue_type=IssueType.BEST_PRACTICE,
                            rule_id="missing_parameter_type",
                            title="Missing Parameter Type Hint",
                            description=f"Parameter '{arg.arg}' in function '{node.name}' is missing type annotation",
                            suggestion=f"Add type annotation: {arg.arg}: SomeType"
                        ))
        
        return issues
    
    def _check_exception_handling(self, file_path: str, tree: ast.AST, config: AnalyzerConfig) -> List[Issue]:
        """Check exception handling patterns."""
        issues = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                # Check for bare except
                if node.type is None:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset + 1,
                        severity=Severity.MEDIUM,
                        issue_type=IssueType.BEST_PRACTICE,
                        rule_id="bare_except",
                        title="Bare Except Clause",
                        description="Bare except clauses can hide important errors",
                        suggestion="Specify exception types: except SpecificException:"
                    ))
                
                # Check for catching Exception
                elif (isinstance(node.type, ast.Name) and node.type.id == 'Exception'):
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset + 1,
                        severity=Severity.LOW,
                        issue_type=IssueType.BEST_PRACTICE,
                        rule_id="broad_except",
                        title="Broad Exception Clause",
                        description="Catching Exception is too broad",
                        suggestion="Catch specific exception types instead of Exception"
                    ))
        
        return issues
    
    def _check_unused_imports(self, file_path: str, tree: ast.AST, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for unused imports (basic implementation)."""
        issues = []
        
        # Extract imported names
        imported_names = set()
        import_nodes = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                import_nodes.append(node)
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name.split('.')[0]
                    imported_names.add(name)
            elif isinstance(node, ast.ImportFrom):
                import_nodes.append(node)
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    imported_names.add(name)
        
        # Check which imports are used
        for import_node in import_nodes:
            if isinstance(import_node, ast.Import):
                for alias in import_node.names:
                    name = alias.asname if alias.asname else alias.name.split('.')[0]
                    if not self._is_name_used(name, tree, import_node):
                        issues.append(Issue(
                            file_path=file_path,
                            line_number=import_node.lineno,
                            column=import_node.col_offset + 1,
                            severity=Severity.LOW,
                            issue_type=IssueType.BEST_PRACTICE,
                            rule_id="unused_import",
                            title="Unused Import",
                            description=f"Import '{alias.name}' is unused",
                            suggestion="Remove unused import"
                        ))
        
        return issues
    
    def _is_name_used(self, name: str, tree: ast.AST, import_node: ast.AST) -> bool:
        """Check if an imported name is used in the code."""
        for node in ast.walk(tree):
            if node is import_node:
                continue
            if isinstance(node, ast.Name) and node.id == name:
                return True
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == name:
                return True
        return False
    
    def _check_dangerous_patterns(self, file_path: str, tree: ast.AST, config: AnalyzerConfig) -> List[Issue]:
        """Check for dangerous coding patterns."""
        issues = []
        
        for node in ast.walk(tree):
            # Check for eval/exec usage
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ['eval', 'exec']:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset + 1,
                        severity=Severity.HIGH,
                        issue_type=IssueType.SECURITY,
                        rule_id="dangerous_eval",
                        title="Dangerous eval/exec Usage",
                        description=f"Usage of {node.func.id}() can be dangerous",
                        suggestion="Avoid eval/exec or ensure input is sanitized"
                    ))
            
            # Check for assert statements in production code
            elif isinstance(node, ast.Assert):
                issues.append(Issue(
                    file_path=file_path,
                    line_number=node.lineno,
                    column=node.col_offset + 1,
                    severity=Severity.LOW,
                    issue_type=IssueType.BEST_PRACTICE,
                    rule_id="assert_usage",
                    title="Assert Statement Usage",
                    description="Assert statements are disabled when Python is run with -O",
                    suggestion="Use proper error checking instead of assert"
                ))
        
        return issues
    
    def _calculate_function_complexity(self, func_node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity of a function."""
        complexity = 1  # Base complexity
        
        for node in ast.walk(func_node):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1
            elif isinstance(node, ast.With):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
        
        return complexity
    
    def _calculate_nesting_depth(self, node: ast.AST) -> int:
        """Calculate nesting depth of a code block."""
        max_depth = 1
        
        for child in ast.walk(node):
            if child != node and isinstance(child, (ast.If, ast.For, ast.While, ast.With)):
                child_depth = 1 + self._calculate_nesting_depth(child)
                max_depth = max(max_depth, child_depth)
        
        return max_depth
    
    def _check_line_endings(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for consistent line endings."""
        issues = []
        
        # Count different line ending types
        crlf_count = content.count('\r\n')
        lf_count = content.count('\n') - crlf_count
        cr_count = content.count('\r') - crlf_count
        
        if sum(bool(x) for x in [crlf_count, lf_count, cr_count]) > 1:
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.LOW,
                issue_type=IssueType.CODE_STYLE,
                rule_id="inconsistent_line_endings",
                title="Inconsistent Line Endings",
                description="File contains mixed line ending types",
                suggestion="Use consistent line endings (preferably LF on Unix systems)"
            ))
        
        return issues