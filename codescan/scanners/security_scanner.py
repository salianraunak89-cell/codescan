"""Security vulnerability scanner."""

import re
import hashlib
import base64
from typing import List, Dict, Any, Set
from pathlib import Path

from ..core.result import Issue, Severity, IssueType
from ..core.config import AnalyzerConfig


class SecurityScanner:
    """Scanner for security vulnerabilities and issues."""
    
    def __init__(self):
        """Initialize the security scanner."""
        self.crypto_patterns = self._init_crypto_patterns()
        self.injection_patterns = self._init_injection_patterns()
        self.authentication_patterns = self._init_authentication_patterns()
        self.file_security_patterns = self._init_file_security_patterns()
        self.hardcoded_secrets_patterns = self._init_hardcoded_secrets_patterns()
    
    def scan_file(self, file_path: str, language: str, config: AnalyzerConfig) -> List[Issue]:
        """
        Scan a file for security vulnerabilities.
        
        Args:
            file_path: Path to file to scan
            language: Programming language
            config: Analyzer configuration
            
        Returns:
            List of security issues found
        """
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Run security checks
            issues.extend(self._check_hardcoded_secrets(file_path, content, config))
            issues.extend(self._check_crypto_issues(file_path, content, language, config))
            issues.extend(self._check_injection_vulnerabilities(file_path, content, language, config))
            issues.extend(self._check_authentication_issues(file_path, content, language, config))
            issues.extend(self._check_file_security(file_path, content, language, config))
            issues.extend(self._check_xss_vulnerabilities(file_path, content, language, config))
            issues.extend(self._check_path_traversal(file_path, content, language, config))
            issues.extend(self._check_deserialization_issues(file_path, content, language, config))
            
        except Exception as e:
            # Create an issue for scan failure
            issues.append(Issue(
                file_path=file_path,
                line_number=1,
                column=1,
                severity=Severity.LOW,
                issue_type=IssueType.BUG,
                rule_id="security_scan_error",
                title="Security Scan Error",
                description=f"Failed to scan file for security issues: {str(e)}",
                suggestion="Check file accessibility and format"
            ))
        
        return issues
    
    def _init_crypto_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize cryptography-related patterns."""
        return {
            "weak_hash_md5": {
                "pattern": re.compile(r'\b(?:md5|MD5)\s*\('),
                "severity": "high",
                "cwe": "CWE-327",
                "title": "Weak Hash Algorithm (MD5)",
                "description": "MD5 is cryptographically broken and should not be used",
                "suggestion": "Use SHA-256 or stronger hash algorithms"
            },
            "weak_hash_sha1": {
                "pattern": re.compile(r'\b(?:sha1|SHA1)\s*\('),
                "severity": "medium",
                "cwe": "CWE-327",
                "title": "Weak Hash Algorithm (SHA-1)",
                "description": "SHA-1 is deprecated and should not be used for security purposes",
                "suggestion": "Use SHA-256 or stronger hash algorithms"
            },
            "hardcoded_crypto_key": {
                "pattern": re.compile(r'(?:key|password|secret)\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']'),
                "severity": "critical",
                "cwe": "CWE-798",
                "title": "Hardcoded Cryptographic Key",
                "description": "Cryptographic keys should not be hardcoded in source code",
                "suggestion": "Use environment variables or secure key management"
            },
            "weak_random": {
                "pattern": re.compile(r'\b(?:random\.random|Math\.random|rand\(\))\b'),
                "severity": "medium",
                "cwe": "CWE-338",
                "title": "Weak Random Number Generator",
                "description": "Standard random functions are not cryptographically secure",
                "suggestion": "Use cryptographically secure random number generators"
            },
            "des_encryption": {
                "pattern": re.compile(r'\b(?:DES|3DES|TripleDES)\b'),
                "severity": "high",
                "cwe": "CWE-327",
                "title": "Weak Encryption Algorithm",
                "description": "DES and 3DES are weak encryption algorithms",
                "suggestion": "Use AES or other modern encryption algorithms"
            }
        }
    
    def _init_injection_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize injection vulnerability patterns."""
        return {
            "sql_injection": {
                "pattern": re.compile(r'(?:SELECT|INSERT|UPDATE|DELETE).*\+.*(?:request|input|param)', re.IGNORECASE),
                "severity": "critical",
                "cwe": "CWE-89",
                "title": "Potential SQL Injection",
                "description": "String concatenation in SQL queries can lead to SQL injection",
                "suggestion": "Use parameterized queries or prepared statements"
            },
            "command_injection": {
                "pattern": re.compile(r'(?:system|exec|eval|popen|subprocess)\s*\([^)]*(?:request|input|param|argv)', re.IGNORECASE),
                "severity": "critical",
                "cwe": "CWE-78",
                "title": "Potential Command Injection",
                "description": "Executing user input as system commands can lead to command injection",
                "suggestion": "Validate and sanitize input, avoid dynamic command execution"
            },
            "ldap_injection": {
                "pattern": re.compile(r'ldap.*search.*\+.*(?:request|input|param)', re.IGNORECASE),
                "severity": "high",
                "cwe": "CWE-90",
                "title": "Potential LDAP Injection",
                "description": "String concatenation in LDAP queries can lead to LDAP injection",
                "suggestion": "Use parameterized LDAP queries and input validation"
            },
            "xpath_injection": {
                "pattern": re.compile(r'xpath.*\+.*(?:request|input|param)', re.IGNORECASE),
                "severity": "high",
                "cwe": "CWE-91",
                "title": "Potential XPath Injection",
                "description": "String concatenation in XPath expressions can lead to XPath injection",
                "suggestion": "Use parameterized XPath queries and input validation"
            }
        }
    
    def _init_authentication_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize authentication-related patterns."""
        return {
            "weak_password_policy": {
                "pattern": re.compile(r'password.*length.*[<<=]\s*[1-6]\b'),
                "severity": "medium",
                "cwe": "CWE-521",
                "title": "Weak Password Policy",
                "description": "Password length requirement is too weak",
                "suggestion": "Require passwords of at least 8-12 characters"
            },
            "password_in_url": {
                "pattern": re.compile(r'https?://[^:]*:[^@]*@'),
                "severity": "high",
                "cwe": "CWE-598",
                "title": "Password in URL",
                "description": "Credentials in URLs can be logged and exposed",
                "suggestion": "Use proper authentication headers instead"
            },
            "insecure_session": {
                "pattern": re.compile(r'session.*(?:secure\s*=\s*false|httponly\s*=\s*false)', re.IGNORECASE),
                "severity": "medium",
                "cwe": "CWE-614",
                "title": "Insecure Session Configuration",
                "description": "Session cookies should be secure and httponly",
                "suggestion": "Set secure and httponly flags for session cookies"
            }
        }
    
    def _init_file_security_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize file security patterns."""
        return {
            "path_traversal": {
                "pattern": re.compile(r'\.\.[\\/]'),
                "severity": "high",
                "cwe": "CWE-22",
                "title": "Path Traversal Pattern",
                "description": "Directory traversal patterns detected",
                "suggestion": "Validate and sanitize file paths"
            },
            "file_upload_no_validation": {
                "pattern": re.compile(r'upload.*file.*without.*validation', re.IGNORECASE),
                "severity": "high",
                "cwe": "CWE-434",
                "title": "Unrestricted File Upload",
                "description": "File uploads without proper validation",
                "suggestion": "Validate file types, sizes, and content"
            },
            "temp_file_creation": {
                "pattern": re.compile(r'(?:mktemp|tempfile|NamedTemporaryFile).*mode.*[0-7]*[2367]'),
                "severity": "medium",
                "cwe": "CWE-377",
                "title": "Insecure Temporary File",
                "description": "Temporary files created with overly permissive permissions",
                "suggestion": "Create temporary files with restrictive permissions"
            }
        }
    
    def _init_hardcoded_secrets_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize patterns for detecting hardcoded secrets."""
        return {
            "api_key": {
                "pattern": re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']', re.IGNORECASE),
                "severity": "critical",
                "cwe": "CWE-798",
                "title": "Hardcoded API Key",
                "description": "API key found hardcoded in source code",
                "suggestion": "Use environment variables or secure configuration"
            },
            "password": {
                "pattern": re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
                "severity": "critical",
                "cwe": "CWE-798",
                "title": "Hardcoded Password",
                "description": "Password found hardcoded in source code",
                "suggestion": "Use environment variables or secure configuration"
            },
            "private_key": {
                "pattern": re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
                "severity": "critical",
                "cwe": "CWE-798",
                "title": "Hardcoded Private Key",
                "description": "Private key found in source code",
                "suggestion": "Remove private key and use secure key management"
            },
            "jwt_secret": {
                "pattern": re.compile(r'(?:jwt[_-]?secret|jwt[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9_-]{32,}["\']', re.IGNORECASE),
                "severity": "critical",
                "cwe": "CWE-798",
                "title": "Hardcoded JWT Secret",
                "description": "JWT secret found hardcoded in source code",
                "suggestion": "Use environment variables for JWT secrets"
            },
            "database_url": {
                "pattern": re.compile(r'(?:mongodb|mysql|postgresql|postgres)://[^:]*:[^@]*@'),
                "severity": "high",
                "cwe": "CWE-798",
                "title": "Database Credentials in URL",
                "description": "Database credentials found in connection string",
                "suggestion": "Use environment variables for database credentials"
            }
        }
    
    def _check_hardcoded_secrets(self, file_path: str, content: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for hardcoded secrets and credentials."""
        issues = []
        
        if not config.rules.get('check_hardcoded_secrets', True):
            return issues
        
        lines = content.splitlines()
        
        for rule_id, pattern_info in self.hardcoded_secrets_patterns.items():
            pattern = pattern_info['pattern']
            
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=Severity(pattern_info['severity']),
                        issue_type=IssueType.SECURITY,
                        rule_id=f"hardcoded_secret_{rule_id}",
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        suggestion=pattern_info['suggestion'],
                        cwe_id=pattern_info['cwe'],
                        code_snippet=line.strip(),
                        confidence=0.8
                    ))
        
        return issues
    
    def _check_crypto_issues(self, file_path: str, content: str, language: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for cryptographic issues."""
        issues = []
        
        if not config.rules.get('check_weak_crypto', True):
            return issues
        
        lines = content.splitlines()
        
        for rule_id, pattern_info in self.crypto_patterns.items():
            pattern = pattern_info['pattern']
            
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=Severity(pattern_info['severity']),
                        issue_type=IssueType.SECURITY,
                        rule_id=f"crypto_{rule_id}",
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        suggestion=pattern_info['suggestion'],
                        cwe_id=pattern_info['cwe'],
                        code_snippet=line.strip(),
                        confidence=0.7
                    ))
        
        return issues
    
    def _check_injection_vulnerabilities(self, file_path: str, content: str, language: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for injection vulnerabilities."""
        issues = []
        
        if not config.rules.get('check_sql_injection', True):
            return issues
        
        lines = content.splitlines()
        
        for rule_id, pattern_info in self.injection_patterns.items():
            pattern = pattern_info['pattern']
            
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=Severity(pattern_info['severity']),
                        issue_type=IssueType.VULNERABILITY,
                        rule_id=f"injection_{rule_id}",
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        suggestion=pattern_info['suggestion'],
                        cwe_id=pattern_info['cwe'],
                        code_snippet=line.strip(),
                        confidence=0.6
                    ))
        
        return issues
    
    def _check_authentication_issues(self, file_path: str, content: str, language: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for authentication and authorization issues."""
        issues = []
        
        lines = content.splitlines()
        
        for rule_id, pattern_info in self.authentication_patterns.items():
            pattern = pattern_info['pattern']
            
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=Severity(pattern_info['severity']),
                        issue_type=IssueType.SECURITY,
                        rule_id=f"auth_{rule_id}",
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        suggestion=pattern_info['suggestion'],
                        cwe_id=pattern_info['cwe'],
                        code_snippet=line.strip(),
                        confidence=0.7
                    ))
        
        return issues
    
    def _check_file_security(self, file_path: str, content: str, language: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for file security issues."""
        issues = []
        
        if not config.rules.get('check_path_traversal', True):
            return issues
        
        lines = content.splitlines()
        
        for rule_id, pattern_info in self.file_security_patterns.items():
            pattern = pattern_info['pattern']
            
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=Severity(pattern_info['severity']),
                        issue_type=IssueType.SECURITY,
                        rule_id=f"file_{rule_id}",
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        suggestion=pattern_info['suggestion'],
                        cwe_id=pattern_info['cwe'],
                        code_snippet=line.strip(),
                        confidence=0.6
                    ))
        
        return issues
    
    def _check_xss_vulnerabilities(self, file_path: str, content: str, language: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for XSS vulnerabilities."""
        issues = []
        
        if not config.rules.get('check_xss', True):
            return issues
        
        xss_patterns = [
            (re.compile(r'innerHTML\s*=.*(?:request|input|param)', re.IGNORECASE), "DOM-based XSS via innerHTML"),
            (re.compile(r'document\.write\s*\(.*(?:request|input|param)', re.IGNORECASE), "DOM-based XSS via document.write"),
            (re.compile(r'eval\s*\(.*(?:request|input|param)', re.IGNORECASE), "Code injection via eval"),
        ]
        
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in xss_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=Severity.HIGH,
                        issue_type=IssueType.VULNERABILITY,
                        rule_id="xss_vulnerability",
                        title="Potential XSS Vulnerability",
                        description=description,
                        suggestion="Sanitize and escape user input before output",
                        cwe_id="CWE-79",
                        code_snippet=line.strip(),
                        confidence=0.7
                    ))
        
        return issues
    
    def _check_path_traversal(self, file_path: str, content: str, language: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for path traversal vulnerabilities."""
        issues = []
        
        if not config.rules.get('check_path_traversal', True):
            return issues
        
        # Language-specific file operations
        file_operations = {
            'python': [r'open\s*\(', r'file\s*\(', r'with\s+open'],
            'javascript': [r'fs\.readFile', r'fs\.writeFile', r'require\s*\('],
            'java': [r'new\s+File\s*\(', r'Files\.read', r'FileInputStream'],
            'php': [r'fopen\s*\(', r'file_get_contents', r'include', r'require'],
            'c': [r'fopen\s*\(', r'open\s*\('],
            'go': [r'os\.Open', r'ioutil\.ReadFile'],
        }
        
        patterns = file_operations.get(language, file_operations['python'])
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Check for directory traversal in file operations
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns):
                if '..' in line and ('/' in line or '\\' in line):
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=1,
                        severity=Severity.HIGH,
                        issue_type=IssueType.VULNERABILITY,
                        rule_id="path_traversal",
                        title="Potential Path Traversal",
                        description="File operation with potential directory traversal",
                        suggestion="Validate and sanitize file paths, use absolute paths",
                        cwe_id="CWE-22",
                        code_snippet=line.strip(),
                        confidence=0.6
                    ))
        
        return issues
    
    def _check_deserialization_issues(self, file_path: str, content: str, language: str, config: AnalyzerConfig) -> List[Issue]:
        """Check for unsafe deserialization."""
        issues = []
        
        deserialization_patterns = {
            'python': [r'pickle\.loads?', r'yaml\.load(?!\(.*Loader)', r'eval\s*\('],
            'java': [r'ObjectInputStream', r'readObject', r'XMLDecoder'],
            'javascript': [r'eval\s*\(', r'Function\s*\(', r'JSON\.parse.*(?:request|input)'],
            'php': [r'unserialize\s*\(', r'eval\s*\('],
        }
        
        patterns = deserialization_patterns.get(language, [])
        if not patterns:
            return issues
        
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    issues.append(Issue(
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=Severity.HIGH,
                        issue_type=IssueType.VULNERABILITY,
                        rule_id="unsafe_deserialization",
                        title="Unsafe Deserialization",
                        description="Potentially unsafe deserialization detected",
                        suggestion="Validate input before deserialization, use safe alternatives",
                        cwe_id="CWE-502",
                        code_snippet=line.strip(),
                        confidence=0.7
                    ))
        
        return issues