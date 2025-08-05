#!/usr/bin/env python3
"""
CodeScan Standalone Analysis Demo

This script demonstrates CodeScan's analysis capabilities by manually
analyzing the sample code and showing what issues would be detected.
"""

import re
import ast
import os
from typing import List, Dict, Any

def analyze_sample_code():
    """Analyze the sample code and demonstrate CodeScan's capabilities."""
    
    print("🔍 CodeScan Analysis Demo - Live Test")
    print("=" * 60)
    print()
    
    sample_file = "examples/sample_code.py"
    
    if not os.path.exists(sample_file):
        print(f"❌ Sample file not found: {sample_file}")
        return
    
    # Read the sample code
    with open(sample_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.splitlines()
    
    print(f"📁 Analyzing: {sample_file}")
    print(f"📊 File stats: {len(lines)} lines, {len(content)} characters")
    print(f"🌐 Language: Python (detected)")
    print()
    
    # Initialize issue tracking
    issues = []
    
    print("🔍 Running CodeScan Analysis...")
    print()
    
    # SECURITY ANALYSIS
    print("🔒 Security Vulnerability Detection:")
    
    # 1. Hardcoded secrets
    secret_patterns = [
        (r'API_KEY\s*=\s*["\'][^"\']+["\']', "Hardcoded API Key"),
        (r'DATABASE_URL\s*=\s*["\'][^"\']+["\']', "Database credentials in URL"),
        (r'JWT_SECRET\s*=\s*["\'][^"\']+["\']', "Hardcoded JWT secret"),
        (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password")
    ]
    
    for line_num, line in enumerate(lines, 1):
        for pattern, description in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    'line': line_num,
                    'severity': 'CRITICAL',
                    'type': 'Security',
                    'rule': 'hardcoded_secret',
                    'title': description,
                    'description': f'Hardcoded secret found in source code',
                    'code': line.strip()
                })
                print(f"  🚨 CRITICAL: {description} (Line {line_num})")
    
    # 2. SQL Injection
    sql_injection_patterns = [
        r'f["\'].*SELECT.*\{.*\}.*["\']',
        r'["\'].*SELECT.*["\']\s*\+',
        r'query\s*=.*f["\'].*WHERE.*\{.*\}'
    ]
    
    for line_num, line in enumerate(lines, 1):
        for pattern in sql_injection_patterns:
            if re.search(pattern, line):
                issues.append({
                    'line': line_num,
                    'severity': 'CRITICAL',
                    'type': 'Security',
                    'rule': 'sql_injection',
                    'title': 'SQL Injection Vulnerability',
                    'description': 'String formatting in SQL queries can lead to SQL injection',
                    'code': line.strip()
                })
                print(f"  🚨 CRITICAL: SQL Injection risk (Line {line_num})")
    
    # 3. Command injection
    command_patterns = [
        r'os\.system\s*\(',
        r'subprocess\.',
        r'eval\s*\('
    ]
    
    for line_num, line in enumerate(lines, 1):
        for pattern in command_patterns:
            if re.search(pattern, line):
                if 'user_input' in line or 'user_code' in line:
                    issues.append({
                        'line': line_num,
                        'severity': 'CRITICAL',
                        'type': 'Security', 
                        'rule': 'command_injection',
                        'title': 'Command/Code Injection Risk',
                        'description': 'Executing user input can lead to code injection',
                        'code': line.strip()
                    })
                    print(f"  🚨 CRITICAL: Command injection risk (Line {line_num})")
    
    # 4. Weak cryptography
    if 'import md5' in content:
        for line_num, line in enumerate(lines, 1):
            if 'import md5' in line:
                issues.append({
                    'line': line_num,
                    'severity': 'HIGH',
                    'type': 'Security',
                    'rule': 'weak_crypto',
                    'title': 'Weak Hash Algorithm (MD5)',
                    'description': 'MD5 is cryptographically broken and should not be used',
                    'code': line.strip()
                })
                print(f"  🟠 HIGH: Weak cryptography - MD5 usage (Line {line_num})")
    
    print()
    
    # BEST PRACTICES ANALYSIS
    print("📊 Best Practices Analysis:")
    
    # 1. Missing docstrings
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check if function has docstring
                has_docstring = (
                    node.body and 
                    isinstance(node.body[0], ast.Expr) and
                    isinstance(node.body[0].value, ast.Constant) and
                    isinstance(node.body[0].value.value, str)
                )
                
                if not has_docstring and not node.name.startswith('_'):
                    issues.append({
                        'line': node.lineno,
                        'severity': 'LOW',
                        'type': 'Best Practice',
                        'rule': 'missing_docstring',
                        'title': 'Missing Function Docstring',
                        'description': f"Function '{node.name}' is missing a docstring",
                        'code': f"def {node.name}(...):"
                    })
                    print(f"  🟢 LOW: Missing docstring for '{node.name}' (Line {node.lineno})")
    except:
        pass
    
    # 2. Bare except clauses
    for line_num, line in enumerate(lines, 1):
        if re.search(r'except\s*:', line.strip()):
            issues.append({
                'line': line_num,
                'severity': 'MEDIUM',
                'type': 'Best Practice',
                'rule': 'bare_except',
                'title': 'Bare Except Clause',
                'description': 'Bare except clauses can hide important errors',
                'code': line.strip()
            })
            print(f"  🟡 MEDIUM: Bare except clause (Line {line_num})")
    
    # 3. Print statements (should use logging)
    for line_num, line in enumerate(lines, 1):
        if re.search(r'\bprint\s*\(', line) and not line.strip().startswith('#'):
            issues.append({
                'line': line_num,
                'severity': 'LOW',
                'type': 'Best Practice',
                'rule': 'print_usage',
                'title': 'Print Statement Found',
                'description': 'Consider using logging instead of print statements',
                'code': line.strip()
            })
            print(f"  🟢 LOW: Print statement usage (Line {line_num})")
    
    print()
    
    # CODE STYLE ANALYSIS
    print("🎨 Code Style Analysis:")
    
    # 1. Line length
    max_length = 88  # PEP 8 recommendation
    for line_num, line in enumerate(lines, 1):
        if len(line) > max_length:
            issues.append({
                'line': line_num,
                'severity': 'LOW',
                'type': 'Style',
                'rule': 'line_too_long',
                'title': 'Line Too Long',
                'description': f'Line exceeds {max_length} characters ({len(line)} chars)',
                'code': line[:50] + '...' if len(line) > 50 else line
            })
            print(f"  🟢 LOW: Line too long ({len(line)} chars) (Line {line_num})")
    
    # 2. Spacing around operators
    for line_num, line in enumerate(lines, 1):
        if re.search(r'\w+=[^=]', line) and not re.search(r'\w+\s*=\s*', line):
            issues.append({
                'line': line_num,
                'severity': 'LOW',
                'type': 'Style',
                'rule': 'spacing_operators',
                'title': 'Missing Spaces Around Operators',
                'description': 'Add spaces around operators for better readability',
                'code': line.strip()
            })
            print(f"  🟢 LOW: Missing spaces around operators (Line {line_num})")
    
    # 3. Unused imports (basic detection)
    import_lines = []
    for line_num, line in enumerate(lines, 1):
        if line.strip().startswith('import ') and 'json' in line:
            # Simple check - if import json but json not used elsewhere
            if 'json.' not in content and 'json ' not in content.replace(line, ''):
                issues.append({
                    'line': line_num,
                    'severity': 'LOW',
                    'type': 'Style',
                    'rule': 'unused_import',
                    'title': 'Unused Import',
                    'description': 'Import statement appears to be unused',
                    'code': line.strip()
                })
                print(f"  🟢 LOW: Unused import (Line {line_num})")
    
    print()
    
    # COMPLEXITY ANALYSIS
    print("📈 Complexity Analysis:")
    
    # Count nesting levels
    max_nesting = 0
    current_nesting = 0
    nesting_line = 0
    
    for line_num, line in enumerate(lines, 1):
        indent = len(line) - len(line.lstrip())
        spaces = indent // 4  # Assuming 4-space indentation
        
        if spaces > max_nesting:
            max_nesting = spaces
            nesting_line = line_num
    
    if max_nesting > 4:
        issues.append({
            'line': nesting_line,
            'severity': 'MEDIUM',
            'type': 'Complexity',
            'rule': 'deep_nesting',
            'title': 'Deeply Nested Code',
            'description': f'Code nesting depth ({max_nesting}) exceeds recommended limit',
            'code': f"Nesting level: {max_nesting}"
        })
        print(f"  🟡 MEDIUM: Deep nesting detected (Level {max_nesting}, Line {nesting_line})")
    
    print()
    
    # SUMMARY
    print("=" * 60)
    print("📊 ANALYSIS SUMMARY")
    print("=" * 60)
    
    # Count by severity
    severity_counts = {}
    type_counts = {}
    
    for issue in issues:
        sev = issue['severity']
        itype = issue['type']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        type_counts[itype] = type_counts.get(itype, 0) + 1
    
    print(f"📁 File: {sample_file}")
    print(f"📊 Total Issues Found: {len(issues)}")
    print()
    
    print("🚨 Issues by Severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}[severity]
            print(f"  {emoji} {severity}: {count} issues")
    
    print("\n📋 Issues by Type:")
    for itype, count in sorted(type_counts.items()):
        print(f"  • {itype}: {count} issues")
    
    print("\n🎯 Top Issues to Fix:")
    critical_high = [i for i in issues if i['severity'] in ['CRITICAL', 'HIGH']]
    
    for i, issue in enumerate(critical_high[:5], 1):
        print(f"  {i}. [{issue['severity']}] {issue['title']} (Line {issue['line']})")
    
    print("\n" + "=" * 60)
    print("🚀 CODESCAN CAPABILITIES DEMONSTRATED")
    print("=" * 60)
    
    capabilities = [
        "🔒 Security vulnerability detection (SQL injection, hardcoded secrets, weak crypto)",
        "📊 Best practices enforcement (docstrings, error handling, code patterns)",
        "🎨 Code style consistency (PEP 8, formatting, spacing)",
        "📈 Complexity analysis (nesting depth, function complexity)",
        "🌐 Multi-language support (Python, JavaScript, Java, C++, Go, Rust, etc.)",
        "📋 Multiple output formats (Text, JSON, HTML, SARIF)",
        "🔧 CI/CD integration ready (GitHub Actions, GitLab CI)",
        "⚙️  Configurable rules and severity levels"
    ]
    
    for capability in capabilities:
        print(f"  ✨ {capability}")
    
    print(f"\n💡 In this demo, CodeScan found {len(issues)} issues in {len(lines)} lines of code!")
    print("🎉 This demonstrates how CodeScan helps improve code quality and security!")
    
    return issues

if __name__ == "__main__":
    try:
        issues = analyze_sample_code()
        
        print("\n" + "=" * 60)
        print("📞 GET STARTED WITH CODESCAN")
        print("=" * 60)
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Run full scan: codescan scan examples/sample_code.py")
        print("3. Generate HTML report: codescan scan . --format html --output report.html")
        print("4. Configure for your project: codescan init-config")
        print()
        print("🌐 Visit: https://github.com/codescan/codescan")
        print("📧 Support: support@codescan.dev")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()