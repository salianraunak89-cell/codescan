#!/usr/bin/env python3
"""
CodeScan Live Analysis Test

This script demonstrates CodeScan analyzing real code with security
vulnerabilities and best practice violations.
"""

import sys
import os
import ast
import re
from datetime import datetime

sys.path.insert(0, '/workspace')

# Import core components
from codescan.core.result import Issue, Severity, IssueType, ScanResult, FileResult
from codescan.core.language_detector import LanguageDetector
from codescan.analyzers.python_analyzer import PythonAnalyzer
from codescan.core.config import Config, AnalyzerConfig

def analyze_sample_code():
    """Analyze the sample Python file and show results."""
    
    print("🔍 CodeScan Live Analysis Test")
    print("=" * 60)
    print()
    
    sample_file = "examples/sample_code.py"
    
    # Check if sample file exists
    if not os.path.exists(sample_file):
        print(f"❌ Sample file not found: {sample_file}")
        return
    
    print(f"📁 Analyzing: {sample_file}")
    print()
    
    # Detect language
    detector = LanguageDetector()
    language = detector.detect_language(sample_file)
    print(f"🌐 Language detected: {language}")
    
    # Read file content
    with open(sample_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.splitlines()
    print(f"📊 File stats: {len(lines)} lines, {len(content)} characters")
    print()
    
    # Create analyzer and config
    analyzer = PythonAnalyzer()
    config = AnalyzerConfig()
    
    # Run analysis
    print("🔍 Running analysis...")
    issues = analyzer.analyze(sample_file, config)
    
    print(f"✅ Analysis complete! Found {len(issues)} issues")
    print()
    
    # Group issues by severity
    severity_groups = {}
    for issue in issues:
        sev = issue.severity.value
        if sev not in severity_groups:
            severity_groups[sev] = []
        severity_groups[sev].append(issue)
    
    # Display summary
    print("📈 Issues by Severity:")
    total_issues = 0
    for severity in ['critical', 'high', 'medium', 'low']:
        count = len(severity_groups.get(severity, []))
        if count > 0:
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}[severity]
            print(f"  {emoji} {severity.upper()}: {count} issues")
            total_issues += count
    print(f"  📊 TOTAL: {total_issues} issues")
    print()
    
    # Group by type
    type_groups = {}
    for issue in issues:
        itype = issue.issue_type.value
        type_groups[itype] = type_groups.get(itype, 0) + 1
    
    print("📋 Issues by Type:")
    for issue_type, count in sorted(type_groups.items()):
        print(f"  • {issue_type.replace('_', ' ').title()}: {count}")
    print()
    
    # Show detailed issues (first 15)
    print("🎯 Detailed Issues Found:")
    print("-" * 40)
    
    shown = 0
    for severity in ['critical', 'high', 'medium', 'low']:
        if severity not in severity_groups:
            continue
            
        for issue in severity_groups[severity]:
            if shown >= 15:  # Limit output
                break
                
            # Color coding
            severity_colors = {
                'critical': '🔴 CRITICAL',
                'high': '🟠 HIGH',
                'medium': '🟡 MEDIUM', 
                'low': '🟢 LOW'
            }
            
            print(f"\n{shown + 1}. [{severity_colors[issue.severity.value]}] {issue.title}")
            print(f"   📍 Line {issue.line_number}, Column {issue.column}")
            print(f"   🔍 Rule: {issue.rule_id}")
            print(f"   💬 {issue.description}")
            
            if issue.suggestion:
                print(f"   💡 Suggestion: {issue.suggestion}")
            
            if issue.code_snippet:
                print(f"   📝 Code: {issue.code_snippet}")
            
            if issue.cwe_id:
                print(f"   🔗 CWE: {issue.cwe_id}")
            
            shown += 1
        
        if shown >= 15:
            break
    
    if len(issues) > 15:
        print(f"\n... and {len(issues) - 15} more issues")
    
    # Show some specific security findings
    print("\n" + "=" * 60)
    print("🔒 Security Highlights")
    print("=" * 60)
    
    security_issues = [issue for issue in issues if issue.issue_type == IssueType.SECURITY]
    if security_issues:
        print(f"Found {len(security_issues)} security-related issues:")
        for issue in security_issues[:5]:  # Show first 5
            print(f"  🚨 {issue.title} (Line {issue.line_number})")
    else:
        print("✅ No security issues detected")
    
    # Show code quality highlights
    print("\n📊 Code Quality Highlights")
    print("-" * 30)
    
    complexity_issues = [issue for issue in issues if 'complex' in issue.rule_id.lower()]
    style_issues = [issue for issue in issues if issue.issue_type == IssueType.CODE_STYLE]
    
    print(f"• Complexity issues: {len(complexity_issues)}")
    print(f"• Style issues: {len(style_issues)}")
    print(f"• Best practice violations: {len([i for i in issues if i.issue_type == IssueType.BEST_PRACTICE])}")
    
    print("\n🎉 Analysis completed!")
    print(f"💡 CodeScan found {len(issues)} total issues to help improve your code")
    
    return issues

if __name__ == "__main__":
    try:
        issues = analyze_sample_code()
        
        print("\n" + "=" * 60)
        print("🚀 What CodeScan Can Do For You")
        print("=" * 60)
        print("✨ Multi-language support (Python, JS, Java, C++, Go, Rust, etc.)")
        print("🔒 Comprehensive security vulnerability detection") 
        print("📊 Code quality and best practices analysis")
        print("🎨 Consistent code style enforcement")
        print("📋 Multiple output formats (JSON, HTML, SARIF)")
        print("🔧 CI/CD pipeline integration")
        print("⚙️  Configurable rules and severity levels")
        print()
        print("To run with full functionality:")
        print("1. pip install -r requirements.txt")
        print("2. codescan scan examples/sample_code.py")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()