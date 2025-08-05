#!/usr/bin/env python3
"""Basic test of CodeScan core functionality without external dependencies."""

import sys
import os
sys.path.insert(0, '/workspace')

# Mock the missing dependencies
class MockChardet:
    @staticmethod
    def detect(content):
        return {'encoding': 'utf-8'}

class MockClick:
    def __init__(self):
        pass

class MockConsole:
    def print(self, *args, **kwargs):
        print(*args)
    
    def capture(self):
        return self
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass
    
    def get(self):
        return "Mock output"

# Patch modules
import builtins
original_import = builtins.__import__

def mock_import(name, *args, **kwargs):
    if name == 'chardet':
        return MockChardet()
    elif name == 'click':
        return MockClick()
    elif name == 'rich.console':
        class Module:
            Console = MockConsole
        return Module()
    elif name in ['jinja2', 'yaml', 'pathspec', 'rich', 'tomllib', 'tomli']:
        class Module:
            pass
        return Module()
    else:
        return original_import(name, *args, **kwargs)

builtins.__import__ = mock_import

try:
    # Test core components
    from codescan.core.result import Issue, Severity, IssueType, ScanResult, FileResult
    from codescan.core.language_detector import LanguageDetector
    
    print("🔍 CodeScan Basic Test")
    print("=" * 50)
    
    # Test language detection
    detector = LanguageDetector()
    language = detector.detect_language("test.py")
    print(f"✅ Language detection: {language}")
    
    # Test issue creation
    issue = Issue(
        file_path="test.py",
        line_number=10,
        column=5,
        severity=Severity.HIGH,
        issue_type=IssueType.SECURITY,
        rule_id="test_rule",
        title="Test Issue",
        description="This is a test issue",
        suggestion="Fix the issue"
    )
    print(f"✅ Issue creation: {issue.title}")
    
    # Test file result
    file_result = FileResult("test.py", "python")
    file_result.add_issue(issue)
    print(f"✅ File result: {len(file_result.issues)} issues")
    
    # Test scan result
    scan_result = ScanResult("/workspace", "2024-01-01T00:00:00")
    scan_result.add_file_result(file_result)
    summary = scan_result.get_summary_stats()
    print(f"✅ Scan result: {summary['total_issues']} total issues")
    
    # Test Python analyzer (basic functionality)
    from codescan.analyzers.python_analyzer import PythonAnalyzer
    analyzer = PythonAnalyzer()
    print(f"✅ Python analyzer: {analyzer._get_language()}")
    
    print("\n🎉 Basic functionality test completed successfully!")
    print("\nTo run full functionality:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Run: python -m codescan.cli scan examples/sample_code.py")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()