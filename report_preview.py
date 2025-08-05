#!/usr/bin/env python3
"""
CodeScan HTML Report Preview

This script shows what the HTML report would look like when viewed in a browser,
presenting the visual layout and key information in a readable format.
"""

def show_report_preview():
    """Display a visual preview of the HTML report."""
    
    print("🌐 CodeScan HTML Report - Browser Preview")
    print("=" * 80)
    print()
    
    # Header Section
    print("┌" + "─" * 78 + "┐")
    print("│" + " " * 78 + "│")
    print("│" + "🔍 CodeScan Analysis Report".center(78) + "│")
    print("│" + "Comprehensive code analysis for examples/sample_code.py".center(78) + "│")
    print("│" + f"Generated on December 31, 2024 at 2:47 PM".center(78) + "│")
    print("│" + " " * 78 + "│")
    print("└" + "─" * 78 + "┘")
    print()
    
    # Summary Cards Section
    print("📊 ANALYSIS SUMMARY")
    print("─" * 50)
    print()
    
    summary_data = [
        ("File Analyzed", "examples/sample_code.py"),
        ("Lines of Code", "169"),
        ("Total Issues", "30"),
        ("Analysis Time", "< 2s")
    ]
    
    # Display summary in 2x2 grid format
    print("┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐")
    print("│ File Analyzed   │ Lines of Code   │ Total Issues    │ Analysis Time   │")
    print("├─────────────────┼─────────────────┼─────────────────┼─────────────────┤")
    print("│ examples/       │       169       │       30        │      < 2s       │")
    print("│ sample_code.py  │                 │                 │                 │")
    print("└─────────────────┴─────────────────┴─────────────────┴─────────────────┘")
    print()
    
    # Severity Distribution Chart
    print("📈 ISSUES BY SEVERITY DISTRIBUTION")
    print("─" * 50)
    print()
    
    # ASCII Progress Bar
    total_issues = 30
    critical = 6
    high = 1
    medium = 2
    low = 21
    
    bar_width = 60
    critical_width = int((critical / total_issues) * bar_width)
    high_width = int((high / total_issues) * bar_width)
    medium_width = int((medium / total_issues) * bar_width)
    low_width = bar_width - critical_width - high_width - medium_width
    
    print("Progress Bar:")
    print("┌" + "─" * bar_width + "┐")
    print("│" + "█" * critical_width + "▓" * high_width + "▒" * medium_width + "░" * low_width + "│")
    print("└" + "─" * bar_width + "┘")
    print()
    
    print("Legend:")
    print("  ██ Critical (6)    ▓▓ High (1)    ▒▒ Medium (2)    ░░ Low (21)")
    print()
    
    # Severity Cards
    print("🚨 SEVERITY BREAKDOWN")
    print("─" * 50)
    print()
    
    print("┌─────────────┬─────────────┬─────────────┬─────────────┐")
    print("│   🔴 CRITICAL   │   🟠 HIGH   │   🟡 MEDIUM   │   🟢 LOW   │")
    print("│       6     │      1      │      2      │     21     │")
    print("│   Issues    │   Issues    │   Issues    │   Issues   │")
    print("└─────────────┴─────────────┴─────────────┴─────────────┘")
    print()
    
    # Critical Issues Section
    print("🚨 CRITICAL & HIGH PRIORITY ISSUES")
    print("=" * 80)
    print()
    
    critical_issues = [
        {
            "severity": "CRITICAL",
            "title": "Hardcoded API Key",
            "line": 15,
            "description": "API key exposed in source code can lead to unauthorized access",
            "code": 'API_KEY = "sk-1234567890abcdef"',
            "suggestion": "Store in environment variables: API_KEY = os.getenv('API_KEY')",
            "cwe": "CWE-798"
        },
        {
            "severity": "CRITICAL",
            "title": "Database Credentials in URL", 
            "line": 16,
            "description": "Database credentials exposed, potential data breach",
            "code": 'DATABASE_URL = "postgresql://user:password123@localhost/db"',
            "suggestion": "Use environment variables for database connection strings",
            "cwe": "CWE-798"
        },
        {
            "severity": "CRITICAL",
            "title": "SQL Injection Vulnerability",
            "line": 24,
            "description": "String formatting in SQL queries can lead to SQL injection",
            "code": 'query = f"SELECT * FROM users WHERE id = {user_id}..."',
            "suggestion": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            "cwe": "CWE-89"
        }
    ]
    
    for i, issue in enumerate(critical_issues, 1):
        print(f"Issue #{i}")
        print("┌" + "─" * 78 + "┐")
        print(f"│ 🔴 {issue['severity']} │ {issue['title']:<45} │ Line {issue['line']:<6} │")
        print("├" + "─" * 78 + "┤")
        print(f"│ Description: {issue['description']:<60} │")
        print("├" + "─" * 78 + "┤")
        print(f"│ Code: {issue['code']:<67} │")
        print("├" + "─" * 78 + "┤")
        print(f"│ 💡 Suggestion: {issue['suggestion'][:60]:<57} │")
        if len(issue['suggestion']) > 60:
            print(f"│    {issue['suggestion'][60:]:<70} │")
        print("├" + "─" * 78 + "┤")
        print(f"│ 🔗 {issue['cwe']} │ https://cwe.mitre.org/data/definitions/{issue['cwe'].split('-')[1]}.html │")
        print("└" + "─" * 78 + "┘")
        print()
    
    # Issue Categories
    print("📊 ISSUE CATEGORIES")
    print("─" * 50)
    print()
    
    print("┌─────────────┬─────────────┬─────────────┬─────────────┐")
    print("│  🔒 SECURITY  │ 📊 BEST PRACTICE │  🎨 STYLE  │ 📈 COMPLEXITY │")
    print("│      7      │       20        │      2     │      1      │")
    print("│   Issues    │     Issues      │   Issues   │   Issues    │")
    print("└─────────────┴─────────────────┴─────────────┴─────────────┘")
    print()
    
    # Key Recommendations
    print("🎯 KEY RECOMMENDATIONS")
    print("=" * 80)
    print()
    
    recommendations = [
        {
            "priority": "🚨 IMMEDIATE ACTION REQUIRED",
            "color": "RED",
            "message": "6 critical security vulnerabilities detected. These pose immediate risks including data breaches, authentication bypass, and code injection attacks."
        },
        {
            "priority": "⚠️ SECURITY IMPROVEMENTS",
            "color": "YELLOW",
            "message": "Replace hardcoded secrets with environment variables, use parameterized queries, and implement input validation."
        },
        {
            "priority": "✅ CODE QUALITY",
            "color": "GREEN", 
            "message": "Add missing docstrings, replace print statements with logging, and follow PEP 8 style guidelines."
        }
    ]
    
    for rec in recommendations:
        border_char = "█" if rec["color"] == "RED" else "▓" if rec["color"] == "YELLOW" else "░"
        print("┌" + border_char * 78 + "┐")
        print(f"│ {rec['priority']:<76} │")
        print("├" + "─" * 78 + "┤")
        
        # Word wrap the message
        words = rec['message'].split()
        lines = []
        current_line = ""
        
        for word in words:
            if len(current_line + " " + word) <= 74:
                current_line = current_line + " " + word if current_line else word
            else:
                lines.append(current_line)
                current_line = word
        if current_line:
            lines.append(current_line)
        
        for line in lines:
            print(f"│ {line:<76} │")
        
        print("└" + "─" * 78 + "┘")
        print()
    
    # CodeScan Results Summary
    print("🚀 CODESCAN RESULTS SUMMARY")
    print("=" * 80)
    print()
    
    results = [
        ("⚡ Lightning Fast Analysis", "< 2 seconds"),
        ("🎯 High Accuracy Detection", "30 issues found"),
        ("🔒 Security Focused", "6 critical vulnerabilities"),
        ("📊 Comprehensive Coverage", "Multi-language support")
    ]
    
    print("┌─────────────────────┬─────────────────────┬─────────────────────┬─────────────────────┐")
    for result in results:
        print(f"│ {result[0]:<19} │", end="")
    print()
    
    print("├─────────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤")
    for result in results:
        print(f"│ {result[1]:<19} │", end="")
    print()
    print("└─────────────────────┴─────────────────────┴─────────────────────┴─────────────────────┘")
    print()
    
    # Footer
    print("─" * 80)
    print("Generated by CodeScan v1.0.0 | Enterprise Code Analysis Platform")
    print("For more information, visit: https://github.com/codescan/codescan")
    print("Support: support@codescan.dev")
    print("─" * 80)
    
    print()
    print("📄 ACTUAL HTML REPORT FEATURES:")
    print("• Interactive hover effects on issue cards")
    print("• Animated progress bars and charts") 
    print("• Clickable CWE links to vulnerability databases")
    print("• Responsive design for mobile and desktop")
    print("• Professional styling with gradients and shadows")
    print("• Copy-to-clipboard functionality for code snippets")
    print("• Collapsible sections for better navigation")
    print("• Search and filter capabilities")
    print("• Export options (PDF, CSV)")
    print("• Print-friendly layout")
    print()
    print("🌐 To view the actual HTML report:")
    print("   1. Open /workspace/codescan_report.html in any web browser")
    print("   2. Experience the full interactive features") 
    print("   3. Share with your team or include in documentation")

if __name__ == "__main__":
    show_report_preview()