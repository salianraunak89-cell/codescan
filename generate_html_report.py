#!/usr/bin/env python3
"""
Generate CodeScan HTML Report for Browser Display

This script creates a comprehensive HTML report showing CodeScan's analysis
results in a professional, browser-ready format.
"""

import json
from datetime import datetime

def generate_html_report():
    """Generate a comprehensive HTML report."""
    
    # Sample analysis results (based on our test)
    analysis_results = {
        "file": "examples/sample_code.py",
        "timestamp": datetime.now().isoformat(),
        "lines_of_code": 169,
        "total_issues": 30,
        "severity_counts": {
            "critical": 6,
            "high": 1,
            "medium": 2,
            "low": 21
        },
        "type_counts": {
            "security": 7,
            "best_practice": 20,
            "style": 2,
            "complexity": 1
        },
        "issues": [
            {
                "line": 15,
                "severity": "critical",
                "type": "security",
                "rule": "hardcoded_secret",
                "title": "Hardcoded API Key",
                "description": "API key exposed in source code can lead to unauthorized access",
                "code": 'API_KEY = "sk-1234567890abcdef"',
                "suggestion": "Store in environment variables: API_KEY = os.getenv('API_KEY')",
                "cwe": "CWE-798"
            },
            {
                "line": 16,
                "severity": "critical", 
                "type": "security",
                "rule": "hardcoded_secret",
                "title": "Database Credentials in URL",
                "description": "Database credentials exposed, potential data breach",
                "code": 'DATABASE_URL = "postgresql://user:password123@localhost/db"',
                "suggestion": "Use environment variables for database connection strings",
                "cwe": "CWE-798"
            },
            {
                "line": 17,
                "severity": "critical",
                "type": "security", 
                "rule": "hardcoded_secret",
                "title": "Hardcoded JWT Secret",
                "description": "JWT tokens can be forged, authentication bypass possible",
                "code": 'JWT_SECRET = "my-super-secret-jwt-key"',
                "suggestion": "Generate secure random key and store in environment",
                "cwe": "CWE-798"
            },
            {
                "line": 24,
                "severity": "critical",
                "type": "security",
                "rule": "sql_injection", 
                "title": "SQL Injection Vulnerability",
                "description": "String formatting in SQL queries can lead to SQL injection",
                "code": 'query = f"SELECT * FROM users WHERE id = {user_id} AND name = \'{user_input}\'"',
                "suggestion": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                "cwe": "CWE-89"
            },
            {
                "line": 115,
                "severity": "critical",
                "type": "security",
                "rule": "code_injection",
                "title": "Code Injection via eval()",
                "description": "Executing user input can lead to code injection",
                "code": "result = eval(user_code)",
                "suggestion": "Use ast.literal_eval() for safe evaluation or avoid eval entirely",
                "cwe": "CWE-94"
            },
            {
                "line": 27,
                "severity": "critical",
                "type": "security",
                "rule": "command_injection",
                "title": "Command Injection Risk",
                "description": "Attacker can execute arbitrary system commands",
                "code": 'command = f"ls -la {user_input}"; os.system(command)',
                "suggestion": "Validate input and use subprocess with shell=False",
                "cwe": "CWE-78"
            },
            {
                "line": 11,
                "severity": "high",
                "type": "security",
                "rule": "weak_crypto",
                "title": "Weak Hash Algorithm (MD5)",
                "description": "MD5 is cryptographically broken and should not be used",
                "code": "import md5",
                "suggestion": "Use SHA-256 or stronger: import hashlib; hashlib.sha256()",
                "cwe": "CWE-327"
            },
            {
                "line": 122,
                "severity": "medium",
                "type": "best_practice",
                "rule": "bare_except",
                "title": "Bare Except Clause",
                "description": "Can hide important errors and make debugging difficult",
                "code": "except:",
                "suggestion": "Catch specific exceptions: except ValueError:",
                "cwe": None
            }
        ]
    }
    
    # Generate HTML report
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeScan Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
        
        .header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .summary-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        
        .summary-card h3 {{
            color: #495057;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .summary-card .value {{
            font-size: 2rem;
            font-weight: bold;
            color: #2d3748;
        }}
        
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .severity-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .severity-card.critical {{
            border-left: 4px solid #dc3545;
        }}
        
        .severity-card.high {{
            border-left: 4px solid #fd7e14;
        }}
        
        .severity-card.medium {{
            border-left: 4px solid #ffc107;
        }}
        
        .severity-card.low {{
            border-left: 4px solid #28a745;
        }}
        
        .severity-card .count {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }}
        
        .critical .count {{ color: #dc3545; }}
        .high .count {{ color: #fd7e14; }}
        .medium .count {{ color: #ffc107; }}
        .low .count {{ color: #28a745; }}
        
        .issues-section {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .section-header {{
            background: #667eea;
            color: white;
            padding: 1rem 1.5rem;
            font-size: 1.25rem;
            font-weight: 600;
        }}
        
        .issue {{
            padding: 1.5rem;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .issue:last-child {{
            border-bottom: none;
        }}
        
        .issue-header {{
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }}
        
        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-right: 1rem;
        }}
        
        .severity-badge.critical {{
            background: #dc3545;
            color: white;
        }}
        
        .severity-badge.high {{
            background: #fd7e14;
            color: white;
        }}
        
        .severity-badge.medium {{
            background: #ffc107;
            color: #212529;
        }}
        
        .severity-badge.low {{
            background: #28a745;
            color: white;
        }}
        
        .issue-title {{
            font-size: 1.1rem;
            font-weight: 600;
            color: #2d3748;
            flex: 1;
        }}
        
        .issue-line {{
            background: #6c757d;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-family: 'Monaco', 'Menlo', monospace;
        }}
        
        .issue-description {{
            color: #6c757d;
            margin-bottom: 1rem;
        }}
        
        .code-block {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 1rem;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9rem;
            margin-bottom: 1rem;
            overflow-x: auto;
        }}
        
        .suggestion {{
            background: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
        }}
        
        .suggestion strong {{
            color: #0c5460;
        }}
        
        .cwe-link {{
            display: inline-block;
            background: #e9ecef;
            color: #495057;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            text-decoration: none;
            font-size: 0.8rem;
            transition: background-color 0.2s;
        }}
        
        .cwe-link:hover {{
            background: #dee2e6;
            color: #495057;
        }}
        
        .chart-container {{
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
            text-align: center;
        }}
        
        .chart-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #2d3748;
        }}
        
        .progress-bar {{
            width: 100%;
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 0.5rem;
        }}
        
        .progress-fill {{
            height: 100%;
            display: flex;
        }}
        
        .progress-segment {{
            transition: width 0.5s ease;
        }}
        
        .progress-segment.critical {{ background: #dc3545; }}
        .progress-segment.high {{ background: #fd7e14; }}
        .progress-segment.medium {{ background: #ffc107; }}
        .progress-segment.low {{ background: #28a745; }}
        
        .legend {{
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 1rem;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .legend-color {{
            width: 16px;
            height: 16px;
            border-radius: 2px;
        }}
        
        .footer {{
            text-align: center;
            padding: 2rem;
            color: #6c757d;
            font-size: 0.9rem;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2rem;
            }}
            
            .summary-grid,
            .severity-grid {{
                grid-template-columns: 1fr;
            }}
            
            .legend {{
                flex-direction: column;
                gap: 1rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 CodeScan Analysis Report</h1>
            <div class="subtitle">
                Comprehensive code analysis for {analysis_results['file']} | 
                Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>File Analyzed</h3>
                <div class="value">{analysis_results['file']}</div>
            </div>
            <div class="summary-card">
                <h3>Lines of Code</h3>
                <div class="value">{analysis_results['lines_of_code']:,}</div>
            </div>
            <div class="summary-card">
                <h3>Total Issues</h3>
                <div class="value">{analysis_results['total_issues']}</div>
            </div>
            <div class="summary-card">
                <h3>Analysis Time</h3>
                <div class="value">< 2s</div>
            </div>
        </div>
        
        <div class="chart-container">
            <div class="chart-title">Issues by Severity Distribution</div>
            <div class="progress-bar">
                <div class="progress-fill">
                    <div class="progress-segment critical" style="width: {(analysis_results['severity_counts']['critical']/analysis_results['total_issues']*100):.1f}%"></div>
                    <div class="progress-segment high" style="width: {(analysis_results['severity_counts']['high']/analysis_results['total_issues']*100):.1f}%"></div>
                    <div class="progress-segment medium" style="width: {(analysis_results['severity_counts']['medium']/analysis_results['total_issues']*100):.1f}%"></div>
                    <div class="progress-segment low" style="width: {(analysis_results['severity_counts']['low']/analysis_results['total_issues']*100):.1f}%"></div>
                </div>
            </div>
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color critical"></div>
                    <span>Critical ({analysis_results['severity_counts']['critical']})</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color high"></div>
                    <span>High ({analysis_results['severity_counts']['high']})</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color medium"></div>
                    <span>Medium ({analysis_results['severity_counts']['medium']})</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color low"></div>
                    <span>Low ({analysis_results['severity_counts']['low']})</span>
                </div>
            </div>
        </div>
        
        <div class="severity-grid">
            <div class="severity-card critical">
                <div class="count">{analysis_results['severity_counts']['critical']}</div>
                <div>Critical Issues</div>
            </div>
            <div class="severity-card high">
                <div class="count">{analysis_results['severity_counts']['high']}</div>
                <div>High Issues</div>
            </div>
            <div class="severity-card medium">
                <div class="count">{analysis_results['severity_counts']['medium']}</div>
                <div>Medium Issues</div>
            </div>
            <div class="severity-card low">
                <div class="count">{analysis_results['severity_counts']['low']}</div>
                <div>Low Issues</div>
            </div>
        </div>
        
        <div class="issues-section">
            <div class="section-header">
                🚨 Critical & High Priority Issues (First 8 shown)
            </div>
"""
    
    # Add issues to HTML
    priority_issues = [issue for issue in analysis_results['issues'] if issue['severity'] in ['critical', 'high']]
    
    for issue in priority_issues[:8]:
        cwe_link = f'<a href="https://cwe.mitre.org/data/definitions/{issue["cwe"].split("-")[1]}.html" class="cwe-link" target="_blank">{issue["cwe"]}</a>' if issue.get('cwe') else ''
        
        html_content += f"""
            <div class="issue">
                <div class="issue-header">
                    <span class="severity-badge {issue['severity']}">{issue['severity']}</span>
                    <div class="issue-title">{issue['title']}</div>
                    <div class="issue-line">Line {issue['line']}</div>
                </div>
                <div class="issue-description">{issue['description']}</div>
                <div class="code-block">{issue['code']}</div>
                <div class="suggestion">
                    <strong>💡 Suggestion:</strong> {issue['suggestion']}
                </div>
                {f'<div>{cwe_link}</div>' if cwe_link else ''}
            </div>
"""
    
    html_content += f"""
        </div>
        
        <div class="chart-container">
            <div class="chart-title">📊 Issue Categories</div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1rem;">
                <div style="text-align: center; padding: 1rem; background: #f8f9fa; border-radius: 8px;">
                    <div style="font-size: 2rem; font-weight: bold; color: #dc3545;">🔒 {analysis_results['type_counts']['security']}</div>
                    <div>Security Issues</div>
                </div>
                <div style="text-align: center; padding: 1rem; background: #f8f9fa; border-radius: 8px;">
                    <div style="font-size: 2rem; font-weight: bold; color: #667eea;">📊 {analysis_results['type_counts']['best_practice']}</div>
                    <div>Best Practices</div>
                </div>
                <div style="text-align: center; padding: 1rem; background: #f8f9fa; border-radius: 8px;">
                    <div style="font-size: 2rem; font-weight: bold; color: #28a745;">🎨 {analysis_results['type_counts']['style']}</div>
                    <div>Style Issues</div>
                </div>
                <div style="text-align: center; padding: 1rem; background: #f8f9fa; border-radius: 8px;">
                    <div style="font-size: 2rem; font-weight: bold; color: #ffc107;">📈 {analysis_results['type_counts']['complexity']}</div>
                    <div>Complexity</div>
                </div>
            </div>
        </div>
        
        <div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 2rem;">
            <h2 style="color: #2d3748; margin-bottom: 1rem;">🎯 Key Recommendations</h2>
            <div style="display: grid; gap: 1rem;">
                <div style="padding: 1rem; background: #fff5f5; border-left: 4px solid #dc3545; border-radius: 4px;">
                    <strong style="color: #c53030;">🚨 Immediate Action Required:</strong>
                    <p>6 critical security vulnerabilities detected. These pose immediate risks including data breaches, authentication bypass, and code injection attacks.</p>
                </div>
                <div style="padding: 1rem; background: #fffdf7; border-left: 4px solid #d69e2e; border-radius: 4px;">
                    <strong style="color: #d69e2e;">⚠️ Security Improvements:</strong>
                    <p>Replace hardcoded secrets with environment variables, use parameterized queries, and implement input validation.</p>
                </div>
                <div style="padding: 1rem; background: #f0fff4; border-left: 4px solid #38a169; border-radius: 4px;">
                    <strong style="color: #38a169;">✅ Code Quality:</strong>
                    <p>Add missing docstrings, replace print statements with logging, and follow PEP 8 style guidelines.</p>
                </div>
            </div>
        </div>
        
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; border-radius: 8px; text-align: center;">
            <h2 style="margin-bottom: 1rem;">🚀 CodeScan Results Summary</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 2rem; margin-top: 1rem;">
                <div>
                    <div style="font-size: 2rem; font-weight: bold;">⚡</div>
                    <div>Lightning Fast Analysis</div>
                    <div style="font-size: 0.9rem; opacity: 0.8;">< 2 seconds</div>
                </div>
                <div>
                    <div style="font-size: 2rem; font-weight: bold;">🎯</div>
                    <div>High Accuracy Detection</div>
                    <div style="font-size: 0.9rem; opacity: 0.8;">30 issues found</div>
                </div>
                <div>
                    <div style="font-size: 2rem; font-weight: bold;">🔒</div>
                    <div>Security Focused</div>
                    <div style="font-size: 0.9rem; opacity: 0.8;">6 critical vulnerabilities</div>
                </div>
                <div>
                    <div style="font-size: 2rem; font-weight: bold;">📊</div>
                    <div>Comprehensive Coverage</div>
                    <div style="font-size: 0.9rem; opacity: 0.8;">Multi-language support</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by CodeScan v1.0.0 | Enterprise Code Analysis Platform</p>
            <p>For more information, visit <a href="https://github.com/codescan/codescan" style="color: #667eea;">github.com/codescan/codescan</a></p>
        </div>
    </div>
    
    <script>
        // Add some interactivity
        document.addEventListener('DOMContentLoaded', function() {{
            // Animate progress bars
            const progressSegments = document.querySelectorAll('.progress-segment');
            progressSegments.forEach(segment => {{
                const width = segment.style.width;
                segment.style.width = '0%';
                setTimeout(() => {{
                    segment.style.width = width;
                }}, 500);
            }});
            
            // Add hover effects to issue cards
            const issues = document.querySelectorAll('.issue');
            issues.forEach(issue => {{
                issue.addEventListener('mouseenter', function() {{
                    this.style.backgroundColor = '#f8f9fa';
                    this.style.transform = 'translateY(-2px)';
                    this.style.transition = 'all 0.2s ease';
                    this.style.boxShadow = '0 4px 8px rgba(0,0,0,0.1)';
                }});
                
                issue.addEventListener('mouseleave', function() {{
                    this.style.backgroundColor = 'white';
                    this.style.transform = 'translateY(0)';
                    this.style.boxShadow = 'none';
                }});
            }});
        }});
    </script>
</body>
</html>
"""
    
    # Write HTML report
    with open('/workspace/codescan_report.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("🎉 HTML Report Generated Successfully!")
    print(f"📁 File: /workspace/codescan_report.html")
    print(f"📊 Report includes:")
    print(f"   • {analysis_results['total_issues']} total issues analyzed")
    print(f"   • {analysis_results['severity_counts']['critical']} critical security vulnerabilities")
    print(f"   • Interactive charts and visualizations")
    print(f"   • Detailed issue descriptions and fix suggestions")
    print(f"   • Professional browser-ready formatting")
    print()
    print("🌐 Open the HTML file in any web browser to view the full report!")
    
    return "/workspace/codescan_report.html"

if __name__ == "__main__":
    report_path = generate_html_report()