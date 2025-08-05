"""HTML report generator."""

from typing import Optional
from datetime import datetime
from jinja2 import Template

from .base_reporter import BaseReporter
from ..core.result import ScanResult


class HtmlReporter(BaseReporter):
    """Generate HTML format reports."""
    
    def generate_report(self, scan_result: ScanResult, output_file: Optional[str] = None) -> str:
        """Generate HTML report."""
        template = Template(self._get_html_template())
        
        # Prepare data for template
        template_data = {
            'scan_result': scan_result,
            'summary': scan_result.get_summary_stats(),
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'issues_by_severity': self._group_issues_by_severity(scan_result),
            'issues_by_file': self._group_issues_by_file(scan_result),
        }
        
        report_content = template.render(**template_data)
        
        if output_file:
            self._write_to_file(report_content, output_file)
        
        return report_content
    
    def _group_issues_by_severity(self, scan_result: ScanResult):
        """Group issues by severity level."""
        issues_by_severity = {}
        for issue in scan_result.get_all_issues():
            severity = issue.severity.value
            if severity not in issues_by_severity:
                issues_by_severity[severity] = []
            issues_by_severity[severity].append(issue)
        return issues_by_severity
    
    def _group_issues_by_file(self, scan_result: ScanResult):
        """Group issues by file."""
        issues_by_file = {}
        for file_path, file_result in scan_result.file_results.items():
            if file_result.issues:
                issues_by_file[file_path] = file_result.issues
        return issues_by_file
    
    def _get_html_template(self) -> str:
        """Get HTML template string."""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeScan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }
        
        .header p {
            margin: 0;
            opacity: 0.9;
        }
        
        .content {
            padding: 30px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }
        
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #495057;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #495057;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .severity-card {
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            color: white;
            font-weight: bold;
        }
        
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; }
        .severity-low { background-color: #28a745; }
        
        .file-section {
            background: #f8f9fa;
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .file-header {
            background: #e9ecef;
            padding: 15px;
            font-weight: bold;
            border-bottom: 1px solid #dee2e6;
        }
        
        .issue {
            padding: 15px;
            border-bottom: 1px solid #e9ecef;
            transition: background-color 0.2s;
        }
        
        .issue:hover {
            background-color: #ffffff;
        }
        
        .issue:last-child {
            border-bottom: none;
        }
        
        .issue-header {
            display: flex;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .issue-severity {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
            margin-right: 10px;
        }
        
        .issue-title {
            font-weight: bold;
            flex-grow: 1;
        }
        
        .issue-rule {
            color: #6c757d;
            font-size: 0.9em;
        }
        
        .issue-location {
            color: #6c757d;
            font-size: 0.9em;
            margin-bottom: 8px;
        }
        
        .issue-description {
            margin-bottom: 8px;
        }
        
        .issue-suggestion {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-radius: 4px;
            padding: 8px;
            font-size: 0.9em;
            color: #0c5460;
        }
        
        .code-snippet {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 8px 0;
            overflow-x: auto;
        }
        
        .cwe-link {
            color: #007bff;
            text-decoration: none;
            font-size: 0.9em;
        }
        
        .cwe-link:hover {
            text-decoration: underline;
        }
        
        .no-issues {
            text-align: center;
            padding: 40px;
            color: #6c757d;
            background: #d4edda;
            border-radius: 6px;
            border: 1px solid #c3e6cb;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            background: #f8f9fa;
            border-top: 1px solid #e9ecef;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 CodeScan Report</h1>
            <p>Project: {{ scan_result.project_path }}</p>
            <p>Generated: {{ generated_at }}</p>
        </div>
        
        <div class="content">
            <!-- Summary Section -->
            <div class="section">
                <h2>📊 Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card">
                        <h3>Files Scanned</h3>
                        <div class="value">{{ summary.total_files }}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Total Issues</h3>
                        <div class="value">{{ summary.total_issues }}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Files with Issues</h3>
                        <div class="value">{{ summary.files_with_issues }}</div>
                    </div>
                    {% if summary.scan_duration %}
                    <div class="summary-card">
                        <h3>Scan Duration</h3>
                        <div class="value">{{ "%.2f"|format(summary.scan_duration) }}s</div>
                    </div>
                    {% endif %}
                </div>
            </div>
            
            <!-- Severity Breakdown -->
            <div class="section">
                <h2>🚨 Issues by Severity</h2>
                <div class="severity-grid">
                    <div class="severity-card severity-critical">
                        <div>CRITICAL</div>
                        <div style="font-size: 1.5em;">{{ summary.severity_breakdown.critical or 0 }}</div>
                    </div>
                    <div class="severity-card severity-high">
                        <div>HIGH</div>
                        <div style="font-size: 1.5em;">{{ summary.severity_breakdown.high or 0 }}</div>
                    </div>
                    <div class="severity-card severity-medium">
                        <div>MEDIUM</div>
                        <div style="font-size: 1.5em;">{{ summary.severity_breakdown.medium or 0 }}</div>
                    </div>
                    <div class="severity-card severity-low">
                        <div>LOW</div>
                        <div style="font-size: 1.5em;">{{ summary.severity_breakdown.low or 0 }}</div>
                    </div>
                </div>
            </div>
            
            <!-- Detailed Issues -->
            <div class="section">
                <h2>📋 Detailed Issues</h2>
                
                {% if issues_by_file %}
                    {% for file_path, issues in issues_by_file.items() %}
                    <div class="file-section">
                        <div class="file-header">
                            📄 {{ file_path }}
                        </div>
                        
                        {% for issue in issues %}
                        <div class="issue">
                            <div class="issue-header">
                                <span class="issue-severity severity-{{ issue.severity.value }}">
                                    {{ issue.severity.value.upper() }}
                                </span>
                                <span class="issue-title">{{ issue.title }}</span>
                                <span class="issue-rule">({{ issue.rule_id }})</span>
                            </div>
                            
                            <div class="issue-location">
                                📍 Line {{ issue.line_number }}, Column {{ issue.column }}
                            </div>
                            
                            <div class="issue-description">
                                {{ issue.description }}
                            </div>
                            
                            {% if issue.code_snippet %}
                            <div class="code-snippet">
                                {{ issue.code_snippet }}
                            </div>
                            {% endif %}
                            
                            {% if issue.suggestion %}
                            <div class="issue-suggestion">
                                💡 <strong>Suggestion:</strong> {{ issue.suggestion }}
                            </div>
                            {% endif %}
                            
                            {% if issue.cwe_id %}
                            <div style="margin-top: 8px;">
                                <a href="https://cwe.mitre.org/data/definitions/{{ issue.cwe_id.replace('CWE-', '') }}.html" 
                                   class="cwe-link" target="_blank">
                                    🔗 {{ issue.cwe_id }}
                                </a>
                            </div>
                            {% endif %}
                        </div>
                        {% endfor %}
                    </div>
                    {% endfor %}
                {% else %}
                    <div class="no-issues">
                        ✅ <strong>Great!</strong> No issues found in your code.
                    </div>
                {% endif %}
            </div>
        </div>
        
        <div class="footer">
            Generated by CodeScan - A comprehensive code analysis tool
        </div>
    </div>
</body>
</html>
        '''