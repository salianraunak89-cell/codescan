"""Text report generator for terminal output."""

from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .base_reporter import BaseReporter
from ..core.result import ScanResult, Severity, IssueType


class TextReporter(BaseReporter):
    """Generate human-readable text reports."""
    
    def __init__(self):
        """Initialize text reporter."""
        self.console = Console()
    
    def generate_report(self, scan_result: ScanResult, output_file: Optional[str] = None) -> str:
        """Generate text report."""
        
        # Capture console output
        with self.console.capture() as capture:
            self._generate_summary(scan_result)
            self._generate_issues_by_severity(scan_result)
            self._generate_detailed_issues(scan_result)
        
        report_content = capture.get()
        
        if output_file:
            self._write_to_file(report_content, output_file)
        
        return report_content
    
    def _generate_summary(self, scan_result: ScanResult) -> None:
        """Generate summary section."""
        summary = scan_result.get_summary_stats()
        
        # Create summary table
        summary_table = Table(title="📊 Scan Summary", box=box.ROUNDED)
        summary_table.add_column("Metric", style="cyan", no_wrap=True)
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("📁 Files Scanned", str(summary['total_files']))
        summary_table.add_row("⚠️ Total Issues", str(summary['total_issues']))
        summary_table.add_row("📂 Files with Issues", str(summary['files_with_issues']))
        
        if 'scan_duration' in summary:
            summary_table.add_row("⏱️ Scan Duration", f"{summary['scan_duration']:.2f}s")
        
        self.console.print(summary_table)
        self.console.print()
    
    def _generate_issues_by_severity(self, scan_result: ScanResult) -> None:
        """Generate issues breakdown by severity."""
        summary = scan_result.get_summary_stats()
        severity_breakdown = summary['severity_breakdown']
        
        # Create severity table
        severity_table = Table(title="🚨 Issues by Severity", box=box.ROUNDED)
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="right")
        severity_table.add_column("Bar", width=20)
        
        total_issues = sum(severity_breakdown.values())
        
        # Define colors for each severity
        severity_colors = {
            'critical': 'red',
            'high': 'bright_red',
            'medium': 'yellow',
            'low': 'green'
        }
        
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_breakdown.get(severity, 0)
            if total_issues > 0:
                bar_length = int((count / total_issues) * 20)
                bar = "█" * bar_length + "░" * (20 - bar_length)
            else:
                bar = "░" * 20
            
            color = severity_colors.get(severity, 'white')
            severity_table.add_row(
                f"[{color}]{severity.upper()}[/{color}]",
                str(count),
                f"[{color}]{bar}[/{color}]"
            )
        
        self.console.print(severity_table)
        self.console.print()
        
        # Issue types breakdown
        type_breakdown = summary['type_breakdown']
        if any(count > 0 for count in type_breakdown.values()):
            type_table = Table(title="📋 Issues by Type", box=box.ROUNDED)
            type_table.add_column("Type", style="cyan")
            type_table.add_column("Count", justify="right")
            
            for issue_type, count in type_breakdown.items():
                if count > 0:
                    type_table.add_row(issue_type.replace('_', ' ').title(), str(count))
            
            self.console.print(type_table)
            self.console.print()
    
    def _generate_detailed_issues(self, scan_result: ScanResult) -> None:
        """Generate detailed issues section."""
        all_issues = scan_result.get_all_issues()
        
        if not all_issues:
            self.console.print(Panel.fit("✅ No issues found!", style="green"))
            return
        
        # Group issues by severity
        issues_by_severity = {}
        for issue in all_issues:
            severity = issue.severity.value
            if severity not in issues_by_severity:
                issues_by_severity[severity] = []
            issues_by_severity[severity].append(issue)
        
        # Display issues by severity (most severe first)
        severity_order = ['critical', 'high', 'medium', 'low']
        
        for severity in severity_order:
            if severity not in issues_by_severity:
                continue
            
            issues = issues_by_severity[severity]
            
            # Create panel for this severity level
            severity_colors = {
                'critical': 'red',
                'high': 'bright_red',
                'medium': 'yellow',
                'low': 'green'
            }
            
            color = severity_colors.get(severity, 'white')
            
            self.console.print(Panel.fit(
                f"🚨 {severity.upper()} SEVERITY ISSUES ({len(issues)} found)",
                style=color
            ))
            
            # Group by file for better organization
            issues_by_file = {}
            for issue in issues:
                if issue.file_path not in issues_by_file:
                    issues_by_file[issue.file_path] = []
                issues_by_file[issue.file_path].append(issue)
            
            for file_path, file_issues in issues_by_file.items():
                self.console.print(f"\n📄 [bold]{file_path}[/bold]")
                
                for issue in file_issues:
                    self._print_issue(issue, color)
            
            self.console.print()
    
    def _print_issue(self, issue, color: str) -> None:
        """Print a single issue."""
        # Issue header
        location = f"Line {issue.line_number}, Column {issue.column}"
        rule_text = f"[dim]({issue.rule_id})[/dim]"
        
        self.console.print(f"  [{color}]●[/{color}] {issue.title} {rule_text}")
        self.console.print(f"    📍 {location}")
        self.console.print(f"    💬 {issue.description}")
        
        if issue.suggestion:
            self.console.print(f"    💡 [dim]{issue.suggestion}[/dim]")
        
        if issue.code_snippet:
            self.console.print(f"    📝 [dim]Code: {issue.code_snippet}[/dim]")
        
        if issue.cwe_id:
            self.console.print(f"    🔗 [dim]CWE: {issue.cwe_id}[/dim]")
        
        self.console.print()