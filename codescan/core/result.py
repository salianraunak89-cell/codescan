"""Data structures for scan results."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import json


class Severity(Enum):
    """Issue severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IssueType(Enum):
    """Types of issues that can be found."""
    SECURITY = "security"
    BEST_PRACTICE = "best_practice"
    CODE_STYLE = "code_style"
    COMPLEXITY = "complexity"
    MAINTAINABILITY = "maintainability"
    PERFORMANCE = "performance"
    BUG = "bug"
    VULNERABILITY = "vulnerability"


@dataclass
class Issue:
    """Represents a single issue found during scanning."""
    
    file_path: str
    line_number: int
    column: int
    severity: Severity
    issue_type: IssueType
    rule_id: str
    title: str
    description: str
    suggestion: Optional[str] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    confidence: float = 1.0  # Confidence level (0.0 to 1.0)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert issue to dictionary."""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "severity": self.severity.value,
            "issue_type": self.issue_type.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "suggestion": self.suggestion,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
            "metadata": self.metadata
        }


@dataclass
class FileResult:
    """Results for a single file."""
    
    file_path: str
    language: str
    issues: List[Issue] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def add_issue(self, issue: Issue) -> None:
        """Add an issue to this file result."""
        self.issues.append(issue)
    
    def get_issues_by_severity(self, severity: Severity) -> List[Issue]:
        """Get issues filtered by severity."""
        return [issue for issue in self.issues if issue.severity == severity]
    
    def get_issues_by_type(self, issue_type: IssueType) -> List[Issue]:
        """Get issues filtered by type."""
        return [issue for issue in self.issues if issue.issue_type == issue_type]


@dataclass
class ScanResult:
    """Complete scan results for a project."""
    
    project_path: str
    scan_timestamp: str
    file_results: Dict[str, FileResult] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    
    def add_file_result(self, file_result: FileResult) -> None:
        """Add a file result."""
        self.file_results[file_result.file_path] = file_result
    
    def get_all_issues(self) -> List[Issue]:
        """Get all issues from all files."""
        all_issues = []
        for file_result in self.file_results.values():
            all_issues.extend(file_result.issues)
        return all_issues
    
    def get_issues_by_severity(self, severity: Severity) -> List[Issue]:
        """Get all issues filtered by severity."""
        return [issue for issue in self.get_all_issues() if issue.severity == severity]
    
    def get_issues_by_type(self, issue_type: IssueType) -> List[Issue]:
        """Get all issues filtered by type."""
        return [issue for issue in self.get_all_issues() if issue.issue_type == issue_type]
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        all_issues = self.get_all_issues()
        
        severity_counts = {severity.value: 0 for severity in Severity}
        type_counts = {issue_type.value: 0 for issue_type in IssueType}
        
        for issue in all_issues:
            severity_counts[issue.severity.value] += 1
            type_counts[issue.issue_type.value] += 1
        
        return {
            "total_files": len(self.file_results),
            "total_issues": len(all_issues),
            "severity_breakdown": severity_counts,
            "type_breakdown": type_counts,
            "files_with_issues": len([f for f in self.file_results.values() if f.issues])
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "project_path": self.project_path,
            "scan_timestamp": self.scan_timestamp,
            "file_results": {
                path: {
                    "file_path": result.file_path,
                    "language": result.language,
                    "issues": [issue.to_dict() for issue in result.issues],
                    "metrics": result.metrics
                }
                for path, result in self.file_results.items()
            },
            "summary": self.get_summary_stats()
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert scan result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)