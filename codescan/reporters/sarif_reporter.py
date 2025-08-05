"""SARIF (Static Analysis Results Interchange Format) reporter."""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime

from .base_reporter import BaseReporter
from ..core.result import ScanResult


class SarifReporter(BaseReporter):
    """Generate SARIF format reports for integration with security tools."""
    
    def generate_report(self, scan_result: ScanResult, output_file: Optional[str] = None) -> str:
        """Generate SARIF report."""
        sarif_report = self._create_sarif_report(scan_result)
        report_content = json.dumps(sarif_report, indent=2, ensure_ascii=False)
        
        if output_file:
            self._write_to_file(report_content, output_file)
        
        return report_content
    
    def _create_sarif_report(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Create SARIF format report structure."""
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeScan",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/codescan/codescan",
                            "rules": self._generate_rules(scan_result)
                        }
                    },
                    "results": self._generate_results(scan_result),
                    "invocation": {
                        "executionSuccessful": True,
                        "startTimeUtc": scan_result.scan_timestamp,
                        "endTimeUtc": datetime.now().isoformat(),
                        "workingDirectory": {
                            "uri": f"file://{scan_result.project_path}"
                        }
                    }
                }
            ]
        }
    
    def _generate_rules(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Generate SARIF rules from scan results."""
        rules = {}
        
        for issue in scan_result.get_all_issues():
            if issue.rule_id not in rules:
                rules[issue.rule_id] = {
                    "id": issue.rule_id,
                    "name": issue.title,
                    "shortDescription": {
                        "text": issue.title
                    },
                    "fullDescription": {
                        "text": issue.description
                    },
                    "help": {
                        "text": issue.suggestion or issue.description
                    },
                    "properties": {
                        "category": issue.issue_type.value,
                        "precision": "medium"
                    }
                }
                
                if issue.cwe_id:
                    rules[issue.rule_id]["properties"]["cwe"] = issue.cwe_id
        
        return list(rules.values())
    
    def _generate_results(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Generate SARIF results from scan results."""
        results = []
        
        for issue in scan_result.get_all_issues():
            result = {
                "ruleId": issue.rule_id,
                "message": {
                    "text": issue.description
                },
                "level": self._map_severity_to_sarif(issue.severity.value),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": issue.file_path
                            },
                            "region": {
                                "startLine": issue.line_number,
                                "startColumn": issue.column
                            }
                        }
                    }
                ]
            }
            
            if issue.code_snippet:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": issue.code_snippet
                }
            
            if issue.cwe_id:
                result["properties"] = {
                    "cwe": issue.cwe_id
                }
            
            results.append(result)
        
        return results
    
    def _map_severity_to_sarif(self, severity: str) -> str:
        """Map our severity levels to SARIF levels."""
        mapping = {
            "critical": "error",
            "high": "error", 
            "medium": "warning",
            "low": "note"
        }
        return mapping.get(severity, "warning")