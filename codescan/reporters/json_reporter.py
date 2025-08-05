"""JSON report generator."""

import json
from typing import Optional
from .base_reporter import BaseReporter
from ..core.result import ScanResult


class JsonReporter(BaseReporter):
    """Generate JSON format reports."""
    
    def generate_report(self, scan_result: ScanResult, output_file: Optional[str] = None) -> str:
        """Generate JSON report."""
        report_content = json.dumps(scan_result.to_dict(), indent=2, ensure_ascii=False)
        
        if output_file:
            self._write_to_file(report_content, output_file)
        
        return report_content