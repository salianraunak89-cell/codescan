"""Base reporter class."""

from abc import ABC, abstractmethod
from typing import Optional
from ..core.result import ScanResult


class BaseReporter(ABC):
    """Base class for report generation."""
    
    @abstractmethod
    def generate_report(self, scan_result: ScanResult, output_file: Optional[str] = None) -> str:
        """
        Generate report from scan results.
        
        Args:
            scan_result: Scan results to report
            output_file: Optional output file path
            
        Returns:
            Report content as string
        """
        pass
    
    def _write_to_file(self, content: str, output_file: str) -> None:
        """Write content to file."""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)