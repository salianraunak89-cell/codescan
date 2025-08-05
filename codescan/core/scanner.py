"""Main scanning engine for CodeScan."""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .config import Config
from .language_detector import LanguageDetector
from .result import ScanResult, FileResult, Issue
from ..analyzers import get_analyzer_for_language
from ..scanners import get_security_scanner


class CodeScanner:
    """Main code scanning engine."""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the code scanner.
        
        Args:
            config: Configuration object, or None to use default
        """
        self.config = config or Config()
        self.language_detector = LanguageDetector()
        self.logger = self._setup_logging()
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the scanner."""
        logger = logging.getLogger('codescan')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        level = logging.DEBUG if self.config.config.verbose else logging.INFO
        logger.setLevel(level)
        return logger
    
    def scan_directory(self, directory_path: str) -> ScanResult:
        """
        Scan a directory for code issues.
        
        Args:
            directory_path: Path to directory to scan
            
        Returns:
            ScanResult containing all findings
        """
        self.logger.info(f"Starting scan of directory: {directory_path}")
        start_time = time.time()
        
        # Initialize scan result
        scan_result = ScanResult(
            project_path=directory_path,
            scan_timestamp=datetime.now().isoformat()
        )
        
        # Discover files to scan
        files_to_scan = list(self._discover_files(directory_path))
        self.logger.info(f"Found {len(files_to_scan)} files to scan")
        
        if not files_to_scan:
            self.logger.warning("No files found to scan")
            return scan_result
        
        # Scan files in parallel
        self._scan_files_parallel(files_to_scan, scan_result)
        
        # Generate summary
        scan_result.summary = scan_result.get_summary_stats()
        scan_result.summary['scan_duration'] = time.time() - start_time
        
        self.logger.info(f"Scan completed in {scan_result.summary['scan_duration']:.2f} seconds")
        self.logger.info(f"Found {scan_result.summary['total_issues']} issues")
        
        return scan_result
    
    def scan_file(self, file_path: str) -> Optional[FileResult]:
        """
        Scan a single file.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            FileResult or None if file couldn't be scanned
        """
        try:
            # Check if file should be excluded
            if self.config.should_exclude_file(file_path):
                return None
            
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > self.config.config.max_file_size:
                self.logger.warning(f"Skipping large file: {file_path} ({file_size} bytes)")
                return None
            
            # Detect language
            language = self.language_detector.detect_language(file_path)
            if not language:
                self.logger.debug(f"Unknown language for file: {file_path}")
                return None
            
            if not self.config.is_language_enabled(language):
                self.logger.debug(f"Language {language} disabled for file: {file_path}")
                return None
            
            self.logger.debug(f"Scanning {file_path} as {language}")
            
            # Create file result
            file_result = FileResult(
                file_path=file_path,
                language=language
            )
            
            # Run language-specific analysis
            self._run_language_analysis(file_path, language, file_result)
            
            # Run security scanning
            if self.config.config.security_scan:
                self._run_security_analysis(file_path, language, file_result)
            
            # Calculate metrics
            self._calculate_metrics(file_path, file_result)
            
            return file_result
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            return None
    
    def _discover_files(self, directory_path: str) -> Generator[str, None, None]:
        """
        Discover files to scan in a directory.
        
        Args:
            directory_path: Directory to search
            
        Yields:
            File paths to scan
        """
        directory = Path(directory_path)
        
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                file_str = str(file_path)
                
                # Skip if excluded
                if self.config.should_exclude_file(file_str):
                    continue
                
                # Check if it's a code file
                if self.language_detector.is_code_file(file_str):
                    yield file_str
    
    def _scan_files_parallel(self, file_paths: List[str], scan_result: ScanResult):
        """
        Scan files in parallel.
        
        Args:
            file_paths: List of file paths to scan
            scan_result: ScanResult to populate
        """
        max_workers = self.config.config.parallel_workers
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all file scan tasks
            future_to_file = {
                executor.submit(self.scan_file, file_path): file_path
                for file_path in file_paths
            }
            
            # Process completed tasks
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_result = future.result(timeout=self.config.config.timeout_per_file)
                    if file_result:
                        scan_result.add_file_result(file_result)
                        
                        if self.config.config.verbose:
                            issue_count = len(file_result.issues)
                            self.logger.debug(f"Scanned {file_path}: {issue_count} issues")
                            
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {e}")
    
    def _run_language_analysis(self, file_path: str, language: str, file_result: FileResult):
        """
        Run language-specific analysis.
        
        Args:
            file_path: Path to file
            language: Detected language
            file_result: FileResult to add issues to
        """
        try:
            analyzer = get_analyzer_for_language(language)
            if analyzer and self.config.is_analyzer_enabled(language):
                analyzer_config = self.config.get_analyzer_config(language)
                issues = analyzer.analyze(file_path, analyzer_config)
                file_result.issues.extend(issues)
        except Exception as e:
            self.logger.error(f"Error in language analysis for {file_path}: {e}")
    
    def _run_security_analysis(self, file_path: str, language: str, file_result: FileResult):
        """
        Run security analysis.
        
        Args:
            file_path: Path to file
            language: Detected language
            file_result: FileResult to add issues to
        """
        try:
            if self.config.is_analyzer_enabled('security'):
                security_scanner = get_security_scanner()
                if security_scanner:
                    analyzer_config = self.config.get_analyzer_config('security')
                    issues = security_scanner.scan_file(file_path, language, analyzer_config)
                    file_result.issues.extend(issues)
        except Exception as e:
            self.logger.error(f"Error in security analysis for {file_path}: {e}")
    
    def _calculate_metrics(self, file_path: str, file_result: FileResult):
        """
        Calculate code metrics for a file.
        
        Args:
            file_path: Path to file
            file_result: FileResult to add metrics to
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.splitlines()
            
            metrics = {
                'lines_of_code': len(lines),
                'blank_lines': len([line for line in lines if not line.strip()]),
                'comment_lines': self._count_comment_lines(lines, file_result.language),
                'file_size_bytes': len(content.encode('utf-8')),
            }
            
            # Calculate effective lines of code
            metrics['effective_loc'] = (
                metrics['lines_of_code'] - 
                metrics['blank_lines'] - 
                metrics['comment_lines']
            )
            
            file_result.metrics = metrics
            
        except Exception as e:
            self.logger.error(f"Error calculating metrics for {file_path}: {e}")
            file_result.metrics = {}
    
    def _count_comment_lines(self, lines: List[str], language: str) -> int:
        """
        Count comment lines for a given language.
        
        Args:
            lines: Lines of code
            language: Programming language
            
        Returns:
            Number of comment lines
        """
        comment_patterns = {
            'python': ['#'],
            'javascript': ['//', '/*', '*/', '*'],
            'typescript': ['//', '/*', '*/', '*'],
            'java': ['//', '/*', '*/', '*'],
            'c': ['//', '/*', '*/', '*'],
            'cpp': ['//', '/*', '*/', '*'],
            'csharp': ['//', '/*', '*/', '*'],
            'go': ['//', '/*', '*/', '*'],
            'rust': ['//', '/*', '*/', '*'],
            'php': ['//', '#', '/*', '*/', '*'],
            'ruby': ['#'],
            'shell': ['#'],
            'sql': ['--', '/*', '*/', '*'],
        }
        
        patterns = comment_patterns.get(language, [])
        if not patterns:
            return 0
        
        comment_count = 0
        for line in lines:
            stripped = line.strip()
            for pattern in patterns:
                if stripped.startswith(pattern):
                    comment_count += 1
                    break
        
        return comment_count
    
    def get_scan_summary(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Get a detailed summary of scan results.
        
        Args:
            scan_result: ScanResult to summarize
            
        Returns:
            Dictionary with summary information
        """
        summary = scan_result.get_summary_stats()
        
        # Add language breakdown
        language_stats = {}
        for file_result in scan_result.file_results.values():
            lang = file_result.language
            if lang not in language_stats:
                language_stats[lang] = {
                    'files': 0,
                    'issues': 0,
                    'lines_of_code': 0
                }
            
            language_stats[lang]['files'] += 1
            language_stats[lang]['issues'] += len(file_result.issues)
            language_stats[lang]['lines_of_code'] += file_result.metrics.get('lines_of_code', 0)
        
        summary['language_breakdown'] = language_stats
        
        # Add top issues
        all_issues = scan_result.get_all_issues()
        rule_counts = {}
        for issue in all_issues:
            rule_counts[issue.rule_id] = rule_counts.get(issue.rule_id, 0) + 1
        
        top_issues = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        summary['top_issues'] = [{'rule_id': rule, 'count': count} for rule, count in top_issues]
        
        return summary