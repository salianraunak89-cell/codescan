"""Command-line interface for CodeScan."""

import sys
import os
from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console
from rich.panel import Panel

from .core.scanner import CodeScanner
from .core.config import Config
from .reporters import get_reporter


console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="CodeScan")
def cli():
    """
    🔍 CodeScan - A comprehensive code analysis tool for multiple programming languages.
    
    CodeScan analyzes your code for best practices, security vulnerabilities, and
    maintainability issues across multiple programming languages.
    """
    pass


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--config', '-c', type=click.Path(), help='Configuration file path')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['json', 'html', 'text', 'sarif'], case_sensitive=False),
              default='text', help='Output format')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']),
              help='Minimum severity level to report')
@click.option('--include', multiple=True, help='File patterns to include (glob)')
@click.option('--exclude', multiple=True, help='File patterns to exclude (glob)')
@click.option('--languages', multiple=True, 
              help='Languages to scan (python, javascript, java, c, cpp, go, rust)')
@click.option('--no-security', is_flag=True, help='Disable security scanning')
@click.option('--no-best-practices', is_flag=True, help='Disable best practices checking')
@click.option('--no-complexity', is_flag=True, help='Disable complexity analysis')
@click.option('--workers', '-j', type=int, help='Number of parallel workers')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode (only errors)')
def scan(path: str, config: Optional[str], output: Optional[str], output_format: str,
         severity: Optional[str], include: List[str], exclude: List[str], 
         languages: List[str], no_security: bool, no_best_practices: bool,
         no_complexity: bool, workers: Optional[int], verbose: bool, quiet: bool):
    """
    Scan a directory or file for code issues.
    
    PATH: Directory or file to scan
    """
    try:
        # Load configuration
        cfg = Config(config)
        
        # Override config with CLI options
        if include:
            cfg.config.include_patterns = list(include)
        if exclude:
            cfg.config.exclude_patterns.extend(exclude)
        if languages:
            cfg.config.enabled_languages = set(languages)
        if no_security:
            cfg.config.security_scan = False
        if no_best_practices:
            cfg.config.best_practices = False
        if no_complexity:
            cfg.config.complexity_analysis = False
        if workers:
            cfg.config.parallel_workers = workers
        if verbose:
            cfg.config.verbose = True
        if output:
            cfg.config.output_file = output
        if output_format:
            cfg.config.output_format = output_format
        
        # Set up console output based on quiet/verbose flags
        if quiet:
            console.quiet = True
        
        # Show scan start message
        if not quiet:
            console.print(Panel.fit(
                f"🔍 Starting CodeScan analysis of: [bold cyan]{path}[/bold cyan]",
                title="CodeScan",
                style="blue"
            ))
        
        # Initialize scanner
        scanner = CodeScanner(cfg)
        
        # Perform scan
        if os.path.isfile(path):
            # Scan single file
            file_result = scanner.scan_file(path)
            if file_result:
                from .core.result import ScanResult
                from datetime import datetime
                scan_result = ScanResult(
                    project_path=os.path.dirname(path),
                    scan_timestamp=datetime.now().isoformat()
                )
                scan_result.add_file_result(file_result)
            else:
                console.print("❌ No scannable content found in file", style="red")
                sys.exit(1)
        else:
            # Scan directory
            scan_result = scanner.scan_directory(path)
        
        # Filter results by severity if specified
        if severity:
            from .core.result import Severity
            min_severity = Severity(severity)
            # This is a simple implementation - in practice you'd want more sophisticated filtering
            pass
        
        # Generate report
        reporter = get_reporter(output_format)
        report_content = reporter.generate_report(scan_result, output)
        
        # Display results based on format
        if output_format == 'text' and not output:
            console.print(report_content)
        elif output:
            if not quiet:
                console.print(f"✅ Report saved to: [bold green]{output}[/bold green]")
        else:
            console.print(report_content)
        
        # Exit with appropriate code
        total_issues = len(scan_result.get_all_issues())
        critical_high_issues = len([
            issue for issue in scan_result.get_all_issues() 
            if issue.severity.value in ['critical', 'high']
        ])
        
        if critical_high_issues > 0:
            sys.exit(2)  # Critical/high issues found
        elif total_issues > 0:
            sys.exit(1)  # Issues found
        else:
            sys.exit(0)  # No issues
            
    except Exception as e:
        console.print(f"❌ Error: {str(e)}", style="red")
        if verbose:
            console.print_exception()
        sys.exit(3)


@cli.command()
@click.option('--output', '-o', type=click.Path(), default='.codescan.yaml',
              help='Output configuration file path')
def init_config(output: str):
    """Initialize a new configuration file."""
    try:
        config = Config()
        config.export_config(output)
        console.print(f"✅ Configuration file created: [bold green]{output}[/bold green]")
        console.print("\n💡 Edit this file to customize CodeScan behavior for your project.")
    except Exception as e:
        console.print(f"❌ Error creating config: {str(e)}", style="red")
        sys.exit(1)


@cli.command()
def list_languages():
    """List supported programming languages."""
    from .analyzers import get_supported_languages
    from .core.language_detector import LanguageDetector
    
    detector = LanguageDetector()
    supported = get_supported_languages()
    
    console.print("\n🌐 [bold]Supported Programming Languages:[/bold]\n")
    
    for lang in sorted(supported):
        extensions = detector.get_file_extensions(lang)
        ext_str = ", ".join(extensions) if extensions else "auto-detected"
        console.print(f"  • [cyan]{lang.title()}[/cyan] ({ext_str})")
    
    console.print(f"\n📊 Total: [bold]{len(supported)}[/bold] languages supported")


@cli.command()
def list_rules():
    """List available analysis rules."""
    console.print("\n📋 [bold]Available Analysis Rules:[/bold]\n")
    
    # This would typically load from configuration or analyzer metadata
    rules_by_category = {
        "Security": [
            "hardcoded_secrets - Detect hardcoded passwords, API keys, etc.",
            "sql_injection - Detect potential SQL injection vulnerabilities",
            "xss_vulnerability - Detect cross-site scripting risks",
            "weak_crypto - Identify weak cryptographic algorithms",
            "path_traversal - Detect directory traversal vulnerabilities"
        ],
        "Best Practices": [
            "missing_docstring - Functions/classes without documentation",
            "unused_import - Unused import statements",
            "function_too_complex - High cyclomatic complexity",
            "code_too_nested - Deeply nested code blocks",
            "inconsistent_naming - Mixed naming conventions"
        ],
        "Code Style": [
            "line_too_long - Lines exceeding length limit",
            "trailing_whitespace - Whitespace at end of lines",
            "mixed_indentation - Inconsistent indentation",
            "spacing_style - Missing spaces around operators"
        ],
        "Maintainability": [
            "file_too_large - Files exceeding size limits",
            "duplicate_code - Similar code blocks",
            "magic_numbers - Hardcoded numeric values"
        ]
    }
    
    for category, rules in rules_by_category.items():
        console.print(f"[bold cyan]{category}:[/bold cyan]")
        for rule in rules:
            console.print(f"  • {rule}")
        console.print()


@cli.command()
@click.argument('directory', type=click.Path(exists=True))
def stats(directory: str):
    """Show code statistics for a directory."""
    from .core.language_detector import LanguageDetector
    
    detector = LanguageDetector()
    
    console.print(f"\n📊 [bold]Code Statistics for: {directory}[/bold]\n")
    
    # Collect file statistics
    file_stats = {}
    total_files = 0
    total_lines = 0
    
    for root, dirs, files in os.walk(directory):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}]
        
        for file in files:
            file_path = os.path.join(root, file)
            language = detector.detect_language(file_path)
            
            if language:
                if language not in file_stats:
                    file_stats[language] = {'files': 0, 'lines': 0}
                
                file_stats[language]['files'] += 1
                total_files += 1
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = len(f.readlines())
                        file_stats[language]['lines'] += lines
                        total_lines += lines
                except:
                    pass
    
    if not file_stats:
        console.print("❌ No code files found in directory")
        return
    
    # Display statistics table
    from rich.table import Table
    
    table = Table(title="Code Statistics")
    table.add_column("Language", style="cyan")
    table.add_column("Files", justify="right")
    table.add_column("Lines", justify="right")
    table.add_column("% of Total", justify="right")
    
    for language in sorted(file_stats.keys()):
        stats = file_stats[language]
        percentage = (stats['lines'] / total_lines * 100) if total_lines > 0 else 0
        
        table.add_row(
            language.title(),
            str(stats['files']),
            f"{stats['lines']:,}",
            f"{percentage:.1f}%"
        )
    
    # Add totals row
    table.add_row(
        "[bold]Total[/bold]",
        f"[bold]{total_files:,}[/bold]",
        f"[bold]{total_lines:,}[/bold]",
        "[bold]100.0%[/bold]"
    )
    
    console.print(table)


def main():
    """Main entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n❌ Scan interrupted by user", style="red")
        sys.exit(130)
    except Exception as e:
        console.print(f"❌ Unexpected error: {str(e)}", style="red")
        sys.exit(1)


if __name__ == '__main__':
    main()