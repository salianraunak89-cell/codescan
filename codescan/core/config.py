"""Configuration management for CodeScan."""

import os
import yaml
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class AnalyzerConfig:
    """Configuration for a specific analyzer."""
    enabled: bool = True
    severity_level: str = "medium"  # low, medium, high, critical
    rules: Dict[str, Any] = field(default_factory=dict)
    exclude_patterns: List[str] = field(default_factory=list)


@dataclass
class ScanConfig:
    """Main scan configuration."""
    
    # General settings
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    timeout_per_file: int = 30  # seconds
    parallel_workers: int = 4
    
    # File filtering
    include_patterns: List[str] = field(default_factory=lambda: ["**/*"])
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "**/.git/**",
        "**/node_modules/**",
        "**/__pycache__/**",
        "**/.venv/**",
        "**/venv/**",
        "**/.env/**",
        "**/build/**",
        "**/dist/**",
        "**/*.min.js",
        "**/*.min.css",
        "**/*.map",
    ])
    
    # Language settings
    enabled_languages: Set[str] = field(default_factory=lambda: {
        "python", "javascript", "typescript", "java", "c", "cpp",
        "go", "rust", "php", "ruby", "csharp", "swift", "kotlin"
    })
    
    # Analyzer configurations
    analyzers: Dict[str, AnalyzerConfig] = field(default_factory=dict)
    
    # Security scanning
    security_scan: bool = True
    dependency_scan: bool = True
    
    # Best practices
    best_practices: bool = True
    code_style: bool = True
    complexity_analysis: bool = True
    
    # Output settings
    output_format: str = "json"  # json, html, text, sarif
    output_file: Optional[str] = None
    verbose: bool = False
    
    def __post_init__(self):
        """Initialize default analyzer configurations."""
        if not self.analyzers:
            self._setup_default_analyzers()
    
    def _setup_default_analyzers(self):
        """Set up default analyzer configurations."""
        # Python analyzers
        self.analyzers["python"] = AnalyzerConfig(
            enabled=True,
            severity_level="medium",
            rules={
                "max_line_length": 88,
                "max_complexity": 10,
                "check_docstrings": True,
                "check_type_hints": True,
                "check_imports": True,
            }
        )
        
        # JavaScript/TypeScript analyzers
        self.analyzers["javascript"] = AnalyzerConfig(
            enabled=True,
            severity_level="medium",
            rules={
                "max_line_length": 100,
                "max_complexity": 15,
                "check_console_logs": True,
                "check_unused_vars": True,
                "prefer_const": True,
            }
        )
        
        self.analyzers["typescript"] = AnalyzerConfig(
            enabled=True,
            severity_level="medium",
            rules={
                "strict_null_checks": True,
                "no_any": True,
                "explicit_return_types": True,
            }
        )
        
        # Security analyzers
        self.analyzers["security"] = AnalyzerConfig(
            enabled=self.security_scan,
            severity_level="high",
            rules={
                "check_sql_injection": True,
                "check_xss": True,
                "check_hardcoded_secrets": True,
                "check_weak_crypto": True,
                "check_path_traversal": True,
            }
        )
        
        # Best practices analyzer
        self.analyzers["best_practices"] = AnalyzerConfig(
            enabled=self.best_practices,
            severity_level="medium",
            rules={
                "check_naming_conventions": True,
                "check_function_length": True,
                "check_class_design": True,
                "check_error_handling": True,
            }
        )


class Config:
    """Configuration manager for CodeScan."""
    
    DEFAULT_CONFIG_PATHS = [
        ".codescan.yaml",
        ".codescan.yml",
        "codescan.yaml",
        "codescan.yml",
        "pyproject.toml",  # For [tool.codescan] section
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_path: Path to configuration file, or None to auto-discover
        """
        self.config = ScanConfig()
        self.config_path = config_path
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file."""
        config_file = self._find_config_file()
        if config_file:
            self._load_from_file(config_file)
        
        # Override with environment variables
        self._load_from_env()
    
    def _find_config_file(self) -> Optional[Path]:
        """Find configuration file."""
        if self.config_path:
            config_file = Path(self.config_path)
            if config_file.exists():
                return config_file
            else:
                raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        # Look for config files in current directory and parents
        current_dir = Path.cwd()
        for parent in [current_dir] + list(current_dir.parents):
            for config_name in self.DEFAULT_CONFIG_PATHS:
                config_file = parent / config_name
                if config_file.exists():
                    return config_file
        
        return None
    
    def _load_from_file(self, config_file: Path):
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.suffix == '.toml':
                    # Handle pyproject.toml
                    try:
                        import tomllib
                    except ImportError:
                        import tomli as tomllib
                    data = tomllib.load(f)
                    config_data = data.get('tool', {}).get('codescan', {})
                else:
                    # Handle YAML files
                    config_data = yaml.safe_load(f) or {}
            
            self._update_config_from_dict(config_data)
            
        except Exception as e:
            print(f"Warning: Failed to load config from {config_file}: {e}")
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        env_mappings = {
            'CODESCAN_MAX_FILE_SIZE': ('max_file_size', int),
            'CODESCAN_TIMEOUT': ('timeout_per_file', int),
            'CODESCAN_WORKERS': ('parallel_workers', int),
            'CODESCAN_OUTPUT_FORMAT': ('output_format', str),
            'CODESCAN_OUTPUT_FILE': ('output_file', str),
            'CODESCAN_VERBOSE': ('verbose', lambda x: x.lower() in ('true', '1', 'yes')),
        }
        
        for env_var, (attr_name, type_converter) in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                try:
                    setattr(self.config, attr_name, type_converter(env_value))
                except ValueError:
                    print(f"Warning: Invalid value for {env_var}: {env_value}")
    
    def _update_config_from_dict(self, config_data: Dict[str, Any]):
        """Update configuration from dictionary."""
        # Update basic settings
        for key, value in config_data.items():
            if hasattr(self.config, key) and key != 'analyzers':
                if key in ['include_patterns', 'exclude_patterns']:
                    # Handle list fields
                    setattr(self.config, key, value)
                elif key == 'enabled_languages':
                    # Handle set fields
                    setattr(self.config, key, set(value))
                else:
                    setattr(self.config, key, value)
        
        # Update analyzer configurations
        if 'analyzers' in config_data:
            for analyzer_name, analyzer_config in config_data['analyzers'].items():
                if analyzer_name not in self.config.analyzers:
                    self.config.analyzers[analyzer_name] = AnalyzerConfig()
                
                analyzer = self.config.analyzers[analyzer_name]
                for key, value in analyzer_config.items():
                    setattr(analyzer, key, value)
    
    def get_analyzer_config(self, analyzer_name: str) -> AnalyzerConfig:
        """Get configuration for a specific analyzer."""
        return self.config.analyzers.get(analyzer_name, AnalyzerConfig())
    
    def is_analyzer_enabled(self, analyzer_name: str) -> bool:
        """Check if an analyzer is enabled."""
        return self.get_analyzer_config(analyzer_name).enabled
    
    def is_language_enabled(self, language: str) -> bool:
        """Check if a language is enabled for scanning."""
        return language in self.config.enabled_languages
    
    def should_exclude_file(self, file_path: str) -> bool:
        """Check if a file should be excluded from scanning."""
        from pathspec import PathSpec
        
        # Convert to relative path for pattern matching
        try:
            rel_path = os.path.relpath(file_path)
        except ValueError:
            rel_path = file_path
        
        # Check exclude patterns
        exclude_spec = PathSpec.from_lines('gitwildmatch', self.config.exclude_patterns)
        if exclude_spec.match_file(rel_path):
            return True
        
        # Check include patterns (if file doesn't match any include pattern, exclude it)
        include_spec = PathSpec.from_lines('gitwildmatch', self.config.include_patterns)
        if not include_spec.match_file(rel_path):
            return True
        
        return False
    
    def export_config(self, output_path: str):
        """Export current configuration to file."""
        config_dict = {
            'max_file_size': self.config.max_file_size,
            'timeout_per_file': self.config.timeout_per_file,
            'parallel_workers': self.config.parallel_workers,
            'include_patterns': self.config.include_patterns,
            'exclude_patterns': self.config.exclude_patterns,
            'enabled_languages': list(self.config.enabled_languages),
            'security_scan': self.config.security_scan,
            'dependency_scan': self.config.dependency_scan,
            'best_practices': self.config.best_practices,
            'code_style': self.config.code_style,
            'complexity_analysis': self.config.complexity_analysis,
            'output_format': self.config.output_format,
            'verbose': self.config.verbose,
            'analyzers': {}
        }
        
        for name, analyzer in self.config.analyzers.items():
            config_dict['analyzers'][name] = {
                'enabled': analyzer.enabled,
                'severity_level': analyzer.severity_level,
                'rules': analyzer.rules,
                'exclude_patterns': analyzer.exclude_patterns,
            }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)