"""Language detection for code files."""

import os
import re
from typing import Dict, Optional, List, Set
from pathlib import Path
import chardet


class LanguageDetector:
    """Detects programming language from file extension and content."""
    
    # File extension mappings
    EXTENSION_MAP = {
        # Python
        '.py': 'python',
        '.pyw': 'python',
        '.pyi': 'python',
        
        # JavaScript/TypeScript
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        
        # Java
        '.java': 'java',
        '.class': 'java',
        '.jar': 'java',
        
        # C/C++
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cxx': 'cpp',
        '.cc': 'cpp',
        '.hpp': 'cpp',
        '.hxx': 'cpp',
        '.hh': 'cpp',
        
        # C#
        '.cs': 'csharp',
        '.csx': 'csharp',
        
        # Go
        '.go': 'go',
        
        # Rust
        '.rs': 'rust',
        
        # PHP
        '.php': 'php',
        '.phtml': 'php',
        '.php3': 'php',
        '.php4': 'php',
        '.php5': 'php',
        '.phps': 'php',
        
        # Ruby
        '.rb': 'ruby',
        '.rbw': 'ruby',
        
        # Swift
        '.swift': 'swift',
        
        # Kotlin
        '.kt': 'kotlin',
        '.kts': 'kotlin',
        
        # Scala
        '.scala': 'scala',
        '.sc': 'scala',
        
        # Shell
        '.sh': 'shell',
        '.bash': 'shell',
        '.zsh': 'shell',
        '.fish': 'shell',
        
        # PowerShell
        '.ps1': 'powershell',
        '.psm1': 'powershell',
        '.psd1': 'powershell',
        
        # Perl
        '.pl': 'perl',
        '.pm': 'perl',
        '.pod': 'perl',
        
        # R
        '.r': 'r',
        '.R': 'r',
        
        # MATLAB
        '.m': 'matlab',
        
        # SQL
        '.sql': 'sql',
        
        # HTML/XML
        '.html': 'html',
        '.htm': 'html',
        '.xhtml': 'html',
        '.xml': 'xml',
        
        # CSS
        '.css': 'css',
        '.scss': 'scss',
        '.sass': 'sass',
        '.less': 'less',
        
        # Configuration files
        '.json': 'json',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.toml': 'toml',
        '.ini': 'ini',
        '.cfg': 'ini',
        '.conf': 'config',
        
        # Dockerfile
        '.dockerfile': 'dockerfile',
        
        # Makefile
        '.mk': 'makefile',
    }
    
    # Content-based detection patterns
    CONTENT_PATTERNS = {
        'python': [
            re.compile(r'#!/usr/bin/env python'),
            re.compile(r'#!/usr/bin/python'),
            re.compile(r'#.*coding[:=]\s*(utf-8|latin-1)'),
            re.compile(r'from\s+\w+\s+import'),
            re.compile(r'import\s+\w+'),
            re.compile(r'def\s+\w+\s*\('),
            re.compile(r'class\s+\w+\s*\('),
        ],
        'javascript': [
            re.compile(r'#!/usr/bin/env node'),
            re.compile(r'function\s+\w+\s*\('),
            re.compile(r'var\s+\w+\s*='),
            re.compile(r'let\s+\w+\s*='),
            re.compile(r'const\s+\w+\s*='),
            re.compile(r'require\s*\('),
            re.compile(r'module\.exports'),
        ],
        'java': [
            re.compile(r'package\s+[\w.]+'),
            re.compile(r'import\s+[\w.]+'),
            re.compile(r'public\s+class\s+\w+'),
            re.compile(r'public\s+static\s+void\s+main'),
        ],
        'c': [
            re.compile(r'#include\s*<[^>]+>'),
            re.compile(r'int\s+main\s*\('),
            re.compile(r'printf\s*\('),
            re.compile(r'scanf\s*\('),
        ],
        'cpp': [
            re.compile(r'#include\s*<[^>]+>'),
            re.compile(r'using\s+namespace'),
            re.compile(r'std::'),
            re.compile(r'class\s+\w+'),
        ],
        'go': [
            re.compile(r'package\s+\w+'),
            re.compile(r'import\s*\('),
            re.compile(r'func\s+\w+\s*\('),
            re.compile(r'fmt\.Print'),
        ],
        'rust': [
            re.compile(r'fn\s+\w+\s*\('),
            re.compile(r'use\s+\w+'),
            re.compile(r'struct\s+\w+'),
            re.compile(r'impl\s+\w+'),
        ],
        'shell': [
            re.compile(r'#!/bin/bash'),
            re.compile(r'#!/bin/sh'),
            re.compile(r'#!/usr/bin/env bash'),
        ],
    }
    
    # Special filename patterns
    FILENAME_PATTERNS = {
        'dockerfile': [
            re.compile(r'^Dockerfile$', re.IGNORECASE),
            re.compile(r'^Dockerfile\..+$', re.IGNORECASE),
        ],
        'makefile': [
            re.compile(r'^Makefile$', re.IGNORECASE),
            re.compile(r'^makefile$', re.IGNORECASE),
            re.compile(r'^.*\.mk$', re.IGNORECASE),
        ],
        'shell': [
            re.compile(r'^.*rc$'),  # .bashrc, .zshrc, etc.
            re.compile(r'^.*profile$'),
        ],
        'yaml': [
            re.compile(r'^.*\.ya?ml$', re.IGNORECASE),
            re.compile(r'^docker-compose.*\.ya?ml$', re.IGNORECASE),
        ],
    }
    
    def __init__(self):
        """Initialize the language detector."""
        self.supported_languages = set(self.EXTENSION_MAP.values())
        self.supported_languages.update(self.CONTENT_PATTERNS.keys())
        self.supported_languages.update(self.FILENAME_PATTERNS.keys())
    
    def detect_language(self, file_path: str) -> Optional[str]:
        """
        Detect the programming language of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Detected language or None if unknown
        """
        file_path = Path(file_path)
        
        # First, try extension-based detection
        language = self._detect_by_extension(file_path)
        if language:
            return language
        
        # Then try filename pattern detection
        language = self._detect_by_filename(file_path)
        if language:
            return language
        
        # Finally, try content-based detection
        try:
            language = self._detect_by_content(file_path)
            if language:
                return language
        except (OSError, UnicodeDecodeError, PermissionError):
            # If we can't read the file, fall back to unknown
            pass
        
        return None
    
    def _detect_by_extension(self, file_path: Path) -> Optional[str]:
        """Detect language by file extension."""
        extension = file_path.suffix.lower()
        return self.EXTENSION_MAP.get(extension)
    
    def _detect_by_filename(self, file_path: Path) -> Optional[str]:
        """Detect language by filename patterns."""
        filename = file_path.name
        
        for language, patterns in self.FILENAME_PATTERNS.items():
            for pattern in patterns:
                if pattern.match(filename):
                    return language
        
        return None
    
    def _detect_by_content(self, file_path: Path) -> Optional[str]:
        """Detect language by file content."""
        try:
            # Read file with encoding detection
            with open(file_path, 'rb') as f:
                raw_content = f.read(8192)  # Read first 8KB
            
            # Detect encoding
            encoding_result = chardet.detect(raw_content)
            encoding = encoding_result.get('encoding', 'utf-8')
            
            if not encoding:
                return None
            
            # Decode content
            try:
                content = raw_content.decode(encoding)
            except UnicodeDecodeError:
                content = raw_content.decode('utf-8', errors='ignore')
            
            # Check content patterns
            for language, patterns in self.CONTENT_PATTERNS.items():
                matches = 0
                for pattern in patterns:
                    if pattern.search(content):
                        matches += 1
                
                # If we find multiple patterns, it's likely this language
                if matches >= 2:
                    return language
                # For some languages, even one strong pattern is enough
                elif matches >= 1 and language in ['python', 'shell']:
                    return language
            
        except Exception:
            # If anything fails, return None
            pass
        
        return None
    
    def get_supported_languages(self) -> Set[str]:
        """Get set of supported languages."""
        return self.supported_languages.copy()
    
    def is_supported(self, language: str) -> bool:
        """Check if a language is supported."""
        return language in self.supported_languages
    
    def get_file_extensions(self, language: str) -> List[str]:
        """Get file extensions for a given language."""
        extensions = []
        for ext, lang in self.EXTENSION_MAP.items():
            if lang == language:
                extensions.append(ext)
        return extensions
    
    def is_code_file(self, file_path: str) -> bool:
        """Check if a file is a code file."""
        return self.detect_language(file_path) is not None
    
    def filter_code_files(self, file_paths: List[str]) -> List[str]:
        """Filter a list of file paths to only include code files."""
        return [path for path in file_paths if self.is_code_file(path)]