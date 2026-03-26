import os
import re
from pathlib import Path
from pysec.deps import scan_dependencies
from pysec.code import scan_code_vulnerabilities
from pysec.secrets import scan_secrets
from pysec.config import scan_config_files


def load_ignore_patterns(path):
    """Load ignore patterns from .pysecignore file"""
    ignore_file = Path(path) / ".pysecignore"
    patterns = []
    
    if ignore_file.exists():
        for line in ignore_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    
    return patterns


def should_ignore(filepath, patterns):
    """Check if filepath matches any ignore pattern"""
    filepath_str = str(filepath)
    
    for pattern in patterns:
        if pattern in filepath_str:
            return True
        if pattern.endswith("/") and pattern.rstrip("/") in filepath_str:
            return True
        if "*" in pattern:
            import fnmatch
            if fnmatch.fnmatch(filepath_str, pattern):
                return True
    
    return False


class Scanner:
    def __init__(self, path=".", full_scan=False, skip_test=False, skip_example=False, ignore_file=None):
        self.path = Path(path)
        self.full_scan = full_scan
        self.skip_test = skip_test
        self.skip_example = skip_example
        self.ignore_patterns = load_ignore_patterns(path) if ignore_file is None else ignore_file
    
    def scan(self):
        results = []
        
        results.extend(scan_dependencies(self.path, ignore_patterns=self.ignore_patterns))
        results.extend(scan_code_vulnerabilities(self.path, skip_test=self.skip_test, skip_example=self.skip_example, ignore_patterns=self.ignore_patterns))
        results.extend(scan_secrets(self.path, skip_test=self.skip_test, skip_example=self.skip_example, ignore_patterns=self.ignore_patterns))
        results.extend(scan_config_files(self.path, skip_example=self.skip_example, ignore_patterns=self.ignore_patterns))
        
        from pysec.multilang import scan_multilang
        results.extend(scan_multilang(self.path))
        
        if self.full_scan:
            from pysec.iac import scan_iac
            from pysec.license import scan_licenses
            from pysec.privacy import scan_privacy
            
            results.extend(scan_iac(self.path))
            results.extend(scan_licenses(self.path))
            results.extend(scan_privacy(self.path))
        
        return results