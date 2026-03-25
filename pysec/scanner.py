import os
import re
from pathlib import Path
from pysec.deps import scan_dependencies
from pysec.code import scan_code_vulnerabilities
from pysec.secrets import scan_secrets
from pysec.config import scan_config_files


class Scanner:
    def __init__(self, path=".", full_scan=False):
        self.path = Path(path)
        self.full_scan = full_scan
    
    def scan(self):
        results = []
        
        results.extend(scan_dependencies(self.path))
        results.extend(scan_code_vulnerabilities(self.path))
        results.extend(scan_secrets(self.path))
        results.extend(scan_config_files(self.path))
        
        if self.full_scan:
            from pysec.iac import scan_iac
            from pysec.license import scan_licenses
            from pysec.privacy import scan_privacy
            from pysec.multilang import scan_multilang
            
            results.extend(scan_iac(self.path))
            results.extend(scan_licenses(self.path))
            results.extend(scan_privacy(self.path))
            results.extend(scan_multilang(self.path))
        
        return results