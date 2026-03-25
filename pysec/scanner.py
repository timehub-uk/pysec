import os
import re
from pathlib import Path
from pysec.deps import scan_dependencies
from pysec.code import scan_code_vulnerabilities
from pysec.secrets import scan_secrets
from pysec.config import scan_config_files


class Scanner:
    def __init__(self, path="."):
        self.path = Path(path)
    
    def scan(self):
        results = []
        
        results.extend(scan_dependencies(self.path))
        results.extend(scan_code_vulnerabilities(self.path))
        results.extend(scan_secrets(self.path))
        results.extend(scan_config_files(self.path))
        
        return results