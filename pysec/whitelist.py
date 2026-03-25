"""
False Positive Whitelist - Config to ignore known safe patterns
"""

import json
from pathlib import Path
from typing import Optional


DEFAULT_WHITELIST = {
    "patterns": [
        r".*test.*",
        r".*example.*",
        r".*mock.*",
        r".*fake.*",
        r".*placeholder.*"
    ],
    "files": [
        r".*test\.py$",
        r".*_test\.py$",
        r".*\.example\..*$",
        r".*\/mocks\/.*",
        r".*\/fixtures\/.*"
    ],
    "rules": [
        "vulnerable_dependency:click",
        "vulnerable_dependency:rich"
    ],
    "locations": [
        "pysec/__pycache__",
        ".git/",
        "node_modules/",
        "venv/",
        ".venv/"
    ]
}


class Whitelist:
    def __init__(self, config_file: str = None):
        self.config = DEFAULT_WHITELIST.copy()
        
        if config_file and Path(config_file).exists():
            try:
                user_config = json.loads(Path(config_file).read_text())
                self._merge_config(user_config)
            except:
                pass
    
    def _merge_config(self, user_config: dict):
        """Merge user config with defaults"""
        for key in ["patterns", "files", "rules", "locations"]:
            if key in user_config:
                if isinstance(user_config[key], list):
                    self.config[key].extend(user_config[key])
    
    def should_ignore_pattern(self, pattern: str) -> bool:
        """Check if pattern matches whitelist"""
        import re
        for whitelisted in self.config.get("patterns", []):
            if re.match(whitelisted, pattern, re.IGNORECASE):
                return True
        return False
    
    def should_ignore_file(self, filepath: str) -> bool:
        """Check if file matches whitelist"""
        import re
        for whitelisted in self.config.get("files", []):
            if re.search(whitelisted, filepath, re.IGNORECASE):
                return True
        return False
    
    def should_ignore_rule(self, rule: str) -> bool:
        """Check if rule is whitelisted"""
        return rule in self.config.get("rules", [])
    
    def should_ignore_location(self, location: str) -> bool:
        """Check if location is in ignored paths"""
        for ignored in self.config.get("locations", []):
            if ignored in location:
                return True
        return False
    
    def filter_results(self, results: list[dict]) -> list[dict]:
        """Filter out whitelisted results"""
        filtered = []
        
        for result in results:
            location = result.get("location", "")
            
            if self.should_ignore_location(location):
                continue
            
            if self.should_ignore_file(location):
                continue
            
            rule_type = result.get("type", "")
            if self.should_ignore_rule(rule_type):
                continue
            
            filtered.append(result)
        
        return filtered
    
    def add_pattern(self, pattern: str):
        """Add pattern to whitelist"""
        self.config["patterns"].append(pattern)
    
    def add_file(self, filepath: str):
        """Add file pattern to whitelist"""
        self.config["files"].append(filepath)
    
    def add_rule(self, rule: str):
        """Add rule to whitelist"""
        self.config["rules"].append(rule)
    
    def save(self, config_file: str):
        """Save whitelist config"""
        Path(config_file).write_text(json.dumps(self.config, indent=2))


def load_whitelist(config_file: str = None) -> Whitelist:
    """Load whitelist from config file"""
    return Whitelist(config_file)