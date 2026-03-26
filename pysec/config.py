import re
from pathlib import Path


CONFIG_VULNERABILITIES = {
    "exposed_secret": {
        "pattern": r"(SECRET|TOKEN|KEY|PASSWORD|API_KEY)\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "severity": "high",
        "description": "Secret exposed in configuration file"
    },
    "debug_true": {
        "pattern": r"(DEBUG|DEBUG_MODE)\s*=\s*['\"]?(True|true|1)['\"]?",
        "severity": "medium",
        "description": "Debug mode enabled in configuration"
    },
    "insecure_cookie": {
        "pattern": r"(SESSION_COOKIE|SECURE_COOKIE)\s*=\s*['\"]?(False|false|0)['\"]?",
        "severity": "medium",
        "description": "Insecure cookie configuration"
    },
    "cors_allow_all": {
        "pattern": r"(CORS_ALLOW_ORIGINS|CORS_ORIGINS)\s*=\s*['\"]?\*['\"]?",
        "severity": "medium",
        "description": "CORS allows all origins"
    },
    "ssl_disabled": {
        "pattern": r"(SSL|CERTIFICATE|VERIFY)\s*=\s*['\"]?(False|false|0)['\"]?",
        "severity": "high",
        "description": "SSL/TLS verification disabled"
    },
    "weak_algorithm": {
        "pattern": r"(ALGORITHM|CRYPTO_METHOD)\s*=\s*['\"]?(MD5|SHA1|DES)['\"]?",
        "severity": "medium",
        "description": "Weak cryptographic algorithm configured"
    }
}


def scan_config_files(path, skip_example=False, ignore_patterns=None):
    results = []
    seen = set()
    
    if ignore_patterns is None:
        ignore_patterns = []
    
    import fnmatch
    def check_ignore(filepath_str, patterns):
        for pattern in patterns:
            if pattern in filepath_str:
                return True
            if pattern.endswith("/") and pattern.rstrip("/") in filepath_str:
                return True
            if "*" in pattern:
                if fnmatch.fnmatch(filepath_str, pattern):
                    return True
        return False
    
    example_patterns = ('/example', '/demo', '/doc', '/docs/', '/sample', '/sample_')
    
    config_files = [
        "*.env",
        ".env*",
        "*.config",
        "*.conf",
        "settings.py",
        "config.py",
        "configuration.py",
        "*/settings.py",
        "*/config.py",
    ]
    
    config_extensions = {".py", ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf"}
    
    for ext in config_extensions:
        for filepath in path.rglob(f"*{ext}"):
            if any(skip in str(filepath) for skip in [".git", "venv", ".venv", "node_modules"]):
                continue
            
            if skip_example and any(p in str(filepath) for p in example_patterns):
                continue
            
            if check_ignore(str(filepath), ignore_patterns):
                continue
            
            try:
                content = filepath.read_text(errors="ignore")
                lines = content.split("\n")
                
                for vuln_type, info in CONFIG_VULNERABILITIES.items():
                    for match in re.finditer(info["pattern"], content, re.IGNORECASE):
                        line_num = content[:match.start()].count("\n") + 1
                        key = f"{vuln_type}:{filepath}:{line_num}"
                        
                        if key not in seen:
                            seen.add(key)
                            results.append({
                                "type": vuln_type,
                                "severity": info["severity"],
                                "description": info["description"],
                                "location": f"{filepath}:{line_num}"
                            })
            except Exception:
                pass
    
    return results