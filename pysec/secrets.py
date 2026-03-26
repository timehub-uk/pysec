import re
from pathlib import Path


SECRET_PATTERNS = {
    "api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"](?!env|var|\$\{|example|test|xxx)[a-zA-Z0-9]{20,})['\"]",
        "severity": "critical",
        "description": "Potential API key detected",
        "redaction": "api_key=***"
    },
    "aws_key": {
        "pattern": r"(?i)(aws[_-]?(access[_-]?key|secret)[_-]?(id|key)?)\s*[=:]\s*['\"](?!env|var|\$\{|example|test)[A-Z0-9]{20,})['\"]",
        "severity": "critical",
        "description": "Potential AWS credentials detected",
        "redaction": "aws_access_key_id=***"
    },
    "github_token": {
        "pattern": r"(?i)(github[_-]?token|ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}",
        "severity": "critical",
        "description": "Potential GitHub token detected",
        "redaction": "github_token=***"
    },
    "password": {
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"](?!env|var|\$\{|example|test|xxx)[^'\"]+)['\"]",
        "severity": "critical",
        "description": "Hardcoded password detected",
        "redaction": "password=***"
    },
    "private_key": {
        "pattern": r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PRIVATE|PGP)\s+PRIVATE\s+KEY-----",
        "severity": "critical",
        "description": "Private key detected",
        "redaction": "-----BEGIN PRIVATE KEY-----"
    },
    "jwt_token": {
        "pattern": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        "severity": "high",
        "description": "Potential JWT token detected",
        "redaction": "jwt=***"
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
        "severity": "critical",
        "description": "Slack token detected",
        "redaction": "xoxb-***"
    },
    "stripe_key": {
        "pattern": r"(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "description": "Stripe API key detected",
        "redaction": "sk_live_***"
    },
    "sendgrid_key": {
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "critical",
        "description": "SendGrid API key detected",
        "redaction": "SG.***"
    },
    "twilio_key": {
        "pattern": r"SK[a-f0-9]{32}",
        "severity": "critical",
        "description": "Twilio API key detected",
        "redaction": "SK***"
    },
    "database_url": {
        "pattern": r"(mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@[a-zA-Z0-9.-]+",
        "severity": "high",
        "description": "Database connection URL with credentials",
        "redaction": "postgresql://user:***@host"
    },
    "ssh_key": {
        "pattern": r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
        "severity": "critical",
        "description": "SSH private key detected",
        "redaction": "-----BEGIN OPENSSH PRIVATE KEY-----"
    },
    "google_api": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "critical",
        "description": "Google API key detected",
        "redaction": "AIza***"
    }
}


IGNORE_PATTERNS = [
    r"/test[s]?/",
    r"/example[s]?/",
    r"/mock/",
    r"/fake/",
    r"_test\.py$",
    r"\.example$",
    r"example_",
    r"placeholder",
    r"xxx+",
    r"###",
]


def should_ignore(filepath):
    for pattern in IGNORE_PATTERNS:
        if re.search(pattern, str(filepath), re.IGNORECASE):
            return True
    return False


def scan_secrets(path, skip_test=False, skip_example=False, ignore_patterns=None):
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
    
    test_patterns = ('test_', '_test.py', '/tests/', '/test_', 'conftest.py')
    example_patterns = ('/example', '/demo', '/doc', '/docs/', '/sample', '/sample_')
    
    extensions = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env", ".sh", ".txt", ".conf", ".config"}
    
    for ext in extensions:
        for filepath in path.rglob(f"*{ext}"):
            if any(skip in str(filepath) for skip in ["node_modules", ".git", "__pycache__", "venv", ".venv"]):
                continue
            
            if skip_test and any(p in str(filepath) for p in test_patterns):
                continue
            
            if skip_example and any(p in str(filepath) for p in example_patterns):
                continue
            
            if check_ignore(str(filepath), ignore_patterns):
                continue
            
            try:
                content = filepath.read_text(errors="ignore")
                lines = content.split("\n")
                
                for secret_type, info in SECRET_PATTERNS.items():
                    for match in re.finditer(info["pattern"], content):
                        line_num = content[:match.start()].count("\n") + 1
                        key = f"{secret_type}:{filepath}:{line_num}"
                        
                        if key not in seen:
                            seen.add(key)
                            snippet = lines[line_num - 1].strip()[:80]
                            results.append({
                                "type": "secret_leak",
                                "severity": info["severity"],
                                "description": info["description"],
                                "redaction": info["redaction"],
                                "location": f"{filepath}:{line_num}",
                                "snippet": snippet
                            })
            except Exception:
                pass
    
    return results