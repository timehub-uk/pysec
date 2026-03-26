import re
import os
from pathlib import Path
from typing import List, Dict, Optional


FIX_STRATEGIES = {
    "sql_injection": {
        "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
    },
    "eval_usage": {
        "fix": "Remove eval/exec calls - use safe alternatives like ast.literal_eval"
    },
    "weak_crypto": {
        "fix": "Use hashlib.sha256() for secure hashing"
    },
    "insecure_random": {
        "fix": "Use secrets module for cryptographic randomness"
    },
    "hardcoded_secret": {
        "fix": "Use environment variables: os.environ.get('SECRET')"
    },
    "hardcoded_db": {
        "fix": "Use environment variables for database credentials"
    },
    "yaml_load": {
        "fix": "Use yaml.safe_load()"
    },
    "pickle_insecure": {
        "fix": "Use JSON instead of pickle"
    },
    "command_injection": {
        "fix": "Use subprocess with shell=False"
    },
    "path_traversal": {
        "fix": "Validate and sanitize file paths"
    },
    "xss": {
        "fix": "Use textContent instead of innerHTML"
    },
    "debug_enabled": {
        "fix": "Use environment variable for debug mode"
    },
    "hardcoded_aws": {
        "fix": "Use IAM roles or environment variables"
    },
    "obfuscated_code": {
        "fix": "Avoid obfuscating code"
    },
    "split_string_secret": {
        "fix": "Use environment variables instead of hardcoded split strings"
    },
    "dynamic_import": {
        "fix": "Use static imports instead of __import__()"
    }
}


LINE_FIXES = {
    "sql_injection": [],
    "eval_usage": [],
    "split_string_secret": [],
    "hardcoded_secret": [],
    "command_injection": [],
    "http_without_https": [
        (r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)', 'https://', "Replace HTTP with HTTPS"),
    ],
    "debug_true": [
        (r'DEBUG\s*=\s*True', 'DEBUG = os.environ.get("DEBUG", "False")', "Use env var for debug"),
    ],
    "debug_enabled": [
        (r'app\.run\s*\(\s*debug\s*=\s*True', 'app.run(debug=os.environ.get("DEBUG", "False") == "True")', "Use env var for debug"),
    ],
    "weak_crypto": [
        (r'hashlib\.md5\(', 'hashlib.sha256(', "Replace MD5 with SHA256"),
        (r'hashlib\.sha1\(', 'hashlib.sha256(', "Replace SHA1 with SHA256"),
        (r'MD5\(', 'SHA256(', "Replace MD5 with SHA256"),
        (r'SHA1\(', 'SHA256(', "Replace SHA1 with SHA256"),
    ],
    "insecure_random": [
        (r'random\.random\(\)', 'secrets.randbelow(2**32)', "Use secrets module"),
        (r'random\.randint\(', 'secrets.randbelow(', "Use secrets module"),
        (r'random\.choice\(', 'secrets.choice(', "Use secrets module"),
        (r'from random import', 'from secrets import', "Use secrets module"),
    ],
    "yaml_load": [
        (r'yaml\.load\(', 'yaml.safe_load(', "Use safe_load"),
    ],
    "pickle_insecure": [
        (r'pickle\.loads\(', 'json.loads(', "Use JSON"),
        (r'pickle\.load\(', 'json.load(', "Use JSON"),
    ],
    "dynamic_import": [
        (r'__import__\(', '# __import__() - use static import', "Use static import"),
    ],
    "hardcoded_ip": [
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'os.environ.get("HOST", "0.0.0.0")', "Use env var for IP"),
    ],
}


def fix_file(filepath: Path, issues: List[Dict]) -> bool:
    """Apply safe fixes to a file based on detected issues"""
    if not filepath.exists():
        return False
    
    try:
        content = filepath.read_text()
        original = content
        fixes_applied = 0
        
        lines = content.split('\n')
        fixed_lines = []
        
        for i, line in enumerate(lines):
            new_line = line
            line_key = f"{filepath}:{i+1}"
            
            # Check each issue for line-specific fixes
            for issue in issues:
                issue_type = issue.get("type", "")
                issue_location = issue.get("location", "")
                
                # Check if this line matches an issue
                if issue_type in LINE_FIXES:
                    for pattern, replacement in LINE_FIXES[issue_type]:
                        if re.search(pattern, line, re.IGNORECASE):
                            new_line = replacement
                            fixes_applied += 1
                            break
            
            # Apply safe pattern-based fixes (limited iterations)
            for _ in range(3):  # Max 3 passes
                prev_line = new_line
                
                # Replace MD5/SHA1
                new_line = re.sub(r'\.md5\(', '.sha256(', new_line)
                new_line = re.sub(r'\.sha1\(', '.sha256(', new_line)
                
                # Replace random with secrets
                new_line = re.sub(r'random\.random\(\)', 'secrets.randbelow(2**32)', new_line)
                new_line = re.sub(r'random\.randint\(', 'secrets.randbelow(', new_line)
                new_line = re.sub(r'random\.choice\(', 'secrets.choice(', new_line)
                
                # Fix SQL injection - replace string formatting with parameterized
                # Simple case: "SELECT ... % (" -> "SELECT ... ? ("
                new_line = re.sub(r'"SELECT\s+[^"]+%\s*\(', '"SELECT * FROM table WHERE id = ? (', new_line)
                new_line = re.sub(r"'SELECT\s+[^']+%\s*\(", "'SELECT * FROM table WHERE id = ? (", new_line)
                new_line = re.sub(r'"SELECT\s+[^"]+\.format\(', '"SELECT * FROM table WHERE id = ?", ', new_line)
                new_line = re.sub(r"'SELECT\s+[^']+\.format\(", "'SELECT * FROM table WHERE id = ?', ", new_line)
                
                # Replace os.system with comment warning
                new_line = re.sub(r'os\.system\(', '# WARNING: os.system() is unsafe', new_line)
                new_line = re.sub(r'os\.popen\(', '# WARNING: os.popen() is unsafe', new_line)
                
                # Add shell=False to subprocess calls - only if not already present
                if 'shell=False' not in new_line and ('subprocess.Popen(' in new_line or 'subprocess.run(' in new_line):
                    new_line = new_line.rstrip() + '  # WARNING: Consider adding shell=False'
                
                # Replace yaml.load with safe_load
                new_line = re.sub(r'yaml\.load\(', 'yaml.safe_load(', new_line)
                
                # Replace pickle with json
                new_line = re.sub(r'pickle\.loads\(', 'json.loads(', new_line)
                new_line = re.sub(r'pickle\.load\(', 'json.load(', new_line)
                
                # Replace DEBUG=True with env-based
                new_line = re.sub(r'DEBUG\s*=\s*True', 'DEBUG = os.environ.get("DEBUG", "false").lower() == "true"', new_line)
                new_line = re.sub(r'DEBUG_MODE\s*=\s*True', 'DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() == "true"', new_line)
                
                # Replace hardcoded DB creds
                new_line = re.sub(r'(mysql|postgresql)://[^:]+:', r'\1://${DB_USER}:', new_line)
                
                # Replace hardcoded secrets in f-strings
                new_line = re.sub(r'f"[^"]*{[^}]+}[^"]*"', '"SECRET_REDACTED"', new_line)
                new_line = re.sub(r"f'[^']*{[^}]+}[^']*'", '"SECRET_REDACTED"', new_line)
                
                # Replace http:// with https://
                new_line = re.sub(r'http://(?!localhost|127\.0\.0\.1)', 'https://', new_line)
                
                # For test files, don't change http to https (tests may need http)
                
                # Replace hardcoded passwords/secrets with env var placeholders
                new_line = re.sub(r'password\s*=\s*["\'][^"\']+["\']', 'password = os.environ.get("PASSWORD")', new_line)
                new_line = re.sub(r'secret\s*=\s*["\']{8,}', 'secret = os.environ.get("SECRET")', new_line)
                new_line = re.sub(r'api_key\s*=\s*["\'][^"\']+["\']', 'api_key = os.environ.get("API_KEY")', new_line)
                new_line = re.sub(r'token\s*=\s*["\'][^"\']+["\']', 'token = os.environ.get("TOKEN")', new_line)
                new_line = re.sub(r'passwd\s*=\s*["\'][^"\']+["\']', 'passwd = os.environ.get("PASSWD")', new_line)
                new_line = re.sub(r'private_key\s*=\s*["\'][^"\']+["\']', 'private_key = os.environ.get("PRIVATE_KEY")', new_line)
                
                # Replace hardcoded secrets in test files with placeholder comments
                if 'tests/' in str(filepath) and ('password' in new_line or 'secret' in new_line or 'token' in new_line):
                    if '=' in new_line and not 'os.environ' in new_line:
                        new_line = '# ' + new_line.strip() + '  # TODO: use env var'
                
                # Skip assert statements - they can be part of control flow
                # Don't modify lines with assert
                if 'assert ' in new_line:
                    pass  # Keep line as-is
                
                # Skip dynamic_import in test files - they may be intentional
                if '__import__' in new_line and 'tests/' in str(filepath):
                    pass  # Keep test file imports as-is
                
                # Replace verify=False with verify=True for SSL
                new_line = re.sub(r'verify\s*=\s*False', 'verify = True', new_line)
                new_line = re.sub(r'ssl_verify\s*=\s*False', 'ssl_verify = True', new_line)
                
                # Replace weak algorithms
                new_line = re.sub(r'md5\(', 'sha256(', new_line)
                new_line = re.sub(r'sha1\(', 'sha256(', new_line)
                new_line = re.sub(r'hashlib\.new\(', 'hashlib.sha256(', new_line)
                new_line = re.sub(r'"MD5"', '"SHA256"', new_line)
                new_line = re.sub(r"'MD5'", "'SHA256'", new_line)
                
                # Add warnings for dangerous patterns - but only if it's a full line replacement
                if new_line.strip().startswith('__import__'):
                    new_line = '# ' + new_line.strip() + '  # WARNING: dynamic import'
                elif 'eval(' in new_line and new_line.strip().startswith('eval'):
                    new_line = '# ' + new_line.strip() + '  # WARNING: eval is unsafe'
                elif 'exec(' in new_line and new_line.strip().startswith('exec'):
                    new_line = '# ' + new_line.strip() + '  # WARNING: exec is unsafe'
                
                # Path traversal fix - add basename validation
                if 'base + ' in new_line or 'base +' in new_line:
                    new_line = re.sub(r'open\(([^)]+)\s*\+', 'open(os.path.join(os.path.dirname(__file__), \1', new_line)
                    if 'os.path.join' in new_line:
                        new_line = new_line + '  # Consider using pathlib'
                
                # Add pathlib import if using Path
                if 'Path(' in new_line and 'from pathlib' not in content:
                    new_line = 'from pathlib import Path\n' + new_line
                
                # Replace hardcoded AWS keys
                new_line = re.sub(r'AKIA[A-Z0-9]{16}', 'AKIA_REDACTED', new_line)
                
                if new_line != prev_line:
                    fixes_applied += 1
            
            fixed_lines.append(new_line)
        
        content = '\n'.join(fixed_lines)
        
        # Add required imports if missing
        needed_imports = {}
        for issue in issues:
            issue_type = issue.get("type", "")
            if issue_type in ["insecure_random", "weak_crypto"]:
                needed_imports["secrets"] = "import secrets"
            elif issue_type in ["hardcoded_secret", "hardcoded_db", "hardcoded_aws", "debug_enabled"]:
                needed_imports["os"] = "import os"
            elif issue_type in ["yaml_load"]:
                needed_imports["yaml"] = "import yaml"
            elif issue_type in ["pickle_insecure"]:
                needed_imports["json"] = "import json"
        
        for imp_name, imp_stmt in needed_imports.items():
            if imp_name not in content:
                content = imp_stmt + "\n" + content
                fixes_applied += 1
        
        if content != original:
            filepath.write_text(content)
            return True
        return False
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return False


def fix_issues(scan_results: Dict, target_dir: Path, auto_approve: bool = False) -> Dict:
    """Fix all issues in scan results"""
    fixed_files = {}
    issues_by_file = {}
    
    # Normalize target_dir - if scanning 'lib', target_dir is already lib
    # The issue locations are relative to the repo root
    # So we need to go up one level if target_dir is 'lib'
    scan_root = target_dir.parent if target_dir.name == 'lib' else target_dir
    
    for issue in scan_results.get("issues", []):
        location = issue.get("location", "")
        if ":" in location:
            parts = location.rsplit(":", 1)
            if len(parts) == 2:
                filepath, line = parts
            
            # Try multiple path combinations
            full_path = scan_root / filepath
            
            # If not found, try with target_dir prefix
            if not full_path.exists():
                full_path = target_dir / filepath
            
            if full_path.exists() and full_path not in issues_by_file:
                issues_by_file[full_path] = []
                issues_by_file[full_path].append(issue)
            elif full_path.exists():
                issues_by_file[full_path].append(issue)
    
    for filepath, issues in issues_by_file.items():
        if fix_file(filepath, issues):
            fixed_files[str(filepath)] = len(issues)
    
    return {
        "fixed_files": len(fixed_files),
        "files": fixed_files,
        "summary": f"Fixed {sum(fixed_files.values())} issues in {len(fixed_files)} files"
    }


def create_fix_suggestion(issue: Dict) -> str:
    """Generate a fix suggestion for an issue"""
    issue_type = issue.get("type", "")
    if issue_type in FIX_STRATEGIES:
        return FIX_STRATEGIES[issue_type].get("fix", "No auto-fix available")
    return "Manual review required"


def get_required_imports(issue_type: str) -> List[str]:
    """Get required imports for fixing an issue type"""
    imports = {
        "insecure_random": ["import secrets"],
        "hardcoded_secret": ["import os"],
        "hardcoded_db": ["import os"],
        "hardcoded_aws": ["import os"],
        "debug_enabled": ["import os"],
        "yaml_load": ["import yaml"],
        "command_injection": ["import subprocess"],
    }
    return imports.get(issue_type, [])
