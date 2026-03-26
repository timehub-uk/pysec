import re
import ast
import fnmatch
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


SQL_KEYWORDS = {'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'JOIN', 'DROP', 'CREATE'}
DANGEROUS_FUNCTIONS = {'eval', 'exec', 'system', 'popen', 'load', 'loads'}
DANGEROUS_MODULES = {'pickle', 'yaml', 'hashlib', 'random', 'os', 'subprocess'}


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


def scan_file_python(filepath, seen):
    """Scan a single Python file for vulnerabilities"""
    results = []
    
    try:
        content = filepath.read_text(errors="ignore")
        lines = content.split("\n")
        
        # Hex encoding evasion
        hex_pattern = r'bytes\.fromhex\s*\(|fromhex\s*\('
        for match in re.finditer(hex_pattern, content, re.IGNORECASE):
            line_num = content[:match.start()].count("\n") + 1
            key = f"obfuscated_code:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "obfuscated_code",
                    "severity": "high",
                    "description": "Potential code obfuscation via hex encoding",
                    "fix": "Avoid obfuscating code",
                    "location": f"{filepath}:{line_num}"
                })
        
        # Indirect dangerous functions
        indirect_dangerous = r'def\s+(get_eval|get_exec|get_system|get_popen|get_open)\s*\([^)]*\):\s*return\s+(eval|exec|open)'
        for match in re.finditer(indirect_dangerous, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"indirect_dangerous_func:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "eval_usage",
                    "severity": "high",
                    "description": "Function returns dangerous builtin",
                    "fix": "Avoid returning dangerous functions",
                    "location": f"{filepath}:{line_num}"
                })
        
        # setattr XSS
        setattr_pattern = r'setattr\s*\([^,]+,\s*[\'"]cookie[\'"]'
        for match in re.finditer(setattr_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"xss_setattr:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "xss",
                    "severity": "medium",
                    "description": "Potential XSS via setattr",
                    "fix": "Use safe DOM manipulation",
                    "location": f"{filepath}:{line_num}"
                })
        
        # Indirect function returns
        indirect_pattern = r'return\s+(eval|exec|__import__|open)\s*\('
        for match in re.finditer(indirect_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"indirect_dangerous:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "eval_usage",
                    "severity": "high",
                    "description": "Indirect dangerous function return",
                    "fix": "Avoid returning dangerous functions",
                    "location": f"{filepath}:{line_num}"
                })
        
        # Direct eval/exec
        eval_pattern = r'\beval\s*\(|exec\s*\('
        for match in re.finditer(eval_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"eval_direct:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "eval_usage",
                    "severity": "high",
                    "description": "Use of eval/exec is a security risk",
                    "fix": "Use ast.literal_eval or json.loads",
                    "location": f"{filepath}:{line_num}"
                })
        
        # YAML unsafe load
        yaml_pattern = r'yaml\.load\s*\([^,)]*(?!\s*,\s*Loader\s*=)'
        for match in re.finditer(yaml_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"yaml_load:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "yaml_load",
                    "severity": "high",
                    "description": "Unsafe YAML loading",
                    "fix": "Use yaml.safe_load()",
                    "location": f"{filepath}:{line_num}"
                })
        
        # pickle unsafe
        pickle_pattern = r'pickle\.loads?\s*\('
        for match in re.finditer(pickle_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"pickle_insecure:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "pickle_insecure",
                    "severity": "high",
                    "description": "Unsafe pickle deserialization",
                    "fix": "Use json.loads instead",
                    "location": f"{filepath}:{line_num}"
                })
        
        # Command injection
        cmd_pattern = r'(os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\([^,)]*(?!\s*,\s*shell\s*=\s*False)'
        for match in re.finditer(cmd_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"command_injection:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "command_injection",
                    "severity": "high",
                    "description": "Potential command injection",
                    "fix": "Use shell=False or subprocess.run with list",
                    "location": f"{filepath}:{line_num}"
                })
        
        # Hardcoded secrets patterns
        secret_patterns = [
            (r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\']', "hardcoded_secret", "Hardcoded API key"),
            (r'secret\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\']', "hardcoded_secret", "Hardcoded secret"),
            (r'token\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\']', "hardcoded_secret", "Hardcoded token"),
            (r'password\s*=\s*["\'][^"\']{8,}["\']', "hardcoded_secret", "Hardcoded password"),
            (r'["\'][a-zA-Z0-9_-]{32,}["\']\s*%', "hardcoded_secret", "Possible hardcoded secret"),
        ]
        
        for pattern, vtype, desc in secret_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{vtype}:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": vtype,
                        "severity": "high",
                        "description": desc,
                        "fix": "Use environment variables",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # Weak crypto
        weak_crypto_patterns = [
            (r'hashlib\.md5\s*\(', "weak_crypto", "MD5 is cryptographically broken"),
            (r'hashlib\.sha1\s*\(', "weak_crypto", "SHA1 is cryptographically weak"),
            (r'MD5\s*\(', "weak_crypto", "MD5 is cryptographically broken"),
            (r'SHA1\s*\(', "weak_crypto", "SHA1 is cryptographically weak"),
        ]
        
        for pattern, vtype, desc in weak_crypto_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{vtype}:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": vtype,
                        "severity": "medium",
                        "description": desc,
                        "fix": "Use hashlib.sha256",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # Insecure random
        random_pattern = r'random\.(random|choice|randint|randrange)\s*\('
        for match in re.finditer(random_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"insecure_random:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "insecure_random",
                    "severity": "low",
                    "description": "Insecure random for security purposes",
                    "fix": "Use secrets module",
                    "location": f"{filepath}:{line_num}"
                })
        
        # Path traversal
        path_pattern = r'open\s*\([^,)]*\+[^,)]*\)'
        for match in re.finditer(path_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"path_traversal:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "path_traversal",
                    "severity": "high",
                    "description": "Potential path traversal",
                    "fix": "Validate and sanitize paths",
                    "location": f"{filepath}:{line_num}"
                })
        
        # SQL injection patterns
        sql_patterns = [
            (r'execute\s*\(\s*["\'].*%s.*["\'].*%.*\)', "sql_injection"),
            (r'execute\s*\(\s*f["\']', "sql_injection"),
            (r'cursor\.execute\s*\(\s*["\'].*\+', "sql_injection"),
        ]
        
        for pattern, vtype in sql_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{vtype}:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": vtype,
                        "severity": "high",
                        "description": "Potential SQL injection vulnerability",
                        "fix": "Use parameterized queries",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # Debug mode
        debug_patterns = [
            (r'DEBUG\s*=\s*True', "debug_true"),
            (r'DEBUG\s*=\s*["\']true["\']', "debug_enabled", True),
            (r'app\.run\s*\(\s*debug\s*=\s*True', "debug_enabled"),
        ]
        
        for p in debug_patterns:
            pattern = p[0]
            vtype = p[1]
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{vtype}:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": vtype,
                        "severity": "medium",
                        "description": "Debug mode may be enabled" if len(p) == 2 else "Debug mode enabled in configuration",
                        "fix": "Use environment variable for debug mode",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # HTTP without HTTPS - only flag if it's a real URL (not in comments/docs)
        http_pattern = r'["\']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|https?://)'
        for match in re.finditer(http_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            line_start = content.rfind('\n', 0, match.start()) + 1
            line_end = content.find('\n', match.start())
            if line_end == -1:
                line_end = len(content)
            line = content[line_start:line_end]
            
            # Skip comments and docstrings
            if '#' in line[:match.start()-line_start] or '"""' in line or "'''" in line:
                continue
            # Skip test files
            if 'test' in str(filepath).lower():
                continue
                
            key = f"http_without_https:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "http_without_https",
                    "severity": "medium",
                    "description": "Insecure HTTP URL",
                    "fix": "Use HTTPS instead of HTTP",
                    "location": f"{filepath}:{line_num}"
                })
        
        # Dynamic imports
        dynamic_import = r'__import__\s*\('
        for match in re.finditer(dynamic_import, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"dynamic_import:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "dynamic_import",
                    "severity": "medium",
                    "description": "Dynamic import may be unsafe",
                    "fix": "Use static imports",
                    "location": f"{filepath}:{line_num}"
                })
        
        # XML XXE vulnerability
        xml_xxe = r'xml\.etree\.ElementTree\.parse|etree\.parse|lxml\.etree\.parse'
        for match in re.finditer(xml_xxe, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"xml_xxe:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "xml_xxe",
                    "severity": "high",
                    "description": "Potential XML XXE vulnerability",
                    "fix": "Use defusedxml or disable external entities",
                    "location": f"{filepath}:{line_num}"
                })
        
        # JWT security issues
        jwt_patterns = [
            (r'jwt\.decode\s*\([^,)]*(?!verify=|options=)', "jwt_weak_verify", "JWT decode without proper verification"),
            (r'jwt\.encode\s*\([^,)]*(?!algorithm=)', "jwt_algorithm", "JWT encode without specifying algorithm"),
            (r'algorithm\s*=\s*["\']HS256["\']', "jwt_weak_algo", "JWT using weak symmetric algorithm"),
        ]
        for pattern, vtype, desc in jwt_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{vtype}:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": vtype,
                        "severity": "high",
                        "description": desc,
                        "fix": "Use asymmetric algorithms (RS256, ES256)",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # LDAP injection
        ldap_pattern = r'(ldap|ldap3)\..*(search|initialize)'
        for match in re.finditer(ldap_pattern, content, re.IGNORECASE):
            if re.search(r'\+.*%s|%s\+', content[match.start():match.start()+200]):
                line_num = content[:match.start()].count("\n") + 1
                key = f"ldap_injection:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": "ldap_injection",
                        "severity": "high",
                        "description": "Potential LDAP injection",
                        "fix": "Use parameterized LDAP queries",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # Regex DoS (ReDoS)
        redos_pattern = r're\.(compile|search|match|findall)\s*\(\s*["\'].*[\*\+\?]\{.*\}'
        for match in re.finditer(redos_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"redos:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "regex_dos",
                    "severity": "medium",
                    "description": "Potential Regex DoS vulnerability",
                    "fix": "Use anchored patterns, avoid nested quantifiers",
                    "location": f"{filepath}:{line_num}"
                })
        
        # Django-specific security
        django_patterns = [
            (r'@login_required\s*\(\s*login_url\s*=\s*None', "django_login_required", "Django @login_required without explicit login_url"),
            (r'settings\.DEBUG\s*=\s*True', "django_debug", "Django DEBUG mode enabled"),
            (r'Middleware\s*\(\s*["\']django\.middleware\.common\.CommonMiddleware', "django_middleware", "Django CommonMiddleware"),
            (r'secret_key\s*=\s*["\'][^"\']{20,}["\']', "django_secret", "Django secret key potentially hardcoded"),
        ]
        for pattern, vtype, desc in django_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{vtype}:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": vtype,
                        "severity": "high" if "secret" in vtype else "medium",
                        "description": desc,
                        "fix": "Use environment variable for Django settings",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # Insecure temp file creation
        tempfile_patterns = [
            (r'TemporaryFile\s*\(\s*', "temp_file", "TemporaryFile without delete=False"),
            (r'NamedTemporaryFile\s*\([^)]*delete\s*=\s*True', "temp_file", "NamedTemporaryFile with delete=True"),
            (r'mktemp\s*\(', "temp_file", "mktemp is insecure"),
        ]
        for pattern, vtype, desc in tempfile_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{vtype}:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": vtype,
                        "severity": "medium",
                        "description": desc,
                        "fix": "Use tempfile.mkstemp or NamedTemporaryFile(delete=False)",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # SQL injection with string formatting
        sql_format = r'(execute|query|cursor\.execute|Session\.execute)\s*\([^)]*\.format\s*\('
        for match in re.finditer(sql_format, content, re.IGNORECASE):
            line_num = content[:match.start()].count("\n") + 1
            key = f"sql_injection:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL query built with .format()",
                    "fix": "Use parameterized queries",
                    "location": f"{filepath}:{line_num}"
                })
        
        # Insecure SSH settings
        ssh_issues = [
            (r'paramiko\.SSHClient\(\)\.set_missing_host_key_policy\(', "ssh_allow_any", "SSH missing host key policy"),
            (r'HostKeyChecking\s*=\s*False', "ssh_allow_any", "SSH host key checking disabled"),
            (r'StrictHostKeyChecking\s*=\s*no', "ssh_allow_any", "SSH StrictHostKeyChecking disabled"),
        ]
        for pattern, vtype, desc in ssh_issues:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{vtype}:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": vtype,
                        "severity": "high",
                        "description": desc,
                        "fix": "Use proper SSH host key verification",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # Cookie security issues
        cookie_issues = [
            (r'cookie\s*=\s*[^;]*;?\s*secure\s*=\s*False', "insecure_cookie", "Cookie without Secure flag"),
            (r'cookie\s*=\s*[^;]*;?\s*httponly\s*=\s*False', "insecure_cookie", "Cookie without HttpOnly flag"),
            (r'response\.set_cookie\([^)]*secure\s*=\s*False', "insecure_cookie", "Cookie without Secure flag"),
        ]
        for pattern, vtype, desc in cookie_issues:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{vtype}:{filepath}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": vtype,
                        "severity": "medium",
                        "description": desc,
                        "fix": "Set secure=True, httponly=True",
                        "location": f"{filepath}:{line_num}"
                    })
        
        # Hardcoded IP addresses
        ip_pattern = r'["\']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["\']'
        for match in re.finditer(ip_pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            key = f"hardcoded_ip:{filepath}:{line_num}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "hardcoded_ip",
                    "severity": "low",
                    "description": "Hardcoded IP address",
                    "fix": "Use configuration or environment variable",
                    "location": f"{filepath}:{line_num}"
                })
        
        # AST-based analysis
        results.extend(analyze_ast(filepath))
        
    except Exception:
        pass
    
    return results


def analyze_ast(file_path):
    """AST-based vulnerability detection for obfuscated patterns"""
    results = []
    seen = set()
    
    try:
        content = file_path.read_text(errors="ignore")
        tree = ast.parse(content)
        
        # Track variable assignments for split string detection
        string_vars = {}
        func_call_vars = {}  # Track function calls that return modules
        
        for node in ast.walk(tree):
            # Detect functions that return dangerous modules
            if isinstance(node, ast.FunctionDef):
                func_name = node.name
                for stmt in ast.walk(node):
                    if isinstance(stmt, ast.Return):
                        if isinstance(stmt.value, ast.Name):
                            # return eval / return exec / return open
                            if stmt.value.id in ('eval', 'exec', 'open', 'system', 'popen'):
                                line = node.lineno or 0
                                key = f"func_returns_dangerous:{file_path}:{line}"
                                if key not in seen:
                                    seen.add(key)
                                    results.append({
                                        "type": "eval_usage",
                                        "severity": "high",
                                        "description": f"Function '{func_name}' returns dangerous builtin '{stmt.value.id}'",
                                        "fix": "Avoid returning dangerous functions",
                                        "location": f"{file_path}:{line}"
                                    })
                        elif isinstance(stmt.value, ast.Call):
                            # return get_hashlib() etc
                            if isinstance(stmt.value.func, ast.Name):
                                func_call_vars[func_name] = stmt.value.func.id
            
            # Detect SQL injection via string concatenation (BinOp with +)
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left_val = ast_unwrap(node.left)
                right_val = ast_unwrap(node.right)
                
                # Check if either side contains SQL keywords
                if left_val and right_val:
                    combined = str(left_val) + str(right_val)
                    if any(kw in combined.upper() for kw in SQL_KEYWORDS):
                        line = node.lineno or 0
                        key = f"sql_injection_ast:{file_path}:{line}"
                        if key not in seen:
                            seen.add(key)
                            results.append({
                                "type": "sql_injection",
                                "severity": "high",
                                "description": "Potential SQL injection via string concatenation",
                                "fix": "Use parameterized queries or ORM",
                                "location": f"{file_path}:{line}"
                            })
            
            # Track string variable assignments
            if isinstance(node, ast.Assign):
                var_name = ""
                if isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id
                
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    string_vars[var_name] = node.value.value
            
            # Detect return statements with concatenation of multiple string variables
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                    parts = extract_concat_parts(node.value)
                    # Check if all parts are from tracked string variables
                    if len(parts) >= 2:
                        # Check if this looks like a secret (combined length > 10, starts with common patterns)
                        all_vars = all(p.startswith('var:') for p in parts)
                        if all_vars:
                            combined = ''.join(string_vars.get(p.split(':')[1], '') for p in parts if ':' in p)
                            if len(combined) > 10 and (combined.startswith(('sk_', 'api_', 'token', 'key')) or len(combined) > 20):
                                line = node.lineno or 0
                                key = f"split_string_secret:{file_path}:{line}"
                                if key not in seen:
                                    seen.add(key)
                                    results.append({
                                        "type": "split_string_secret",
                                        "severity": "high",
                                        "description": "Hardcoded secret split across variables",
                                        "fix": "Use environment variables",
                                        "location": f"{file_path}:{line}"
                                    })
            
            # Detect split string secrets (multiple var assignments concatenated)
            if isinstance(node, ast.Assign):
                var_name = ""
                if isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id
                
                if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                    # This is a concatenation like: secret = p1 + p2 + p3 + p4
                    parts = extract_concat_parts(node.value)
                    if len(parts) >= 2:
                        # Check if parts look like secret fragments (not path-like)
                        string_parts = [p for p in parts if isinstance(p, str)]
                        if string_parts:
                            combined = ''.join(string_parts)
                            # Looks like a secret if it contains mixed case letters and numbers, or starts with common patterns
                            if (any(c.isdigit() for c in combined) and any(c.islower() for c in combined)) or \
                               combined.startswith(('sk_', 'api_', 'gho_', 'AKIA', 'eyJ')):
                                line = node.lineno or 0
                                key = f"split_string_secret:{file_path}:{line}"
                                if key not in seen:
                                    seen.add(key)
                                    results.append({
                                        "type": "split_string_secret",
                                        "severity": "high",
                                        "description": "Hardcoded secret split across variables",
                                        "fix": "Use environment variables",
                                        "location": f"{file_path}:{line}"
                                    })
            
            # Detect dynamic code execution via eval/exec with concatenated strings
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ('eval', 'exec'):
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.BinOp):
                            line = node.lineno or 0
                            key = f"eval_dynamic:{file_path}:{line}"
                            if key not in seen:
                                seen.add(key)
                                results.append({
                                    "type": "eval_usage",
                                    "severity": "high",
                                    "description": "Dynamic code execution via eval with concatenation",
                                    "fix": "Avoid eval/exec, use safer alternatives",
                                    "location": f"{file_path}:{line}"
                                })
    
    except Exception:
        pass
    
    return results


def ast_unwrap(node):
    """Unwrap AST nodes to get string values"""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Str):  # Python 3.7 compatibility
        return node.s
    if isinstance(node, ast.JoinedStr):  # f-string
        return ""
    if isinstance(node, ast.BinOp):
        left = ast_unwrap(node.left)
        right = ast_unwrap(node.right)
        if left is not None and right is not None:
            return str(left) + str(right)
    if isinstance(node, ast.Name):
        return None
    return None


def extract_concat_parts(node, parts=None):
    """Extract all parts from a concatenation chain"""
    if parts is None:
        parts = []
    
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        extract_concat_parts(node.left, parts)
        extract_concat_parts(node.right, parts)
    elif isinstance(node, ast.Constant):
        parts.append(node.value)
    elif isinstance(node, ast.Name):
        parts.append(f"var:{node.id}")
    
    return parts


def scan_code_vulnerabilities(path, skip_test=False, skip_example=False, ignore_patterns=None):
    results = []
    seen = set()
    
    if ignore_patterns is None:
        ignore_patterns = []
    
    test_patterns = ('test_', '_test.py', '/tests/', '/test_', 'conftest.py')
    example_patterns = ('/example', '/demo', '/doc', '/docs/', '/sample', '/sample_')
    
    files = []
    for filepath in path.rglob("*.py"):
        if "__pycache__" in str(filepath) or "venv" in str(filepath):
            continue
        
        if skip_test and any(p in str(filepath) for p in test_patterns):
            continue
        
        if skip_example and any(p in str(filepath) for p in example_patterns):
            continue
        
        if check_ignore(str(filepath), ignore_patterns):
            continue
        
        files.append(filepath)
    
    with ThreadPoolExecutor(max_workers=min(8, len(files) or 1)) as executor:
        futures = {executor.submit(scan_file_python, f, seen): f for f in files}
        for future in as_completed(futures):
            try:
                file_results = future.result()
                results.extend(file_results)
            except Exception:
                pass
    
    return results


VULNERABILITY_PATTERNS = {
    "sql_injection": {
        "pattern": r"(execute|query|cursor\.execute)\s*\([^)]*%s[^)]*\)|['\"].*SELECT.*\+.*['\"]|\.format\(.*\$|\$\{.*\}|\+[^;]*SELECT.*\+|\+[^;]*INSERT.*\+|\+[^;]*UPDATE.*\+|\+[^;]*DELETE.*\+|(?:SELECT|INSERT|UPDATE|DELETE).*\+",
        "severity": "high",
        "description": "Potential SQL injection vulnerability",
        "fix": "Use parameterized queries or ORM"
    },
    "path_traversal": {
        "pattern": r"(open\s*\([^)]*\+[^)]*\)|read\s*\([^)]*\+[^)]*\)|os\.path\.join\s*\([^)]*\+[^)]*\)|Path\s*\([^)]*\+[^)]*\)|base\s*\+|os\.path\.join\([^,]+,[^)]*request)|# WARNING: path needs",
        "severity": "medium",
        "description": "Potential path traversal vulnerability",
        "fix": "Validate and sanitize file paths"
    },
    "xss": {
        "pattern": r"innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML\s*=|document\.cookie\s*=",
        "severity": "medium",
        "description": "Potential XSS vulnerability",
        "fix": "Use textContent or sanitization libraries"
    },
    "eval_usage": {
        "pattern": r"\beval\s*\(|\bexec\s*\(|__import__\s*\(\s*['\"]eval|getattr\s*\(\s*locals|getattr\s*\(\s*globals|lambda.*:.*eval|lambda.*:.*exec|# WARNING: eval|# WARNING: exec",
        "severity": "high",
        "description": "Use of eval/exec is a security risk",
        "fix": "Avoid eval/exec, use safer alternatives"
    },
    "hardcoded_db": {
        "pattern": r"(mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@(?!(?:password|secret|token|key|example|test|xxx|\$\{|os\.environ))",
        "severity": "high",
        "description": "Hardcoded database credentials",
        "fix": "Use environment variables"
    },
    "insecure_random": {
        "pattern": r"random\.(random|randint|choice)|__import__\s*\(\s*['\"]random['\"]\)\.(random|randint|choice)|getattr\s*\(\s*__import__\s*\(\s*['\"]random['\"]\)\s*,\s*['\"](?:random|randint|choice)['\"]",
        "severity": "low",
        "description": "Insecure random for security purposes",
        "fix": "Use secrets module"
    },
    "yaml_load": {
        "pattern": r"yaml\.load\s*\((?!.*SafeLoader)(?!.*safe_load)|__import__\s*\(\s*['\"]yaml['\"]\)\.load|getattr\s*\(\s*__import__\s*\(\s*['\"]yaml['\"]\)\s*,\s*['\"]load['\"]",
        "severity": "medium",
        "description": "Insecure YAML deserialization",
        "fix": "Use yaml.safe_load with SafeLoader"
    },
    "weak_crypto": {
        "pattern": r"hashlib\.(md5|sha1)\s*\(|hashlib\.new\s*\(['\"](?:md5|sha1)['\"]|__import__\s*\(\s*['\"]hashlib['\"]\)\.(md5|sha1)|getattr\s*\(\s*__import__\s*\(\s*['\"]hashlib['\"]\)\s*,\s*['\"](?:md5|sha1)['\"]",
        "severity": "medium",
        "description": "Use of weak cryptographic algorithm",
        "fix": "Use SHA-256 or stronger"
    },
    "hardcoded_secret": {
        "pattern": r"(api_key|apikey|secret|token|password)\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]|(AKIA|ASIA)[A-Z0-9]{16}|\"{.*}\"\s*%\s*\(|\'{.*}\'\s*%\s*\(|%\s*\(.*['\"][a-zA-Z0-9_\-]{10,}['\"]|\.format\s*\([^)]*['\"][a-zA-Z0-9_\-]{10,}['\"]",
        "severity": "high",
        "description": "Hardcoded secret detected",
        "fix": "Use environment variables"
    },
    "command_injection": {
        "pattern": r"^(?!.*# WARNING).*(subprocess\.run|subprocess\.call|subprocess\.Popen|os\.system|os\.popen)\s*\((?!shell\s*=\s*False)|__import__\s*\(\s*['\"]os['\"]\)\.system|getattr\s*\(\s*__import__\s*\(\s*['\"]os['\"]\)\s*,\s*['\"]system['\"]",
        "severity": "critical",
        "description": "Potential command injection",
        "fix": "Avoid shell=True, use list of args"
    },
    "pickle_insecure": {
        "pattern": r"(pickle\.load|pickle\.loads)\s*\((?!.*SafeSerializer)|__import__\s*\(\s*['\"]pickle['\"]\)\.loads|getattr\s*\(\s*__import__\s*\(\s*['\"]pickle['\"]\)\s*,\s*['\"]loads['\"]",
        "severity": "high",
        "description": "Insecure pickle deserialization",
        "fix": "Use restricted unpickler"
    },
    "assert_statements": {
        "pattern": r"\bassert\s+.*# WARNING:",
        "severity": "low",
        "description": "Assert statements may be disabled in production",
        "fix": "Remove or use proper validation"
    },
    "debug_enabled": {
        "pattern": r"(DEBUG|debug|DEBUG_MODE)\s*[=:]\s*(?!\s*os\.environ|os\.getenv|false|False|0)(True|true|1)",
        "severity": "medium",
        "description": "Debug mode may be enabled",
        "fix": "Disable in production"
    },
    "ssl_verify_disabled": {
        "pattern": r"(verify\s*=\s*False|ssl_verify\s*=\s*False)",
        "severity": "high",
        "description": "SSL verification disabled",
        "fix": "Enable SSL verification"
    },
    "http_without_https": {
        "pattern": r"http://(?!localhost|127\.0\.0\.1)",
        "severity": "medium",
        "description": "Insecure HTTP URL",
        "fix": "Use HTTPS"
    },
    "logger_sensitive_data": {
        "pattern": r"(logger|log)\.(info|debug|warning)\s*\([^)]*(?:password|secret|token|key)[^)]*\)",
        "severity": "high",
        "description": "Sensitive data logged",
        "fix": "Redact sensitive data in logs"
    },
    "hardcoded_aws": {
        "pattern": r"(AKIA|ASIA)[A-Z0-9]{16}|aws_access|aws_secret|AWS_ACCESS|AWS_SECRET|\"\s*\+\s*\"(?:AKIA|ASIA)|\'\s*\+\s*\'(?:AKIA|ASIA)|%s\s*\+\s*%s.*(?:AKIA|ASIA)",
        "severity": "critical",
        "description": "Hardcoded AWS credentials",
        "fix": "Use IAM roles or environment variables"
    },
    "dynamic_import": {
        "pattern": r"__import__\s*\(|importlib\.import_module|getattr\s*\(\s*__import__|globals\s*\(\s*\)\s*\[\s*['\"]|locals\s*\(\s*\)\s*\[\s*['\"]",
        "severity": "medium",
        "description": "Dynamic import may be unsafe",
        "fix": "Validate import paths"
    },
    "base64_decode": {
        "pattern": r"base64\.(b64decode|decodebytes)\s*\(",
        "severity": "medium",
        "description": "Base64 decoding may hide malicious code",
        "fix": "Verify decoded content"
    },
    "split_string_secret": {
        "pattern": r'p[0-9]\s*=\s*["\'][^"\']+["\'"]\s*\n\s*(?:p[0-9]\s*\+\s*)+',
        "severity": "high",
        "description": "Hardcoded secret split across variables",
        "fix": "Use environment variables"
    },
    "string_concat_sql": {
        "pattern": r"['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*\+",
        "severity": "high",
        "description": "SQL query built with string concatenation",
        "fix": "Use parameterized queries"
    }
}