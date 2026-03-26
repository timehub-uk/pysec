"""
Multi-language Support - Scan JavaScript, TypeScript, Go, Rust, Java, C#
"""

import json
import re
from pathlib import Path
from typing import Optional


JS_PATTERNS = {
    "hardcoded_secret": {
        "pattern": r"(const|let|var)?\s*(apiKey|api_secret|apikey|secret|token|password)\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]",
        "severity": "high",
        "description": "Hardcoded secret in JavaScript"
    },
    "eval_usage": {
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "description": "Use of eval() is dangerous"
    },
    "dangerous_redirect": {
        "pattern": r"(window\.location|location\.href)\s*=\s*.*\+",
        "severity": "medium",
        "description": "Potential open redirect vulnerability"
    },
    "innerHTML": {
        "pattern": r"\.innerHTML\s*=",
        "severity": "medium",
        "description": "Potential XSS via innerHTML"
    },
    "disabled_ssl": {
        "pattern": r"rejectUnauthorized\s*:\s*false|secure\s*:\s*false",
        "severity": "high",
        "description": "SSL verification disabled"
    }
}

GO_PATTERNS = {
    "hardcoded_secret": {
        "pattern": r"(apiKey|apikey|secret|token|password)\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "severity": "high",
        "description": "Hardcoded secret in Go"
    },
    "sql_injection": {
        "pattern": r"db\.Exec|db\.Query.*\+.*\%.*\+",
        "severity": "high",
        "description": "Potential SQL injection"
    },
    "goto_statement": {
        "pattern": r"\bgoto\b",
        "severity": "low",
        "description": "Use of goto - code smell"
    },
    "hardcoded_ip": {
        "pattern": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "severity": "low",
        "description": "Hardcoded IP address"
    }
}

RUST_PATTERNS = {
    "unsafe_block": {
        "pattern": r"\bunsafe\s*\{",
        "severity": "medium",
        "description": "Use of unsafe block in Rust"
    },
    "unwrap_usage": {
        "pattern": r"\.unwrap\s*\(",
        "severity": "low",
        "description": "Use of unwrap() - may panic"
    },
    "hardcoded_secret": {
        "pattern": r"(apiKey|apikey|secret|token|password)\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "severity": "high",
        "description": "Hardcoded secret in Rust"
    },
    "expect_usage": {
        "pattern": r"\.expect\s*\(",
        "severity": "low",
        "description": "Use of expect() - may panic"
    }
}

JAVA_PATTERNS = {
    "sql_injection": {
        "pattern": r"(Statement|createStatement)\s*\..*executeQuery.*\+",
        "severity": "high",
        "description": "Potential SQL injection"
    },
    "hardcoded_password": {
        "pattern": r"(password|passwd)\s*=\s*['\"][^'\"]+['\"]",
        "severity": "high",
        "description": "Hardcoded password"
    },
    "xml_external_entity": {
        "pattern": r"DocumentBuilderFactory\.newInstance\(\)",
        "severity": "medium",
        "description": "Check for XXE protection"
    },
    "deserialization": {
        "pattern": r"ObjectInputStream|readObject",
        "severity": "high",
        "description": "Insecure deserialization risk"
    },
    "logger_sensitive": {
        "pattern": r"log\.(info|debug)\s*\([^)]*(?:password|secret|token)",
        "severity": "high",
        "description": "Sensitive data in logs"
    }
}

CSHARP_PATTERNS = {
    "sql_injection": {
        "pattern": r"(SqlCommand|ExecuteScalar).*\+",
        "severity": "high",
        "description": "Potential SQL injection"
    },
    "hardcoded_secret": {
        "pattern": r"(apiKey|apikey|secret|token|password)\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "severity": "high",
        "description": "Hardcoded secret in C#"
    },
    "xml_injection": {
        "pattern": r"XmlReader\.Create.*\(.*\)",
        "severity": "medium",
        "description": "Check XML settings for XXE"
    },
    "weak_crypto": {
        "pattern": r"\.CreateCryptoServiceProvider\(\)",
        "severity": "medium",
        "description": "Weak cryptographic service"
    }
}

LANG_EXTENSIONS = {
    "javascript": [".js", ".mjs"],
    "typescript": [".ts", ".tsx"],
    "go": [".go"],
    "rust": [".rs"],
    "java": [".java"],
    "csharp": [".cs"]
}


def scan_javascript(path: Path) -> list[dict]:
    """Scan JavaScript/TypeScript files"""
    results = []
    
    for ext in LANG_EXTENSIONS["javascript"] + LANG_EXTENSIONS["typescript"]:
        for filepath in path.rglob(f"*{ext}"):
            if any(skip in str(filepath) for skip in ["node_modules", ".git"]):
                continue
            
            try:
                content = filepath.read_text()
                
                for issue_type, info in JS_PATTERNS.items():
                    if re.search(info["pattern"], content):
                        results.append({
                            "type": f"js-{issue_type}",
                            "severity": info["severity"],
                            "description": info["description"],
                            "location": str(filepath)
                        })
            except:
                pass
    
    return results


def scan_go(path: Path) -> list[dict]:
    """Scan Go files"""
    results = []
    
    for filepath in path.rglob("*.go"):
        try:
            content = filepath.read_text()
            
            for issue_type, info in GO_PATTERNS.items():
                if re.search(info["pattern"], content):
                    results.append({
                        "type": f"go-{issue_type}",
                        "severity": info["severity"],
                        "description": info["description"],
                        "location": str(filepath)
                    })
        except:
            pass
    
    return results


def scan_rust(path: Path) -> list[dict]:
    """Scan Rust files"""
    results = []
    
    for filepath in path.rglob("*.rs"):
        if "target" in str(filepath):
            continue
        
        try:
            content = filepath.read_text()
            
            for issue_type, info in RUST_PATTERNS.items():
                if re.search(info["pattern"], content):
                    results.append({
                        "type": f"rust-{issue_type}",
                        "severity": info["severity"],
                        "description": info["description"],
                        "location": str(filepath)
                    })
        except:
            pass
    
    return results


def scan_java(path: Path) -> list[dict]:
    """Scan Java files"""
    results = []
    
    for filepath in path.rglob("*.java"):
        if "target" in str(filepath):
            continue
        
        try:
            content = filepath.read_text()
            
            for issue_type, info in JAVA_PATTERNS.items():
                if re.search(info["pattern"], content):
                    results.append({
                        "type": f"java-{issue_type}",
                        "severity": info["severity"],
                        "description": info["description"],
                        "location": str(filepath)
                    })
        except:
            pass
    
    return results


def scan_csharp(path: Path) -> list[dict]:
    """Scan C# files"""
    results = []
    
    for filepath in path.rglob("*.cs"):
        if "obj" in str(filepath) or "bin" in str(filepath):
            continue
        
        try:
            content = filepath.read_text()
            
            for issue_type, info in CSHARP_PATTERNS.items():
                if re.search(info["pattern"], content):
                    results.append({
                        "type": f"csharp-{issue_type}",
                        "severity": info["severity"],
                        "description": info["description"],
                        "location": str(filepath)
                    })
        except:
            pass
    
    return results


def scan_multilang(path: Path = Path(".")) -> list[dict]:
    """Scan all supported languages"""
    results = []
    
    results.extend(scan_javascript(path))
    results.extend(scan_go(path))
    results.extend(scan_rust(path))
    results.extend(scan_java(path))
    results.extend(scan_csharp(path))
    
    return results