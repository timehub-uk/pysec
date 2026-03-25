"""
Infrastructure as Code Scanning - Terraform, CloudFormation, Kubernetes, Ansible
"""

import json
import re
from pathlib import Path
from typing import Optional


IAC_PATTERNS = {
    "terraform": {
        "aws_access_key": {
            "pattern": r"access_key\s*=\s*['\"][A-Z0-9]{20,}['\"]",
            "severity": "critical",
            "description": "Hardcoded AWS access key in Terraform"
        },
        "aws_secret_key": {
            "pattern": r"secret_key\s*=\s*['\"][a-zA-Z0-9/+=]{40,}['\"]",
            "severity": "critical",
            "description": "Hardcoded AWS secret key in Terraform"
        },
        "password_in_var": {
            "pattern": r"(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]",
            "severity": "high",
            "description": "Hardcoded password in Terraform variable"
        },
        "public_bucket": {
            "pattern": r'acl\s*=\s*["\']public["\']',
            "severity": "high",
            "description": "S3 bucket set to public"
        },
        "unencrypted_storage": {
            "pattern": r'server_side_encryption\s*=\s*false',
            "severity": "high",
            "description": "S3 storage not encrypted"
        },
        "open_port": {
            "pattern": r'cidr_blocks\s*=\s*\[["\'](0\.0\.0\.0/0)["\']\]',
            "severity": "medium",
            "description": "Security group allows open access"
        }
    },
    "kubernetes": {
        "privileged_container": {
            "pattern": r"privileged:\s*true",
            "severity": "critical",
            "description": "Privileged container detected"
        },
        "root_container": {
            "pattern": r"runAsUser:\s*0",
            "severity": "high",
            "description": "Container runs as root user"
        },
        "no_resource_limits": {
            "pattern": r"limits:",
            "severity": "low",
            "description": "No resource limits set"
        },
        "secret_in_env": {
            "pattern": r"env:.*secretKeyRef",
            "severity": "high",
            "description": "Secrets in environment variables"
        },
        "latest_tag": {
            "pattern": r"image:.*:latest",
            "severity": "medium",
            "description": "Using :latest tag - not recommended"
        }
    },
    "cloudformation": {
        "hardcoded_password": {
            "pattern": r'(Password|Passwd)\s*=\s*["\'][^"\']{8,}["\']',
            "severity": "high",
            "description": "Hardcoded password in CloudFormation"
        },
        "public_bucket": {
            "pattern": r'PublicAccessBlockConfiguration.*false',
            "severity": "high",
            "description": "S3 bucket has public access"
        },
        "unencrypted_volume": {
            "pattern": r'Encrypted:\s*false',
            "severity": "high",
            "description": "EBS volume not encrypted"
        }
    },
    "ansible": {
        "sudo_without_password": {
            "pattern": r"become:\s*true.*\n.*become_method:\s*sudo",
            "severity": "medium",
            "description": "sudo without password"
        },
        "hardcoded_password": {
            "pattern": r'(password|passwd)\s*:\s*["\'][^"\']+["\']',
            "severity": "high",
            "description": "Hardcoded password in Ansible"
        },
        "insecure_protocol": {
            "pattern": r"(ftp|http):\/\/",
            "severity": "medium",
            "description": "Insecure protocol (HTTP/FTP) used"
        }
    }
}


def scan_terraform(path: Path) -> list[dict]:
    """Scan Terraform files"""
    results = []
    
    for filepath in path.rglob("*.tf"):
        try:
            content = filepath.read_text()
            
            for issue_type, info in IAC_PATTERNS["terraform"].items():
                for match in re.finditer(info["pattern"], content, re.IGNORECASE):
                    line_num = content[:match.start()].count("\n") + 1
                    results.append({
                        "type": f"iac-terraform-{issue_type}",
                        "severity": info["severity"],
                        "description": info["description"],
                        "location": f"{filepath}:{line_num}"
                    })
        except:
            pass
    
    return results


def scan_kubernetes(path: Path) -> list[dict]:
    """Scan Kubernetes manifests"""
    results = []
    
    for ext in ["*.yaml", "*.yml"]:
        for filepath in path.rglob(ext):
            if "kubeconfig" in str(filepath):
                continue
            
            try:
                content = filepath.read_text()
                
                for issue_type, info in IAC_PATTERNS["kubernetes"].items():
                    for match in re.finditer(info["pattern"], content, re.IGNORECASE):
                        line_num = content[:match.start()].count("\n") + 1
                        results.append({
                            "type": f"iac-k8s-{issue_type}",
                            "severity": info["severity"],
                            "description": info["description"],
                            "location": f"{filepath}:{line_num}"
                        })
            except:
                pass
    
    return results


def scan_cloudformation(path: Path) -> list[dict]:
    """Scan CloudFormation templates"""
    results = []
    
    for ext in ["*.yaml", "*.yml", "*.json"]:
        for filepath in path.rglob(ext):
            if "template" not in str(filepath).lower():
                continue
            
            try:
                content = filepath.read_text()
                
                for issue_type, info in IAC_PATTERNS["cloudformation"].items():
                    for match in re.finditer(info["pattern"], content, re.IGNORECASE):
                        line_num = content[:match.start()].count("\n") + 1
                        results.append({
                            "type": f"iac-cfn-{issue_type}",
                            "severity": info["severity"],
                            "description": info["description"],
                            "location": f"{filepath}:{line_num}"
                        })
            except:
                pass
    
    return results


def scan_ansible(path: Path) -> list[dict]:
    """Scan Ansible playbooks"""
    results = []
    
    for filepath in path.rglob("*.yml"):
        if "ansible" not in str(filepath).lower():
            continue
        
        try:
            content = filepath.read_text()
            
            for issue_type, info in IAC_PATTERNS["ansible"].items():
                for match in re.finditer(info["pattern"], content, re.IGNORECASE):
                    line_num = content[:match.start()].count("\n") + 1
                    results.append({
                        "type": f"iac-ansible-{issue_type}",
                        "severity": info["severity"],
                        "description": info["description"],
                        "location": f"{filepath}:{line_num}"
                    })
        except:
            pass
    
    return results


def scan_iac(path: Path = Path(".")) -> list[dict]:
    """Scan all Infrastructure as Code files"""
    results = []
    
    results.extend(scan_terraform(path))
    results.extend(scan_kubernetes(path))
    results.extend(scan_cloudformation(path))
    results.extend(scan_ansible(path))
    
    if not results:
        results.append({
            "type": "iac",
            "severity": "info",
            "description": "No IaC files detected. Looking for: *.tf, *.yaml (k8s, CFN), *.yml (Ansible)",
            "location": str(path)
        })
    
    return results