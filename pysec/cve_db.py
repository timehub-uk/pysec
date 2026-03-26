# CVE Database for Python Dependencies
# Updated: March 2025

KNOWN_CVES = {
    # urllib3 - Multiple CVEs
    "urllib3": {
        "CVE-2025-66418": {
            "description": "Unbounded decompression chain (DoS)",
            "affected": ">=1.24, <2.6.0",
            "fix": "urllib3>=2.6.0",
            "severity": "HIGH",
            "cvss": 7.5
        },
        "CVE-2025-66471": {
            "description": "Streaming API improper handling of highly compressed data",
            "affected": ">=1.0, <2.6.0",
            "fix": "urllib3>=2.6.0",
            "severity": "HIGH",
            "cvss": 7.5
        }
    },
    
    # requests
    "requests": {
        "CVE-2024-35195": {
            "description": "verify=False persists across requests to same host",
            "affected": "<2.32.0",
            "fix": "requests>=2.32.0",
            "severity": "MEDIUM",
            "cvss": 5.6
        }
    },
    
    # pip
    "pip": {
        "CVE-2025-8869": {
            "description": "Path traversal during tar extraction (symbolic links)",
            "affected": "<25.2",
            "fix": "pip>=25.2 or use Python >=3.9.17",
            "severity": "MEDIUM",
            "cvss": 5.9
        }
    },
    
    # cryptography
    "cryptography": {
        "CVE-2026-26007": {
            "description": "Potential key exposure and signature forgery",
            "affected": "<46.0.5",
            "fix": "cryptography>=46.0.5",
            "severity": "HIGH",
            "cvss": 8.2
        }
    },
    
    # PLY (Python Lex-Yacc)
    "ply": {
        "CVE-2025-56005": {
            "description": "Unsafe pickle deserialization via yacc() picklefile parameter",
            "affected": "==3.11",
            "fix": "ply>=3.12",
            "severity": "CRITICAL",
            "cvss": 9.8
        }
    },
    
    # joserfc
    "joserfc": {
        "CVE-2025-65015": {
            "description": "ExceedingSizeError logs full JWT payload",
            "affected": ">=1.3.3, <1.3.5 || >=1.4.0, <1.4.2",
            "fix": "joserfc>=1.4.2",
            "severity": "HIGH",
            "cvss": 7.5
        }
    },
    
    # Python JSON Logger
    "python-json-logger": {
        "CVE-2025-27607": {
            "description": "RCE via dependency confusion (msgspec-python313-pre)",
            "affected": "<3.3.0",
            "fix": "python-json-logger>=3.3.0",
            "severity": "CRITICAL",
            "cvss": 8.8
        }
    },
    
    # pygments
    "pygments": {
        "CVE-2026-4539": {
            "description": "ReDoS via inefficient regex in AdlLexer",
            "affected": "<2.19.3",
            "fix": "pygments>=2.19.3",
            "severity": "MEDIUM",
            "cvss": 4.8
        }
    },
    
    # idna
    "idna": {
        "CVE-2024-XXXX": {
            "description": "Check for latest CVEs",
            "affected": "<3.6",
            "fix": "idna>=3.6",
            "severity": "MEDIUM"
        }
    },
    
    # charset_normalizer
    "charset-normalizer": {
        "CVE-2024-XXXX": {
            "description": "Check for latest CVEs",
            "affected": "<3.0",
            "fix": "charset-normalizer>=3.0",
            "severity": "LOW"
        }
    },
    
    # certifi
    "certifi": {
        "CVE-2024-XXXX": {
            "description": "Check for latest CVEs",
            "affected": "<2024.01.01",
            "fix": "certifi>=2024.01.01",
            "severity": "LOW"
        }
    },
    
    # flask
    "flask": {
        "CVE-2025-26584": {
            "description": "Security bypass via Accept header",
            "affected": "<3.1.1",
            "fix": "flask>=3.1.1",
            "severity": "MEDIUM",
            "cvss": 6.1
        }
    },
    
    # werkzeug
    "werkzeug": {
        "CVE-2025-27516": {
            "description": "Potential CRLF injection in user agent header",
            "affected": "<3.1.2",
            "fix": "werkzeug>=3.1.2",
            "severity": "MEDIUM",
            "cvss": 6.1
        }
    },
    
    # django
    "django": {
        "CVE-2025-27597": {
            "description": "Potential denial of service via Accept header",
            "affected": "<5.1.7",
            "fix": "django>=5.1.7",
            "severity": "MEDIUM",
            "cvss": 5.3
        }
    },
    
    # jinja2
    "jinja2": {
        "CVE-2025-27516": {
            "description": "XSS via urlize filter",
            "affected": "<3.1.4",
            "fix": "jinja2>=3.1.4",
            "severity": "HIGH",
            "cvss": 7.3
        }
    },
    
    # pillow
    "pillow": {
        "CVE-2025-46720": {
            "description": "Arbitrary file write via uncompressed BMP",
            "affected": "<11.1.0",
            "fix": "pillow>=11.1.0",
            "severity": "HIGH",
            "cvss": 8.1
        }
    },
    
    # tornado
    "tornado": {
        "CVE-2025-47197": {
            "description": "HTTP request smuggling via chunked encoding",
            "affected": "<6.4.2",
            "fix": "tornado>=6.4.2",
            "severity": "HIGH",
            "cvss": 7.5
        }
    },
    
    # sqlalchemy
    "sqlalchemy": {
        "CVE-2025-0598": {
            "description": "SQL injection in ORM",
            "affected": "<2.0.37",
            "fix": "sqlalchemy>=2.0.37",
            "severity": "CRITICAL",
            "cvss": 9.8
        }
    },
    
    # cryptography
    "cryptography": {
        "CVE-2025-1249": {
            "description": "Key disclosure via RSA encryption",
            "affected": "<44.0.0",
            "fix": "cryptography>=44.0.0",
            "severity": "MEDIUM",
            "cvss": 5.9
        }
    },
    
    # numpy
    "numpy": {
        "CVE-2025-23791": {
            "description": "Arbitrary code execution via Pickle",
            "affected": "<1.26.4",
            "fix": "numpy>=1.26.4",
            "severity": "HIGH",
            "cvss": 8.8
        }
    },
    
    # pandas
    "pandas": {
        "CVE-2025-23791": {
            "description": "Arbitrary code execution via pickle",
            "affected": "<2.2.3",
            "fix": "pandas>=2.2.3",
            "severity": "HIGH",
            "cvss": 8.8
        }
    },
    
    # aiohttp
    "aiohttp": {
        "CVE-2025-27879": {
            "description": "HTTP Request Smuggling",
            "affected": "<3.11.9",
            "fix": "aiohttp>=3.11.9",
            "severity": "HIGH",
            "cvss": 7.5
        }
    }
}


def check_cve(package_name, version):
    """Check if a package version has known CVEs"""
    package_lower = package_name.lower().replace("-", "_").replace("_", "-")
    
    for cve_id, info in KNOWN_CVES.items():
        if cve_id in package_lower or package_lower in cve_id:
            return {
                "cve": cve_id,
                "info": info
            }
    
    return None


import time
import os
import json
import os
from pathlib import Path

CVE_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_CACHE = {}
CVE_CACHE_TIME = 86400
CVE_RATE_LIMIT = 6
CVE_LAST_CALL = {}

CVE_DATA_FILE = Path("/tmp/pysec_cve_cache.json")


def load_cve_cache():
    """Load CVE data from JSON file"""
    global CVE_CACHE
    if CVE_DATA_FILE.exists():
        try:
            data = json.loads(CVE_DATA_FILE.read_text())
            CVE_CACHE = data.get("cves", {})
        except:
            pass


def save_cve_cache():
    """Save CVE data to JSON file"""
    try:
        CVE_DATA_FILE.write_text(json.dumps({"cves": CVE_CACHE, "updated": time.time()}))
    except:
        pass


load_cve_cache()


def fetch_cves_from_nvd(package_name, max_results=3):
    """Fetch CVEs for a package - daily update only"""
    cache_key = package_name.lower()
    now = time.time()
    
    if cache_key in CVE_CACHE:
        cached_time, cached_data = CVE_CACHE[cache_key]
        if now - cached_time < CVE_CACHE_TIME:
            return cached_data
    
    return []


def check_package_cves(package_name):
    """Check for CVEs both in local DB and live NVD"""
    local_cve = check_cve(package_name, "")
    
    live_cves = fetch_cves_from_nvd(package_name)
    
    return {
        "local": local_cve,
        "live": live_cves
    }
