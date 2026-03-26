# CVE Vulnerability Checker for pysec

## Known CVEs for Python Dependencies

### urllib3
- **CVE-2025-66418**: Unbounded decompression chain (DoS)
  - Affects: versions >= 1.24 and < 2.6.0
  - Fix: Upgrade to urllib3 >= 2.6.0
  - Severity: HIGH (CVSS 7.5)

### idna
- **CVE-2024-XXXX**: Check current CVEs for idna
- Fix: Upgrade to latest version

### charset_normalizer
- Check for known vulnerabilities

### certifi
- Check for known vulnerabilities

## Common Vulnerability Patterns

1. **Outdated Dependencies**: Using old versions with known CVEs
2. **Unpatched Vulnerabilities**: Not applying security patches
3. **Transitive Dependencies**: Vulnerabilities in indirect dependencies

## Fix Instructions for OpenCode

When you find vulnerable dependencies, update them to the latest secure versions:

### Example Fix:
```toml
# Before (vulnerable)
dependencies = [
    "urllib3>=1.26,<3",
]

# After (secure)
dependencies = [
    "urllib3>=2.6.0",
]
```

Or run:
```bash
pip install --upgrade urllib3>=2.6.0
```
