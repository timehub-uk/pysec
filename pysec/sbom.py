"""
SBOM Generation - Software Bill of Materials in SPDX format
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional


def get_package_info(package: str) -> Optional[dict]:
    """Get package info from PyPI"""
    result = subprocess.run(
        ["pip", "show", package],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        return None
    
    info = {}
    for line in result.stdout.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            info[key.strip().lower()] = value.strip()
    return info


def get_installed_packages() -> list[dict]:
    """Get all installed packages"""
    result = subprocess.run(
        ["pip", "list", "--format=json"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        return []
    
    try:
        return json.loads(result.stdout)
    except:
        return []


def generate_sbom_spdx(output_file: str = None) -> str:
    """Generate SBOM in SPDX format"""
    timestamp = datetime.now().isoformat()
    packages = get_installed_packages()
    
    spdx_doc = f"""SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: Project SBOM
DocumentNamespace: https://example.org/sbom/{timestamp}
Creator: Tool: pysec
Created: {timestamp}

"""
    package_refs = []
    
    for pkg in packages:
        name = pkg.get("name", "unknown")
        version = pkg.get("version", "unknown")
        pkg_id = f"SPDXRef-PKG-{name.replace('-', '_')}"
        
        info = get_package_info(name)
        license_info = info.get("license", "NOASSERTION") if info else "NOASSERTION"
        
        spdx_doc += f"""PackageName: {name}
SPDXID: {pkg_id}
PackageVersion: {version}
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: {license_info}
PackageLicenseDeclared: {license_info}
PackageCopyrightText: NOASSERTION

"""
        package_refs.append(pkg_id)
    
    if output_file:
        Path(output_file).write_text(spdx_doc)
    
    return spdx_doc


def generate_sbom_cyclonedx(output_file: str = None) -> str:
    """Generate SBOM in CycloneDX format"""
    packages = get_installed_packages()
    
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{datetime.now().uuid}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tools": [{"name": "pysec", "version": "0.1.0"}]
        },
        "components": []
    }
    
    for pkg in packages:
        cyclonedx["components"].append({
            "type": "library",
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "purl": f"pkg:pypi/{pkg.get('name')}@{pkg.get('version')}",
            "bom-ref": f"pkg:pypi/{pkg.get('name')}"
        })
    
    json_output = json.dumps(cyclonedx, indent=2)
    
    if output_file:
        Path(output_file).write_text(json_output)
    
    return json_output


def generate_sbom_json(output_file: str = None) -> dict:
    """Generate SBOM in JSON format"""
    packages = get_installed_packages()
    
    sbom = {
        "format": "pysec-sbom",
        "version": "1.0",
        "generated": datetime.now().isoformat(),
        "packages": []
    }
    
    for pkg in packages:
        info = get_package_info(pkg.get("name", ""))
        sbom["packages"].append({
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "license": info.get("license", "unknown") if info else "unknown",
            "summary": info.get("summary", "") if info else ""
        })
    
    json_output = json.dumps(sbom, indent=2)
    
    if output_file:
        Path(output_file).write_text(json_output)
    
    return json_output