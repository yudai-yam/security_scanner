"""SBOM generation in CycloneDX JSON format."""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path


def _parse_deps(path: Path) -> list[tuple[str, str]]:
    """Parse dependencies from requirements.txt or pyproject.toml."""
    packages = []
    content = path.read_text()

    if path.name == "requirements.txt":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)", line)
            if match:
                packages.append((match.group(1), match.group(2)))
            else:
                # Handle deps without pinned version
                match = re.match(r"([A-Za-z0-9_.-]+)", line)
                if match:
                    packages.append((match.group(1), ""))
    elif path.name == "pyproject.toml":
        for match in re.finditer(
            r"""['"]([A-Za-z0-9_.-]+)(?:\s*[><=!~]+\s*([^'";\s,\]]+))?['"]""",
            content,
        ):
            name = match.group(1)
            version = match.group(2) or ""
            packages.append((name, version))

    return packages


def generate_sbom(target: str) -> str:
    """Generate a CycloneDX 1.5 SBOM in JSON format."""
    path = Path(target)

    if path.is_dir():
        # Look for common dependency files
        for candidate in ("requirements.txt", "pyproject.toml"):
            dep_file = path / candidate
            if dep_file.exists():
                path = dep_file
                break

    packages = _parse_deps(path) if path.is_file() else []

    components = []
    for name, version in packages:
        purl = f"pkg:pypi/{name.lower()}"
        if version:
            purl += f"@{version}"
        component = {
            "type": "library",
            "name": name,
            "purl": purl,
            "bom-ref": purl,
        }
        if version:
            component["version"] = version
        components.append(component)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "SecAudit",
                    "name": "secaudit",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": Path(target).name,
                "bom-ref": f"pkg:generic/{Path(target).name}",
            },
        },
        "components": components,
    }

    return json.dumps(sbom, indent=2)
