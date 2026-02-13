"""Tests for SBOM generation."""

import json

from secaudit.sbom import generate_sbom


class TestSBOM:
    def test_requirements_txt(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\nrequests==2.31.0\n")
        sbom = json.loads(generate_sbom(str(req)))
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert len(sbom["components"]) == 2
        names = {c["name"] for c in sbom["components"]}
        assert "flask" in names
        assert "requests" in names

    def test_purl_format(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\n")
        sbom = json.loads(generate_sbom(str(req)))
        assert sbom["components"][0]["purl"] == "pkg:pypi/flask@2.3.0"

    def test_directory_detection(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("click==8.1.0\n")
        sbom = json.loads(generate_sbom(str(tmp_path)))
        assert len(sbom["components"]) == 1

    def test_empty_file(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# no deps\n")
        sbom = json.loads(generate_sbom(str(req)))
        assert len(sbom["components"]) == 0

    def test_metadata(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\n")
        sbom = json.loads(generate_sbom(str(req)))
        assert sbom["metadata"]["tools"][0]["name"] == "secaudit"
        assert "serialNumber" in sbom
