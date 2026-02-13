"""Click-based CLI interface for SecAudit."""

import sys
from pathlib import Path

import click

from secaudit.models import ScanResult, Severity
from secaudit.report import render_json, render_table
from secaudit.scanners.code import CodeScanner
from secaudit.scanners.dependencies import DependencyScanner
from secaudit.scanners.headers import HeaderScanner
from secaudit.scanners.secrets import SecretScanner
from secaudit.scanners.tls import TLSScanner

SEVERITY_CHOICES = [s.value for s in Severity]


def _run_scanners(scanners, targets, fmt, min_severity, output, exit_code):
    results: list[ScanResult] = []
    for scanner, target in zip(scanners, targets):
        result = scanner._timed_scan(target)
        results.append(result)

    sev = Severity(min_severity)

    if fmt == "json":
        json_out = render_json(results, min_severity=sev)
        if output:
            Path(output).write_text(json_out)
            click.echo(f"Report written to {output}")
        else:
            click.echo(json_out)
    else:
        render_table(results, min_severity=sev)
        if output:
            json_out = render_json(results, min_severity=sev)
            Path(output).write_text(json_out)
            click.echo(f"JSON report also written to {output}")

    if exit_code:
        has_findings = any(
            f.severity >= sev for r in results for f in r.findings
        )
        if has_findings:
            sys.exit(1)


@click.group()
@click.version_option(package_name="secaudit")
def cli():
    """SecAudit - Automated Security Audit Toolkit."""


@cli.command()
@click.argument("url")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--severity", "min_severity", type=click.Choice(SEVERITY_CHOICES), default="INFO")
@click.option("--output", "-o", type=str, default=None, help="Write JSON report to file.")
@click.option("--exit-code", is_flag=True, help="Exit with code 1 if findings >= severity.")
def scan_url(url, fmt, min_severity, output, exit_code):
    """Run HTTP header and TLS scanners against a URL."""
    scanners = [HeaderScanner(), TLSScanner()]
    targets = [url, url]
    _run_scanners(scanners, targets, fmt, min_severity, output, exit_code)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--severity", "min_severity", type=click.Choice(SEVERITY_CHOICES), default="INFO")
@click.option("--output", "-o", type=str, default=None)
@click.option("--exit-code", is_flag=True)
def scan_code(path, fmt, min_severity, output, exit_code):
    """Run secret and SAST scanners on a directory."""
    scanners = [SecretScanner(), CodeScanner()]
    targets = [path, path]
    _run_scanners(scanners, targets, fmt, min_severity, output, exit_code)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--severity", "min_severity", type=click.Choice(SEVERITY_CHOICES), default="INFO")
@click.option("--output", "-o", type=str, default=None)
@click.option("--exit-code", is_flag=True)
def scan_deps(path, fmt, min_severity, output, exit_code):
    """Run dependency vulnerability scanner."""
    scanners = [DependencyScanner()]
    targets = [path]
    _run_scanners(scanners, targets, fmt, min_severity, output, exit_code)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--url", type=str, default=None, help="URL for header/TLS scanning.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--severity", "min_severity", type=click.Choice(SEVERITY_CHOICES), default="INFO")
@click.option("--output", "-o", type=str, default=None)
@click.option("--exit-code", is_flag=True)
def scan_all(path, url, fmt, min_severity, output, exit_code):
    """Run all scanners. Provide a path and optionally a --url."""
    scanners = [SecretScanner(), CodeScanner(), DependencyScanner()]
    targets = [path, path, path]

    if url:
        scanners.extend([HeaderScanner(), TLSScanner()])
        targets.extend([url, url])

    _run_scanners(scanners, targets, fmt, min_severity, output, exit_code)
