"""Click-based CLI interface for SecAudit."""

import sys
from pathlib import Path

import click

from secaudit.baseline import compute_diff, has_new_findings, load_baseline
from secaudit.config import load_config
from secaudit.models import ScanResult, Severity
from secaudit.formatters.sarif import render_sarif
from secaudit.report import render_json, render_owasp, render_table, render_diff_summary
from secaudit.sbom import generate_sbom
from secaudit.scanners.code import CodeScanner
from secaudit.scanners.dependencies import DependencyScanner
from secaudit.scanners.headers import HeaderScanner
from secaudit.scanners.secrets import SecretScanner
from secaudit.scanners.git_history import GitHistoryScanner
from secaudit.scanners.tls import TLSScanner

SEVERITY_CHOICES = [s.value for s in Severity]


def _run_scanners(scanners, targets, fmt, min_severity, output, exit_code, baseline=None, compliance=None):
    results: list[ScanResult] = []
    for scanner, target in zip(scanners, targets):
        result = scanner._timed_scan(target)
        results.append(result)

    sev = Severity(min_severity)

    # Baseline diff mode
    diff = None
    if baseline:
        baseline_data = load_baseline(baseline)
        diff = compute_diff(results, baseline_data)

    if fmt in ("json", "sarif"):
        if fmt == "sarif":
            text_out = render_sarif(results, min_severity=sev)
        else:
            text_out = render_json(results, min_severity=sev)
        if output:
            Path(output).write_text(text_out)
            click.echo(f"Report written to {output}")
        else:
            click.echo(text_out)
    else:
        render_table(results, min_severity=sev)
        if output:
            json_out = render_json(results, min_severity=sev)
            Path(output).write_text(json_out)
            click.echo(f"JSON report also written to {output}")

    if diff:
        render_diff_summary(diff)

    if compliance == "owasp":
        render_owasp(results, min_severity=sev)

    if exit_code:
        if diff:
            # With baseline, only fail on NEW findings
            if has_new_findings(diff, sev):
                sys.exit(1)
        else:
            has_findings_flag = any(
                f.severity >= sev for r in results for f in r.findings
            )
            if has_findings_flag:
                sys.exit(1)


@click.group()
@click.version_option(package_name="secaudit")
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="Path to .secaudit.yml config file.")
@click.pass_context
def cli(ctx, config_path):
    """SecAudit - Automated Security Audit Toolkit."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path


@cli.command()
@click.argument("url")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "sarif"]), default="table")
@click.option("--severity", "min_severity", type=click.Choice(SEVERITY_CHOICES), default="INFO")
@click.option("--output", "-o", type=str, default=None, help="Write JSON report to file.")
@click.option("--exit-code", is_flag=True, help="Exit with code 1 if findings >= severity.")
@click.option("--baseline", type=click.Path(exists=True), default=None, help="Baseline JSON for diff mode.")
@click.option("--compliance", type=click.Choice(["owasp"]), default=None, help="Compliance report (owasp).")
def scan_url(url, fmt, min_severity, output, exit_code, baseline, compliance):
    """Run HTTP header and TLS scanners against a URL."""
    scanners = [HeaderScanner(), TLSScanner()]
    targets = [url, url]
    _run_scanners(scanners, targets, fmt, min_severity, output, exit_code, baseline=baseline, compliance=compliance)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json", "sarif"]), default="table")
@click.option("--severity", "min_severity", type=click.Choice(SEVERITY_CHOICES), default="INFO")
@click.option("--output", "-o", type=str, default=None)
@click.option("--exit-code", is_flag=True)
@click.option("--baseline", type=click.Path(exists=True), default=None, help="Baseline JSON for diff mode.")
@click.option("--compliance", type=click.Choice(["owasp"]), default=None, help="Compliance report (owasp).")
def scan_code(path, fmt, min_severity, output, exit_code, baseline, compliance):
    """Run secret and SAST scanners on a directory."""
    scanners = [SecretScanner(), CodeScanner()]
    targets = [path, path]
    _run_scanners(scanners, targets, fmt, min_severity, output, exit_code, baseline=baseline, compliance=compliance)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json", "sarif"]), default="table")
@click.option("--severity", "min_severity", type=click.Choice(SEVERITY_CHOICES), default="INFO")
@click.option("--output", "-o", type=str, default=None)
@click.option("--exit-code", is_flag=True)
@click.option("--baseline", type=click.Path(exists=True), default=None, help="Baseline JSON for diff mode.")
@click.option("--compliance", type=click.Choice(["owasp"]), default=None, help="Compliance report (owasp).")
def scan_deps(path, fmt, min_severity, output, exit_code, baseline, compliance):
    """Run dependency vulnerability scanner."""
    scanners = [DependencyScanner()]
    targets = [path]
    _run_scanners(scanners, targets, fmt, min_severity, output, exit_code, baseline=baseline, compliance=compliance)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json", "sarif"]), default="table")
@click.option("--severity", "min_severity", type=click.Choice(SEVERITY_CHOICES), default="INFO")
@click.option("--output", "-o", type=str, default=None)
@click.option("--exit-code", is_flag=True)
@click.option("--max-commits", type=int, default=100, help="Max commits to scan.")
@click.option("--baseline", type=click.Path(exists=True), default=None, help="Baseline JSON for diff mode.")
@click.option("--compliance", type=click.Choice(["owasp"]), default=None, help="Compliance report (owasp).")
def scan_git(path, fmt, min_severity, output, exit_code, max_commits, baseline, compliance):
    """Scan git history for leaked secrets."""
    scanners = [GitHistoryScanner(max_commits=max_commits)]
    targets = [path]
    _run_scanners(scanners, targets, fmt, min_severity, output, exit_code, baseline=baseline, compliance=compliance)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", type=str, default=None, help="Write SBOM to file.")
def sbom(path, output):
    """Generate a CycloneDX SBOM from project dependencies."""
    sbom_json = generate_sbom(path)
    if output:
        Path(output).write_text(sbom_json)
        click.echo(f"SBOM written to {output}")
    else:
        click.echo(sbom_json)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--url", type=str, default=None, help="URL for header/TLS scanning.")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "sarif"]), default="table")
@click.option("--severity", "min_severity", type=click.Choice(SEVERITY_CHOICES), default="INFO")
@click.option("--output", "-o", type=str, default=None)
@click.option("--exit-code", is_flag=True)
@click.option("--baseline", type=click.Path(exists=True), default=None, help="Baseline JSON for diff mode.")
@click.option("--compliance", type=click.Choice(["owasp"]), default=None, help="Compliance report (owasp).")
def scan_all(path, url, fmt, min_severity, output, exit_code, baseline, compliance):
    """Run all scanners. Provide a path and optionally a --url."""
    scanners = [SecretScanner(), CodeScanner(), DependencyScanner()]
    targets = [path, path, path]

    if url:
        scanners.extend([HeaderScanner(), TLSScanner()])
        targets.extend([url, url])

    _run_scanners(scanners, targets, fmt, min_severity, output, exit_code, baseline=baseline, compliance=compliance)
