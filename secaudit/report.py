"""Report generation - rich terminal tables and JSON output."""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

from secaudit.models import Finding, ScanResult, Severity

if TYPE_CHECKING:
    from secaudit.baseline import DiffResult

from secaudit.compliance import OWASP_TOP_10, group_by_owasp

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_table(results: list[ScanResult], min_severity: Severity = Severity.INFO) -> None:
    console = Console()
    all_findings: list[Finding] = []
    for r in results:
        all_findings.extend(f for f in r.findings if f.severity >= min_severity)

    all_findings.sort(key=lambda f: f.severity.rank, reverse=True)

    if not all_findings:
        console.print("\n[bold green]No findings above the severity threshold.[/]")
        _print_summary(console, results, all_findings)
        return

    table = Table(title="SecAudit Findings", show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("Scanner", width=14)
    table.add_column("Title", width=40)
    table.add_column("Location", width=40)
    table.add_column("CWE", width=10)

    for f in all_findings:
        color = SEVERITY_COLORS[f.severity]
        table.add_row(
            f"[{color}]{f.severity.value}[/]",
            f.scanner,
            f.title,
            f.location,
            f.cwe_id or "",
        )

    console.print()
    console.print(table)
    _print_summary(console, results, all_findings)


def _print_summary(console: Console, results: list[ScanResult], findings: list[Finding]) -> None:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    parts = []
    for sev in Severity:
        if counts[sev] > 0:
            color = SEVERITY_COLORS[sev]
            parts.append(f"[{color}]{sev.value}: {counts[sev]}[/]")

    total_duration = sum(r.duration_seconds for r in results)
    console.print(f"\n[bold]Summary:[/] {len(findings)} finding(s) | {' | '.join(parts) if parts else 'Clean'}")
    console.print(f"Scanners run: {len(results)} | Duration: {total_duration:.2f}s\n")


def render_json(results: list[ScanResult], min_severity: Severity = Severity.INFO) -> str:
    output = {
        "$schema": "secaudit-v1",
        "generated_at": datetime.now().isoformat(),
        "results": [],
        "summary": {"total": 0},
    }

    total_by_severity = {s.value: 0 for s in Severity}

    for r in results:
        filtered = [f for f in r.findings if f.severity >= min_severity]
        result_dict = r.to_dict()
        result_dict["findings"] = [f.to_dict() for f in filtered]
        output["results"].append(result_dict)
        for f in filtered:
            total_by_severity[f.severity.value] += 1

    output["summary"] = {
        "total": sum(total_by_severity.values()),
        "by_severity": total_by_severity,
    }

    return json.dumps(output, indent=2)


def render_owasp(results: list[ScanResult], min_severity: Severity = Severity.INFO) -> None:
    """Render findings grouped by OWASP Top 10 2021 categories."""
    console = Console()
    groups = group_by_owasp(results, min_severity)

    if not groups:
        console.print("\n[bold green]No findings mapped to OWASP Top 10 categories.[/]\n")
        return

    console.print("\n[bold]OWASP Top 10 2021 Compliance Report[/]\n")

    for owasp_id in sorted(groups.keys()):
        findings = groups[owasp_id]
        cat_name = OWASP_TOP_10[owasp_id]["name"]
        console.print(f"[bold]{owasp_id} - {cat_name}[/] ({len(findings)} finding(s))")

        table = Table(show_lines=False, box=None, padding=(0, 2))
        table.add_column("Severity", width=10)
        table.add_column("Title", width=50)
        table.add_column("Location", width=40)

        for f in findings:
            color = SEVERITY_COLORS[f.severity]
            table.add_row(
                f"[{color}]{f.severity.value}[/]",
                f.title,
                f.location,
            )
        console.print(table)
        console.print()


def render_diff_summary(diff: DiffResult) -> None:
    """Render a colored summary of baseline diff results."""
    console = Console()
    console.print("\n[bold]Baseline Comparison:[/]")
    console.print(f"  [bold red]New findings:[/]       {len(diff.new_findings)}")
    console.print(f"  [bold green]Fixed findings:[/]     {len(diff.fixed_findings)}")
    console.print(f"  [dim]Unchanged findings:[/]  {len(diff.unchanged_findings)}")

    if diff.new_findings:
        console.print("\n[bold red]New findings:[/]")
        for f in diff.new_findings:
            color = SEVERITY_COLORS[f.severity]
            console.print(f"  [{color}]{f.severity.value}[/] {f.title} @ {f.location}")

    if diff.fixed_findings:
        console.print("\n[bold green]Fixed findings:[/]")
        for f in diff.fixed_findings:
            console.print(f"  [green]{f.get('title', 'unknown')}[/] @ {f.get('location', 'unknown')}")

    console.print()
