"""Informes en texto (terminal), Markdown y JSON.

Sirven para el análisis de SSH (`Analysis`) y para el web (`WebAnalysis`): los dos
tienen una lista de `Finding` y cada hallazgo se pinta igual. Todo lo que viene del
log (usuarios, URLs) se escapa antes de sacarlo, porque lo controla el atacante.
"""

from __future__ import annotations

import json
import re

from .ansi import clean, paint
from .detectors import Analysis, Severity

COLOR = {Severity.CRITICAL: "bright_red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "blue"}
INDENT = " " * 10

_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|!~])")


def _md(text: str) -> str:
    """Escapa texto para Markdown: que una URL del log no se convierta en un enlace, una imagen o HTML."""
    return _MD_SPECIAL.sub(r"\\\1", clean(text))


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _span(f) -> str:
    if f.first_seen.date() == f.last_seen.date():
        return f"{_fmt(f.first_seen)} -> {f.last_seen:%H:%M:%S}"
    return f"{_fmt(f.first_seen)} -> {_fmt(f.last_seen)}"


def severity_tag(severity: Severity) -> str:
    return paint(f"[{severity.label}]".ljust(len(INDENT)), "bold", COLOR[severity])


def _finding_text(f) -> list[str]:
    when = _span(f) + (f"  ({f.mitre})" if f.mitre else "")
    return [
        f"{severity_tag(f.severity)}{paint(clean(f.title), 'bold')}",
        INDENT + paint(when, "gray"),
        INDENT + clean(f.details),
        "",
    ]


def _finding_md(f) -> list[str]:
    out = [
        f"### [{f.severity.label}] {_md(f.title)}",
        "",
        f"- **Cuándo:** {_fmt(f.first_seen)} -> {_fmt(f.last_seen)}",
        f"- **Detalle:** {_md(f.details)}",
    ]
    if f.mitre:
        out.append(f"- **MITRE ATT&CK:** {f.mitre}")
    out.append("")
    return out


def _header_text(title: str, events, stats: list[tuple[str, int]]) -> list[str]:
    out = [paint(title, "bold", "cyan")]
    if events:
        out.append(paint(f"Periodo: {_fmt(events[0].timestamp)} -> {_fmt(events[-1].timestamp)}", "gray"))
    out.append(", ".join(f"{paint(str(n), 'bold')} {label}" for label, n in stats))
    out.append("")
    return out


# SSH


def to_text(analysis: Analysis, source: str) -> str:
    stats = [
        ("eventos", len(analysis.events)),
        ("fallos", len(analysis.failures)),
        ("accesos", len(analysis.successes)),
        ("IPs con fallos", len({e.ip for e in analysis.failures})),
        ("hallazgos", len(analysis.findings)),
    ]
    out = _header_text(f"log-sentinel: {source}", analysis.events, stats)
    if not analysis.findings:
        out.append(paint("Sin hallazgos.", "green"))
    for f in analysis.findings:
        out += _finding_text(f)
    if analysis.failures:
        top_ips = ", ".join(f"{ip} ({n})" for ip, n in analysis.top_ips(5))
        top_users = ", ".join(f"{clean(user) or '(vacío)'} ({n})" for user, n in analysis.top_users(5))
        out.append(f"{paint('IPs con más fallos:', 'bold')}     {top_ips}")
        out.append(f"{paint('Usuarios más probados:', 'bold')}  {top_users}")
    return "\n".join(out)


def to_markdown(analysis: Analysis, source: str) -> str:
    events = analysis.events
    out = [f"# Informe de log-sentinel: `{source}`", ""]
    if events:
        out += [f"Periodo analizado: {_fmt(events[0].timestamp)} -> {_fmt(events[-1].timestamp)}", ""]
    out += [
        "| Métrica | Valor |",
        "|---|---:|",
        f"| Eventos de autenticación | {len(events)} |",
        f"| Intentos fallidos | {len(analysis.failures)} |",
        f"| Accesos correctos | {len(analysis.successes)} |",
        f"| IPs con fallos | {len({e.ip for e in analysis.failures})} |",
        f"| Hallazgos | {len(analysis.findings)} |",
        "",
        "## Hallazgos",
        "",
    ]
    if not analysis.findings:
        out += ["Sin hallazgos.", ""]
    for f in analysis.findings:
        out += _finding_md(f)
    if analysis.failures:
        out += ["## IPs con más fallos", "", "| IP | Fallos |", "|---|---:|"]
        out += [f"| `{ip}` | {n} |" for ip, n in analysis.top_ips()]
        out += ["", "## Usuarios más probados", "", "| Usuario | Intentos |", "|---|---:|"]
        out += [f"| {_md(user) or '(vacío)'} | {n} |" for user, n in analysis.top_users()]
        out.append("")
    return "\n".join(out)


def to_json(analysis: Analysis, source: str) -> str:
    report = {
        "source": source,
        "kind": "ssh",
        "summary": {
            "events": len(analysis.events),
            "failures": len(analysis.failures),
            "successes": len(analysis.successes),
        },
        "findings": [f.to_dict() for f in analysis.findings],
        "top_ips": analysis.top_ips(),
        "top_users": analysis.top_users(),
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


# Web


def web_to_text(analysis, source: str) -> str:
    events = analysis.events
    stats = [
        ("peticiones", len(events)),
        ("IPs", len({e.ip for e in events})),
        ("404/403", sum(e.status in (404, 403) for e in events)),
        ("hallazgos", len(analysis.findings)),
    ]
    out = _header_text(f"log-sentinel (web): {source}", events, stats)
    if not analysis.findings:
        out.append(paint("Sin hallazgos.", "green"))
    for f in analysis.findings:
        out += _finding_text(f)
    if events:
        top_ips = ", ".join(f"{ip} ({n})" for ip, n in analysis.top_ips(5))
        out.append(f"{paint('IPs con más peticiones:', 'bold')} {top_ips}")
    return "\n".join(out)


def web_to_markdown(analysis, source: str) -> str:
    events = analysis.events
    out = [f"# Informe web de log-sentinel: `{source}`", ""]
    if events:
        out += [f"Periodo analizado: {_fmt(events[0].timestamp)} -> {_fmt(events[-1].timestamp)}", ""]
    out += [
        "| Métrica | Valor |",
        "|---|---:|",
        f"| Peticiones | {len(events)} |",
        f"| IPs distintas | {len({e.ip for e in events})} |",
        f"| Respuestas 404/403 | {sum(e.status in (404, 403) for e in events)} |",
        f"| Hallazgos | {len(analysis.findings)} |",
        "",
        "## Hallazgos",
        "",
    ]
    if not analysis.findings:
        out += ["Sin hallazgos.", ""]
    for f in analysis.findings:
        out += _finding_md(f)
    return "\n".join(out)


def web_to_json(analysis, source: str) -> str:
    report = {
        "source": source,
        "kind": "web",
        "summary": {
            "requests": len(analysis.events),
            "ips": len({e.ip for e in analysis.events}),
            "not_found": sum(e.status in (404, 403) for e in analysis.events),
        },
        "findings": [f.to_dict() for f in analysis.findings],
        "top_ips": analysis.top_ips(),
        "top_paths": analysis.top_paths(),
    }
    return json.dumps(report, indent=2, ensure_ascii=False)
