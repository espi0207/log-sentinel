"""Panel HTML en un solo fichero, para abrirlo con doble clic.

No carga nada de internet: las gráficas son SVG y barras de CSS hechas a mano. Además
lleva una Content-Security-Policy que prohíbe cualquier script, así que aunque algo
del log se colara sin escapar, el navegador no lo ejecutaría.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime

from .detectors import Finding, Severity

SEV_COLOR = {
    Severity.CRITICAL: "#f0506e",
    Severity.HIGH: "#f6994a",
    Severity.MEDIUM: "#f2c744",
    Severity.LOW: "#4aa3f0",
}


def _esc(text) -> str:
    return html.escape(str(text))


def _severity_bars(findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    total = max(sum(counts.values()), 1)
    rows = []
    for sev in sorted(Severity, reverse=True):
        n = counts.get(sev, 0)
        pct = 100 * n / total
        rows.append(
            f'<div class="bar-row"><span class="bar-label">{_esc(sev.label)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{pct:.1f}%;'
            f'background:{SEV_COLOR[sev]}"></span></span>'
            f'<span class="bar-num">{n}</span></div>'
        )
    return "\n".join(rows)


def _timeline_svg(findings: list[Finding], buckets: int = 32) -> str:
    if not findings:
        return '<p class="muted">Sin hallazgos que situar en el tiempo.</p>'
    times = [f.first_seen for f in findings]
    start, end = min(times), max(times)
    span = (end - start).total_seconds() or 1
    step = span / buckets
    # Cada bucket guarda un contador por severidad para apilar las barras.
    grid: list[Counter] = [Counter() for _ in range(buckets)]
    for f in findings:
        idx = min(int((f.first_seen - start).total_seconds() / step), buckets - 1)
        grid[idx][f.severity] += 1
    tallest = max((sum(b.values()) for b in grid), default=1) or 1

    w, h, pad = 720, 150, 22
    bw = (w - 2 * pad) / buckets
    bars = []
    for i, bucket in enumerate(grid):
        x = pad + i * bw
        y = h - pad
        for sev in sorted(Severity):
            n = bucket.get(sev, 0)
            if not n:
                continue
            bh = (h - 2 * pad) * n / tallest
            y -= bh
            bars.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{max(bw - 1.5, 1):.1f}" height="{bh:.1f}" '
                f'fill="{SEV_COLOR[sev]}" rx="1"><title>{_esc(sev.label)}: {n}</title></rect>'
            )
    axis = (
        f'<line x1="{pad}" y1="{h - pad}" x2="{w - pad}" y2="{h - pad}" class="axis"/>'
        f'<text x="{pad}" y="{h - 6}" class="tick">{start:%d/%m %H:%M}</text>'
        f'<text x="{w - pad}" y="{h - 6}" class="tick" text-anchor="end">{end:%d/%m %H:%M}</text>'
    )
    return f'<svg viewBox="0 0 {w} {h}" class="chart" role="img">{"".join(bars)}{axis}</svg>'


def _top_ips_bars(top_ips: list[tuple[str, int]], findings: list[Finding]) -> str:
    if not top_ips:
        return '<p class="muted">Sin datos.</p>'
    worst: dict[str, Severity] = {}
    for f in findings:
        if f.ip and (f.ip not in worst or f.severity > worst[f.ip]):
            worst[f.ip] = f.severity
    biggest = max(n for _, n in top_ips)
    rows = []
    for ip, n in top_ips:
        pct = 100 * n / biggest
        color = SEV_COLOR.get(worst.get(ip), "#6b7280")
        rows.append(
            f'<div class="bar-row"><span class="bar-ip">{_esc(ip)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{pct:.1f}%;background:{color}"></span></span>'
            f'<span class="bar-num">{n}</span></div>'
        )
    return "\n".join(rows)


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return '<tr><td colspan="5" class="muted">Ningún hallazgo.</td></tr>'
    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f'<td><span class="pill" style="background:{SEV_COLOR[f.severity]}">{_esc(f.severity.label)}</span></td>'
            f"<td><b>{_esc(f.title)}</b><br><span class='muted'>{_esc(f.details)}</span></td>"
            f"<td class='mono'>{_esc(f.ip or '-')}</td>"
            f"<td class='mono nowrap'>{f.first_seen:%d/%m %H:%M} - {f.last_seen:%H:%M}</td>"
            f"<td class='mono'>{_esc(f.mitre or '-')}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def build_dashboard(
    findings: list[Finding],
    top_ips: list[tuple[str, int]],
    summary: list[tuple[str, int]],
    source: str,
    kind: str = "ssh",
    generated: datetime | None = None,
) -> str:
    findings = sorted(findings, key=lambda f: (-f.severity, f.first_seen))
    generated = generated or datetime.now()
    tiles = "\n".join(
        f'<div class="tile"><div class="tile-num">{v}</div><div class="tile-label">{_esc(k)}</div></div>'
        for k, v in summary
    )
    crit = sum(f.severity >= Severity.HIGH for f in findings)
    return _TEMPLATE.format(
        source=_esc(source),
        kind=_esc("SSH" if kind == "ssh" else kind),
        generated=generated.strftime("%Y-%m-%d %H:%M"),
        tiles=tiles,
        alert_class="danger" if crit else "ok",
        alert_text=(f"{crit} hallazgo(s) de prioridad alta o crítica" if crit else "Nada de prioridad alta o crítica"),
        severity_bars=_severity_bars(findings),
        timeline=_timeline_svg(findings),
        top_ips=_top_ips_bars(top_ips, findings),
        table=_findings_table(findings),
    )


def dashboard_from(analysis, source: str, kind: str = "ssh") -> str:
    events = analysis.events
    if kind == "web":
        summary = [
            ("Peticiones", len(events)),
            ("IPs", len({e.ip for e in events})),
            ("404/403", sum(e.status in (404, 403) for e in events)),
            ("Hallazgos", len(analysis.findings)),
        ]
    else:
        summary = [
            ("Eventos", len(events)),
            ("Fallos", len(analysis.failures)),
            ("Accesos", len(analysis.successes)),
            ("Hallazgos", len(analysis.findings)),
        ]
    return build_dashboard(analysis.findings, analysis.top_ips(8), summary, source, kind)


_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>log-sentinel - panel</title>
<style>
  :root {{
    --bg: #0f1420; --card: #181f2e; --border: #26304a; --text: #e6e9f0;
    --muted: #8a93a8; --accent: #4aa3f0;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg: #f5f6fa; --card: #ffffff; --border: #e1e4ec; --text: #1a1f2b; --muted: #6b7280; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text);
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; line-height: 1.5; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 24px 16px 64px; }}
  header h1 {{ margin: 0 0 4px; font-size: 1.5rem; }}
  header .sub {{ color: var(--muted); font-size: .9rem; }}
  .banner {{ margin: 18px 0; padding: 12px 16px; border-radius: 10px; font-weight: 600; }}
  .banner.danger {{ background: rgba(240,80,110,.15); color: #f0506e; border: 1px solid rgba(240,80,110,.4); }}
  .banner.ok {{ background: rgba(74,163,240,.12); color: var(--accent); border: 1px solid rgba(74,163,240,.35); }}
  .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }}
  .tile {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 16px; text-align: center; }}
  .tile-num {{ font-size: 1.9rem; font-weight: 700; }}
  .tile-label {{ color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }}
  @media (max-width: 700px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }}
  .card h2 {{ margin: 0 0 12px; font-size: 1rem; }}
  .chart {{ width: 100%; height: auto; }}
  .axis {{ stroke: var(--border); }}
  .tick {{ fill: var(--muted); font-size: 11px; font-family: monospace; }}
  .bar-row {{ display: flex; align-items: center; gap: 8px; margin: 6px 0; font-size: .85rem; }}
  .bar-label {{ width: 62px; color: var(--muted); }}
  .bar-ip {{ width: 118px; font-family: monospace; font-size: .8rem; }}
  .bar-track {{ flex: 1; background: rgba(128,128,128,.15); border-radius: 6px; overflow: hidden; height: 14px; }}
  .bar-fill {{ display: block; height: 100%; border-radius: 6px; }}
  .bar-num {{ width: 34px; text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: var(--card);
    border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border);
    vertical-align: top; font-size: .88rem; }}
  th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: .72rem; letter-spacing: .04em; }}
  tr:last-child td {{ border-bottom: none; }}
  .pill {{ display: inline-block; padding: 2px 8px; border-radius: 20px; color: #0b0e16;
    font-weight: 700; font-size: .72rem; }}
  .mono {{ font-family: monospace; }}
  .nowrap {{ white-space: nowrap; }}
  .muted {{ color: var(--muted); }}
  footer {{ margin-top: 28px; color: var(--muted); font-size: .8rem; text-align: center; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>log-sentinel</h1>
    <div class="sub">Log {kind}: <span class="mono">{source}</span>, generado el {generated}</div>
  </header>
  <div class="banner {alert_class}">{alert_text}</div>
  <div class="tiles">{tiles}</div>
  <div class="grid">
    <div class="card"><h2>Hallazgos en el tiempo</h2>{timeline}</div>
    <div class="card"><h2>Por prioridad</h2>{severity_bars}</div>
  </div>
  <div class="card" style="margin-top:16px"><h2>IPs más activas</h2>{top_ips}</div>
  <table>
    <thead><tr><th>Prioridad</th><th>Hallazgo</th><th>IP</th><th>Cuándo</th><th>MITRE ATT&amp;CK</th></tr></thead>
    <tbody>{table}</tbody>
  </table>
  <footer>log-sentinel</footer>
</div>
</body>
</html>
"""
