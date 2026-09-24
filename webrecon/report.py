"""Render a Report to Markdown."""

from __future__ import annotations

from .scanner import Report


def render(report: Report) -> str:
    out = []
    p = out.append
    p(f"# WebView / in-app browser recon: `{report.target}`\n")
    p(f"- Package: `{report.package}` {report.version_name} (code {report.version_code})")
    p(f"- SDK: min {report.min_sdk} / target {report.target_sdk}")
    f = report.facts
    p(f"- Network security config: `{f.get('nsc_file')}` "
      f"(cleartext permitted = {f.get('nsc_cleartext_permitted')})")
    p(f"- Native libs touching WebView: {len(report.native_webview_libs)}")
    p("")

    counts = {}
    for fi in report.findings:
        counts[fi["severity"]] = counts.get(fi["severity"], 0) + 1
    p("## Summary\n")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if counts.get(sev):
            p(f"- {sev}: {counts[sev]}")
    p("")

    p("## Findings\n")
    for fi in report.findings:
        p(f"### [{fi['severity']}] {fi['rule']} - {fi['title']}")
        if fi.get("location"):
            p(f"_{fi['location']}_")
        p("")
        p(fi["detail"])
        if fi.get("evidence"):
            p("")
            p("```")
            p(str(fi["evidence"])[:600])
            p("```")
        p("")

    p("## WebView hosts\n")
    for h in report.hosts:
        if not h.settings and not h.bridges and not h.loaded_urls:
            continue
        p(f"### `{h.name}`")
        p(f"- sources: {h.source}"
          + (" (exported component)" if h.is_exported_component else ""))
        if h.settings:
            p("- settings:")
            for k, v in sorted(h.settings.items()):
                p(f"  - `{k}` = `{v}`")
        if h.bridges:
            p("- JS bridges: " + ", ".join(f"`{b.name}`" for b in h.bridges))
        if h.loaded_urls:
            p("- loaded URLs:")
            for u in h.loaded_urls[:10]:
                p(f"  - `{u}`")
        if h.unrestricted_navigation:
            p("- navigation: **no allowlist detected**")
        p("")

    p("## Exported components\n")
    p("| kind | name | exported | deeplinks |")
    p("|------|------|----------|-----------|")
    for c in report.components:
        links = "<br>".join(c.deeplinks[:4])
        p(f"| {c.kind} | `{c.name}` | {c.exported} | {links} |")
    p("")

    if report.native_webview_libs:
        p("## Native libraries referencing WebView\n")
        for lib in report.native_webview_libs:
            p(f"- `{lib}`")
        p("")

    if report.errors:
        p("## Errors\n")
        for e in report.errors:
            p(f"- {e}")
    return "\n".join(out)
