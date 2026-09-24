# webrecon

Static reconnaissance for hidden WebView / in-app browser surface in Android apps.

The goal is to answer one question about an app: **which code paths let a user
follow an arbitrary web link inside the app, and what does that web content get
access to?** Apps routinely ship a WebView for a privacy policy, a support page,
a store, or an OAuth flow, and then let that WebView roam anywhere, with
JavaScript on, native bridges injected, and sometimes debug instrumentation
enabled.

This repository contains the analyzer plus a worked analysis of **Apple Music**
(`com.apple.android.music` 6.5.3) as the first target.

## Why static

The container has no `/dev/kvm`, so a hardware-accelerated Android emulator will
not run. Everything here works on the APK bytes: `apktool` for the manifest and
smali, `jadx` for readable Java, and `androguard` for the binary manifest. The
output is a set of `file:line` evidence-backed findings an agent (or a human) can
then confirm dynamically on real hardware if desired.

## Install

```bash
./install_sdk.sh          # JDK 21, apktool, aapt, jadx, androguard
```

## Use

```bash
# full pipeline: unpack + decompile + analyze
python3 -m webrecon.cli samples/apple_music.xapk -o analysis/webrecon

# analyze an already-decompiled tree (work/ holds AndroidManifest.xml, smali*/, java/)
python3 -m webrecon.cli app.apk -o out/app --skip-decompile
```

Outputs `report.md` (human) and `report.json` (machine) in the `-o` directory.

## What it looks for

| Rule | Severity | Meaning |
|------|----------|---------|
| `CORR-001` | CRITICAL | `setAllowUniversalAccessFromFileURLs(true)` + JS: a `file://` page can exfiltrate itself to any host |
| `CORR-002` | HIGH | local file access + injected JS bridge |
| `CORR-003` | HIGH | JS bridge reachable through unrestricted navigation |
| `CORR-004` | HIGH | `WebView.setWebContentsDebuggingEnabled(true)` |
| `CORR-006` | HIGH | `onReceivedSslError` proceeds past certificate failure |
| `CORR-007` | HIGH | native JS bridge injected into a remote origin |
| `CORR-005` | MEDIUM | `shouldOverrideUrlLoading` forwards every URL in-app, no host allowlist |
| `CORR-010` | MEDIUM | cleartext HTTP permitted globally in the network security config |
| `CORR-021` | MEDIUM | exported component accepts arbitrary `http(s)` URLs |
| `CORR-022` | MEDIUM | exported deep-link handler routes on URL path without checking host |
| `WV-SET-00x` | varies | individual `WebSettings` hardening failures (literal-aware) |
| `WV-SINK-004` | INFO | JS bridge exposed via `addJavascriptInterface` |

Rule definitions and mapping to OWASP MASVS / MASTG live in
[`webrecon/rules.py`](webrecon/rules.py).

The scanner recovers the literal boolean passed to each `WebSettings` call from
the smali register flow, so `setJavaScriptEnabled(true)` is reported while
`setAllowFileAccess(false)` (correct hardening) is not.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite runs against a synthetic decompiled work dir (a deliberately
vulnerable WebView plus a correctly hardened one) so it needs no APK and no
Android toolchain.

## Example finding: the Apple Music privacy-policy chain

`com.apple.android.music.common.activity.StaticHtmlActivity` renders the
privacy policy / acknowledgements / feedback pages in a WebView with JavaScript
enabled, and its `WebViewClient` is:

```java
public final boolean shouldOverrideUrlLoading(WebView webView, String str) {
    webView.loadUrl(str);
    return false;   // any URL stays in-app, no allowlist
}
```

There is no host check and no external-browser handoff, so a tap on any link in
the privacy policy navigates the app's own WebView onward: Apple's support site →
an App Store listing → a developer website → a login page → an arbitrary link.
The WebView keeps the app's cookies and stays on the app-controlled navigation
stack the whole way. `com.apple.android.music.common.activity.UriHandlerActivity`
is also `exported=true` with an `http`/`https` scheme filter (no host pinned), so
another app can feed URLs into that same dispatch path.

These are reported as `CORR-005` and `CORR-021`; the full report is in
`analysis/webrecon/report.md` after running the pipeline.

## Adding a target

```bash
# APKPure mirror; -L follows the CDN redirect
curl -sSL -o samples/apple_music.xapk \
  -A 'Mozilla/5.0' \
  'https://d.apkpure.com/b/APK/com.apple.android.music?version=latest'
```

An `.xapk`/`.apks` bundle is unpacked automatically; the largest inner `.apk` is
treated as the base module and split APKs are still scanned for native libraries.

## Scope

This is a defensive research tool. It reads APKs and produces a report; it does
not exploit anything, and it does not send any data anywhere. Findings are
static hypotheses with evidence attached, not confirmed exploits — confirm
dynamically (a rooted device or a KVM-enabled host) before treating any of them
as a vulnerability.
