---
name: find-hidden-webviews
description: >
  Find hidden WebView / in-app browser surface in an Android app and reason about
  what web content it can reach. Use when asked to "find hidden webviews", "scan
  an Android app for WebView issues", "check if this app can open arbitrary
  links", "analyze an APK's in-app browser", or to audit a specific app's
  WebView configuration. Produces an evidence-backed static report.
---

# Finding hidden WebViews in an Android app

## Mental model

You are chasing one thing: **can the user (or another app) make this app follow
an arbitrary web link inside its own WebView, and what can the resulting page
reach?**

A real chain looks like this (this is exactly what happened in Apple Music):

1. App ships a WebView for a fixed page (privacy policy, support, acknowledgements).
2. The WebView's `WebViewClient.shouldOverrideUrlLoading` calls `loadUrl(url)`
   and returns `false` for every URL — no host allowlist, no browser handoff.
3. The user taps a link on that trusted page, which lands on a third-party site.
4. That site links onward, and the user keeps going — login pages, app-store
   listings, developer sites, anything — all inside the app's WebView.
5. The WebView carries the app's cookies, injected JS bridges, and any enabled
   debug instrumentation across every hop.

## Workflow

### 1. Setup

```bash
./install_sdk.sh
```

If there is no `/dev/kvm`, do not attempt an emulator — this is a static analysis
task. The pipeline needs only the JDK.

### 2. Get the APK

Prefer the mirror that works; APKPure is reliable:

```bash
mkdir -p samples
curl -sSL -o samples/target.xapk -A 'Mozilla/5.0' \
  'https://d.apkpure.com/b/APK/<package.name>?version=latest'
```

An `.xapk`/`.apks` bundle is fine; the tool unpacks it.

### 3. Run the analyzer

```bash
python3 -m webrecon.cli samples/target.xapk -o analysis/<name>
```

Read `analysis/<name>/report.md` first, then `report.json` for detail. Start at
the highest severity and confirm each finding against the source before
believing it.

### 4. Confirm findings by hand

The report is a hypothesis list. For each `CORR-*` finding, open the cited
`<out>/work/java/...` file and check:

- **Navigation**: is there really a `shouldOverrideUrlLoading` that calls
  `loadUrl` on the incoming URL and returns `false`, with no host check?
- **Bridges**: what does the `addJavascriptInterface` object actually expose?
  Look for `@JavascriptInterface` methods and whether any return device data
  (`getData`, `getDeviceInfo`, token/password getters).
- **Origin**: does the bridge get injected into a `http(s)` URL (remote origin)
  or only `file://`/`about:blank` (less reachable)?
- **Debug**: is `setWebContentsDebuggingEnabled(true)` called unconditionally?

### 5. Trace the entry points

Find how a user reaches the WebView and how another app can:

```bash
# exported components with broad deep links
grep -A30 'intent-filter' <out>/work/AndroidManifest.xml
```

An exported activity with an `http`/`https` `<data android:scheme=...>` and no
`android:host` accepts **any** URL. Trace where it sends the URL: an in-app
navigation stack (interesting) or a browser `ACTION_VIEW` (less so).

Also check the inverse trap: a handler whose intent-filter **does** pin a host
but whose code routes on `Uri.getPath()` alone. An intent-filter only constrains
*implicit* intents; an explicit intent (`setComponent`/`setClassName`) from any
other app on the device reaches the component regardless of its filters. So a
pinned filter gives no protection if the handler trusts the path. Grep the
handler for `getHost`/`getAuthority`:

```bash
grep -c 'Landroid/net/Uri;->getHost\|Landroid/net/Uri;->getAuthority' <out>/work/smali*/**/Handler.smali
```

Zero host reads plus several `getPath`/`getPathSegments` reads means another app
can drive a privileged route (OAuth confirm, payment, account edit chains) with
an attacker-chosen origin. The analyzer reports this as `CORR-022`.

### 6. Report

State each finding with `file:line` evidence, the concrete reachability path,
and a severity. Do not upgrade a static hypothesis to a confirmed exploit —
say what would confirm it (a rooted device, `chrome://inspect`, an instrumented
build).

## Evidence to collect for a strong report

- The exact override method and its `return false` (navigation is unpinned).
- Each bridge name plus the `@JavascriptInterface` method list.
- The initial `loadUrl` origin and whether it is remote.
- The network security config's `cleartextTrafficPermitted` value.
- The exported component + intent-filter that feeds URLs in.

## Anti-patterns

- Reporting a `setAllowFileAccess(false)` as a finding — that is correct
  hardening. The scanner already filters on the literal; keep that behavior.
- Calling a WebView "hidden" without showing how the user reaches it. Locate the
  activity/fragment and the tap path.
- Treating the emulator as required. It is not, and it will not run here.
