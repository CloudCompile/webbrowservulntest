# WebView survey — ten consumer Android apps

Static in-app-browser / WebView attack-surface recon with `webrecon`. No
emulator (`/dev/kvm` absent), so every result below comes from decompiled
manifest + smali/java. Raw scanner output for each app is in `<app>.md` /
`<app>.json` next to this file.

## Summary

| app | package | version | WebView hosts | CRIT | HIGH | MED | LOW | INFO |
|---|---|---|---|---|---|---|---|---|
| Atomic Mail | com.atomicmail | 1.7.0 | 22 | 1 | 7 | 3 | 4 | 1 |
| Brilliant | org.brilliant.android | 10.14.0 | 34 | 0 | 0 | 5 | 4 | 3 |
| Calm | com.calm.android | 7.1.2 | 24 | 0 | 0 | 8 | 4 | 2 |
| Duolingo | com.duolingo | 6.98.4 | 253 | 5 | 31 | 56 | 20 | 6 |
| Fly Delta | com.delta.mobile.android | 5.21.1 | 75 | 2 | 10 | 32 | 16 | 8 |
| Gospel Library | org.lds.ldssa | 6.5.3 | 26 | 0 | 4 | 6 | 2 | 3 |
| Meet Mobile | com.active.aps.meetmobile | 5.3.1.2549 | 64 | 0 | 1 | 8 | 3 | 0 |
| MuseScore | com.musescore.playerlite | 2.14.48 | 60 | 1 | 9 | 16 | 5 | 0 |
| NYT Games | com.nytimes.crossword | 6.43.0 | 144 | 6 | 7 | 24 | 12 | 4 |
| Skyward | com.skyward.mobileaccess | 3.3.0 | 39 | 1 | 14 | 6 | 4 | 3 |

("WebView hosts" = classes that configure a `WebView`; counts include third-party
SDK code — ads, Intercom, Datadome, Unity, Expo — which dominates the tail.)

## Themes

Three patterns recur, and only the first is the bug class this exercise is
about:

1. **No boundary on in-app navigation.** Nothing tells the WebView to stop at
   the origin it started on, so a trusted page becomes a general browser.
2. **Over-privileged WebView settings.** JS + DOM storage + file access, or
   remote debugging, on by default and sometimes app-wide.
3. **`file://` origin escapes.** `setAllowUniversalAccessFromFileURLs(true)`
   with JS enabled, letting a local page read/exfiltrate from any origin.

## Notable per app

### Duolingo — highest raw count, real chain exposure
`com.duolingo.web.WebViewActivity` and the Unity bridge
`com.unity3d.services.core.webview.WebView` both tick the worst combination:
`setAllowUniversalAccessFromFileURLs(true)` with JS on (`CORR-001`, CRITICAL),
local file access plus a JS bridge ( `CORR-002`, HIGH), and remote debugging
(`CORR-004`). This is the app to walk by hand next.

### NYT Games — three distinct `file://` escape surfaces
`VanillaGameComponentActivityKt`, `HybridWebViewConfigurer`, and the shared
`com.nytimes.android.hybrid.HybridWebView` all enable universal access from file
URLs with JS (`CORR-001` x3, CRITICAL). A hybrid (native+web) game shell is
exactly where a game-hosted page could bridge into the native side.

### Fly Delta — the only TLS-bypass finding in the set
`com.delta.mobile.android.webview.DeltaEmbeddedWebViewClient` proceeds past TLS
errors (`CORR-006`, HIGH) — the WebView trusts a connection it should have
refused. Also a `file://` escape in `locuslabs...JavaScriptEnvironment`
(CRITICAL) and remote debugging across several classes.

### Skyward — the most HIGH-severity findings per class
The Expo/React-Native WebView stack (`expo.modules.webview.DomWebView`,
`RNCWebViewManagerImpl`) drives 14 HIGH findings; local file access plus a JS
bridge (`CORR-002`) and remote debugging. A high-school SIS handling grades and
payroll is a sensitive place for a general-purpose bridge.

### MuseScore — third-party Intercom chat is the in-app browser
The three `CORR-005` hits are all Intercom's support-sheet clients
(`SheetWebViewPresenter`, `SheetWebViewClient`,
`MessengerCardWebViewClient`): no host allowlist, so the support chat's inline
links navigate in-app. Useful reminder that the in-app browser is often a
vendored SDK, not the first-party app.

### Atomic Mail — cleartext + remote debugging
`CORR-010` (cleartext HTTP globally permitted) and remote debugging enabled on
the React-Native WebView (`CORR-004`). A privacy-branded mail client allowing
plaintext transport is worth flagging on its own.

### Gospel Library — content WebView with bridge + file access
`org.lds.ldssa.ui.web.ContentWebView` combines local file access with a
`glContentInterface` JS bridge (`CORR-002`), and permits cleartext.

### Brilliant / Calm / Meet Mobile — settings-only, no correlated chain
These report only WebView *settings* (JS, DOM storage, mixed content, window
handling). No `file://` escape, no bridge+file combination, no navigation rule
fired — i.e. no evidence of the in-app-browser chain. Calm's JS bridge findings
are the PerimeterX bot-detection SDK, and Meet Mobile's are standard settings.

### BAND — not scanned
Skipped per request after the 225 MB XAPK crashed the container twice.

## Caveats

- Static only. A finding is an attack-surface fact, not proof of exploitability;
  whether the WebView is user-reachable needs the manual walk (as was done for
  Apple Music and Garmin).
- Rule IDs: `WV-SET-*` are raw setting hits, `WV-SINK-*` are JS-bridge
  exposures, `CORR-*` are correlated chains (the interesting ones). See
  `../README.md` for the rule table.
