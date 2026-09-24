# WebView / in-app browser recon: `samples/nyt_games.xapk`

- Package: `com.nytimes.crossword` 6.43.0 (code 6427643)
- SDK: min 29 / target 36
- Network security config: `None` (cleartext permitted = None)
- Native libs touching WebView: 0

## Summary

- CRITICAL: 6
- HIGH: 7
- MEDIUM: 24
- LOW: 12
- INFO: 4

## Findings

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/android/hybrid/HybridWebView.smali:152 (<init>)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
.line 18
    invoke-virtual {p0, p2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/games/features/hybrid/components/vanilla/VanillaGameComponentActivityKt.smali:997 (j)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (True)
_analysis/nyt_games/work/smali_classes6/com/nytimes/games/integrations/hybrid/HybridWebViewConfigurer.smali:106 (a)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [CRITICAL] CORR-001 - com.nytimes.games.features.hybrid.components.vanilla.VanillaGameComponentActivityKt: file:// pages can reach any remote origin with JS on
_com.nytimes.games.features.hybrid.components.vanilla.VanillaGameComponentActivityKt_

A local file rendered in this WebView can exfiltrate itself to any attacker-controlled host. This is the worst-case WebView configuration.

```
setAllowUniversalAccessFromFileURLs(true) + setJavaScriptEnabled(true)
```

### [CRITICAL] CORR-001 - com.nytimes.games.integrations.hybrid.HybridWebViewConfigurer: file:// pages can reach any remote origin with JS on
_com.nytimes.games.integrations.hybrid.HybridWebViewConfigurer_

A local file rendered in this WebView can exfiltrate itself to any attacker-controlled host. This is the worst-case WebView configuration.

```
setAllowUniversalAccessFromFileURLs(true) + setJavaScriptEnabled(true)
```

### [CRITICAL] CORR-001 - com.nytimes.android.hybrid.HybridWebView: file:// pages can reach any remote origin with JS on
_com.nytimes.android.hybrid.HybridWebView_

A local file rendered in this WebView can exfiltrate itself to any attacker-controlled host. This is the worst-case WebView configuration.

```
setAllowUniversalAccessFromFileURLs(true) + setJavaScriptEnabled(true)
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (argument unresolved)
_analysis/nyt_games/work/smali_classes2/com/amazon/aps/ads/util/adview/ApsAdViewUtils$Companion.smali:446 (e)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
move-result p1

    invoke-static {p1}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/nyt_games/work/smali_classes3/com/google/android/gms/internal/ads/zzcko.smali:307 (<init>)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
if-eqz p3, :cond_1

    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/android/hybrid/HybridWebView.smali:149 (<init>)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
.line 17
    invoke-virtual {p0, p2}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/games/features/hybrid/components/vanilla/VanillaGameComponentActivityKt.smali:995 (j)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
invoke-virtual {p1, p4}, Landroid/webkit/WebSettings;->setDisplayZoomControls(Z)V

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_analysis/nyt_games/work/smali_classes6/com/nytimes/games/integrations/hybrid/HybridWebViewConfigurer.smali:104 (a)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setDisplayZoomControls(Z)V

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (argument unresolved)
_analysis/nyt_games/work/smali_classes6/com/nytimes/games/integrations/hybrid/view/BaseHybridFragment.smali:2569 (h3)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
move-result p0

    invoke-static {p0}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (argument unresolved)
_analysis/nyt_games/work/smali_classes6/com/nytimes/games/integrations/hybrid/devsettings/GamesHybridDevSettingFactory$devSettings$2.smali:123 (invokeSuspend)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
invoke-static {p1}, Lkotlin/ResultKt;->b(Ljava/lang/Object;)V

    invoke-static {v0}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes2/co/datadome/sdk/DataDomeWebView.smali:254 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes2/co/datadome/sdk/ChallengeActivity.smali:889 (setupWebview)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object v3

    invoke-virtual {v3, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes2/com/amazon/aps/ads/util/adview/ApsAdViewUtils$Companion.smali:450 (e)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p1, 0x1

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-005 - content:// access enabled (True)
_analysis/nyt_games/work/smali_classes2/com/amazon/aps/ads/util/adview/ApsAdViewUtils$Companion.smali:452 (e)_

setAllowContentAccess(true) lets the WebView follow content:// URLs, widening the reachable data set.

```
invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setAllowContentAccess(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes3/com/google/android/gms/ads/internal/zzs.smali:67 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p2, 0x1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes3/com/google/android/gms/internal/ads/zzcko.smali:265 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:try_start_0
    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_analysis/nyt_games/work/smali_classes3/com/google/android/gms/internal/ads/zzcko.smali:287 (<init>)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V

    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes3/com/google/android/gms/internal/ads/zzfty.smali:28 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes3/com/google/android/gms/internal/ads/zzfub.smali:54 (a)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes4/com/iab/omid/library/amazon/publisher/a.smali:29 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes4/com/iab/omid/library/amazon/publisher/b.smali:189 (t)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes4/com/iteratehq/iterate/view/SurveyView.smali:861 (o3)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v3, 0x1

    invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes4/com/nytimes/android/composeui/webview/WebviewScreenKt.smali:1811 (t)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p9, 0x1

    invoke-virtual {p1, p9}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes4/com/google/android/gms/internal/consent_sdk/zzbc.smali:318 (g)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v3, 0x1

    invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/android/hybrid/HybridWebView.smali:135 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 13
    invoke-virtual {p0, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/games/core/activity/PurrCookiedWebActivity.smali:228 (onCreate)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v3, 0x1

    invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/games/features/hybrid/components/vanilla/VanillaGameComponentActivityKt.smali:977 (j)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p2, 0x1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes6/com/nytimes/games/integrations/hybrid/HybridWebViewConfigurer.smali:84 (a)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p1, 0x1

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_analysis/nyt_games/work/smali_classes6/com/statsig/androidsdk/DebugView$Companion.smali:104 (getConfiguredWebView)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
const/4 p2, 0x1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/nyt_games/work/smali_classes6/com/statsig/androidsdk/DebugView$Companion.smali:106 (getConfiguredWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_com.amazon.aps.ads.util.adview.ApsAdViewUtils_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [MEDIUM] WV-SET-005 - content:// access enabled (True)
_com.amazon.aps.ads.util.adview.ApsAdViewUtils_

setAllowContentAccess(true) lets the WebView follow content:// URLs, widening the reachable data set.

```
access -> True
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_com.statsig.androidsdk.DebugView_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_com.statsig.androidsdk.DebugView_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
automatically -> True
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/nyt_games/work/smali_classes2/com/amazon/aps/ads/util/adview/ApsAdViewUtils$Companion.smali:454 (e)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setAllowContentAccess(Z)V

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/nyt_games/work/smali_classes3/com/google/android/gms/ads/internal/util/zzn.smali:55 (call)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setDatabaseEnabled(Z)V

    invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/nyt_games/work/smali_classes3/com/google/android/gms/internal/ads/zzcko.smali:285 (<init>)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
invoke-virtual {p2, p5}, Landroid/webkit/WebSettings;->setSavePassword(Z)V

    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/android/hybrid/HybridWebView.smali:146 (<init>)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 16
    invoke-virtual {p0, p2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/games/core/activity/PurrCookiedWebActivity.smali:230 (onCreate)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/games/features/hybrid/components/vanilla/VanillaGameComponentActivityKt.smali:985 (j)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {p1, p4}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/nyt_games/work/smali_classes5/com/nytimes/games/features/hybrid/components/vanilla/VanillaGameComponentActivityKt.smali:999 (j)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/nyt_games/work/smali_classes6/com/nytimes/games/integrations/hybrid/HybridWebViewConfigurer.smali:92 (a)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/nyt_games/work/smali_classes6/com/nytimes/games/integrations/hybrid/HybridWebViewConfigurer.smali:108 (a)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/nyt_games/work/smali_classes6/com/statsig/androidsdk/DebugView$Companion.smali:110 (getConfiguredWebView)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setDatabaseEnabled(Z)V

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_com.amazon.aps.ads.util.adview.ApsAdViewUtils_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
enabled -> True
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_com.statsig.androidsdk.DebugView_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
enabled -> True
```

### [INFO] WV-SINK-004 - JS bridge `android` exposed by co.datadome.sdk.ChallengeActivity
_co.datadome.sdk.ChallengeActivity:437_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(new JavascriptInterfaceDataDomeListener(new h(stringExtra)), "android")
```

### [INFO] WV-SINK-004 - JS bridge `message` exposed by com.iteratehq.iterate.view.SurveyView
_com.iteratehq.iterate.view.SurveyView:232_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(new Object() { // from class: com.iteratehq.iterate.view.SurveyView$setupView$2$, "message")  methods=['postMessage']
```

### [INFO] WV-SINK-004 - JS bridge `amzn_bridge` exposed by com.amazon.aps.ads.util.adview.ApsAdViewImpl
_com.amazon.aps.ads.util.adview.ApsAdViewImpl:453_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(apsAdViewWebBridge, "amzn_bridge")
```

### [INFO] WV-SINK-004 - JS bridge `NYTG` exposed by com.nytimes.android.hybrid.bridge.NativeBridge
_com.nytimes.android.hybrid.bridge.NativeBridge:80_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(this, "NYTG")  methods=['enqueue']
```

## WebView hosts

### `com.nytimes.games.features.hybrid.components.vanilla.VanillaGameComponentActivityKt`
- sources: smali
- settings:
  - `allow_file_access_from_file_urls` = `True`
  - `allow_universal_access_from_file_urls` = `True`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `False`
  - `support_multiple_windows` = `True`

### `com.nytimes.games.features.hybrid.components.base.HybridComponentActivity`
- sources: smali (exported component)
- settings:
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`
  - `dom_storage_enabled` = `False`
  - `javascript_enabled` = `False`
  - `js_can_open_windows_automatically` = `False`
  - `support_multiple_windows` = `False`

### `com.nytimes.games.integrations.hybrid.HybridWebViewConfigurer`
- sources: smali
- settings:
  - `allow_file_access_from_file_urls` = `True`
  - `allow_universal_access_from_file_urls` = `True`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `False`
  - `support_multiple_windows` = `True`

### `com.amazon.aps.ads.util.adview.ApsAdViewUtils$Companion`
- sources: smali
- settings:
  - `allow_content_access` = `True`
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `None`

### `com.google.android.gms.internal.ads.zzcko`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`
  - `mixed_content_mode` = `2`
  - `support_multiple_windows` = `True`
- loaded URLs:
  - `about:blank`

### `com.nytimes.android.hybrid.HybridWebView`
- sources: smali
- settings:
  - `allow_file_access_from_file_urls` = `True`
  - `allow_universal_access_from_file_urls` = `True`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `False`

### `com.amazon.aps.ads.util.adview.ApsAdViewUtils`
- sources: java
- settings:
  - `allow_content_access` = `True`
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.google.android.gms.internal.ads.zzfub`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.iab.omid.library.amazon.publisher.b`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.google.android.gms.internal.consent_sdk.zzbc`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.statsig.androidsdk.DebugView$Companion`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`
- loaded URLs:
  - `https://console.statsig.com/client_sdk_debugger_redirect?sdkKey=`

### `com.statsig.androidsdk.DebugView`
- sources: java
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`
- loaded URLs:
  - `https://console.statsig.com/client_sdk_debugger_redirect?sdkKey=`

### `co.datadome.sdk.ChallengeActivity`
- sources: smali
- settings:
  - `allow_file_access_from_file_urls` = `False`
  - `javascript_enabled` = `True`
- JS bridges: `android`

### `com.google.android.gms.ads.internal.util.zzn`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `dom_storage_enabled` = `True`

### `com.google.android.gms.ads.internal.util.zzs`
- sources: smali
- settings:
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`

### `com.nytimes.games.core.activity.PurrCookiedWebActivity`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `co.datadome.sdk.DataDomeWebView`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.google.android.gms.ads.internal.zzs`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.google.android.gms.internal.ads.zzfty`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.iab.omid.library.amazon.publisher.a`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.iteratehq.iterate.view.SurveyView`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- JS bridges: `message`

### `com.nytimes.android.composeui.webview.WebviewScreenKt`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.nytimes.games.integrations.hybrid.view.BaseHybridFragment`
- sources: smali
- settings:
  - `web_contents_debugging` = `None`

### `com.nytimes.games.integrations.hybrid.devsettings.GamesHybridDevSettingFactory$devSettings$2`
- sources: smali
- settings:
  - `web_contents_debugging` = `None`

### `com.iab.omid.library.amazon.internal.h`
- sources: java
- loaded URLs:
  - `javascript: `

### `com.amazon.aps.ads.util.adview.ApsAdViewImpl`
- sources: java
- JS bridges: `amzn_bridge`

### `com.nytimes.android.hybrid.bridge.NativeBridge`
- sources: java
- JS bridges: `NYTG`

### `com.google.android.gms.internal.consent_sdk.zzct`
- sources: java
- loaded URLs:
  - `javascript:`

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `com.nytimes.games.core.activity.MainActivity` | True | nytxwd://featured<br>nytxwd://packs<br>nytxwd://spelling-bee<br>nytxwd://tiles |
| activity | `com.nytimes.games.core.activity.PackDetailsActivity` | False |  |
| activity | `com.nytimes.games.core.activity.GameActivity` | False |  |
| activity | `com.nytimes.games.core.activity.IntentFilterActivity` | True |  |
| activity | `com.nytimes.games.core.activity.PuzzleInfoActivity` | False |  |
| activity | `com.nytimes.games.core.activity.ProductLandingActivity` | False |  |
| activity | `com.nytimes.games.core.activity.AboutActivity` | False |  |
| activity | `com.nytimes.games.core.activity.ThemeSettingsActivity` | False |  |
| activity | `com.nytimes.games.core.activity.LicenseActivity` | False |  |
| activity | `com.nytimes.games.core.activity.TeamRosterActivity` | False |  |
| activity | `com.nytimes.games.core.activity.SubscriptionDetailsActivity` | False |  |
| activity | `com.nytimes.games.core.activity.SettingsActivity` | False |  |
| activity | `com.nytimes.games.core.activity.AnalyticsLoggerActivity` | False |  |
| activity | `com.nytimes.games.core.activity.GamesHybridHostActivity` | True | nytxwd://games/ |
| activity | `com.nytimes.games.core.activity.PurrCookiedWebActivity` | False |  |
| activity | `com.nytimes.games.core.subauth.SubauthLIREFeedbackHelperActivity` | False |  |
| activity | `com.nytimes.subauth.ui.purr.webview.PurrUIWebViewActivity` | False |  |
| activity | `com.nytimes.games.features.hybrid.components.base.HybridComponentActivity` | True |  |
| activity | `com.nytimes.subauth.ui.login.SubauthLoginActivity` | True | nytmobile://authorize/games<br>nytxwd://login |
| activity | `com.nytimes.games.features.hybrid.components.vanilla.VanillaGameComponentActivity` | True | nytxwd://vanilla-games/ |
| activity | `com.nytimes.games.features.me.profile.ProfileManagementPlaygroundActivity` | False |  |
| activity | `com.nytimes.games.features.me.badges.BadgeComponentPlaygroundActivity` | False |  |
| activity | `com.nytimes.games.features.comments.ViewingCommentsActivity` | False |  |
| activity | `com.nytimes.games.features.comments.writenewcomment.WriteNewCommentActivity` | False |  |
| activity | `com.nytimes.games.integrations.push.ui.settings.PushSettingsActivity` | False |  |
| activity | `com.nytimes.games.features.home.DynamicCrossplayCardPlaygroundActivity` | False |  |
| activity | `com.nytimes.games.features.home.CardExpansionPlaygroundActivity` | False |  |
| activity | `com.nytimes.games.features.home.HeadlineCardsPlaygroundActivity` | False |  |
| activity | `com.nytimes.games.features.postoffer.ui.view.PostRegiLoginOfferActivity` | False |  |
| activity | `com.nytimes.games.features.maintenance.MaintenanceActivity` | False |  |
| activity | `com.nytimes.android.poisonpill.devsettings.PoisonPillDevBlockerActivity` | True |  |
| activity | `com.nytimes.android.eventtracker.devsettings.logviewer.ET2EventViewerActivity` | False |  |
| activity | `com.nytimes.android.eventtracker.devsettings.logviewer.EventGateEventViewerActivity` | False |  |
| activity | `com.nytimes.android.devsettings.home.DevSettingsActivity` | False |  |
| activity | `com.nytimes.android.devsettings.home.DevSettingsXmlActivity` | False |  |
| activity | `com.nytimes.android.devsettings.utils.ProcessPhoenix` | False |  |
| activity | `com.nytimes.subauth.ui.accountdelete.AccountDeleteActivity` | True |  |
| activity | `com.nytimes.subauth.ui.purr.privacysettings.PrivacySettingsActivity` | False |  |
| activity | `com.nytimes.android.poisonpill.ui.PoisonPillActivity` | True |  |
| activity | `com.nytimes.android.growthui.landingpage.LandingPageActivity` | False |  |
| activity | `com.nytimes.android.growthui.postauth.PostAuthActivity` | False |  |
| activity | `com.nytimes.android.growthui.postfreemonthoffer.PostFreeMonthInterstitialActivity` | False |  |
| activity | `com.nytimes.android.bugreporting.BugReportingWebViewActivity` | False |  |
| activity | `com.nytimes.android.bugreporting.BugReportingActivity` | False |  |
| activity | `com.google.android.gms.ads.AdActivity` | False |  |
| activity | `com.google.android.gms.ads.OutOfContextTestingActivity` | False |  |
| activity | `com.google.android.gms.ads.NotificationHandlerActivity` | False |  |
| activity | `com.airbnb.android.showkase.ui.ShowkaseBrowserActivity` | False |  |
| activity | `androidx.compose.ui.tooling.PreviewActivity` | True |  |
| activity | `co.datadome.sdk.ChallengeActivity` | False |  |
| activity | `androidx.credentials.playservices.controllers.identityauth.HiddenActivity` | False |  |
| activity | `androidx.credentials.playservices.controllers.identitycredentials.IdentityCredentialApiHiddenActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivityV2` | False |  |
| activity | `com.google.android.gms.auth.api.signin.internal.SignInHubActivity` | False |  |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| activity | `com.google.android.play.core.common.PlayCoreDialogWrapperActivity` | False |  |
| activity | `com.amazon.aps.ads.activity.ApsInterstitialActivity` | True |  |
| activity | `com.amazon.device.ads.DTBInterstitialActivity` | True |  |
| service | `com.nytimes.android.internal.pushmessaging.fcmprovider.FCMService` | False |  |
| service | `com.nytimes.android.eventtracker.buffer.EventReporterService` | False |  |
| service | `com.google.android.gms.ads.AdService` | False |  |
| service | `androidx.work.impl.background.systemalarm.SystemAlarmService` | False |  |
| service | `androidx.work.impl.background.systemjob.SystemJobService` | True |  |
| service | `androidx.work.impl.foreground.SystemForegroundService` | False |  |
| service | `androidx.room.MultiInstanceInvalidationService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `com.google.firebase.messaging.FirebaseMessagingService` | False |  |
| service | `androidx.credentials.playservices.CredentialProviderMetadataHolder` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementJobService` | False |  |
| service | `com.google.android.gms.auth.api.signin.RevocationBoundService` | True |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| receiver | `com.nytimes.games.core.util.InstallReferrerReceiver` | True |  |
| receiver | `com.nytimes.android.eventtracker.worker.EventReporterReceiver` | False |  |
| receiver | `androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.RescheduleReceiver` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver` | False |  |
| receiver | `androidx.work.impl.diagnostics.DiagnosticsReceiver` | True |  |
| receiver | `com.google.firebase.iid.FirebaseInstanceIdReceiver` | True |  |
| receiver | `com.google.android.gms.measurement.AppMeasurementReceiver` | False |  |
| receiver | `androidx.profileinstaller.ProfileInstallReceiver` | True |  |
| receiver | `com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver` | False |  |
| receiver | `com.instacart.library.truetime.BootCompletedBroadcastReceiver` | False |  |
| provider | `androidx.startup.InitializationProvider` | False |  |
| provider | `androidx.core.content.FileProvider` | False |  |
| provider | `com.nytimes.android.subauth.core.auth.provider.CrossAppLoginProvider` | True |  |
| provider | `com.nytimes.android.subauth.core.auth.provider.CrossAppAnonProvider` | True |  |
| provider | `com.google.android.gms.ads.MobileAdsInitProvider` | False |  |
| provider | `com.google.firebase.provider.FirebaseInitProvider` | False |  |
| provider | `com.nytimes.android.sharedkeyvalue.provider.SharedKeyValueContentProvider` | True |  |
| provider | `com.datadog.android.rum.DdRumContentProvider` | False |  |
