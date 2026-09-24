# WebView / in-app browser recon: `samples/fly_delta.apk`

- Package: `com.delta.mobile.android` 5.21.1 (code 23080)
- SDK: min 24 / target 30
- Network security config: `network_security_config.xml` (cleartext permitted = False)
- Native libs touching WebView: 0

## Summary

- CRITICAL: 2
- HIGH: 10
- MEDIUM: 32
- LOW: 16
- INFO: 8

## Findings

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (True)
_analysis/fly_delta/work/smali_classes5/com/locuslabs/sdk/javascriptintegration/JavaScriptEnvironment.smali:249 (initializeWebView)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
.line 9
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [CRITICAL] CORR-001 - com.locuslabs.sdk.javascriptintegration.JavaScriptEnvironment: file:// pages can reach any remote origin with JS on
_com.locuslabs.sdk.javascriptintegration.JavaScriptEnvironment_

A local file rendered in this WebView can exfiltrate itself to any attacker-controlled host. This is the worst-case WebView configuration.

```
setAllowUniversalAccessFromFileURLs(true) + setJavaScriptEnabled(true)
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/fly_delta/work/smali_classes2/com/delta/bridge/WebViewPage.smali:972 (load)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 9
    invoke-static {v1}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/booking/checkout/viewmodel/TripInsuranceViewModel.smali:82 (setTripInsurancePage)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 6
    invoke-static {v1}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_analysis/fly_delta/work/smali_classes5/com/locuslabs/sdk/javascriptintegration/JavaScriptEnvironment.smali:136 (addJellyBeanSettings)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
.line 2
    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/fly_delta/work/smali_classes5/com/locuslabs/sdk/javascriptintegration/JavaScriptEnvironment.smali:155 (addKitKatSettings)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 2
    invoke-static {v0}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/fly_delta/work/smali_classes5/com/locuslabs/sdk/javascriptintegration/JavaScriptEnvironment.smali:171 (addKitKatSettings)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 4
    invoke-static {v0}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_analysis/fly_delta/work/smali_classes5/com/locuslabs/sdk/javascriptintegration/JavaScriptEnvironment.smali:239 (initializeWebView)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
.line 7
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] CORR-004 - com.locuslabs.sdk.javascriptintegration.JavaScriptEnvironment: remote WebView debugging enabled
_com.locuslabs.sdk.javascriptintegration.JavaScriptEnvironment_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [HIGH] CORR-004 - com.delta.bridge.WebViewPage: remote WebView debugging enabled
_com.delta.bridge.WebViewPage_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [HIGH] CORR-004 - com.delta.mobile.android.booking.checkout.viewmodel.TripInsuranceViewModel: remote WebView debugging enabled
_com.delta.mobile.android.booking.checkout.viewmodel.TripInsuranceViewModel_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [HIGH] CORR-006 - com.delta.mobile.android.webview.DeltaEmbeddedWebViewClient: proceeds past TLS errors
_com.delta.mobile.android.webview.DeltaEmbeddedWebViewClient_

Invalid certificates are accepted; enables man-in-the-middle.

```
onReceivedSslError -> handler.proceed()
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes2/com/delta/bridge/WebViewPage.smali:912 (load)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes2/com/delta/mobile/android/WebPage.smali:90 (onCreate)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes2/com/cardinalcommerce/cardinalmobilesdk/a/c/a$1.smali:71 (run)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes2/com/adobe/marketing/mobile/AndroidFullscreenMessage$MessageFullScreenRunner.smali:125 (run)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 8
    invoke-virtual {v2, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes2/com/adobe/marketing/mobile/services/ui/MessageWebViewRunner.smali:956 (run)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 20
    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/traveling/AircraftLayout.smali:90 (initializeBrowser)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 4
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/traveling/AircraftLayout.smali:107 (initializeBrowser)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
iget-object v0, p0, Lcom/delta/mobile/android/traveling/AircraftLayout;->browserSettings:Landroid/webkit/WebSettings;

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/webview/DeltaEmbeddedWeb.smali:1567 (initializeWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 2
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/webview/DeltaEmbeddedWeb.smali:2085 (setDeltaDotComLinkOutBrowserSettings)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 2
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/merchandise/MerchandiseDetailsActivity.smali:136 (getHtmlData)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 2
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/citydetail/CityAirportMapDetail.smali:77 (initializeBrowser)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 3
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/citydetail/CityAirportMapDetail.smali:94 (initializeBrowser)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
iget-object v0, p0, Lcom/delta/mobile/android/citydetail/CityAirportMapDetail;->browserSettings:Landroid/webkit/WebSettings;

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/extras/TermsAndConditions.smali:39 (onCreate)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/booking/checkout/viewmodel/TripInsuranceViewModel.smali:47 (setTripInsurancePage)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/feeds/fragments/NewsFragment.smali:218 (renderInfo)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 2
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/todaymode/composables/ConnectedCabinPasscodeViewKt$UserAuthWebView$1.smali:97 (invoke)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v3, 0x1

    invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/checkin/view/AmexView.smali:93 (loadBanner)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v2, 0x1

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes4/com/foresee/sdk/common/ui/a/c.smali:69 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object p2

    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes4/com/foresee/sdk/cxMeasure/tracker/app/survey/SurveyActivity.smali:155 (Z)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes4/com/dynatrace/android/agent/Dynatrace.smali:614 (instrumentWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes4/com/google/android/gms/ads/internal/zzbp.smali:111 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p2, 0x1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_analysis/fly_delta/work/smali_classes4/com/google/android/gms/internal/ads/zzass.smali:114 (<init>)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
invoke-virtual {v0, p1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V

    invoke-virtual {v0, p1}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes4/com/google/android/gms/internal/ads/zzass.smali:150 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object v0

    invoke-virtual {v0, p1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes4/com/google/android/gms/internal/ads/zzari.smali:303 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:try_start_0
    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_analysis/fly_delta/work/smali_classes4/com/google/android/gms/internal/ads/zzari.smali:321 (<init>)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V

    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes5/com/locuslabs/sdk/javascriptintegration/JavaScriptEnvironment.smali:227 (initializeWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 3
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-005 - content:// access enabled (True)
_analysis/fly_delta/work/smali_classes5/com/locuslabs/sdk/javascriptintegration/JavaScriptEnvironment.smali:253 (initializeWebView)_

setAllowContentAccess(true) lets the WebView follow content:// URLs, widening the reachable data set.

```
.line 10
    :cond_0
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowContentAccess(Z)V
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_analysis/fly_delta/work/smali_classes5/com/locuslabs/sdk/javascriptintegration/JavaScriptEnvironment.smali:267 (initializeWebView)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
.line 14
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/fly_delta/work/smali_classes5/io/branch/referral/BranchViewHandler.smali:172 (createAndShowBranchView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v0, 0x1

    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_com.adobe.marketing.mobile.AndroidFullscreenMessage_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_com.delta.mobile.android.todaymode.composables.ConnectedCabinPasscodeViewKt_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_com.cardinalcommerce.cardinalmobilesdk.a.c.a_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes2/com/delta/bridge/WebViewPage.smali:921 (load)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v0

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes2/com/cardinalcommerce/cardinalmobilesdk/a/c/a$1.smali:83 (run)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v0

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes2/com/adobe/marketing/mobile/AndroidFullscreenMessage$MessageFullScreenRunner.smali:131 (run)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 10
    invoke-virtual {v2, v0}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes2/com/adobe/marketing/mobile/services/ui/MessageWebViewRunner.smali:966 (run)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
iget-object v1, p0, Lcom/adobe/marketing/mobile/services/ui/MessageWebViewRunner;->webviewSettings:Landroid/webkit/WebSettings;

    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/webview/DeltaEmbeddedWeb.smali:1580 (initializeWebView)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 5
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/webview/DeltaEmbeddedWeb.smali:2088 (setDeltaDotComLinkOutBrowserSettings)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 3
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/booking/checkout/viewmodel/TripInsuranceViewModel.smali:54 (setTripInsurancePage)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v0

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes3/com/delta/mobile/android/todaymode/composables/ConnectedCabinPasscodeViewKt$UserAuthWebView$1.smali:104 (invoke)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v2

    invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes4/com/foresee/sdk/common/ui/a/c.smali:81 (<init>)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object p2

    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/fly_delta/work/smali_classes4/com/google/android/gms/internal/ads/zzass.smali:112 (<init>)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
const/4 p1, 0x1

    invoke-virtual {v0, p1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/fly_delta/work/smali_classes4/com/google/android/gms/internal/ads/zzari.smali:319 (<init>)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
invoke-virtual {p2, p5}, Landroid/webkit/WebSettings;->setSavePassword(Z)V

    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes4/com/google/android/gms/internal/ads/zzaku.smali:106 (call)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
iget-object v0, p0, Lcom/google/android/gms/internal/ads/zzaku;->zzcrw:Landroid/webkit/WebSettings;

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/fly_delta/work/smali_classes5/com/locuslabs/sdk/javascriptintegration/JavaScriptEnvironment.smali:233 (initializeWebView)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 5
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_com.adobe.marketing.mobile.AndroidFullscreenMessage_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
enabled -> True
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_com.delta.mobile.android.todaymode.composables.ConnectedCabinPasscodeViewKt_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
enabled -> True
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_com.cardinalcommerce.cardinalmobilesdk.a.c.a_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
enabled -> True
```

### [INFO] WV-SINK-004 - JS bridge `googleAdsJsInterface` exposed by com.google.android.gms.internal.ads.zzari
_com.google.android.gms.internal.ads.zzari:174_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(zzaro.zzk(this), "googleAdsJsInterface")
```

### [INFO] WV-SINK-004 - JS bridge `container` exposed by com.delta.bridge.WebViewPage
_com.delta.bridge.WebViewPage:407_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(this.jsContainer, "container")  methods=['enablePinchAndZoom', 'getJsObject', 'getRhino', 'getWebViewHeight', 'handleEvent', 'handleFooterEvent', 'hasField', 'init', 'onPageLoaded', 'onRenderComplete', 'provideValueFor', 'retrieveValueFor', 'setJsObject', 'setResult']
```

### [INFO] WV-SINK-004 - JS bridge `resultHolder` exposed by com.delta.bridge.WebViewPage
_com.delta.bridge.WebViewPage:408_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(this.jsEvalResultHolder, "resultHolder")  methods=['enablePinchAndZoom', 'getJsObject', 'getRhino', 'getWebViewHeight', 'handleEvent', 'handleFooterEvent', 'hasField', 'init', 'onPageLoaded', 'onRenderComplete', 'provideValueFor', 'retrieveValueFor', 'setJsObject', 'setResult']
```

### [INFO] WV-SINK-004 - JS bridge `coverageDetailInterface` exposed by com.delta.mobile.android.merchandise.MerchandiseDetailsActivity
_com.delta.mobile.android.merchandise.MerchandiseDetailsActivity:60_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(new MerchandiseJSInterface(str), "coverageDetailInterface")
```

### [INFO] WV-SINK-004 - JS bridge `nativeBridge` exposed by com.delta.mobile.android.checkin.view.AmexView
_com.delta.mobile.android.checkin.view.AmexView:39_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(new AmexJavaScriptInterface(this.amexEligibilityView), "nativeBridge")
```

### [INFO] WV-SINK-004 - JS bridge `fsrTracker` exposed by com.foresee.sdk.cxMeasure.tracker.app.survey.SurveyActivity
_com.foresee.sdk.cxMeasure.tracker.app.survey.SurveyActivity:76_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(dVar, "fsrTracker")
```

### [INFO] WV-SINK-004 - JS bridge `googleAdsJsInterface` exposed by com.google.android.gms.internal.ads.zzasq
_com.google.android.gms.internal.ads.zzasq:134_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(zzaro.zzk(this), "googleAdsJsInterface")
```

### [INFO] WV-SINK-004 - JS bridge `GoogleJsInterface` exposed by com.google.android.gms.internal.ads.zzuf
_com.google.android.gms.internal.ads.zzuf:45_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(new zzun(this), "GoogleJsInterface")
```

## WebView hosts

### `com.locuslabs.sdk.javascriptintegration.JavaScriptEnvironment`
- sources: smali
- settings:
  - `allow_content_access` = `True`
  - `allow_file_access` = `True`
  - `allow_file_access_from_file_urls` = `True`
  - `allow_universal_access_from_file_urls` = `True`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`
  - `support_multiple_windows` = `False`
  - `web_contents_debugging` = `True`
- loaded URLs:
  - `javascript:`

### `com.google.android.gms.internal.ads.zzass`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`
  - `mixed_content_mode` = `2`
  - `support_multiple_windows` = `True`

### `com.google.android.gms.internal.ads.zzari`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`
  - `mixed_content_mode` = `2`
  - `support_multiple_windows` = `True`
- JS bridges: `googleAdsJsInterface`

### `com.delta.bridge.WebViewPage`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `True`
- JS bridges: `container`, `resultHolder`
- loaded URLs:
  - `file:///android_asset/hybrid/views/`
  - `javascript:(function() { interval = setInterval(function() { if (window.`
  - `javascript:(function() { window.deltaWindowHeight = window.innerHeight; })();`
  - `javascript:container.onPageLoaded();`
  - `javascript:container.onRenderComplete(window.`
  - `javascript:container.provideValueFor(`
  - `javascript:window.`
  - `javascript:window.footerView.bind(`

### `com.adobe.marketing.mobile.AndroidFullscreenMessage$MessageFullScreenRunner`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.adobe.marketing.mobile.services.ui.MessageWebViewRunner`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.delta.mobile.android.booking.checkout.viewmodel.TripInsuranceViewModel`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `True`

### `com.adobe.marketing.mobile.AndroidFullscreenMessage`
- sources: java
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.cardinalcommerce.cardinalmobilesdk.a.c.a$1`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.delta.mobile.android.webview.DeltaEmbeddedWeb`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.delta.mobile.android.todaymode.composables.ConnectedCabinPasscodeViewKt$UserAuthWebView$1`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.foresee.sdk.common.ui.a.c`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.google.android.gms.internal.ads.zzaky`
- sources: smali
- settings:
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`

### `com.google.android.gms.internal.ads.zzaku`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `dom_storage_enabled` = `True`

### `com.delta.mobile.android.todaymode.composables.ConnectedCabinPasscodeViewKt`
- sources: java
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.cardinalcommerce.cardinalmobilesdk.a.c.a`
- sources: java
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.delta.mobile.android.WebPage`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.cardinalcommerce.shared.cs.userinterfaces.ChallengeHTMLView`
- sources: smali
- settings:
  - `javascript_enabled` = `False`

### `com.delta.mobile.android.traveling.AircraftLayout`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.delta.mobile.android.merchandise.MerchandiseDetailsActivity`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- JS bridges: `coverageDetailInterface`
- loaded URLs:
  - `file:///android_asset/html/merchandise/insuranceCoverage.html`

### `com.delta.mobile.android.citydetail.CityAirportMapDetail`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.delta.mobile.android.extras.TermsAndConditions`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.delta.mobile.android.feeds.fragments.NewsFragment`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- loaded URLs:
  - `file:///android_asset/hybrid/views/noNewsContent.html`

### `com.delta.mobile.android.checkin.view.AmexView`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- JS bridges: `nativeBridge`

### `com.foresee.sdk.cxMeasure.tracker.app.survey.SurveyActivity`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- JS bridges: `fsrTracker`

### `com.dynatrace.android.agent.Dynatrace`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.google.android.gms.ads.internal.zzbp`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `io.branch.referral.BranchViewHandler`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.delta.mobile.android.todaymode.composables.ConnectedCabinPasscodeViewKt$UserAuthWebView$1$1$2`
- sources: java
- loaded URLs:
  - `javascript:postOk()`

### `com.google.android.gms.internal.ads.zzasv`
- sources: java
- loaded URLs:
  - `about:blank`

### `com.google.android.gms.internal.ads.zzasq`
- sources: java
- JS bridges: `googleAdsJsInterface`

### `com.google.android.gms.internal.ads.zzuf`
- sources: java
- JS bridges: `GoogleJsInterface`

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `com.delta.mobile.android.SplashScreen` | True | @string/my_trips_schema://*<br>@string/check_in_schema://*<br>@string/today_mode_schema://*<br>@string/flight_search_schema://* |
| activity | `com.delta.mobile.android.checkin.MilitaryBaggageActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.MobileCheckInStepsActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.SelectBaggageActivity` | False |  |
| activity | `com.delta.mobile.android.booking.checkout.view.OutOfPolicyReasonActivity` | False |  |
| activity | `com.delta.mobile.android.umnr.PinActivity` | False |  |
| activity | `com.delta.mobile.android.SplashScreenActivity` | False |  |
| activity | `com.delta.mobile.android.WebPage` | False |  |
| activity | `com.delta.mobile.android.JsInjectableWebPage` | False |  |
| activity | `com.delta.mobile.android.itineraries.MyTripsActivity` | False |  |
| activity | `com.delta.mobile.android.itineraries.CustomerFindTrips` | False |  |
| activity | `com.delta.mobile.android.mydelta.MyReceipts` | False |  |
| activity | `com.delta.mobile.android.receipts.views.ReceiptsListActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.filter.ReceiptsListFilterActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.filter.DateFilterSelectionActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.FlightReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.WifiReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.SeatReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.UpgradeSeatReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.CarReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.BaggageReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.InsuranceReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.HotelReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.SkyMilesReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.SkyClubReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.MultiProductReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.ServiceFeeReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.receipts.views.MyTripReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.mydelta.MyReceiptsFilter` | False |  |
| activity | `com.delta.mobile.android.mydelta.MyReceiptsFilterDateRange` | False |  |
| activity | `com.delta.mobile.android.mydelta.ReceiptDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.mydelta.ConsolidateReceipts` | False |  |
| activity | `com.delta.mobile.android.mydelta.accountactivity.AccountActivity` | False |  |
| activity | `com.delta.mobile.android.mydelta.accountactivity.ActivityDetails` | False |  |
| activity | `com.delta.mobile.android.mydelta.accountactivity.AccountActivityFilter` | False |  |
| activity | `com.delta.mobile.android.mydelta.wallet.SkymilesCard` | False |  |
| activity | `com.delta.mobile.android.mydelta.wallet.SkyClubCard` | False |  |
| activity | `com.delta.mobile.android.LaunchActivity` | False |  |
| activity | `com.delta.mobile.android.settings.TogglesSettingActivity` | False |  |
| activity | `com.delta.mobile.android.flightstatus.FlightStatusActivity` | False |  |
| activity | `com.delta.mobile.android.flightstatus.FlightStatusResultActivity` | False |  |
| activity | `com.delta.mobile.android.schedules.CustFlightSchedulesResult` | False |  |
| activity | `com.delta.mobile.android.criticalalert.view.CriticalAlertActivity` | False |  |
| activity | `com.delta.mobile.android.wifihelper.view.WiFiHelperActivity` | False |  |
| activity | `com.delta.mobile.android.schedules.CustFlightSchedulesResultDetails` | False |  |
| activity | `com.delta.mobile.android.webview.DeltaEmbeddedWeb` | False |  |
| activity | `com.delta.mobile.android.flightstatus.FlightTracker` | False |  |
| activity | `com.delta.mobile.android.itineraries.FlightDetailsPolaris` | False |  |
| activity | `com.delta.mobile.android.itineraries.UpgradeRequestActivity` | False |  |
| activity | `com.delta.mobile.android.itineraries.TripOverview` | False |  |
| activity | `com.delta.mobile.android.checkin.CheckInPolaris` | False |  |
| activity | `com.delta.mobile.android.checkin.CheckinPassengerActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.CheckinIntercept` | False |  |
| activity | `com.delta.mobile.android.checkin.legacy.CheckInConfirmation` | False |  |
| activity | `com.delta.mobile.android.checkin.CheckInConfirmationActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.legacy.CheckInPassportActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.CheckInPassportActivity` | False |  |
| activity | `com.delta.mobile.android.navigationDrawer.OfflineModeActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.IntlCheckInPolaris` | False |  |
| activity | `com.delta.mobile.android.checkin.CheckInReturnDateActivity` | False |  |
| activity | `com.delta.mobile.android.cardScan.CardScanActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.USAddressActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.AdvisoryActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.UsEntryAdvisoryActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.CheckInTerms` | False |  |
| activity | `com.delta.mobile.android.irop.IropAffectedFlightReference` | False |  |
| activity | `com.delta.mobile.trips.irop.view.IropAlternativeSearchResultsActivity` | False |  |
| activity | `com.delta.mobile.android.legacycsm.SeatMapActivity` | False |  |
| activity | `com.delta.mobile.android.seatmap.MyTripsSeatMapActivity` | False |  |
| activity | `com.delta.mobile.android.payment.upsell.PurchaseSummaryActivity` | False |  |
| activity | `com.delta.mobile.android.PredictiveCitySearch` | False |  |
| activity | `com.delta.mobile.android.citydetail.CityDetailTabHost` | False |  |
| activity | `com.delta.mobile.android.citydetail.CityDetailActivity` | False |  |
| activity | `com.delta.mobile.android.citydetail.CityAirportMap` | False |  |
| activity | `com.delta.mobile.android.airportmaps.MapActivity` | False |  |
| activity | `com.delta.mobile.android.citydetail.CityAirportMapDetail` | False |  |
| activity | `com.delta.mobile.android.citydetail.CityAirportMapKey` | False |  |
| activity | `com.delta.mobile.android.citydetail.CityGoogleMapTransit` | False |  |
| activity | `com.delta.mobile.android.citydetail.CityWeather` | False |  |
| activity | `com.delta.mobile.android.citydetail.CitySkyClubs` | False |  |
| activity | `com.delta.mobile.android.citydetail.CitySkyClubInfo` | False |  |
| activity | `com.delta.mobile.android.baggage.BaggageSearchActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.BaggageRecentSearchActivity` | False |  |
| activity | `com.delta.mobile.android.profile.PassportInfoActivity` | False |  |
| activity | `com.delta.mobile.android.profile.AirLoyaltyActivity` | False |  |
| activity | `com.delta.mobile.android.profile.AddEditLoyaltyActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.SpecialItemsActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.legacy.BaggageDisclaimer` | False |  |
| activity | `com.delta.mobile.android.baggage.BaggageDisclaimerActivity` | False |  |
| activity | `com.delta.mobile.android.payment.CheckinPurchaseSummaryActivity` | False |  |
| activity | `com.delta.mobile.android.booking.bookingconfirmation.ConfirmationActivity` | False |  |
| activity | `com.delta.mobile.android.payment.legacy.pcr.BagsPurchaseConfirmationActivity` | False |  |
| activity | `com.delta.mobile.android.payment.pcr.BagsPurchaseConfirmationActivity` | False |  |
| activity | `com.delta.mobile.android.payment.pcr.EFirstUpgradePurchaseConfirmationActivity` | False |  |
| activity | `com.delta.mobile.android.upsell.UpsellPurchaseSummaryActivity` | False |  |
| activity | `com.delta.mobile.android.payment.pcr.UpsellPurchaseConfirmationActivity` | False |  |
| activity | `com.delta.mobile.android.traveling.AircraftList` | False |  |
| activity | `com.delta.mobile.android.traveling.AircraftDetail` | False |  |
| activity | `com.delta.mobile.android.traveling.AircraftLayout` | False |  |
| activity | `com.delta.mobile.android.traveling.DeltaPartners` | False |  |
| activity | `com.delta.mobile.android.recentsearches.RecentSearches` | False |  |
| activity | `com.delta.mobile.android.traveling.AirportsRecentSearch` | False |  |
| activity | `com.delta.mobile.android.upsell.UpSellInfoActivity` | False |  |
| activity | `com.delta.mobile.android.ssrs.SSRActivity` | False |  |
| activity | `com.delta.mobile.android.ssrs.AddSpecialServices` | False |  |
| activity | `com.delta.mobile.android.extras.TermsAndConditions` | False |  |
| activity | `com.delta.mobile.android.frequentflyer.FrequentFlyerNumber` | False |  |
| activity | `com.delta.mobile.android.checkin.EUpgradeActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.MilitaryBags` | False |  |
| activity | `com.delta.mobile.android.merchandise.MerchandiseDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.booking.FlightSearchActivity` | False |  |
| activity | `com.delta.mobile.android.booking.flightsearch.FlightSearchResultsActivity` | False |  |
| activity | `com.delta.mobile.android.booking.legacy.seatmap.LogicalSeatmapActivity` | False |  |
| activity | `com.delta.mobile.android.booking.legacy.seatmap.InteractiveSeatmapActivity` | False |  |
| activity | `com.delta.bridge.WebViewActivity` | False |  |
| activity | `com.delta.bridge.WebViewHideAutofillActivity` | False |  |
| activity | `com.delta.mobile.android.booking.legacy.SeatsActivity` | False |  |
| activity | `com.delta.mobile.android.booking.flightsearch.AddPassengerActivity` | False |  |
| activity | `com.delta.mobile.android.forceappupdate.ForceAppUpdatePageActivity` | False |  |
| activity | `com.delta.mobile.android.booking.flightchange.checkout.view.FlightChangeCheckoutActivity` | False |  |
| activity | `com.delta.mobile.android.booking.flightchange.purchaseconfirmation.view.FlightChangePurchaseConfirmationActivity` | False |  |
| activity | `com.delta.mobile.android.booking.flightchange.search.view.FlightChangeSearchResultsActivity` | False |  |
| activity | `com.delta.mobile.android.scanner.view.ScannerActivity` | False |  |
| activity | `com.delta.mobile.android.productModalPages.flightSpecificProductModal.PostPurchaseFlightSpecificProductActivity` | False |  |
| activity | `com.delta.mobile.android.productModalPages.flightSpecificProductModal.BookingFlightSpecificProductActivity` | False |  |
| activity | `com.delta.mobile.android.mydelta.wallet.MyWalletActivity` | False |  |
| activity | `com.delta.mobile.android.appunavailable.AppUnavailableActivity` | False |  |
| activity | `com.delta.mobile.android.navigationDrawer.NavigationDrawerActivity` | False |  |
| activity | `com.delta.mobile.android.profile.UsernameActivity` | False |  |
| activity | `com.delta.mobile.android.profile.PasswordActivity` | False |  |
| activity | `com.delta.mobile.android.citydetail.CityDetailSkyClubActivity` | False |  |
| activity | `com.delta.mobile.android.todaymode.views.TourActivity` | False |  |
| activity | `com.delta.mobile.android.todaymode.views.TodayTripsListActivity` | False |  |
| activity | `com.delta.mobile.android.whatsnew.WhatsNewActivity` | False |  |
| activity | `com.delta.mobile.android.mydelta.wallet.VoucherListActivity` | False |  |
| activity | `com.delta.mobile.android.mydelta.wallet.RedeemBarcodeVoucherActivity` | False |  |
| activity | `com.delta.mobile.android.mydelta.wallet.RedeemPromoCodeVoucherActivity` | False |  |
| activity | `com.delta.mobile.android.mydelta.wallet.VoucherDisclaimerActivity` | False |  |
| activity | `com.delta.mobile.trips.irop.view.IropAlternateItinerariesActivity` | False |  |
| activity | `com.delta.mobile.trips.irop.view.IropAlternateItineraryDetailActivity` | False |  |
| activity | `com.delta.mobile.android.asl.AirportStandbyListActivity` | False |  |
| activity | `com.delta.mobile.android.mydelta.profile.UpgradePreferenceActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.BaggageTrackingActivity` | False |  |
| activity | `com.delta.mobile.android.asl.UpgradeStandbyFlightSelectionActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.BaggagePassengerSelectionActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.BaggageTrackingOnMapActivity` | False |  |
| activity | `com.delta.mobile.android.booking.compareExperiences.ui.CompareExperiencesActivity` | False |  |
| activity | `com.delta.mobile.android.productModalPages.genericProductModal.ui.GenericProductModalActivity` | False |  |
| activity | `com.delta.mobile.android.booking.companionlist.CompanionListActivity` | False |  |
| activity | `com.delta.mobile.android.skyclub.AirportSkyClubsResultActivity` | False |  |
| activity | `com.delta.mobile.android.skyMilesEnrollment.SkyMilesEnrollmentActivity` | False |  |
| activity | `com.delta.mobile.android.skyMilesEnrollment.booking.SkyMilesEnrollmentBookingActivity` | False |  |
| activity | `com.delta.mobile.android.skyMilesEnrollment.EnrollmentConfirmationActivity` | False |  |
| activity | `com.delta.mobile.android.skyMilesEnrollment.trips.SkyMilesEnrollmentTripsActivity` | False |  |
| activity | `com.delta.mobile.android.minimalebp.ui.MinimalEbpActivity` | False |  |
| activity | `com.delta.mobile.android.minimalebp.ui.MinimalEbpListActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.legacy.complimentaryupgrade.ComplimentaryUpgradeActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.complimentaryupgrade.ComplimentaryUpgradeActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.FileReportForBaggageActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.ReportConfirmationActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.BagTypeSelectionActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.BaggageClaimStatusActivity` | False |  |
| activity | `com.delta.mobile.android.booking.expresscheckout.ExpressCheckoutActivity` | False |  |
| activity | `com.delta.mobile.android.booking.reshop.ReshopActivity` | False |  |
| activity | `com.delta.mobile.android.booking.checkout.CheckoutActivity` | False |  |
| activity | `com.delta.mobile.android.booking.seatmap.SeatMapActivity` | False |  |
| activity | `com.delta.mobile.android.baggage.BaggageSelectionActivity` | False |  |
| activity | `com.delta.mobile.android.preselectmeal.views.PreSelectMealActivity` | False |  |
| activity | `com.delta.mobile.android.booking.payment.CreditCardEntryActivity` | False |  |
| activity | `com.delta.mobile.android.booking.flightsearch.OnTimePerformanceActivity` | False |  |
| activity | `com.delta.mobile.android.todaymode.views.BoardingStatusActivity` | False |  |
| activity | `com.delta.mobile.android.inFlightMenu.InFlightMenuActivity` | False |  |
| activity | `com.delta.mobile.android.booking.flightdetails.FlightDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.booking.passengerinformation.PassengerInformationActivity` | False |  |
| activity | `com.delta.mobile.android.booking.expresscheckout.upgradePreference.CheckoutUpgradePreferenceActivity` | False |  |
| activity | `com.delta.mobile.android.booking.payment.PaymentInfoForPurchaserActivity` | False |  |
| activity | `com.delta.mobile.android.booking.passengerinformation.CompanionSearchActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.SaferTravelAdvisoryActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.BiometricConsentActivity` | False |  |
| activity | `com.delta.mobile.android.booking.seatmap.OnBoardUpdatesActivity` | False |  |
| activity | `com.delta.mobile.android.edocs.EdocsMainActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.legacy.CheckinAdvisoryActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.CheckInAdvisoryActivity` | False |  |
| activity | `com.delta.bridge.FallbackNativeActivity` | False |  |
| activity | `com.delta.mobile.android.healthform.ContactTracingActivity` | False |  |
| activity | `com.delta.mobile.android.edocs.EdocsInformationActivity` | False |  |
| activity | `com.delta.mobile.android.edocs.GiftCardsInformationActivity` | False |  |
| activity | `com.delta.mobile.android.booking.flightMessaging.FlightMessagingActivity` | False |  |
| activity | `com.delta.mobile.android.booking.seatmap.DynamicSeatKeyActivity` | False |  |
| activity | `com.delta.mobile.android.healthform.AttestationActivity` | False |  |
| activity | `com.delta.mobile.android.profile.SecureFlightInfoActivity` | False |  |
| activity | `com.delta.mobile.android.checkin.nonrevcheckin.NonRevenueCheckInActivity` | False |  |
| activity | `com.delta.mobile.android.settings.autofillcustomization.AutofillCustomizationActivity` | False |  |
| activity | `com.delta.mobile.android.booking.checkout.view.InternalReferenceNumberActivity` | False |  |
| activity | `com.delta.mobile.android.booking.flightsearch.view.TravelPolicyDetailsActivity` | False |  |
| activity | `com.delta.mobile.android.todaymode.views.ConnectedCabinActivity` | False |  |
| activity | `com.delta.mobile.android.todaymode.views.EntertainmentPreferencesActivity` | False |  |
| activity | `com.delta.mobile.android.login.LoginActivity` | True |  |
| activity | `com.delta.mobile.android.login.ForceLoginActivity` | False |  |
| activity | `com.delta.mobile.android.login.ReshopVerifyAccountActivity` | False |  |
| activity | `com.google.firebase.auth.internal.GenericIdpActivity` | True | genericidp://firebase.auth/ |
| activity | `com.google.firebase.auth.internal.RecaptchaActivity` | True | recaptcha://firebase.auth/ |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| activity | `com.google.android.gms.ads.AdActivity` | False |  |
| activity | `com.foresee.sdk.cxMeasure.tracker.app.invite.InviteActivity` | False |  |
| activity | `com.foresee.sdk.cxMeasure.tracker.app.survey.SurveyActivity` | False |  |
| activity | `androidx.compose.ui.tooling.PreviewActivity` | True |  |
| activity | `io.card.payment.CardIOActivity` | False |  |
| activity | `io.card.payment.DataEntryActivity` | False |  |
| activity | `com.cardinalcommerce.shared.cs.userinterfaces.ChallengeHTMLView` | False |  |
| activity | `com.cardinalcommerce.shared.cs.userinterfaces.ChallengeNativeView` | False |  |
| activity | `com.cyberfend.cyfsecurity.CCADialogActivity` | False |  |
| service | `com.delta.apiclient.DeltaSpiceService` | False |  |
| service | `com.delta.apiclient.DeltaSpiceImageDownloadService` | False |  |
| service | `com.delta.mobile.services.fcm.FCMIntentService` | False |  |
| service | `com.delta.mobile.services.cart.DeltaCartService` | False |  |
| service | `com.delta.mobile.services.notification.shareablemoments.LocationMonitoringService` | False |  |
| service | `com.delta.mobile.android.ibeacon.DeltaBeaconJobWorker` | False |  |
| service | `com.delta.mobile.android.ibeacon.StopBeaconJobWorker` | False |  |
| service | `com.radiusnetworks.ibeacon.service.IBeaconService` | False |  |
| service | `com.radiusnetworks.ibeacon.IBeaconIntentProcessor` | False |  |
| service | `com.delta.mobile.services.AirportImageDeleteService` | False |  |
| service | `com.delta.mobile.android.minimalebp.service.EbpCleanupJobWorker` | False |  |
| service | `com.delta.mobile.services.notification.EbpNotificationJobWorker` | False |  |
| service | `com.delta.mobile.android.notification.AppNotificationJobWorker` | False |  |
| service | `com.delta.mobile.android.todaymode.notification.PnrNotificationJobWorker` | False |  |
| service | `com.delta.mobile.android.notification.display.CheckInNotificationJobWorker` | False |  |
| service | `com.delta.mobile.android.forceappupdate.ForceAppUpdateCheckJobWorker` | False |  |
| service | `com.delta.mobile.android.serversidetoggles.ServerSideTogglesJobWorker` | False |  |
| service | `com.delta.mobile.android.notificationbanner.NotificationBannerJobWorker` | False |  |
| service | `com.delta.mobile.android.notificationbanner.NotificationBannerDisplayJobWorker` | False |  |
| service | `com.delta.mobile.services.notification.IropNotificationJobWorker` | False |  |
| service | `com.delta.mobile.services.notification.VirtualQueueNotificationJobWorker` | False |  |
| service | `com.delta.mobile.services.notification.action.IropFlightService` | False |  |
| service | `com.delta.mobile.services.notification.CustomAppNotificationJobWorker` | False |  |
| service | `com.locuslabs.sdk.ibeacon.BeaconService` | False |  |
| service | `com.locuslabs.sdk.ibeacon.service.IBeaconService` | False |  |
| service | `com.locuslabs.sdk.ibeacon.IBeaconIntentProcessor` | False |  |
| service | `com.google.mlkit.common.internal.MlKitComponentDiscoveryService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `com.google.firebase.auth.api.fallback.service.FirebaseAuthFallbackService` | False |  |
| service | `com.google.firebase.messaging.FirebaseMessagingService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementJobService` | False |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| receiver | `com.delta.mobile.android.homewidget.TodayModeAppWidgetProvider` | True |  |
| receiver | `com.delta.mobile.android.notification.display.AlarmNotificationReceiver` | False | notify://com.delta.mobile.android |
| receiver | `com.delta.mobile.android.notification.schedule.NotificationAlarmsSchedulerReceiver` | False |  |
| receiver | `com.delta.mobile.services.notification.NotificationActionReceiver` | False |  |
| receiver | `com.google.firebase.iid.FirebaseInstanceIdReceiver` | True |  |
| receiver | `com.google.android.gms.measurement.AppMeasurementReceiver` | False |  |
| receiver | `com.foresee.sdk.cxMeasure.tracker.services.NotificationReceiver` | False |  |
| receiver | `com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver` | False |  |
| receiver | `androidx.profileinstaller.ProfileInstallReceiver` | True |  |
| provider | `com.google.mlkit.common.internal.MlKitInitProvider` | False |  |
| provider | `com.google.firebase.provider.FirebaseInitProvider` | False |  |
| provider | `androidx.startup.InitializationProvider` | False |  |
| provider | `com.cardinalcommerce.shared.cs.utils.CCInitProvider` | False |  |
| provider | `androidx.lifecycle.ProcessLifecycleOwnerInitializer` | False |  |
