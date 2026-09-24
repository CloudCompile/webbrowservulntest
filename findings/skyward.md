# WebView / in-app browser recon: `samples/skyward.apk`

- Package: `com.skyward.mobileaccess` 3.3.0 (code 339)
- SDK: min 24 / target 36
- Network security config: `network_security_config.xml` (cleartext permitted = False)
- Native libs touching WebView: 0

## Summary

- CRITICAL: 1
- HIGH: 14
- MEDIUM: 6
- LOW: 4
- INFO: 3

## Findings

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (argument unresolved)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2058 (setAllowUniversalAccessFromFileURLs)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (argument unresolved)
_analysis/skyward/work/smali/androidx/webkit/internal/ServiceWorkerWebSettingsImpl.smali:434 (setAllowFileAccess)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
move-result-object v0

    invoke-static {v0, p1}, Landroidx/webkit/internal/ApiHelperForN;->setAllowFileAccess(Landroid/webkit/ServiceWorkerWebSettings;Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (argument unresolved)
_analysis/skyward/work/smali/androidx/webkit/internal/ApiHelperForN.smali:144 (setAllowFileAccess)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
.line 132
    invoke-virtual {p0, p1}, Landroid/webkit/ServiceWorkerWebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:1308 (createViewInstance)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
.line 85
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:1325 (createViewInstance)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 93
    invoke-static {v1}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (argument unresolved)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2015 (setAllowFileAccess)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (argument unresolved)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2037 (setAllowFileAccessFromFileURLs)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2996 (setMixedContentMode)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
const/4 p2, 0x1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_analysis/skyward/work/smali_classes3/expo/modules/webview/DomWebView.smali:437 (createWebView)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
move-result-object v1

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (True)
_analysis/skyward/work/smali_classes3/expo/modules/webview/DomWebView.smali:444 (createWebView)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
move-result-object v1

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (argument unresolved)
_analysis/skyward/work/smali_classes3/expo/modules/webview/DomWebView.smali:1311 (setWebviewDebuggingEnabled)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 41
    invoke-static {p1}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/skyward/work/smali_classes3/expo/modules/logbox/ExpoLogBoxWebViewWrapper.smali:189 (<init>)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 27
    invoke-static {p3}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] CORR-004 - com.reactnativecommunity.webview.RNCWebViewManagerImpl: remote WebView debugging enabled
_com.reactnativecommunity.webview.RNCWebViewManagerImpl_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [HIGH] CORR-002 - expo.modules.webview.DomWebView: local file access + JS bridge
_expo.modules.webview.DomWebView_

Page script can read local files and drive an exposed native bridge, so a file:// or navigated-to page escalates into native capability.

```
file access enabled + addJavascriptInterface + JS enabled
```

### [HIGH] CORR-004 - expo.modules.logbox.ExpoLogBoxWebViewWrapper: remote WebView debugging enabled
_expo.modules.logbox.ExpoLogBoxWebViewWrapper_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [MEDIUM] WV-SET-005 - content:// access enabled (argument unresolved)
_analysis/skyward/work/smali/androidx/webkit/internal/ServiceWorkerWebSettingsImpl.smali:386 (setAllowContentAccess)_

setAllowContentAccess(true) lets the WebView follow content:// URLs, widening the reachable data set.

```
move-result-object v0

    invoke-static {v0, p1}, Landroidx/webkit/internal/ApiHelperForN;->setAllowContentAccess(Landroid/webkit/ServiceWorkerWebSettings;Z)V
```

### [MEDIUM] WV-SET-005 - content:// access enabled (argument unresolved)
_analysis/skyward/work/smali/androidx/webkit/internal/ApiHelperForN.smali:135 (setAllowContentAccess)_

setAllowContentAccess(true) lets the WebView follow content:// URLs, widening the reachable data set.

```
.line 116
    invoke-virtual {p0, p1}, Landroid/webkit/ServiceWorkerWebSettings;->setAllowContentAccess(Z)V
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (argument unresolved)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2765 (setJavaScriptCanOpenWindowsAutomatically)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (argument unresolved)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2787 (setJavaScriptEnabled)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/skyward/work/smali_classes3/expo/modules/webview/DomWebView.smali:430 (createWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v2, 0x1

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/skyward/work/smali_classes3/expo/modules/logbox/ExpoLogBoxWebViewWrapper.smali:186 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p3, 0x1

    invoke-virtual {p2, p3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:1290 (createViewInstance)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 79
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:1293 (createViewInstance)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
.line 80
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (argument unresolved)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2447 (setDomStorageEnabled)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (argument unresolved)
_analysis/skyward/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:3328 (setSetSupportMultipleWindows)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [INFO] WV-SINK-004 - JS bridge `ReactNativeWebView` exposed by expo.modules.webview.DomWebView
_expo.modules.webview.DomWebView:336_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(this.rncWebViewBridge, "ReactNativeWebView")
```

### [INFO] WV-SINK-004 - JS bridge `ExpoDomWebViewBridge` exposed by expo.modules.webview.DomWebView
_expo.modules.webview.DomWebView:337_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(new DomWebViewBridge(this), "ExpoDomWebViewBridge")
```

### [INFO] WV-SINK-004 - JS bridge `rawMessage` exposed by expo.modules.logbox.ExpoLogBoxWebViewWrapper
_expo.modules.logbox.ExpoLogBoxWebViewWrapper:60_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(new Object() { // from class: expo.modules.logbox.ExpoLogBoxWebViewWrapper$webVi, "rawMessage")  methods=['postMessage']
```

## Reachability

No exported entry point was found that loads an attacker-supplied URL into a WebView. The misconfigurations above are latent: reaching them requires either an in-app navigation to attacker-controlled content (e.g. a malicious ad or a link the user opens in-app) or a separate bug that supplies the URL.

## WebView hosts

### `com.reactnativecommunity.webview.RNCWebViewManagerImpl`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `None`
  - `js_can_open_windows_automatically` = `None`
  - `mixed_content_mode` = `2`
  - `support_multiple_windows` = `True`
  - `web_contents_debugging` = `True`

### `expo.modules.webview.DomWebView`
- sources: smali
- settings:
  - `allow_file_access` = `True`
  - `allow_file_access_from_file_urls` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `None`
- JS bridges: `ReactNativeWebView`, `ExpoDomWebViewBridge`

### `androidx.webkit.internal.ServiceWorkerWebSettingsImpl`
- sources: smali
- settings:
  - `allow_content_access` = `None`
  - `allow_file_access` = `None`

### `androidx.webkit.internal.ApiHelperForN`
- sources: smali
- settings:
  - `allow_content_access` = `None`
  - `allow_file_access` = `None`

### `expo.modules.logbox.ExpoLogBoxWebViewWrapper`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `True`
- JS bridges: `rawMessage`
- loaded URLs:
  - `file:///android_asset/ExpoLogBox.bundle/index.html`

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `com.skyward.mobileaccess.MainActivity` | True | exp+mobileaccess://* |
| activity | `app.notifee.core.NotificationReceiverActivity` | True |  |
| activity | `com.google.android.gms.auth.api.signin.internal.SignInHubActivity` | False |  |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| service | `app.notifee.core.ReceiverService` | False |  |
| service | `app.notifee.core.ForegroundService` | False |  |
| service | `io.invertase.firebase.messaging.ReactNativeFirebaseMessagingHeadlessService` | False |  |
| service | `io.invertase.firebase.messaging.ReactNativeFirebaseMessagingService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `expo.modules.location.services.LocationTaskService` | False |  |
| service | `androidx.work.impl.background.systemjob.SystemJobService` | True |  |
| service | `androidx.work.impl.foreground.SystemForegroundService` | False |  |
| service | `com.google.android.gms.auth.api.signin.RevocationBoundService` | True |  |
| service | `com.google.firebase.messaging.FirebaseMessagingService` | False |  |
| service | `com.google.firebase.sessions.SessionLifecycleService` | False |  |
| service | `androidx.room.MultiInstanceInvalidationService` | False |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| receiver | `app.notifee.core.RebootBroadcastReceiver` | False |  |
| receiver | `app.notifee.core.AlarmPermissionBroadcastReceiver` | True |  |
| receiver | `app.notifee.core.NotificationAlarmReceiver` | False |  |
| receiver | `app.notifee.core.BlockStateBroadcastReceiver` | False |  |
| receiver | `io.invertase.firebase.messaging.ReactNativeFirebaseMessagingReceiver` | True |  |
| receiver | `androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.RescheduleReceiver` | False |  |
| receiver | `androidx.work.impl.diagnostics.DiagnosticsReceiver` | True |  |
| receiver | `com.google.firebase.iid.FirebaseInstanceIdReceiver` | True |  |
| receiver | `androidx.profileinstaller.ProfileInstallReceiver` | True |  |
| receiver | `com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver` | False |  |
| provider | `io.invertase.notifee.NotifeeInitProvider` | False |  |
| provider | `com.reactnativecommunity.webview.RNCWebViewFileProvider` | False |  |
| provider | `io.invertase.firebase.crashlytics.ReactNativeFirebaseCrashlyticsInitProvider` | False |  |
| provider | `io.invertase.firebase.app.ReactNativeFirebaseAppInitProvider` | False |  |
| provider | `expo.modules.filesystem.FileSystemFileProvider` | False |  |
| provider | `expo.modules.sharing.SharingFileProvider` | False |  |
| provider | `androidx.startup.InitializationProvider` | False |  |
| provider | `com.google.firebase.provider.FirebaseInitProvider` | False |  |
