# WebView / in-app browser recon: `samples/atomic_mail.apk`

- Package: `com.atomicmail` 1.7.0 (code 186)
- SDK: min 24 / target 36
- Network security config: `network_security_config.xml` (cleartext permitted = True)
- Native libs touching WebView: 0

## Summary

- CRITICAL: 1
- HIGH: 7
- MEDIUM: 3
- LOW: 4
- INFO: 1

## Findings

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (argument unresolved)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:7404 (p)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
.line 14
    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:3895 (R)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
.line 60
    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:5609 (e)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
.line 56
    .line 57
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:5639 (e)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 72
    .line 73
    invoke-static {v1}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (argument unresolved)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:7064 (h0)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 5
    .line 6
    invoke-static {p2}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (argument unresolved)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:7258 (n)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
.line 14
    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (argument unresolved)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:7331 (o)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
.line 14
    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] CORR-004 - com.reactnativecommunity.webview.k: remote WebView debugging enabled
_com.reactnativecommunity.webview.k_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (argument unresolved)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:3237 (J)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
.line 14
    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (argument unresolved)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:3310 (K)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 14
    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] CORR-010 - Cleartext HTTP permitted globally
_AndroidManifest.xml_

The base-config permits http:// for every host, so any WebView navigation or API call can be downgraded to cleartext and modified on-path.

```
networkSecurityConfig=network_security_config.xml cleartextTrafficPermitted=true
```

### [LOW] WV-SET-008 - Multiple windows supported (argument unresolved)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:5087 (Z)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
.line 14
    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:5579 (e)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 38
    .line 39
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:5584 (e)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
.line 41
    .line 42
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (argument unresolved)
_analysis/atomic_mail/work/smali_classes2/com/reactnativecommunity/webview/k.smali:8474 (x)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 14
    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [INFO] WV-SINK-004 - JS bridge `ReactNativeWebView` exposed by com.reactnativecommunity.webview.d
_com.reactnativecommunity.webview.d:333_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(eVar, "ReactNativeWebView")  methods=['postMessage']
```

## WebView hosts

### `com.reactnativecommunity.webview.k`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `None`
  - `js_can_open_windows_automatically` = `None`
  - `mixed_content_mode` = `1`
  - `support_multiple_windows` = `True`
  - `web_contents_debugging` = `True`

### `com.reactnativecommunity.webview.d`
- sources: java
- JS bridges: `ReactNativeWebView`

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `com.atomicmail.MainActivity` | True | atomicmail://stripe-return<br>atomicmail://stripe-cancel<br>atomicmail://stripe-success |
| activity | `com.android.billingclient.api.ProxyBillingActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivityV2` | False |  |
| activity | `com.google.android.gms.auth.api.signin.internal.SignInHubActivity` | False |  |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| activity | `app.notifee.core.NotificationReceiverActivity` | True |  |
| activity | `com.google.android.play.core.common.PlayCoreDialogWrapperActivity` | False |  |
| activity | `com.pairip.licensecheck.LicenseActivity` | False |  |
| service | `io.invertase.firebase.messaging.ReactNativeFirebaseMessagingService` | False |  |
| service | `io.invertase.firebase.messaging.ReactNativeFirebaseMessagingHeadlessService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `com.google.android.gms.auth.api.signin.RevocationBoundService` | True |  |
| service | `com.google.firebase.messaging.FirebaseMessagingService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementJobService` | False |  |
| service | `androidx.work.impl.background.systemalarm.SystemAlarmService` | False |  |
| service | `androidx.work.impl.background.systemjob.SystemJobService` | True |  |
| service | `androidx.work.impl.foreground.SystemForegroundService` | False |  |
| service | `androidx.room.MultiInstanceInvalidationService` | False |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| service | `app.notifee.core.ReceiverService` | False |  |
| service | `app.notifee.core.ForegroundService` | False |  |
| receiver | `io.invertase.firebase.messaging.ReactNativeFirebaseMessagingReceiver` | True |  |
| receiver | `com.google.firebase.iid.FirebaseInstanceIdReceiver` | True |  |
| receiver | `com.google.android.gms.measurement.AppMeasurementReceiver` | False |  |
| receiver | `androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.RescheduleReceiver` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver` | False |  |
| receiver | `androidx.work.impl.diagnostics.DiagnosticsReceiver` | True |  |
| receiver | `androidx.profileinstaller.ProfileInstallReceiver` | True |  |
| receiver | `com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver` | False |  |
| receiver | `app.notifee.core.RebootBroadcastReceiver` | False |  |
| receiver | `app.notifee.core.AlarmPermissionBroadcastReceiver` | True |  |
| receiver | `app.notifee.core.NotificationAlarmReceiver` | False |  |
| receiver | `app.notifee.core.BlockStateBroadcastReceiver` | False |  |
| provider | `com.fileviewerturbo.FileProvider` | False |  |
| provider | `com.reactnativecommunity.webview.RNCWebViewFileProvider` | False |  |
| provider | `io.invertase.notifee.NotifeeInitProvider` | False |  |
| provider | `io.invertase.firebase.app.ReactNativeFirebaseAppInitProvider` | False |  |
| provider | `com.ReactNativeBlobUtil.Utils.FileProvider` | False |  |
| provider | `com.imagepicker.ImagePickerProvider` | False |  |
| provider | `cl.json.RNShareFileProvider` | False |  |
| provider | `com.google.firebase.provider.FirebaseInitProvider` | False |  |
| provider | `androidx.startup.InitializationProvider` | False |  |
