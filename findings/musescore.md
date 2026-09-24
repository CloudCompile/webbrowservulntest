# WebView / in-app browser recon: `samples/musescore.xapk`

- Package: `com.musescore.playerlite` 2.14.48 (code 2701674)
- SDK: min 24 / target 36
- Network security config: `network_security_config.xml` (cleartext permitted = None)
- Native libs touching WebView: 1

## Summary

- CRITICAL: 1
- HIGH: 9
- MEDIUM: 16
- LOW: 5

## Findings

### [CRITICAL] WV-SET-004 - file:// pages may load arbitrary remote origins (argument unresolved)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2058 (setAllowUniversalAccessFromFileURLs)_

setAllowUniversalAccessFromFileURLs(true) lets a file:// page make cross-origin requests to any host, leaking local file contents to a remote server.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:1308 (createViewInstance)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
.line 84
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:1325 (createViewInstance)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 92
    invoke-static {v1}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (argument unresolved)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2015 (setAllowFileAccess)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-003 - file:// pages may load other file:// resources (argument unresolved)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2037 (setAllowFileAccessFromFileURLs)_

setAllowFileAccessFromFileURLs(true) lets a file:// page read other local files via XMLHttpRequest/fetch.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
```

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2996 (setMixedContentMode)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
const/4 p2, 0x1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [HIGH] WV-SET-002 - Local file access enabled (argument unresolved)
_analysis/musescore/work/smali_classes4/androidx/webkit/internal/ServiceWorkerWebSettingsImpl.smali:434 (setAllowFileAccess)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
move-result-object v0

    invoke-static {v0, p1}, Landroidx/webkit/internal/ApiHelperForN;->setAllowFileAccess(Landroid/webkit/ServiceWorkerWebSettings;Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (argument unresolved)
_analysis/musescore/work/smali_classes4/androidx/webkit/internal/ApiHelperForN.smali:144 (setAllowFileAccess)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
.line 132
    invoke-virtual {p0, p1}, Landroid/webkit/ServiceWorkerWebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] WV-SET-009 - io.intercom.android.sdk.blocks.messengercard.MessengerCardWebViewPresenter: mixed content mode ALWAYS_ALLOW
_io.intercom.android.sdk.blocks.messengercard.MessengerCardWebViewPresenter_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
setMixedContentMode(0)
```

### [HIGH] CORR-004 - com.reactnativecommunity.webview.RNCWebViewManagerImpl: remote WebView debugging enabled
_com.reactnativecommunity.webview.RNCWebViewManagerImpl_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (argument unresolved)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2765 (setJavaScriptCanOpenWindowsAutomatically)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (argument unresolved)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2787 (setJavaScriptEnabled)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-005 - content:// access enabled (argument unresolved)
_analysis/musescore/work/smali_classes4/androidx/webkit/internal/ServiceWorkerWebSettingsImpl.smali:386 (setAllowContentAccess)_

setAllowContentAccess(true) lets the WebView follow content:// URLs, widening the reachable data set.

```
move-result-object v0

    invoke-static {v0, p1}, Landroidx/webkit/internal/ApiHelperForN;->setAllowContentAccess(Landroid/webkit/ServiceWorkerWebSettings;Z)V
```

### [MEDIUM] WV-SET-005 - content:// access enabled (argument unresolved)
_analysis/musescore/work/smali_classes4/androidx/webkit/internal/ApiHelperForN.smali:135 (setAllowContentAccess)_

setAllowContentAccess(true) lets the WebView follow content:// URLs, widening the reachable data set.

```
.line 116
    invoke-virtual {p0, p1}, Landroid/webkit/ServiceWorkerWebSettings;->setAllowContentAccess(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/musescore/work/smali_classes5/com/facebook/internal/WebDialog.smali:904 (setUpWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:cond_5
    invoke-virtual {v1, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/musescore/work/smali_classes7/io/intercom/android/sdk/sheets/SheetWebViewPresenter.smali:112 (setUpWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 33
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/musescore/work/smali_classes7/io/intercom/android/sdk/blocks/Video.smali:269 (addVideo)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 60
    invoke-virtual {p1, p5}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/musescore/work/smali_classes7/io/intercom/android/sdk/blocks/VideoFile.smali:245 (addVideoFile)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 60
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/musescore/work/smali_classes7/io/intercom/android/sdk/helpcenter/articles/IntercomArticleActivity$onCreate$1$1$3.smali:195 (invoke$lambda$7$lambda$2)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v2, 0x1

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/musescore/work/smali_classes7/io/intercom/android/sdk/blocks/messengercard/MessengerCardWebViewPresenter.smali:164 (setUpWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 57
    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/musescore/work/smali_classes7/io/intercom/android/sdk/m5/home/ui/components/LegacyMessengerAppCardKt.smali:311 (getWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_io.intercom.android.sdk.helpcenter.articles.IntercomArticleActivity_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [MEDIUM] CORR-005 - io.intercom.android.sdk.sheets.SheetWebViewPresenter: no host allowlist on navigation
_io.intercom.android.sdk.sheets.SheetWebViewPresenter_

The WebViewClient forwards every tapped URL back into the WebView, so a trusted entry page becomes a general-purpose in-app browser.

```
shouldOverrideUrlLoading forwards incoming URL
```

### [MEDIUM] CORR-005 - io.intercom.android.sdk.sheets.SheetWebViewClient: no host allowlist on navigation
_io.intercom.android.sdk.sheets.SheetWebViewClient_

The WebViewClient forwards every tapped URL back into the WebView, so a trusted entry page becomes a general-purpose in-app browser.

```
shouldOverrideUrlLoading forwards incoming URL
```

### [MEDIUM] CORR-005 - io.intercom.android.sdk.blocks.messengercard.MessengerCardWebViewClient: no host allowlist on navigation
_io.intercom.android.sdk.blocks.messengercard.MessengerCardWebViewClient_

The WebViewClient forwards every tapped URL back into the WebView, so a trusted entry page becomes a general-purpose in-app browser.

```
shouldOverrideUrlLoading forwards incoming URL
```

### [MEDIUM] CORR-010 - Cleartext HTTP permitted globally
_AndroidManifest.xml_

The base-config permits http:// for every host, so any WebView navigation or API call can be downgraded to cleartext and modified on-path.

```
networkSecurityConfig=network_security_config.xml cleartextTrafficPermitted=true
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:1290 (createViewInstance)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 78
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:1293 (createViewInstance)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
.line 79
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (argument unresolved)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:2447 (setDomStorageEnabled)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (argument unresolved)
_analysis/musescore/work/smali_classes3/com/reactnativecommunity/webview/RNCWebViewManagerImpl.smali:3246 (setSetSupportMultipleWindows)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
move-result-object p1

    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/musescore/work/smali_classes7/io/intercom/android/sdk/sheets/SheetWebViewPresenter.smali:126 (setUpWebView)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 38
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

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

### `io.intercom.android.sdk.sheets.SheetWebViewPresenter`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
- navigation: **no allowlist detected**

### `io.intercom.android.sdk.blocks.messengercard.MessengerCardWebViewPresenter`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
  - `mixed_content_mode` = `0`

### `io.intercom.android.sdk.m5.home.ui.components.LegacyMessengerAppCardKt`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
  - `mixed_content_mode` = `False`

### `com.facebook.internal.WebDialog`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `io.intercom.android.sdk.blocks.Video`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `io.intercom.android.sdk.blocks.VideoFile`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `io.intercom.android.sdk.helpcenter.articles.IntercomArticleActivity$onCreate$1$1$3`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `io.intercom.android.sdk.blocks.messengercard.CardWebView`
- sources: smali
- settings:
  - `allow_file_access` = `False`

### `io.intercom.android.sdk.helpcenter.articles.IntercomArticleActivity`
- sources: java
- settings:
  - `javascript_enabled` = `True`

### `com.facebook.internal.FacebookWebFallbackDialog`
- sources: java
- loaded URLs:
  - `javascript:(function() {  var event = document.createEvent(`
  - `javascript:(function() {  var event = document.createEvent(\'Event\');  event.initEvent(\'fbPlatformDialogMustClose\',true,true);  document.dispatchEvent(event);})();`

### `io.intercom.android.sdk.conversation.JavascriptRunner`
- sources: java
- loaded URLs:
  - `javascript:`

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `com.musescoremobile.MainActivity` | True | muse-mu://*<br>content://*.*\\.mscz<br>file://*.*\\..*\\..*\\.mscz<br>file://*.*\\..*\\..*\\..*\\..*\\.mscz |
| activity | `com.facebook.FacebookActivity` | False |  |
| activity | `com.facebook.CustomTabActivity` | True | @string/fb_login_protocol_scheme://*<br>fbconnect://cct.com.musescore.playerlite |
| activity | `com.proyecto26.inappbrowser.ChromeTabsManagerActivity` | False |  |
| activity | `io.intercom.android.sdk.lightbox.LightBoxActivity` | False |  |
| activity | `io.intercom.android.sdk.activities.IntercomPostActivity` | False |  |
| activity | `io.intercom.android.sdk.post.PostActivityV2` | False |  |
| activity | `io.intercom.android.sdk.activities.IntercomNoteActivity` | False |  |
| activity | `io.intercom.android.sdk.activities.IntercomSheetActivity` | False |  |
| activity | `io.intercom.android.sdk.activities.IntercomCarouselActivity` | False |  |
| activity | `io.intercom.android.sdk.helpcenter.articles.IntercomArticleActivity` | False |  |
| activity | `io.intercom.android.sdk.survey.ui.IntercomSurveyActivity` | False |  |
| activity | `io.intercom.android.sdk.helpcenter.search.IntercomArticleSearchActivity` | False |  |
| activity | `io.intercom.android.sdk.m5.IntercomRootActivity` | False |  |
| activity | `io.intercom.android.sdk.m5.bubble.IntercomBubbleActivity` | False |  |
| activity | `com.facebook.CustomTabMainActivity` | False |  |
| activity | `com.google.android.gms.auth.api.signin.internal.SignInHubActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivityV2` | False |  |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| activity | `io.intercom.android.sdk.ui.preview.ui.IntercomPreviewActivity` | False |  |
| activity | `app.notifee.core.NotificationReceiverActivity` | True |  |
| activity | `com.google.android.play.core.common.PlayCoreDialogWrapperActivity` | False |  |
| activity | `com.pairip.licensecheck.LicenseActivity` | False |  |
| service | `com.musescoremobile.utils.PushHeadlessUtil` | False |  |
| service | `com.doublesymmetry.trackplayer.service.MusicService` | True |  |
| service | `io.invertase.firebase.messaging.ReactNativeFirebaseMessagingHeadlessService` | False |  |
| service | `io.invertase.firebase.messaging.ReactNativeFirebaseMessagingService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `io.intercom.android.sdk.fcm.IntercomFcmMessengerService` | False |  |
| service | `com.google.firebase.messaging.FirebaseMessagingService` | False |  |
| service | `androidx.camera.core.impl.MetadataHolderService` | False |  |
| service | `com.google.android.gms.auth.api.signin.RevocationBoundService` | True |  |
| service | `com.google.mlkit.common.internal.MlKitComponentDiscoveryService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementJobService` | False |  |
| service | `androidx.work.impl.background.systemalarm.SystemAlarmService` | False |  |
| service | `androidx.work.impl.background.systemjob.SystemJobService` | True |  |
| service | `androidx.work.impl.foreground.SystemForegroundService` | False |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| service | `androidx.room.MultiInstanceInvalidationService` | False |  |
| service | `app.notifee.core.ReceiverService` | False |  |
| service | `app.notifee.core.ForegroundService` | False |  |
| receiver | `com.musescoremobile.receiver.MessageReceiver` | True |  |
| receiver | `io.invertase.firebase.messaging.ReactNativeFirebaseMessagingReceiver` | True |  |
| receiver | `io.intercom.android.sdk.m5.push.ConversationReplyReceiver` | False |  |
| receiver | `com.google.firebase.iid.FirebaseInstanceIdReceiver` | True |  |
| receiver | `com.google.android.gms.measurement.AppMeasurementReceiver` | False |  |
| receiver | `com.facebook.CurrentAccessTokenExpirationBroadcastReceiver` | False |  |
| receiver | `com.facebook.AuthenticationTokenManager$CurrentAuthenticationTokenChangedBroadcastReceiver` | False |  |
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
| provider | `androidx.core.content.FileProvider` | False |  |
| provider | `com.reactnativecommunity.webview.RNCWebViewFileProvider` | False |  |
| provider | `io.invertase.notifee.NotifeeInitProvider` | False |  |
| provider | `io.invertase.firebase.crashlytics.ReactNativeFirebaseCrashlyticsInitProvider` | False |  |
| provider | `io.invertase.firebase.app.ReactNativeFirebaseAppInitProvider` | False |  |
| provider | `com.ReactNativeBlobUtil.Utils.FileProvider` | False |  |
| provider | `com.imagepicker.ImagePickerProvider` | False |  |
| provider | `cl.json.RNShareFileProvider` | False |  |
| provider | `com.oblador.performance.StartTimeProvider` | False |  |
| provider | `io.intercom.android.sdk.IntercomInitializeContentProvider` | False |  |
| provider | `io.intercom.android.sdk.IntercomFileProvider` | False |  |
| provider | `com.google.firebase.provider.FirebaseInitProvider` | False |  |
| provider | `com.google.mlkit.common.internal.MlKitInitProvider` | False |  |
| provider | `androidx.startup.InitializationProvider` | False |  |
| provider | `com.facebook.internal.FacebookInitProvider` | False |  |
| provider | `io.sentry.android.core.SentryInitProvider` | False |  |
| provider | `io.sentry.android.core.SentryPerformanceProvider` | False |  |

## Native libraries referencing WebView

- `lib/arm64-v8a/libappmodules.so`
