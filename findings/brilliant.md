# WebView / in-app browser recon: `samples/brilliant.xapk`

- Package: `org.brilliant.android` 10.14.0 (code 1079)
- SDK: min 32 / target 37
- Network security config: `network_security_config.xml` (cleartext permitted = False)
- Native libs touching WebView: 0

## Summary

- MEDIUM: 5
- LOW: 4
- INFO: 3

## Findings

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/brilliant/work/smali/dka.smali:1107 (f)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 59
    :cond_3
    invoke-virtual {v2, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/brilliant/work/smali/com/braze/ui/BrazeWebViewActivity.smali:289 (onCreate)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 98
    .line 99
    invoke-virtual {v0, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/brilliant/work/smali/com/braze/ui/support/WebViewUtilsKt.smali:306 (setWebViewSettings)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 8
    invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/brilliant/work/smali/com/google/android/recaptcha/internal/zzil.smali:246 (invokeSuspend)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 70
    invoke-virtual {p1, v5}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/brilliant/work/smali_classes4/n91.smali:215 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 98
    .line 99
    invoke-virtual {p3, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/brilliant/work/smali/com/braze/ui/BrazeWebViewActivity.smali:309 (onCreate)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 110
    .line 111
    invoke-virtual {v0, v3}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/brilliant/work/smali/com/braze/ui/support/WebViewUtilsKt.smali:329 (setWebViewSettings)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 20
    .line 21
    invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_analysis/brilliant/work/smali/com/braze/ui/inappmessage/views/InAppMessageHtmlBaseView.smali:954 (getMessageWebView)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
.line 119
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/brilliant/work/smali_classes4/n91.smali:220 (<init>)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 101
    .line 102
    invoke-virtual {p3, p2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [INFO] WV-SINK-004 - JS bridge `brilliantBridge` exposed by defpackage.mq6
_defpackage.mq6:176_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface((s76) nv9Var.f, "brilliantBridge")
```

### [INFO] WV-SINK-004 - JS bridge `brilliantBridge` exposed by defpackage.n88
_defpackage.n88:35_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface((s76) nv9Var.f, "brilliantBridge")
```

### [INFO] WV-SINK-004 - JS bridge `brilliantBridge` exposed by defpackage.xd5
_defpackage.xd5:46_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface((s76) nv9Var.f, "brilliantBridge")
```

## WebView hosts

### `com.braze.ui.BrazeWebViewActivity`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.braze.ui.support.WebViewUtilsKt`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `n91`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `False`

### `dka`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.braze.ui.inappmessage.views.InAppMessageHtmlBaseView`
- sources: smali
- settings:
  - `support_multiple_windows` = `True`
- loaded URLs:
  - `about:blank`

### `com.google.android.recaptcha.internal.zzil`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `defpackage.mq6`
- sources: java
- JS bridges: `brilliantBridge`

### `defpackage.n88`
- sources: java
- JS bridges: `brilliantBridge`

### `defpackage.xd5`
- sources: java
- JS bridges: `brilliantBridge`

### `com.braze.ui.BrazeWebViewClient`
- sources: java
- loaded URLs:
  - `javascript:`

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `org.brilliant.android.ui.common.MainActivity` | True | https://click.brilliant.org<br>https://brilliant.org<br>http://click.brilliant.org<br>http://brilliant.org |
| activity | `com.facebook.FacebookActivity` | False |  |
| activity | `com.shakebugs.shake.ui.ShakeActivity` | False |  |
| activity | `com.shakebugs.shake.ui.permissions.RequestPermissionActivity` | False |  |
| activity | `com.shakebugs.shake.ui.ChatLauncherActivity` | False |  |
| activity | `com.revenuecat.purchases.amazon.purchasing.ProxyAmazonBillingActivity` | False |  |
| activity | `com.revenuecat.purchases.SimulatedStoreErrorDialogActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivityV2` | False |  |
| activity | `com.google.firebase.auth.internal.GenericIdpActivity` | True | genericidp://firebase.auth/ |
| activity | `com.google.firebase.auth.internal.RecaptchaActivity` | True | recaptcha://firebase.auth/ |
| activity | `androidx.credentials.playservices.HiddenActivity` | False |  |
| activity | `com.facebook.CustomTabMainActivity` | False |  |
| activity | `com.facebook.CustomTabActivity` | True | fbconnect://cct.org.brilliant.android |
| activity | `com.google.android.gms.auth.api.signin.internal.SignInHubActivity` | False |  |
| activity | `com.braze.ui.BrazeWebViewActivity` | False |  |
| activity | `com.braze.ui.activities.ContentCardsActivity` | False |  |
| activity | `com.braze.push.NotificationTrampolineActivity` | False |  |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| activity | `com.google.android.play.core.common.PlayCoreDialogWrapperActivity` | False |  |
| activity | `com.pairip.licensecheck.LicenseActivity` | False |  |
| service | `org.brilliant.android.data.network.message.notification.NotificationService` | False |  |
| service | `com.shakebugs.shake.internal.shake.recording.ScreenRecordingService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `com.google.firebase.messaging.FirebaseMessagingService` | False |  |
| service | `com.google.firebase.sessions.SessionLifecycleService` | False |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `androidx.work.impl.background.systemjob.SystemJobService` | True |  |
| service | `androidx.work.impl.foreground.SystemForegroundService` | False |  |
| service | `androidx.room.MultiInstanceInvalidationService` | False |  |
| service | `androidx.credentials.playservices.CredentialProviderMetadataHolder` | False |  |
| service | `com.google.android.gms.auth.api.signin.RevocationBoundService` | True |  |
| service | `com.google.android.gms.measurement.AppMeasurementService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementJobService` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| receiver | `org.brilliant.android.utils.AppUpdateReceiver` | False |  |
| receiver | `com.shakebugs.shake.internal.NotificationReceiver` | False |  |
| receiver | `com.google.firebase.iid.FirebaseInstanceIdReceiver` | True |  |
| receiver | `androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.RescheduleReceiver` | False |  |
| receiver | `androidx.work.impl.diagnostics.DiagnosticsReceiver` | True |  |
| receiver | `com.braze.push.BrazePushReceiver` | False |  |
| receiver | `com.google.android.gms.measurement.AppMeasurementReceiver` | False |  |
| receiver | `com.facebook.CurrentAccessTokenExpirationBroadcastReceiver` | False |  |
| receiver | `com.facebook.AuthenticationTokenManager$CurrentAuthenticationTokenChangedBroadcastReceiver` | False |  |
| receiver | `com.braze.BrazeFlushPushDeliveryReceiver` | False |  |
| receiver | `androidx.profileinstaller.ProfileInstallReceiver` | True |  |
| receiver | `com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver` | False |  |
| provider | `androidx.startup.InitializationProvider` | False |  |
| provider | `com.shakebugs.shake.internal.utils.FileProvider` | False |  |
| provider | `com.google.firebase.provider.FirebaseInitProvider` | False |  |
| provider | `com.facebook.internal.FacebookInitProvider` | False |  |
| provider | `io.sentry.android.core.SentryInitProvider` | False |  |
| provider | `io.sentry.android.core.SentryPerformanceProvider` | False |  |
| provider | `io.sentry.ndk.SentryNdkPreloadProvider` | False |  |
