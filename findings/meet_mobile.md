# WebView / in-app browser recon: `samples/meet_mobile.apk`

- Package: `com.active.aps.meetmobile` 5.3.1.2549 (code 167)
- SDK: min 33 / target 36
- Network security config: `network_security_config.xml` (cleartext permitted = False)
- Native libs touching WebView: 0

## Summary

- HIGH: 1
- MEDIUM: 8
- LOW: 3

## Findings

### [HIGH] WV-SET-009 - Mixed content allowed (True)
_smali_classes3/com/google/android/gms/internal/ads/zzclc.smali:325 (<init>)_

setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources inside an https:// page, enabling network attackers to inject script.

```
.line 21
    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali/com/active/passport2/webview/LoginFragment.smali:669 (onViewCreated)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 185
    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali/com/facebook/internal/WebDialog.smali:814 (setUpWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 48
    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali/com/google/android/gms/ads/internal/zzs.smali:107 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 40
    invoke-virtual {p1, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes3/com/google/android/gms/internal/consent_sdk/zzbe.smali:680 (zzf)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 31
    invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes3/com/google/android/gms/internal/ads/zzfva.smali:52 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 19
    invoke-virtual {p1, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes3/com/google/android/gms/internal/ads/zzclc.smali:275 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 13
    :try_start_0
    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    :try_end_0
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_smali_classes3/com/google/android/gms/internal/ads/zzclc.smali:302 (<init>)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
.line 18
    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes3/com/google/android/gms/internal/ads/zzfvd.smali:84 (zza)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 21
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_smali/com/active/passport2/webview/LoginFragment.smali:689 (onViewCreated)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 196
    .line 197
    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_smali/com/google/android/gms/ads/internal/util/zzn.smali:87 (call)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 23
    .line 24
    invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-008 - Multiple windows supported (True)
_smali_classes3/com/google/android/gms/internal/ads/zzclc.smali:299 (<init>)_

setSupportMultipleWindows(true) is required for popups/new tabs.

```
.line 17
    invoke-virtual {p2, v1}, Landroid/webkit/WebSettings;->setSupportMultipleWindows(Z)V
```

## Reachability

No exported entry point was found that loads an attacker-supplied URL into a WebView. The misconfigurations above are latent: reaching them requires either an in-app navigation to attacker-controlled content (e.g. a malicious ad or a link the user opens in-app) or a separate bug that supplies the URL.

## WebView hosts

### `com.google.android.gms.internal.ads.zzclc`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`
  - `mixed_content_mode` = `2`
  - `support_multiple_windows` = `True`
- loaded URLs:
  - `about:blank`

### `com.google.android.gms.internal.consent_sdk.zzbe`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.google.android.gms.internal.ads.zzfvd`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `javascript_enabled` = `True`

### `com.active.passport2.webview.LoginFragment`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
- loaded URLs:
  - `about:blank`

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

### `com.facebook.internal.WebDialog`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.google.android.gms.ads.internal.zzs`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.google.android.gms.internal.ads.zzfva`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.facebook.internal.FacebookWebFallbackDialog`
- sources: java
- loaded URLs:
  - `javascript:(function() {  var event = document.createEvent(`
  - `javascript:(function() {  var event = document.createEvent(\'Event\');  event.initEvent(\'fbPlatformDialogMustClose\',true,true);  document.dispatchEvent(event);})();`

### `com.google.android.gms.internal.consent_sdk.zzda`
- sources: java
- loaded URLs:
  - `javascript:`

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `com.active.aps.meetmobile.activities.SplashActivity` | True |  |
| activity | `com.active.aps.meetmobile.activities.MainActivity` | True |  |
| activity | `com.active.aps.meetmobile.v2.common.view.ContainerActivity` | True |  |
| activity | `com.facebook.FacebookActivity` | True |  |
| activity | `com.android.billingclient.api.ProxyBillingActivity` | False |  |
| activity | `com.active.aps.meetmobile.activities.ShareActivity` | False |  |
| activity | `com.active.aps.meetmobile.activities.settings.SettingsActivity` | False |  |
| activity | `com.active.aps.meetmobile.activities.settings.GoogleAccountActivity` | False |  |
| activity | `com.active.aps.meetmobile.activities.settings.OtherAppsActivity` | False |  |
| activity | `com.active.aps.meetmobile.activities.settings.NoResultsActivity` | False |  |
| activity | `com.active.aps.meetmobile.feedback.presentation.linkedswimmer.SwimmersActivity` | False |  |
| activity | `com.active.aps.meetmobile.feedback.presentation.linkedcoach.CoachesActivity` | False |  |
| activity | `com.active.aps.meetmobile.passport.view.RoleActivity` | False |  |
| activity | `com.active.aps.meetmobile.search.MeetSearchFilterActivity` | False |  |
| activity | `com.active.aps.meetmobile.search.SwimmerSearchFilterActivity` | False |  |
| activity | `com.active.aps.meetmobile.search.SwimmerSearchActivity` | False |  |
| activity | `com.active.aps.meetmobile.search.MeetSearchActivity` | False |  |
| activity | `com.active.aps.meetmobile.search.SearchActivity` | False |  |
| activity | `com.active.aps.meetmobile.lib.basic.view.activity.WebViewActivity` | False |  |
| activity | `com.active.consumer.passport.activity.FullLoginActivity` | False |  |
| activity | `com.active.consumer.passport.activity.WebAuthActivity` | False |  |
| activity | `com.active.appauth.AuthorizationManagementActivity` | False |  |
| activity | `com.active.appauth.RedirectUriReceiverActivity` | True | com.active.meetmobile://* |
| activity | `com.facebook.CustomTabMainActivity` | False |  |
| activity | `com.facebook.CustomTabActivity` | False |  |
| activity | `com.google.android.gms.auth.api.signin.internal.SignInHubActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivityV2` | False |  |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| activity | `com.google.android.gms.ads.AdActivity` | False |  |
| activity | `com.google.android.gms.ads.OutOfContextTestingActivity` | False |  |
| activity | `com.google.android.gms.ads.NotificationHandlerActivity` | False |  |
| service | `com.active.aps.meetmobile.notification.GcmIntentService` | False |  |
| service | `com.active.aps.meetmobile.notification.GcmJobService` | False |  |
| service | `com.active.aps.meetmobile.notification.MeetMobileMessagingService` | True |  |
| service | `com.active.aps.meetmobile.service.SyncJobService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `com.google.android.gms.auth.api.signin.RevocationBoundService` | True |  |
| service | `com.google.firebase.messaging.FirebaseMessagingService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementJobService` | False |  |
| service | `com.google.firebase.sessions.SessionLifecycleService` | False |  |
| service | `com.google.android.gms.ads.AdService` | False |  |
| service | `androidx.work.impl.background.systemjob.SystemJobService` | True |  |
| service | `androidx.work.impl.foreground.SystemForegroundService` | False |  |
| service | `androidx.room.MultiInstanceInvalidationService` | False |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| receiver | `com.google.firebase.iid.FirebaseInstanceIdReceiver` | True |  |
| receiver | `com.google.android.gms.measurement.AppMeasurementReceiver` | False |  |
| receiver | `androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver` | False |  |
| receiver | `androidx.work.impl.background.systemalarm.RescheduleReceiver` | False |  |
| receiver | `androidx.work.impl.diagnostics.DiagnosticsReceiver` | True |  |
| receiver | `com.facebook.CurrentAccessTokenExpirationBroadcastReceiver` | False |  |
| receiver | `androidx.profileinstaller.ProfileInstallReceiver` | True |  |
| receiver | `com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver` | False |  |
| provider | `com.facebook.FacebookContentProvider` | True |  |
| provider | `androidx.core.content.FileProvider` | False |  |
| provider | `com.active.aps.meetmobile.lib.network.NetworkInitContentProvider` | False |  |
| provider | `com.active.aps.meetmobile.lib.storage.db.MeetMobileContentProvider` | False |  |
| provider | `com.active.aps.meetmobile.lib.basic.BasicLibInitContentProvider` | False |  |
| provider | `com.google.firebase.provider.FirebaseInitProvider` | False |  |
| provider | `com.google.android.gms.ads.MobileAdsInitProvider` | False |  |
| provider | `androidx.startup.InitializationProvider` | False |  |
| provider | `com.facebook.marketing.internal.MarketingInitProvider` | False |  |
| provider | `com.facebook.internal.FacebookInitProvider` | False |  |
