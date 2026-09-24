# WebView / in-app browser recon: `samples/calm.apk`

- Package: `com.calm.android` 7.1.2 (code 4120462)
- SDK: min 29 / target 36
- Network security config: `network_security_config.xml` (cleartext permitted = None)
- Native libs touching WebView: 0

## Summary

- MEDIUM: 8
- LOW: 4
- INFO: 2

## Findings

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes4/com/calm/android/auth/apple/SignInWebViewDialogFragment.smali:336 (onCreateView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 47
    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-007 - Scripts may open windows without user interaction (True)
_smali_classes4/com/calm/android/auth/apple/SignInWebViewDialogFragment.smali:339 (onCreateView)_

setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn windows unprompted, useful for phishing or driving native bridges.

```
.line 48
    invoke-virtual {p2, v0}, Landroid/webkit/WebSettings;->setJavaScriptCanOpenWindowsAutomatically(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes5/com/calm/android/ui/profile/WebSubscriptionActivity.smali:463 (initView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 v7, 0x1

    invoke-virtual {v6, v7}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes5/com/calm/android/ui/webview/WebviewActivity.smali:296 (initView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object v6

    invoke-virtual {v6, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes6/com/facebook/internal/WebDialog.smali:943 (setUpWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
:cond_5
    invoke-virtual {v1, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes7/com/google/androidbrowserhelper/trusted/WebViewFallbackActivity.smali:203 (setupWebSettings)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 280
    invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes8/com/perimeterx/mobile_sdk/PerimeterX.smali:1304 (setupWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
const/4 p2, 0x1

    invoke-virtual {p0, p2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_smali_classes8/com/perimeterx/mobile_sdk/block/PXBlockActivity.smali:595 (onCreate)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
move-result-object v0

    invoke-virtual {v0, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_smali_classes5/com/calm/android/ui/profile/WebSubscriptionActivity.smali:477 (initView)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v6

    invoke-virtual {v6, v7}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_smali_classes5/com/calm/android/ui/webview/WebviewActivity.smali:310 (initView)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v6

    invoke-virtual {v6, v4}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_smali_classes7/com/google/androidbrowserhelper/trusted/WebViewFallbackActivity.smali:206 (setupWebSettings)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 281
    invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_smali_classes8/com/perimeterx/mobile_sdk/block/PXBlockActivity.smali:602 (onCreate)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
move-result-object v0

    invoke-virtual {v0, v4}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [INFO] WV-SINK-004 - JS bridge `pxCaptcha` exposed by com.perimeterx.mobile_sdk.block.PXBlockActivity
_com.perimeterx.mobile_sdk.block.PXBlockActivity:124_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(pXJavaScriptInterface, "pxCaptcha")
```

### [INFO] WV-SINK-004 - JS bridge `pxCaptcha` exposed by com.perimeterx.mobile_sdk.PerimeterX
_com.perimeterx.mobile_sdk.PerimeterX:349_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(pXJavaScriptInterface, "pxCaptcha")
```

## Reachability

No exported entry point was found that loads an attacker-supplied URL into a WebView. The misconfigurations above are latent: reaching them requires either an in-app navigation to attacker-controlled content (e.g. a malicious ad or a link the user opens in-app) or a separate bug that supplies the URL.

## WebView hosts

### `com.calm.android.ui.profile.WebSubscriptionActivity`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `allow_file_access_from_file_urls` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
- intent-supplied URL: `intent extra -> get*Url() -> loadUrl`

### `com.calm.android.ui.webview.WebviewActivity`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `allow_file_access_from_file_urls` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
- intent-supplied URL: `intent extra -> get*Url() -> loadUrl`

### `com.iterable.iterableapi.IterableWebView`
- sources: smali
- settings:
  - `allow_content_access` = `False`
  - `allow_file_access` = `False`
  - `allow_file_access_from_file_urls` = `False`
  - `allow_universal_access_from_file_urls` = `False`
  - `javascript_enabled` = `False`

### `com.calm.android.auth.apple.SignInWebViewDialogFragment`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
  - `js_can_open_windows_automatically` = `True`

### `com.google.androidbrowserhelper.trusted.WebViewFallbackActivity`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
- intent-supplied URL: `intent extra -> get*Url() -> loadUrl`

### `com.perimeterx.mobile_sdk.block.PXBlockActivity`
- sources: smali
- settings:
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`
- JS bridges: `pxCaptcha`

### `com.facebook.internal.WebDialog`
- sources: smali
- settings:
  - `javascript_enabled` = `True`

### `com.perimeterx.mobile_sdk.PerimeterX`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- JS bridges: `pxCaptcha`

### `com.facebook.internal.FacebookWebFallbackDialog`
- sources: java
- loaded URLs:
  - `javascript:`

### `com.calm.android.auth.apple.SignInWebViewClient`
- sources: java
- loaded URLs:
  - `javascript: (function() { `

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `com.calm.android.ui.splash.SplashActivity` | True | @string/deeplink_scheme://*<br>https://@string/deeplink_links_calm_com/a/<br>http://@string/deeplink_links_calm_com/a/<br>https://@string/deeplink_app_www_host/work |
| activity | `com.auth0.android.provider.RedirectActivity` | True | calm-auth://oneid-dev-1.calm.com/android/com.calm.android.staging/callback<br>calm-auth://oneid-dev-1.calm.com/android/com.calm.android.dev/callback<br>calm-auth://oneid-dev-1.calm.com/android/com.calm.android/callback<br>calm-auth://oneid-dev-4.calm.com/android/com.calm.android.staging/callback |
| activity | `com.calm.android.ui.home.MainActivity` | False |  |
| activity | `com.calm.android.ui.intro.OnboardingActivity` | False |  |
| activity | `com.calm.android.ui.login.LoginActivity` | False |  |
| activity | `com.calm.android.ui.player.overlays.SessionPlayerOverlayActivity` | False |  |
| activity | `com.calm.android.ui.reminders.RemindersActivity` | False |  |
| activity | `com.calm.android.ui.profile.ManualSessionActivity` | False |  |
| activity | `com.calm.android.ui.mood.MoodActivity` | False |  |
| activity | `com.calm.android.ui.profile.WebSubscriptionActivity` | False |  |
| activity | `com.calm.android.ui.webview.WebviewActivity` | False |  |
| activity | `com.calm.android.ui.player.VideoPlayerActivity` | False |  |
| activity | `com.calm.android.ui.scenes.ScenesActivity` | False |  |
| activity | `com.calm.android.debug.DebugActivity` | False |  |
| activity | `com.calm.android.ui.misc.ModalActivity` | False |  |
| activity | `com.facebook.FacebookActivity` | False |  |
| activity | `com.facebook.CustomTabActivity` | True | @string/facebook_protocol_scheme://*<br>fbconnect://cct.com.calm.android |
| activity | `com.calm.android.ui.onboarding.familyplan.FamilyPlanOnboardingActivity` | False |  |
| activity | `com.calm.android.feat.healthconnect.activity.HealthConnectPermissionsRationaleActivity` | True |  |
| activity | `com.calm.android.feat.glasses.grounding.ui.GroundingProjectedActivity` | True |  |
| activity | `androidx.activity.ComponentActivity` | False |  |
| activity | `com.perimeterx.mobile_sdk.block.PXBlockActivity` | False |  |
| activity | `com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity` | False |  |
| activity | `com.iterable.iterableapi.IterableTrampolineActivity` | False |  |
| activity | `com.facebook.CustomTabMainActivity` | False |  |
| activity | `com.jakewharton.processphoenix.PhoenixActivity` | False |  |
| activity | `com.auth0.android.provider.AuthenticationActivity` | False |  |
| activity | `androidx.credentials.playservices.HiddenActivity` | False |  |
| activity | `com.google.android.gms.auth.api.signin.internal.SignInHubActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivity` | False |  |
| activity | `com.android.billingclient.api.ProxyBillingActivityV2` | False |  |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| activity | `androidx.xr.projected.permissions.RequestPermissionsOnHostActivity` | False |  |
| activity | `androidx.xr.projected.permissions.GoToHostProjectedActivity` | False |  |
| activity | `androidx.compose.ui.tooling.PreviewActivity` | True |  |
| activity | `com.google.android.play.core.common.PlayCoreDialogWrapperActivity` | False |  |
| activity-alias | `com.calm.android.ViewPermissionUsageActivity` | True |  |
| service | `androidx.work.impl.foreground.SystemForegroundService` | False |  |
| service | `com.calm.android.services.AudioService` | True |  |
| service | `com.calm.android.util.CalmFirebaseService` | False |  |
| service | `com.calm.android.services.WearListenerService` | True | wear://* |
| service | `com.calm.android.widgets.DailyCalmWidgetUpdateJob` | True |  |
| service | `com.calm.android.widgets.SleepStoryWidgetUpdateJob` | True |  |
| service | `com.calm.android.widgets.DailyCalmWidget$UpdaterService` | False |  |
| service | `com.calm.android.widgets.RecommendedSleepStoryWidget$UpdaterService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `com.google.android.gms.cast.framework.ReconnectionService` | False |  |
| service | `com.iterable.iterableapi.IterableFirebaseMessagingService` | False |  |
| service | `com.jakewharton.processphoenix.PhoenixService` | False |  |
| service | `androidx.credentials.playservices.CredentialProviderMetadataHolder` | False |  |
| service | `com.google.android.gms.auth.api.signin.RevocationBoundService` | True |  |
| service | `com.google.firebase.sessions.SessionLifecycleService` | False |  |
| service | `com.google.firebase.messaging.FirebaseMessagingService` | False |  |
| service | `androidx.camera.core.impl.MetadataHolderService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementJobService` | False |  |
| service | `androidx.health.platform.client.impl.sdkservice.HealthDataSdkService` | True |  |
| service | `androidx.work.impl.background.systemalarm.SystemAlarmService` | False |  |
| service | `androidx.work.impl.background.systemjob.SystemJobService` | True |  |
| service | `androidx.room.MultiInstanceInvalidationService` | False |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| receiver | `com.calm.android.util.BootCompletedReceiver` | True |  |
| receiver | `com.calm.android.util.UpgradeReceiver` | True |  |
| receiver | `com.calm.android.util.reminders.trial.TrialReminderAlarmReceiver` | False |  |
| receiver | `com.calm.android.util.reminders.RemindersAlarmReceiver` | False |  |
| receiver | `com.calm.android.util.ShareBroadcastReceiver` | False |  |
| receiver | `com.calm.android.widgets.DailyCalmWidget` | True |  |
| receiver | `com.calm.android.widgets.RecommendedSleepStoryWidget` | True |  |
| receiver | `androidx.mediarouter.media.MediaTransferReceiver` | True |  |
| receiver | `com.google.android.gms.cast.framework.media.MediaIntentReceiver` | False |  |
| receiver | `com.iterable.iterableapi.IterablePushActionReceiver` | False |  |
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
| provider | `androidx.core.content.FileProvider` | False |  |
| provider | `androidx.startup.InitializationProvider` | False |  |
| provider | `com.google.firebase.provider.FirebaseInitProvider` | False |  |
| provider | `com.facebook.internal.FacebookInitProvider` | False |  |
| provider | `com.datadog.android.rum.DdRumContentProvider` | False |  |
| provider | `com.squareup.picasso.PicassoProvider` | False |  |
