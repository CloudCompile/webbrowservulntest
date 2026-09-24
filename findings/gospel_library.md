# WebView / in-app browser recon: `samples/gospel_library.apk`

- Package: `org.lds.ldssa` 6.5.3-(653000.1027012) (code 653000)
- SDK: min 21 / target 33
- Network security config: `None` (cleartext permitted = None)
- Native libs touching WebView: 0

## Summary

- HIGH: 4
- MEDIUM: 6
- LOW: 2
- INFO: 3

## Findings

### [HIGH] WV-SET-010 - WebView remote debugging enabled app-wide (True)
_analysis/gospel_library/work/smali_classes2/org/lds/ldssa/ui/web/ContentWebView.smali:298 (initView$default)_

WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide switch. Any WebView in the app becomes attachable over adb (chrome://inspect) without the debuggable build flag. On a production build this exposes live page content and JS bridges to anyone with USB debugging, and is a ready-made dynamic-instrumentation ramp.

```
.line 35
    :cond_2
    invoke-static {v2}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
```

### [HIGH] WV-SET-002 - Local file access enabled (True)
_analysis/gospel_library/work/smali_classes2/org/lds/ldssa/ui/web/ContentWebView.smali:385 (initView$default)_

setAllowFileAccess(true) lets the WebView read file:// URLs, exposing files the app process can read.

```
.line 76
    .line 77
    invoke-virtual {v4, v2}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
```

### [HIGH] CORR-002 - org.lds.ldssa.ui.web.ContentWebView: local file access + JS bridge
_org.lds.ldssa.ui.web.ContentWebView_

Page script can read local files and drive an exposed native bridge, so a file:// or navigated-to page escalates into native capability.

```
file access enabled + addJavascriptInterface + JS enabled
```

### [HIGH] CORR-004 - org.lds.ldssa.ui.web.ContentWebView: remote WebView debugging enabled
_org.lds.ldssa.ui.web.ContentWebView_

Any WebView in the process is attachable via chrome://inspect. On a production build this is an instrumentation ramp for all in-app web content.

```
WebView.setWebContentsDebuggingEnabled(true)
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/gospel_library/work/smali/com/adobe/marketing/mobile/AndroidFullscreenMessage$MessageFullScreenRunner.smali:137 (run)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 48
    invoke-virtual {v4, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/gospel_library/work/smali/com/google/android/recaptcha/internal/zzda.smali:210 (<init>)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 73
    invoke-virtual {p3, p4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/gospel_library/work/smali_classes2/org/lds/documentedit/widget/DocumentEditorWebView.smali:510 (configureWebView)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 6
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_analysis/gospel_library/work/smali_classes2/org/lds/ldssa/ui/web/ContentWebView.smali:380 (initView$default)_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
.line 74
    invoke-virtual {v4, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
```

### [MEDIUM] WV-SET-001 - JavaScript enabled in WebView (True)
_com.adobe.marketing.mobile.AndroidFullscreenMessage_

setJavaScriptEnabled(true) turns the WebView into a script-capable browser. Expected for web apps, but it is a precondition for every other JS-related issue and must be paired with an allowlist.

```
enabled -> True
```

### [MEDIUM] CORR-010 - Cleartext HTTP permitted globally
_AndroidManifest.xml_

The base-config permits http:// for every host, so any WebView navigation or API call can be downgraded to cleartext and modified on-path.

```
networkSecurityConfig=None cleartextTrafficPermitted=true
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_analysis/gospel_library/work/smali/com/adobe/marketing/mobile/AndroidFullscreenMessage$MessageFullScreenRunner.smali:147 (run)_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
.line 53
    .line 54
    invoke-virtual {v4, v3}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
```

### [LOW] WV-SET-006 - DOM storage enabled (True)
_com.adobe.marketing.mobile.AndroidFullscreenMessage_

setDomStorageEnabled(true) persists origin-scoped localStorage.

```
enabled -> True
```

### [INFO] WV-SINK-004 - JS bridge `glContentInterface` exposed by org.lds.ldssa.ui.web.ContentWebView
_org.lds.ldssa.ui.web.ContentWebView:142_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(contentJsInterface, "glContentInterface")
```

### [INFO] WV-SINK-004 - JS bridge `RN` exposed by com.google.android.recaptcha.internal.zzda
_com.google.android.recaptcha.internal.zzda:68_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(zzcuVar, "RN")
```

### [INFO] WV-SINK-004 - JS bridge `documentEditorInterface` exposed by org.lds.documentedit.widget.DocumentEditorWebView
_org.lds.documentedit.widget.DocumentEditorWebView:205_

addJavascriptInterface exposes a native object to page script. A bridge reachable from an untrusted origin defeats the WebView sandbox.

```
addJavascriptInterface(this.documentEditorJsInterface, "documentEditorInterface")
```

## Reachability

No exported entry point was found that loads an attacker-supplied URL into a WebView. The misconfigurations above are latent: reaching them requires either an in-app navigation to attacker-controlled content (e.g. a malicious ad or a link the user opens in-app) or a separate bug that supplies the URL.

## WebView hosts

### `com.adobe.marketing.mobile.AndroidFullscreenMessage$MessageFullScreenRunner`
- sources: smali
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `org.lds.ldssa.ui.web.ContentWebView`
- sources: smali
- settings:
  - `allow_file_access` = `True`
  - `javascript_enabled` = `True`
  - `web_contents_debugging` = `True`
- JS bridges: `glContentInterface`

### `com.adobe.marketing.mobile.AndroidFullscreenMessage`
- sources: java
- settings:
  - `allow_file_access` = `False`
  - `dom_storage_enabled` = `True`
  - `javascript_enabled` = `True`

### `com.google.android.recaptcha.internal.zzda`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- JS bridges: `RN`

### `org.lds.documentedit.widget.DocumentEditorWebView`
- sources: smali
- settings:
  - `javascript_enabled` = `True`
- JS bridges: `documentEditorInterface`

## Exported components

| kind | name | exported | deeplinks |
|------|------|----------|-----------|
| activity | `org.lds.ldssa.ux.main.MainActivity` | True | gospellibraryapp://* |
| activity | `org.lds.ldssa.ux.signin.SignInActivity` | False |  |
| activity | `org.lds.ldssa.ux.annotations.links.LinksActivity` | True |  |
| activity | `org.lds.ldssa.ui.activity.UriRouterActivity` | True | gospellibrary://*<br>https://www.lds.org/general-conference<br>https://www.lds.org/study<br>https://www.lds.org/scriptures |
| activity | `org.lds.ldssa.ux.video.VideoPlayerActivity` | False |  |
| activity | `org.lds.ldssa.ux.video.LegacyVideoPlayerActivity` | False |  |
| activity | `org.lds.ldssa.ux.studyplans.wizard.StudyPlanWizardActivity` | False |  |
| activity | `androidx.compose.ui.tooling.PreviewActivity` | True |  |
| activity | `com.google.firebase.auth.internal.GenericIdpActivity` | True | genericidp://firebase.auth/ |
| activity | `com.google.firebase.auth.internal.RecaptchaActivity` | True | recaptcha://firebase.auth/ |
| activity | `com.google.android.gms.common.api.GoogleApiActivity` | False |  |
| activity | `com.google.android.play.core.missingsplits.PlayCoreMissingSplitsActivity` | False |  |
| activity | `com.google.android.play.core.common.PlayCoreDialogWrapperActivity` | False |  |
| service | `org.lds.ldssa.media.texttospeech.TextToSpeechService` | False |  |
| service | `org.lds.ldssa.media.exomedia.service.MediaService` | False |  |
| service | `org.lds.ldssa.service.BookmarkWidgetService` | False |  |
| service | `org.lds.ldssa.service.VerseOfTheDayWidgetService` | False |  |
| service | `org.lds.ldssa.service.QuoteOfTheDayWidgetService` | False |  |
| service | `com.google.firebase.components.ComponentDiscoveryService` | False |  |
| service | `com.google.android.gms.cast.framework.ReconnectionService` | False |  |
| service | `androidx.work.impl.background.gcm.WorkManagerGcmService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementService` | False |  |
| service | `com.google.android.gms.measurement.AppMeasurementJobService` | False |  |
| service | `androidx.work.impl.background.systemalarm.SystemAlarmService` | False |  |
| service | `androidx.work.impl.background.systemjob.SystemJobService` | True |  |
| service | `androidx.work.impl.foreground.SystemForegroundService` | False |  |
| service | `androidx.room.MultiInstanceInvalidationService` | False |  |
| service | `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | False |  |
| service | `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | False |  |
| service | `com.google.android.play.core.assetpacks.AssetPackExtractionService` | True |  |
| receiver | `org.lds.ldssa.ui.widget.BookmarkWidgetProvider` | True |  |
| receiver | `org.lds.ldssa.ui.widget.ComeFollowMeWidgetTextProvider` | True |  |
| receiver | `org.lds.ldssa.ui.widget.ComeFollowMeWidgetIconProvider` | True |  |
| receiver | `org.lds.ldssa.ui.widget.VerseOfTheDayWidgetProvider` | True |  |
| receiver | `org.lds.ldssa.ui.widget.QuoteOfTheDayWidgetProvider` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.StudyPlansReminderNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.QuoteOfTheDayNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.VerseOfTheDayNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.PrayerStudyNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.HymnsAdminNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.EldersQuorumAdminNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.ReliefSocietyAdminNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.EldersQuorumMemberNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.ReliefSocietyMemberNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.ui.notification.receiver.BannerEventNotificationReceiver` | True |  |
| receiver | `org.lds.ldssa.receiver.DownloadManagerReceiver` | True |  |
| receiver | `org.lds.ldssa.receiver.ShareIntentReceiver` | False |  |
| receiver | `com.google.android.gms.cast.framework.media.MediaIntentReceiver` | False |  |
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
| provider | `androidx.core.content.FileProvider` | False |  |
| provider | `androidx.startup.InitializationProvider` | False |  |
| provider | `com.google.firebase.provider.FirebaseInitProvider` | False |  |
