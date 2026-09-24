"""Detection rules for WebView attack surface.

Each rule matches an API call or a code shape in decompiled smali and/or Java.
`dialect` selects how the call is recognised:

  smali -> matched against ``Landroid/webkit/...;->method(...)`` invocations
  java  -> matched against ``method(...)`` call sites in jadx output
  both  -> either

Boolean-valued settings carry a `setting` key so the scanner can recover the
literal argument from smali registers or the Java call arguments and grade the
severity accordingly.
"""

from dataclasses import dataclass, field
from typing import Optional

# Severity ordering used for sorting / summary counts.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    description: str
    dialect: str
    pattern: str
    setting: Optional[str] = None
    masvs: tuple = ()
    mastg: tuple = ()
    references: tuple = field(default=())


# --- Dangerous WebSettings -------------------------------------------------
# A `true` literal on any of these is the classic WebView hardening failure.
SETTING_RULES = [
    Rule(
        id="WV-SET-001",
        title="JavaScript enabled in WebView",
        severity="MEDIUM",
        description=(
            "setJavaScriptEnabled(true) turns the WebView into a script-capable "
            "browser. Expected for web apps, but it is a precondition for every "
            "other JS-related issue and must be paired with an allowlist."
        ),
        dialect="both",
        pattern="setJavaScriptEnabled",
        setting="javascript_enabled",
        masvs=("MASVS-PLATFORM-2", "MASVS-CODE-4"),
        mastg=("MASTG-TEST-0233",),
    ),
    Rule(
        id="WV-SET-002",
        title="Local file access enabled",
        severity="HIGH",
        description=(
            "setAllowFileAccess(true) lets the WebView read file:// URLs, exposing "
            "files the app process can read."
        ),
        dialect="both",
        pattern="setAllowFileAccess",
        setting="allow_file_access",
        masvs=("MASVS-PLATFORM-2",),
        mastg=("MASTG-TEST-0234",),
    ),
    Rule(
        id="WV-SET-003",
        title="file:// pages may load other file:// resources",
        severity="HIGH",
        description=(
            "setAllowFileAccessFromFileURLs(true) lets a file:// page read other "
            "local files via XMLHttpRequest/fetch."
        ),
        dialect="both",
        pattern="setAllowFileAccessFromFileURLs",
        setting="allow_file_access_from_file_urls",
        masvs=("MASVS-PLATFORM-2",),
        mastg=("MASTG-TEST-0234",),
    ),
    Rule(
        id="WV-SET-004",
        title="file:// pages may load arbitrary remote origins",
        severity="CRITICAL",
        description=(
            "setAllowUniversalAccessFromFileURLs(true) lets a file:// page make "
            "cross-origin requests to any host, leaking local file contents to a "
            "remote server."
        ),
        dialect="both",
        pattern="setAllowUniversalAccessFromFileURLs",
        setting="allow_universal_access_from_file_urls",
        masvs=("MASVS-PLATFORM-2",),
        mastg=("MASTG-TEST-0234",),
    ),
    Rule(
        id="WV-SET-005",
        title="content:// access enabled",
        severity="MEDIUM",
        description=(
            "setAllowContentAccess(true) lets the WebView follow content:// URLs, "
            "widening the reachable data set."
        ),
        dialect="both",
        pattern="setAllowContentAccess",
        setting="allow_content_access",
        masvs=("MASVS-PLATFORM-2",),
    ),
    Rule(
        id="WV-SET-006",
        title="DOM storage enabled",
        severity="LOW",
        description="setDomStorageEnabled(true) persists origin-scoped localStorage.",
        dialect="both",
        pattern="setDomStorageEnabled",
        setting="dom_storage_enabled",
        masvs=("MASVS-STORAGE-1",),
    ),
    Rule(
        id="WV-SET-007",
        title="Scripts may open windows without user interaction",
        severity="MEDIUM",
        description=(
            "setJavaScriptCanOpenWindowsAutomatically(true) lets page script spawn "
            "windows unprompted, useful for phishing or driving native bridges."
        ),
        dialect="both",
        pattern="setJavaScriptCanOpenWindowsAutomatically",
        setting="js_can_open_windows_automatically",
        masvs=("MASVS-PLATFORM-2",),
    ),
    Rule(
        id="WV-SET-008",
        title="Multiple windows supported",
        severity="LOW",
        description="setSupportMultipleWindows(true) is required for popups/new tabs.",
        dialect="both",
        pattern="setSupportMultipleWindows",
        setting="support_multiple_windows",
        masvs=("MASVS-PLATFORM-2",),
    ),
    Rule(
        id="WV-SET-009",
        title="Mixed content allowed",
        severity="HIGH",
        description=(
            "setMixedContentMode(ALWAYS_ALLOW) permits loading http:// subresources "
            "inside an https:// page, enabling network attackers to inject script."
        ),
        dialect="both",
        pattern="setMixedContentMode",
        setting="mixed_content_mode",
        masvs=("MASVS-NETWORK-1",),
        mastg=("MASTG-TEST-0235",),
    ),
    Rule(
        id="WV-SET-010",
        title="WebView remote debugging enabled app-wide",
        severity="HIGH",
        description=(
            "WebView.setWebContentsDebuggingEnabled(true) is a static, process-wide "
            "switch. Any WebView in the app becomes attachable over adb "
            "(chrome://inspect) without the debuggable build flag. On a production "
            "build this exposes live page content and JS bridges to anyone with USB "
            "debugging, and is a ready-made dynamic-instrumentation ramp."
        ),
        dialect="both",
        pattern="setWebContentsDebuggingEnabled",
        setting="web_contents_debugging",
        masvs=("MASVS-RESILIENCE-4",),
    ),
]

# --- Sinks / attack surface (informational) --------------------------------
SINK_RULES = [
    Rule(
        id="WV-SINK-001",
        title="WebView instantiated",
        severity="INFO",
        description="A WebView is created here; this is in-app browser surface.",
        dialect="both",
        pattern="new WebView|<init>.*Landroid/webkit/WebView",
        masvs=("MASVS-PLATFORM-2",),
    ),
    Rule(
        id="WV-SINK-002",
        title="URL loaded into WebView",
        severity="INFO",
        description="loadUrl is a navigation sink; review where the URL comes from.",
        dialect="both",
        pattern="loadUrl",
        masvs=("MASVS-PLATFORM-2",),
    ),
    Rule(
        id="WV-SINK-003",
        title="JavaScript evaluated in page context",
        severity="LOW",
        description=(
            "evaluateJavascript / loadUrl(\"javascript:...\") injects script into the "
            "page. If any argument is attacker-influenced this is script injection."
        ),
        dialect="both",
        pattern="evaluateJavascript|loadUrl\\(\"javascript",
        masvs=("MASVS-PLATFORM-2", "MASVS-CODE-4"),
    ),
    Rule(
        id="WV-SINK-004",
        title="JavaScript bridge exposed to page",
        severity="INFO",
        description=(
            "addJavascriptInterface exposes a native object to page script. A bridge "
            "reachable from an untrusted origin defeats the WebView sandbox."
        ),
        dialect="both",
        pattern="addJavascriptInterface",
        masvs=("MASVS-PLATFORM-2",),
        mastg=("MASTG-TEST-0232",),
    ),
]

# --- Navigation / TLS handling --------------------------------------------
# These are code-shape rules evaluated against decompiled Java / smali.
CODE_SHAPE_RULES = [
    Rule(
        id="WV-NAV-001",
        title="URL override forwards every URL back into the WebView",
        severity="HIGH",
        description=(
            "shouldOverrideUrlLoading calls loadUrl(url) and returns false, with no "
            "host allowlist or external-browser handoff. Any link the user taps "
            "stays inside the app WebView, so navigation can walk from a trusted "
            "page to arbitrary third-party sites while retaining the app's cookies "
            "and injected JS bridges."
        ),
        dialect="both",
        pattern="shouldOverrideUrlLoading",
        masvs=("MASVS-PLATFORM-2",),
        mastg=("MASTG-TEST-0233",),
    ),
    Rule(
        id="WV-NAV-002",
        title="TLS error handler may proceed on certificate failure",
        severity="HIGH",
        description=(
            "onReceivedSslError calls handler.proceed(), accepting invalid "
            "certificates and enabling TLS interception."
        ),
        dialect="both",
        pattern="onReceivedSslError",
        masvs=("MASVS-NETWORK-1",),
        mastg=("MASTG-TEST-0235",),
    ),
]

ALL_RULES = SETTING_RULES + SINK_RULES

# Tokens that indicate native code involvement (best-effort, .so string scan).
NATIVE_TOKENS = [
    "Landroid/webkit/WebView",
    "addJavascriptInterface",
    "loadUrl",
    "WebViewClient",
    "evaluateJavascript",
    "android/webkit",
]


def severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)
