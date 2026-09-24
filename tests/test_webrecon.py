"""Tests for the webrecon static analyzer.

Uses synthetic decompiler output (a minimal work dir) rather than a real APK so
the suite runs fast and without the Android toolchain. The fixture deliberately
contains both a vulnerable WebView and a hardened one so the tests assert that
findings fire *and* that hardening suppresses them.
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webrecon import scanner  # noqa: E402

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnapp">
    <application android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name="com.example.HandlerActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="http" />
                <data android:scheme="https" />
            </intent-filter>
        </activity>
        <activity android:name="com.example.SafeActivity" android:exported="false" />
        <activity android:name="com.example.PinnedActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" />
                <data android:host="connect.example.com" />
                <data android:pathPrefix="/app/home" />
            </intent-filter>
        </activity>
        <activity android:name="com.example.PathOnlyHandler" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" />
                <data android:host="connect.example.com" />
                <data android:pathPrefix="/oauth2Confirm" />
            </intent-filter>
        </activity>
        <activity android:name="com.example.HostCheckedHandler" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" />
                <data android:host="connect.example.com" />
                <data android:pathPrefix="/oauth2Confirm" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors><certificates src="system" /></trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">pinned.example.com</domain>
        <trust-anchors><certificates src="@raw/example_ca" /></trust-anchors>
    </domain-config>
</network-security-config>
"""

VULN_SMALI = """.class public Lcom/example/Vuln;
.super Ljava/lang/Object;

.method public initWebView(Landroid/webkit/WebView;)V
    .locals 3

    invoke-virtual {p1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v1

    const/4 v2, 0x1
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    const/4 v2, 0x1
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    const/4 v2, 0x1
    invoke-static {v2}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V

    return-void
.end method
"""

HARDENED_SMALI = """.class public Lcom/example/Hardened;
.super Ljava/lang/Object;

.method public initWebView(Landroid/webkit/WebView;)V
    .locals 3

    invoke-virtual {p1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v1

    const/4 v2, 0x0
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V

    const/4 v2, 0x0
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    return-void
.end method
"""

PATH_ONLY_SMALI = """.class public Lcom/example/PathOnlyHandler;
.super Ljava/lang/Object;

.method public route(Landroid/net/Uri;)V
    .locals 3

    invoke-virtual {p0}, Landroid/net/Uri;->getPath()Ljava/lang/String;
    move-result-object v0

    invoke-virtual {p0}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;
    move-result-object v1

    invoke-virtual {p0}, Landroid/net/Uri;->getLastPathSegment()Ljava/lang/String;
    move-result-object v2

    return-void
.end method
"""

HOST_CHECKED_SMALI = """.class public Lcom/example/HostCheckedHandler;
.super Ljava/lang/Object;

.method public route(Landroid/net/Uri;)V
    .locals 3

    invoke-virtual {p0}, Landroid/net/Uri;->getHost()Ljava/lang/String;
    move-result-object v0

    invoke-virtual {p0}, Landroid/net/Uri;->getPath()Ljava/lang/String;
    move-result-object v1

    invoke-virtual {p0}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;
    move-result-object v2

    return-void
.end method
"""

VULN_JAVA = """package com.example;

import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class Vuln {
    public void configure(WebView webView) {
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(new Bridge(), "exampleBridge");
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                view.loadUrl(url);
                return false;
            }
        });
    }

    static class Bridge {
        @JavascriptInterface
        public String getData() {
            return "sensitive";
        }
    }
}
"""

SSL_PROCEED_JAVA = """package com.example;

import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class BadTls extends WebViewClient {
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        handler.proceed();
    }
}
"""


def build_work_dir(base: Path) -> Path:
    work = base / "work"
    (work / "res" / "xml").mkdir(parents=True)
    (work / "smali_classes3" / "com" / "example").mkdir(parents=True)
    (work / "java" / "com" / "example").mkdir(parents=True)

    (work / "AndroidManifest.xml").write_text(MANIFEST)
    (work / "res" / "xml" / "network_security_config.xml").write_text(NSC)
    (work / "smali_classes3" / "com" / "example" / "Vuln.smali").write_text(VULN_SMALI)
    (work / "smali_classes3" / "com" / "example" / "Hardened.smali").write_text(HARDENED_SMALI)
    (work / "smali_classes3" / "com" / "example" / "PathOnlyHandler.smali").write_text(PATH_ONLY_SMALI)
    (work / "smali_classes3" / "com" / "example" / "HostCheckedHandler.smali").write_text(HOST_CHECKED_SMALI)
    (work / "java" / "com" / "example" / "Vuln.java").write_text(VULN_JAVA)
    (work / "java" / "com" / "example" / "BadTls.java").write_text(SSL_PROCEED_JAVA)
    return work


def rule_set(report):
    return {f["rule"] for f in report.findings}


def titles_for(report, rule):
    return [f["title"] for f in report.findings if f["rule"] == rule]


class TestWebrecon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        work = build_work_dir(base)
        cls.report = scanner.analyze(work, None, "fixture", base / "apk")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    # -- manifest -----------------------------------------------------------
    def test_package_and_exports(self):
        self.assertEqual(self.report.package, "com.example.vulnapp")
        exported = {c.name for c in self.report.components if c.exported}
        self.assertIn("com.example.HandlerActivity", exported)
        self.assertNotIn("com.example.SafeActivity", exported)

    def test_nsc_cleartext(self):
        self.assertTrue(self.report.facts["nsc_cleartext_permitted"])
        self.assertEqual(self.report.facts["nsc_file"], "network_security_config.xml")
        self.assertIn("pinned.example.com", self.report.facts["nsc_domains"])

    # -- smali literal recovery --------------------------------------------
    def test_smali_true_literals_recovered(self):
        host = next(h for h in self.report.hosts if h.name == "com.example.Vuln")
        self.assertIs(host.settings.get("javascript_enabled"), True)
        self.assertIs(host.settings.get("allow_universal_access_from_file_urls"), True)
        self.assertIs(host.settings.get("web_contents_debugging"), True)

    def test_hardened_settings_not_flagged(self):
        # setAllowFileAccess(false) / setAllowUniversal...(false) must not raise WV-SET-002/004
        for f in self.report.findings:
            if f["rule"] in ("WV-SET-002", "WV-SET-004"):
                self.assertNotIn("Hardened", f.get("location", ""))

    # -- correlations -------------------------------------------------------
    def test_universal_access_plus_js_is_critical(self):
        crit = [f for f in self.report.findings if f["severity"] == "CRITICAL"]
        self.assertTrue(any("file://" in f["title"] for f in crit))

    def test_unrestricted_navigation_detected(self):
        host = next(h for h in self.report.hosts if h.name == "com.example.Vuln")
        self.assertTrue(host.unrestricted_navigation)
        self.assertIn("CORR-005", rule_set(self.report))

    def test_js_bridge_detected_with_methods(self):
        host = next(h for h in self.report.hosts if h.name == "com.example.Vuln")
        names = {b.name for b in host.bridges}
        self.assertIn("exampleBridge", names)
        bridge = next(b for b in host.bridges if b.name == "exampleBridge")
        self.assertTrue(bridge.has_getdata)
        self.assertIn("getData", bridge.methods)

    def test_ssl_proceed_detected(self):
        self.assertTrue(any(h.ssl_proceed for h in self.report.hosts))
        self.assertIn("CORR-006", rule_set(self.report))

    def test_broad_deeplink_reported(self):
        self.assertIn("CORR-021", rule_set(self.report))
        self.assertTrue(any("HandlerActivity" in t for t in titles_for(self.report, "CORR-021")))

    def test_host_pinned_filter_is_not_flagged(self):
        # scheme=https + host=connect.example.com in one filter is correctly
        # scoped; only the host-less HandlerActivity filter should fire.
        self.assertFalse(
            any("PinnedActivity" in t for t in titles_for(self.report, "CORR-021")),
            "a host-pinned intent-filter must not be reported as accepting any URL",
        )
        pinned = next(c for c in self.report.components if c.name == "com.example.PinnedActivity")
        # merged binding should carry both scheme and host
        self.assertIn("https://connect.example.com/app/home", pinned.deeplinks)
        self.assertNotIn("https://*/app/home", pinned.deeplinks)

    def test_remote_debuggable_reported(self):
        self.assertIn("WV-SET-010", rule_set(self.report))
        self.assertIn("CORR-004", rule_set(self.report))

    def test_path_only_handler_flagged(self):
        self.assertIn("CORR-022", rule_set(self.report))
        titles = titles_for(self.report, "CORR-022")
        self.assertTrue(any("PathOnlyHandler" in t for t in titles))

    def test_host_checked_handler_not_flagged(self):
        self.assertFalse(
            any("HostCheckedHandler" in t for t in titles_for(self.report, "CORR-022")),
            "a handler that reads getHost() must not be reported as path-only",
        )

    # -- report integration -------------------------------------------------
    def test_json_and_markdown_render(self):
        from webrecon import report as report_mod

        blob = self.report.to_json()
        self.assertIn("com.example.vulnapp", blob)
        md = report_mod.render(self.report)
        self.assertIn("# WebView / in-app browser recon", md)
        self.assertIn("CORR-021", md)


if __name__ == "__main__":
    unittest.main()
