"""Core static scanner.

Pipeline
--------
1. unpack the target (.apk or .xapk) and decompile with apktool + jadx
2. parse AndroidManifest.xml -> exported components, deep-link schemes, NSC
3. scan smali for WebSettings calls and recover the literal boolean argument
4. scan decompiled Java for navigation overrides, JS bridges and injected script
5. scan the shipped .so files for native WebView usage
6. correlate everything per WebView-hosting class and emit findings
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from xml.etree import ElementTree as ET

from . import rules as R

# androguard logs every AXML attribute at DEBUG via loguru; that floods the CLI.
# Detach its handlers so our own stdout stays readable.
try:  # pragma: no cover - depends on loguru being present
    from loguru import logger as _loguru_logger

    _loguru_logger.remove()
except Exception:
    pass

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

SMALI_EXT = ".smali"


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------
@dataclass
class Hit:
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    method: str
    literal: Optional[object] = None
    snippet: str = ""
    class_name: str = ""


@dataclass
class Bridge:
    name: str
    java_class: str
    line: int
    exposed_object: str = ""
    has_getdata: bool = False
    methods: List[str] = field(default_factory=list)


@dataclass
class IntentFilter:
    """One <intent-filter>, with its <data> attributes merged per Android rules.

    Android ANDs the attributes within a single <data> element and ORs across
    separate <data> elements. So `scheme=https` in one and `host=x.com` in
    another means "https://x.com/...", NOT "any https host". Each entry below is
    one resolved binding: (scheme, host, path).
    """

    actions: List[str] = field(default_factory=list)
    bindings: List[tuple] = field(default_factory=list)
    is_browsable: bool = False


@dataclass
class Component:
    kind: str
    name: str
    exported: bool
    permission: Optional[str]
    deeplinks: List[str] = field(default_factory=list)
    is_launcher: bool = False
    filters: List[IntentFilter] = field(default_factory=list)


@dataclass
class HostInfo:
    """A class that configures a WebView."""

    name: str
    source: str  # smali / java
    settings: Dict[str, object] = field(default_factory=dict)
    bridges: List[Bridge] = field(default_factory=list)
    loaded_urls: List[str] = field(default_factory=list)
    injected_script: List[str] = field(default_factory=list)
    unrestricted_navigation: bool = False
    ssl_proceed: bool = False
    is_exported_component: bool = False


@dataclass
class Report:
    target: str
    package: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    facts: Dict[str, object] = field(default_factory=dict)
    components: List[Component] = field(default_factory=list)
    hosts: List[HostInfo] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    native_webview_libs: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    # exported deep-link handlers whose routing reads only the URL path
    path_only_handlers: List[dict] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def run(cmd: List[str], log: Optional[Path] = None) -> int:
    if log:
        with log.open("w") as fh:
            return subprocess.call(cmd, stdout=fh, stderr=subprocess.STDOUT)
    return subprocess.call(cmd)


def to_class_name(path: Path, root: Path) -> str:
    rel = path.relative_to(root)
    parts = list(rel.parts)
    # drop the leading smali / smali_classesN / sources segment
    if parts and (parts[0].startswith("smali") or parts[0] == "sources"):
        parts = parts[1:]
    name = "/".join(parts)
    for suffix in (".smali", ".java"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name.replace("/", ".")


# --------------------------------------------------------------------------
# unpack / decompile
# --------------------------------------------------------------------------
def unpack(target: Path, out_dir: Path) -> Path:
    """Return a path to a concrete .apk, extracting XAPK/APKS bundles."""
    if target.suffix.lower() in (".apk",):
        return target
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target) as z:
        candidates = [n for n in z.namelist() if n.endswith(".apk")]
        base = [n for n in candidates if "base" in n.lower()]
        chosen = (base or candidates)
        # prefer the largest apk (the base module)
        chosen = sorted(chosen, key=lambda n: z.getinfo(n).file_size, reverse=True)
        if not chosen:
            raise SystemExit(f"no .apk inside {target}")
        inner = chosen[0]
        dest = out_dir / Path(inner).name
        dest.write_bytes(z.read(inner))
        # also extract any split apks for native-lib scanning
        for n in candidates:
            (out_dir / Path(n).name).write_bytes(z.read(n))
        return dest


def decompile(apk: Path, work: Path, raw_apk: Path) -> Dict[str, Path]:
    smali_dir = work / "smali"
    java_dir = work / "java"
    manifest = work / "AndroidManifest.xml"

    if not manifest.exists():
        run(
            ["apktool", "d", "-f", "-o", str(work), str(raw_apk)],
            log=work.parent / "apktool.log",
        )
    if not java_dir.exists():
        run(
            ["jadx", "-d", str(java_dir), "--no-res", "--threads-count", "8", str(raw_apk)],
            log=work.parent / "jadx.log",
        )
    return {"work": work, "manifest": manifest, "java": java_dir, "smali": smali_dir}


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------
def parse_manifest(manifest: Path, apk: Optional[Path] = None) -> dict:
    """Parse the manifest, merging two sources.

    apktool's decoded XML keeps symbolic resource refs and the full component
    tree, but drops versionCode/versionName/uses-sdk. androguard decodes the
    binary manifest and preserves those. Prefer apktool for structure and
    androguard for the version/SDK metadata, falling back gracefully if only
    one is present.
    """
    aapt_root = ET.parse(manifest).getroot()
    ag_root = None
    if apk is not None:
        try:
            import logging

            logging.disable(logging.CRITICAL)
            from androguard.core.apk import APK

            ag_root = APK(str(apk)).get_android_manifest_xml()
        except Exception:
            ag_root = None

    root = aapt_root
    app = root.find("application")
    info = {
        "package": root.get("package"),
        "version_name": root.get(ANDROID_NS + "versionName"),
        "version_code": root.get(ANDROID_NS + "versionCode"),
        "min_sdk": None,
        "target_sdk": None,
        "uses_cleartext": None,
        "nsc": None,
        "debuggable": None,
    }
    if ag_root is not None:
        info["package"] = info["package"] or ag_root.get("package")
        info["version_name"] = ag_root.get(ANDROID_NS + "versionName")
        info["version_code"] = ag_root.get(ANDROID_NS + "versionCode")
        ag_uses = ag_root.find("uses-sdk")
        if ag_uses is not None:
            info["min_sdk"] = ag_uses.get(ANDROID_NS + "minSdkVersion")
            info["target_sdk"] = ag_uses.get(ANDROID_NS + "targetSdkVersion")
    if app is not None:
        info["uses_cleartext"] = app.get(ANDROID_NS + "usesCleartextTraffic")
        info["nsc"] = app.get(ANDROID_NS + "networkSecurityConfig")
        info["debuggable"] = app.get(ANDROID_NS + "debuggable")

    components: List[Component] = []
    if app is not None:
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for e in app.iter(tag):
                name = e.get(ANDROID_NS + "name")
                filters = e.findall("intent-filter")
                exported_attr = e.get(ANDROID_NS + "exported")
                exported = exported_attr == "true" or (exported_attr is None and bool(filters))
                perm = e.get(ANDROID_NS + "permission")
                deeplinks: List[str] = []
                is_launcher = False
                parsed_filters: List[IntentFilter] = []
                for f in filters:
                    actions = [a.get(ANDROID_NS + "name") for a in f.findall("action")]
                    cats = [c.get(ANDROID_NS + "name") for c in f.findall("category")]
                    if "android.intent.action.MAIN" in actions:
                        is_launcher = True
                    # Android merges all <data> attributes in one filter: the URI
                    # must match the union of schemes AND the union of hosts. A
                    # filter with scheme=https and no host matches ANY https URL;
                    # one that also lists hosts matches only those hosts.
                    schemes, hosts, paths = set(), set(), set()
                    for d in f.findall("data"):
                        for key, bucket in (
                            ("scheme", schemes),
                            ("host", hosts),
                            ("path", paths),
                            ("pathPrefix", paths),
                            ("pathPattern", paths),
                        ):
                            v = d.get(ANDROID_NS + key)
                            if v:
                                bucket.add(v)
                    if not (schemes or hosts):
                        continue
                    # no host constraint -> wildcard host
                    eff_hosts = hosts or {"*"}
                    bindings = []
                    for scheme in (schemes or {"*"}):
                        for host in eff_hosts:
                            if paths:
                                for path in paths:
                                    bindings.append((scheme, host, path))
                            else:
                                bindings.append((scheme, host, None))
                    parsed_filters.append(
                        IntentFilter(
                            actions=actions,
                            bindings=bindings,
                            is_browsable="android.intent.category.BROWSABLE" in cats,
                        )
                    )
                    for scheme, host, path in bindings:
                        deeplinks.append(f"{scheme or '*'}://{host or '*'}{path or ''}")
                components.append(
                    Component(tag, name, exported, perm, deeplinks, is_launcher, parsed_filters)
                )
    return {"info": info, "components": components}


def parse_nsc(nsc_attr: Optional[str], res_xml: Path) -> dict:
    """Parse the network security config referenced from the manifest.

    apktool keeps the symbolic ``@xml/<name>`` reference, so resolve it to the
    matching file under res/xml and read the base-config cleartext policy plus
    any pinned domains. Also captures a @raw trust anchor if one is used.
    """
    facts: Dict[str, object] = {}
    if not nsc_attr:
        return facts
    stem = nsc_attr.split("/")[-1]
    candidates = sorted(res_xml.glob(f"{stem}*.xml"))
    if not candidates:
        facts["nsc_file"] = None
        facts["nsc_cleartext_permitted"] = None
        return facts
    cand = candidates[0]
    try:
        root = ET.parse(cand).getroot()
    except ET.ParseError:
        return facts
    base = root.find("base-config")
    facts["nsc_file"] = cand.name
    facts["nsc_cleartext_permitted"] = None
    if base is not None:
        facts["nsc_cleartext_permitted"] = base.get("cleartextTrafficPermitted") == "true"
        facts["nsc_base_trust_anchors"] = [
            (c.get("src") or "") for c in base.iter("certificates")
        ]
    domains = []
    pinned_apples = []
    for dc in root.iter("domain-config"):
        for d in dc.iter("domain"):
            name = (d.text or "").strip()
            domains.append(name)
            if name.endswith("apple.com"):
                pinned_apples.append(name)
    facts["nsc_domains"] = domains
    facts["nsc_pinned_apple_domains"] = pinned_apples
    return facts


# --------------------------------------------------------------------------
# smali scanning (literal recovery)
# --------------------------------------------------------------------------
CONST_RE = re.compile(r"^\s*const(?:/\w+)?\s+(v\d+|p\d+),\s*(-?0x[0-9a-fA-F]+|-?\d+)")
CONST_STR_RE = re.compile(r'^\s*const-string(?:/jumbo)?\s+(v\d+|p\d+),\s*"(.*)"\s*$')
METHOD_RE = re.compile(r"^\.method\s+.*?\s+([\w$<>]+)\(")


def _resolve_bool(token: str) -> Optional[bool]:
    try:
        val = int(token, 16) if token.lower().startswith(("0x", "-0x")) else int(token)
    except ValueError:
        return None
    return val == 1


def _nearest_method_start(lines: List[str], idx: int) -> int:
    for j in range(idx, -1, -1):
        if lines[j].startswith(".method"):
            return j
    return 0


def resolve_smali_register(lines: List[str], idx: int, register: str) -> Optional[bool]:
    """Find the last constant written to `register` before line idx, within the
    enclosing method (registers are reused across a method)."""
    start = _nearest_method_start(lines, idx)
    for j in range(idx - 1, start - 1, -1):
        m = CONST_RE.match(lines[j])
        if m and m.group(1) == register:
            return _resolve_bool(m.group(2))
    return None


def _method_body(lines: List[str], header_idx: int) -> List[str]:
    for j in range(header_idx + 1, len(lines)):
        if lines[j].startswith(".end method"):
            return lines[header_idx + 1 : j]
    return lines[header_idx + 1 :]


def smali_override_forwards_all(text: str) -> bool:
    """Detect a WebViewClient URL override that sends *every* http(s) URL back
    into the WebView (return false) without a host allowlist.

    Smali shape differs from Java: the handler usually does not call loadUrl on
    the incoming URL (that is the default when it returns false); it only proves
    the scheme is http(s) and returns a zero register. Match on a scheme check
    plus a `return false`, and require the absence of any host read.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith(".method") or "shouldOverrideUrlLoading" not in line:
            continue
        body = _method_body(lines, i)
        body_text = "\n".join(body)
        if "getHost(" in body_text or "getAuthority(" in body_text:
            continue  # pinned: the handler checks the origin
        has_scheme_check = (
            re.search(r'const-string[A-Za-z_/]*\s+\S+,\s*"https?"', body_text) is not None
            or re.search(r'const-string[A-Za-z_/]*\s+\S+,\s*"mailto"', body_text) is not None
        )
        returns_false = False
        for k, bl in enumerate(body):
            rm = re.match(r"\s*return\s+(v\d+|p\d+)\s*$", bl)
            if not rm:
                continue
            if resolve_smali_register(body, k, rm.group(1)) is False:
                returns_false = True
                break
        if has_scheme_check and returns_false:
            return True
    return False


def smali_client_classes(text: str) -> List[str]:
    """Classes instantiated and handed to setWebViewClient()/setWebChromeClient().

    The client is the *argument* (last register in the invoke), which is either
    the target of a preceding new-instance or an iget of a typed field.
    """
    out: List[str] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "->setWebViewClient(" not in line and "->setWebChromeClient(" not in line:
            continue
        rm = re.search(r"\{([^}]*)\}", line)
        if not rm:
            continue
        regs = [r.strip() for r in rm.group(1).split(",")]
        if len(regs) < 2:
            continue
        reg = regs[-1]  # the WebViewClient argument
        for j in range(i, max(-1, i - 30), -1):
            nm = re.search(rf"new-instance\s+{reg},\s+L([\w/$]+);", lines[j])
            if nm:
                out.append(nm.group(1).replace("/", "."))
                break
            ig = re.search(rf"iget-object\s+{reg},\s+\S+,\s+L[\w/$]+;->\w+:L([\w/$]+);", lines[j])
            if ig:
                out.append(ig.group(1).replace("/", "."))
                break
    return out


def scan_smali_file(path: Path, class_name: str) -> List[Hit]:
    hits: List[Hit] = []
    lines = path.read_text(errors="replace").splitlines()
    method = ""
    for i, line in enumerate(lines):
        m = METHOD_RE.match(line)
        if m:
            method = m.group(1)
        if "Landroid/webkit/" not in line:
            continue
        for rule in R.SETTING_RULES:
            if f"->{rule.pattern}(" not in line:
                continue
            literal = None
            if rule.setting:
                rm = re.search(r"\{([^}]*)\}", line)
                args = [a.strip() for a in rm.group(1).split(",")] if rm else []
                # for invoke-virtual the receiver is first and the boolean arg is
                # last; for invoke-static the boolean is the only register, so the
                # trailing register is the setting value in both shapes.
                if args:
                    literal = resolve_smali_register(lines, i, args[-1])
            snip = "\n".join(lines[max(0, i - 2) : i + 2]).strip()
            hits.append(
                Hit(rule.id, rule.severity, rule.title, str(path), i + 1, method,
                    literal, snip, class_name)
            )
    return hits


def scan_smali(smali_roots: Iterable[Path]) -> tuple[List[Hit], Dict[str, HostInfo], List[str]]:
    hits: List[Hit] = []
    hosts: Dict[str, HostInfo] = {}
    urls: List[str] = []
    # pass 1: which classes define an unrestricted URL override
    unrestricted_clients: set = set()
    # pass 2: which class got handed to setWebViewClient()
    client_bindings: List[tuple] = []
    for root in smali_roots:
        for path in root.rglob(f"*{SMALI_EXT}"):
            cls = to_class_name(path, root)
            file_hits = scan_smali_file(path, cls)
            if file_hits:
                hits.extend(file_hits)
                host = hosts.setdefault(cls, HostInfo(cls, "smali"))
                for h in file_hits:
                    rule = next(r for r in R.SETTING_RULES if r.id == h.rule_id)
                    if rule.setting:
                        host.settings[rule.setting] = h.literal
            text = path.read_text(errors="replace")
            if "loadUrl" in text:
                urls.extend(collect_smali_loadurl(path))
            if "shouldOverrideUrlLoading" in text and smali_override_forwards_all(text):
                unrestricted_clients.add(cls)
            if "setWebViewClient" in text:
                client_bindings.append((cls, smali_client_classes(text)))
    for owner, clients in client_bindings:
        if any(c in unrestricted_clients for c in clients):
            hosts.setdefault(owner, HostInfo(owner, "smali")).unrestricted_navigation = True
    return hits, hosts, urls


LOADURL_RE = re.compile(
    r"invoke-\w+\s+\{[^}]*\},\s*Landroid/webkit/WebView;->loadUrl\(Ljava/lang/String;.*"
)


def collect_smali_loadurl(path: Path) -> List[str]:
    out: List[str] = []
    lines = path.read_text(errors="replace").splitlines()
    for i, line in enumerate(lines):
        if not LOADURL_RE.search(line):
            continue
        # look back for a const-string feeding the url register
        for j in range(i - 1, max(-1, i - 12), -1):
            cm = CONST_STR_RE.search(lines[j])
            if cm and ("http" in cm.group(2) or "javascript" in cm.group(2) or "file" in cm.group(2)):
                out.append(cm.group(2)[:300])
                break
    return out


# --------------------------------------------------------------------------
# Java scanning
# --------------------------------------------------------------------------
JSIFACE_RE = re.compile(r"addJavascriptInterface\(\s*([^,]+?)\s*,\s*[\"']([^\"']+)[\"']\s*\)")
SHOULD_OVERRIDE_RE = re.compile(r"shouldOverrideUrlLoading\(WebView[^)]*\)")
EVALJS_RE = re.compile(r"evaluateJavascript\(\s*[\"'](.*?)[\"']", re.S)
LOAD_URL_LIT_RE = re.compile(r"\.loadUrl\(\s*[\"'](.*?)[\"']", re.S)
SSL_PROCEED_RE = re.compile(r"\.proceed\(\)")
SETTING_JAVA_RE = {
    "javascript_enabled": r"setJavaScriptEnabled\(\s*(true|false)",
    "allow_file_access": r"setAllowFileAccess\(\s*(true|false)",
    "allow_file_access_from_file_urls": r"setAllowFileAccessFromFileURLs\(\s*(true|false)",
    "allow_universal_access_from_file_urls": r"setAllowUniversalAccessFromFileURLs\(\s*(true|false)",
    "allow_content_access": r"setAllowContentAccess\(\s*(true|false)",
    "dom_storage_enabled": r"setDomStorageEnabled\(\s*(true|false)",
    "js_can_open_windows_automatically": r"setJavaScriptCanOpenWindowsAutomatically\(\s*(true|false)",
    "support_multiple_windows": r"setSupportMultipleWindows\(\s*(true|false)",
    "web_contents_debugging": r"setWebContentsDebuggingEnabled\(\s*(true|false)",
    "mixed_content_mode": r"setMixedContentMode\(\s*([A-Za-z0-9_.]+)",
}
# Java settings whose `true` value is a hardening regression rather than a
# benign default; False means the app applied the safe value.
JAVA_SECURITY_SETTINGS = {
    "allow_file_access",
    "allow_file_access_from_file_urls",
    "allow_universal_access_from_file_urls",
    "allow_content_access",
    "web_contents_debugging",
}


def scan_java(java_root: Optional[Path]) -> tuple[Dict[str, HostInfo], List[Bridge]]:
    hosts: Dict[str, HostInfo] = {}
    bridges: List[Bridge] = []
    if not java_root or not java_root.exists():
        return hosts, bridges
    for path in java_root.rglob("*.java"):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        cls = to_class_name(path, java_root)
        relevant = (
            "android.webkit.WebView" in text
            or "addJavascriptInterface" in text
            or "shouldOverrideUrlLoading" in text
        )
        if not relevant:
            continue
        host = hosts.setdefault(cls, HostInfo(cls, "java"))
        for setting, pat in SETTING_JAVA_RE.items():
            for m in re.finditer(pat, text):
                val = m.group(1)
                if setting == "mixed_content_mode":
                    host.settings[setting] = val
                else:
                    host.settings[setting] = val == "true"
        for m in JSIFACE_RE.finditer(text):
            obj = m.group(1).strip()
            b = Bridge(m.group(2), cls, text[: m.start()].count("\n") + 1, obj[:80])
            # Resolve the @JavascriptInterface methods reachable from the page.
            b.has_getdata = bool(re.search(r"@JavascriptInterface\b[\s\S]{0,200}?getData\(", text))
            b.methods = sorted(
                {
                    mm.group(1)
                    for mm in re.finditer(
                        r"@JavascriptInterface\s+public\s+(?:final\s+)?[\w<>\[\].]+\s+(\w+)\s*\(",
                        text,
                    )
                }
            )
            bridges.append(b)
            host.bridges.append(b)
        for m in LOAD_URL_LIT_RE.finditer(text):
            u = m.group(1)
            if "http" in u or "javascript:" in u or "file:" in u or "about:" in u:
                host.loaded_urls.append(u[:300])
        for m in EVALJS_RE.finditer(text):
            host.injected_script.append(m.group(1)[:200])
        # A WebViewClient URL override that loads the incoming URL and declines to
        # handle it (returns false) is a general-purpose in-app browser: no host
        # allowlist, no external-browser handoff.
        for m in SHOULD_OVERRIDE_RE.finditer(text):
            body = text[m.start() : m.start() + 600]
            if re.search(r"loadUrl\(\s*\w+\s*\)", body) and "return false" in body:
                host.unrestricted_navigation = True
                break
        if SSL_PROCEED_RE.search(text) and "onReceivedSslError" in text:
            host.ssl_proceed = True
    return hosts, bridges


# --------------------------------------------------------------------------
# native libs
# --------------------------------------------------------------------------
def scan_native(apk_paths: Iterable[Path]) -> List[str]:
    found = set()
    for apk in apk_paths:
        if not apk.exists():
            continue
        try:
            with zipfile.ZipFile(apk) as z:
                for name in z.namelist():
                    if not name.endswith(".so"):
                        continue
                    data = z.read(name)
                    for tok in R.NATIVE_TOKENS:
                        if tok.encode() in data:
                            found.add(name)
                            break
        except zipfile.BadZipFile:
            continue
    return sorted(found)


# --------------------------------------------------------------------------
# correlation + findings
# --------------------------------------------------------------------------
def merge_hosts(a: Dict[str, HostInfo], b: Dict[str, HostInfo]) -> Dict[str, HostInfo]:
    merged = dict(a)
    for k, v in b.items():
        if k in merged:
            m = merged[k]
            m.settings.update(v.settings)
            m.bridges.extend(v.bridges)
            m.loaded_urls.extend(v.loaded_urls)
            m.injected_script.extend(v.injected_script)
            m.unrestricted_navigation |= v.unrestricted_navigation
            m.ssl_proceed |= v.ssl_proceed
        else:
            merged[k] = v
    return merged


def build_findings(report: Report) -> List[dict]:
    findings: List[dict] = []

    def add(sev, rule_id, title, evidence, detail, location=""):
        findings.append(
            {
                "severity": sev,
                "rule": rule_id,
                "title": title,
                "location": location,
                "evidence": evidence,
                "detail": detail,
            }
        )

    # 1. per-host correlated findings
    for host in report.hosts:
        s = host.settings
        js = s.get("javascript_enabled") is True
        bridge = bool(host.bridges)
        file_access = s.get("allow_file_access") is True
        file_urls = s.get("allow_file_access_from_file_urls") is True
        universal = s.get("allow_universal_access_from_file_urls") is True
        debug = s.get("web_contents_debugging") is True

        if universal and js:
            add(
                "CRITICAL",
                "CORR-001",
                f"{host.name}: file:// pages can reach any remote origin with JS on",
                "setAllowUniversalAccessFromFileURLs(true) + setJavaScriptEnabled(true)",
                "A local file rendered in this WebView can exfiltrate itself to any "
                "attacker-controlled host. This is the worst-case WebView configuration.",
                host.name,
            )
        if (file_access or file_urls) and js and bridge:
            add(
                "HIGH",
                "CORR-002",
                f"{host.name}: local file access + JS bridge",
                "file access enabled + addJavascriptInterface + JS enabled",
                "Page script can read local files and drive an exposed native bridge, "
                "so a file:// or navigated-to page escalates into native capability.",
                host.name,
            )
        if js and bridge and host.unrestricted_navigation:
            bridge_desc = ", ".join(
                b.name + ("(getData)" if b.has_getdata else "") for b in host.bridges
            )
            add(
                "HIGH",
                "CORR-003",
                f"{host.name}: JS bridge reachable from unrestricted navigation",
                "addJavascriptInterface + shouldOverrideUrlLoading forwards all URLs",
                "Because navigation is not allowlisted, the injected bridge is reachable "
                "by any origin the WebView is steered to. Bridge: " + bridge_desc,
                host.name,
            )

        # A JS bridge loaded on a remote, non-app origin: page script the app does
        # not control can call into native code.
        remote_urls = [u for u in host.loaded_urls if u.startswith("http")]
        if bridge and remote_urls:
            bridge_desc = ", ".join(
                f"{b.name}->[{', '.join(b.methods) or 'unknown methods'}]"
                for b in host.bridges
            )
            add(
                "HIGH",
                "CORR-007",
                f"{host.name}: native JS bridge exposed to a remote origin",
                "loaded URL " + remote_urls[0] + "; bridges " + bridge_desc,
                "The WebView loads first-party remote content and injects a native "
                "object into it. Any script that ends up on that origin (compromised "
                "CDN, injected third-party tag, or a navigation that is not pinned) "
                "can invoke those methods.",
                host.name,
            )
        if debug:
            add(
                "HIGH",
                "CORR-004",
                f"{host.name}: remote WebView debugging enabled",
                "WebView.setWebContentsDebuggingEnabled(true)",
                "Any WebView in the process is attachable via chrome://inspect. On a "
                "production build this is an instrumentation ramp for all in-app web content.",
                host.name,
            )
        if host.unrestricted_navigation:
            add(
                "MEDIUM",
                "CORR-005",
                f"{host.name}: no host allowlist on navigation",
                "; ".join(host.loaded_urls[:4]) or "shouldOverrideUrlLoading forwards incoming URL",
                "The WebViewClient forwards every tapped URL back into the WebView, so a "
                "trusted entry page becomes a general-purpose in-app browser.",
                host.name,
            )
        if host.ssl_proceed:
            add("HIGH", "CORR-006", f"{host.name}: proceeds past TLS errors",
                "onReceivedSslError -> handler.proceed()",
                "Invalid certificates are accepted; enables man-in-the-middle.",
                host.name)

    # 2. manifest-level findings
    info = report.facts
    if info.get("nsc_cleartext_permitted") is True or info.get("uses_cleartext") == "true":
        add(
            "MEDIUM",
            "CORR-010",
            "Cleartext HTTP permitted globally",
            f"networkSecurityConfig={info.get('nsc_file')} cleartextTrafficPermitted=true",
            "The base-config permits http:// for every host, so any WebView navigation "
            "or API call can be downgraded to cleartext and modified on-path.",
            "AndroidManifest.xml",
        )
    if info.get("debuggable") == "true":
        add("HIGH", "CORR-011", "Application is debuggable",
            "android:debuggable=true", "Build is debuggable; ships with debug affordances.",
            "AndroidManifest.xml")

    # 3. exported WebView-hosting components
    exported_names = {c.name for c in report.components if c.exported}
    for host in report.hosts:
        if host.name in exported_names and (host.loaded_urls or host.bridges):
            add(
                "MEDIUM",
                "CORR-020",
                f"Exported component hosts a WebView: {host.name}",
                f"exported=true; urls={host.loaded_urls[:3]}; bridges={[b.name for b in host.bridges]}",
                "An exported entry point that displays web content is directly drivable "
                "by another app on the device via an Intent.",
                host.name,
            )

    # 4. exported, browsable deep links that accept arbitrary web URLs.
    # A filter is only a finding if it declares http/https AND leaves the host
    # unpinned (host '*') — a filter that lists specific hosts is correctly
    # scoped and must not be reported.
    for c in report.components:
        if not c.exported:
            continue
        for flt in c.filters:
            if not flt.is_browsable:
                continue
            for scheme, host, path in flt.bindings:
                if scheme in ("http", "https") and host in ("*", None):
                    add(
                        "MEDIUM",
                        "CORR-021",
                        f"Exported component accepts arbitrary http(s) URLs: {c.name}",
                        f"{scheme}://{'*' if host in ('*', None) else host}{path or ''}",
                        "An exported browsable intent-filter declares an http/https "
                        "scheme without pinning a host, so any web URL can be handed "
                        "to this component. Combined with the in-app browser surface "
                        "above, an attacker-controlled link can be routed into the "
                        "app's own navigation stack instead of being confined to a "
                        "browser.",
                        c.name,
                    )
                    break
    # 5. exported deep-link handlers that trust the URL path but not the host.
    # The intent-filter's host pinning only applies to implicit intents; an
    # explicit intent from another app reaches the component anyway.
    for h in getattr(report, "path_only_handlers", []) or []:
        add(
            "MEDIUM",
            "CORR-022",
            f"Deep-link handler validates path but not host: {h['name']}",
            f"{h['path_reads']} path reads, no getHost()/getAuthority() check",
            "This exported, browsable component routes incoming deep links purely on "
            "Uri.getPath() and never verifies the host. Its intent-filter host list "
            "does not help: any app can send an explicit intent with an arbitrary URL "
            "and a matching path (e.g. an OAuth-confirm or payment route), bypassing "
            "the intended origin. Treat the path as attacker-controlled.",
            h["name"],
        )
    return findings


def scan(target: Path, work: Path, skip_decompile: bool = False) -> Report:
    """Full pipeline: unpack, decompile, then analyze."""
    report = Report(target=str(target))
    work.parent.mkdir(parents=True, exist_ok=True)
    apk_dir = work.parent / "apk"
    raw = unpack(target, apk_dir)

    paths = {"work": work, "manifest": work / "AndroidManifest.xml",
             "java": work / "java", "smali": work / "smali"}
    if not skip_decompile:
        paths = decompile(apk_dir, work, raw)
    return analyze(paths["work"], raw, str(target), apk_dir, report)


def _smali_file_for(class_name: str, smali_roots: Iterable[Path]) -> Optional[Path]:
    rel = class_name.replace(".", "/") + ".smali"
    for root in smali_roots:
        p = root / rel
        if p.exists():
            return p
    return None


def _dispatches_on_path_only(class_name: str, smali_roots: Iterable[Path]) -> Optional[int]:
    """True when an exported deep-link handler pivots on the URL path but never
    checks the host.

    Intent-filters pin hosts, but that only constrains *implicit* intents. An
    explicit intent (ComponentName set) reaches the component regardless of its
    filters, and this handler drives its routing entirely off Uri.getPath(),
    returning no getHost()/getAuthority() check. So any app on the device can
    hand it an arbitrary URL whose path matches a privileged route.
    """
    p = _smali_file_for(class_name, smali_roots)
    if p is None:
        return None
    try:
        lines = p.read_text(errors="ignore").splitlines()
    except OSError:
        return None
    path_like = 0
    host_check = 0
    for i, line in enumerate(lines):
        if "->getPath(" in line or "->getPathSegments(" in line or "->getLastPathSegment(" in line:
            path_like += 1
        if "->getHost(" in line or "->getAuthority(" in line or "->getScheme(" in line:
            host_check += 1
    if path_like >= 3 and host_check == 0:
        return path_like
    return None


def analyze(
    work: Path,
    raw_apk: Optional[Path],
    target_label: str,
    apk_dir: Optional[Path] = None,
    report: Optional[Report] = None,
) -> Report:
    """Analyze an already-decompiled work directory.

    `work` must contain AndroidManifest.xml plus smali*/ and/or java/ trees
    (symlinks are fine). This is the seam used by the test-suite, which builds
    a synthetic work dir instead of shipping an APK.
    """
    report = report or Report(target=target_label)
    apk_dir = apk_dir or (work.parent / "apk")
    manifest = work / "AndroidManifest.xml"
    if not manifest.exists():
        report.errors.append("decompilation failed: no AndroidManifest.xml")
        return report

    man = parse_manifest(manifest, apk=raw_apk)
    report.package = man["info"]["package"]
    report.version_name = man["info"]["version_name"]
    report.version_code = man["info"]["version_code"]
    report.min_sdk = man["info"]["min_sdk"]
    report.target_sdk = man["info"]["target_sdk"]
    report.components = man["components"]

    facts = {k: v for k, v in man["info"].items()}
    facts.update(parse_nsc(man["info"]["nsc"], work / "res" / "xml"))
    report.facts = facts

    smali_roots = sorted(p for p in work.iterdir() if p.is_dir() and p.name.startswith("smali"))
    smali_hits, smali_hosts, urls = scan_smali(smali_roots)
    java_hosts, bridges = scan_java(work / "java")
    hosts = merge_hosts(smali_hosts, java_hosts)

    # loadUrl literals found from smali go to their class
    for smali_root in smali_roots:
        for path in smali_root.rglob("*.smali"):
            cls = to_class_name(path, smali_root)
            if cls in hosts:
                hosts[cls].loaded_urls.extend(collect_smali_loadurl(path))

    # mark exported components
    exported_names = {c.name for c in report.components if c.exported}
    for h in hosts.values():
        h.is_exported_component = h.name in exported_names
        h.loaded_urls = sorted(set(h.loaded_urls))
        h.injected_script = sorted(set(h.injected_script))

    report.hosts = sorted(hosts.values(), key=lambda h: len(h.settings), reverse=True)

    # exported deep-link handlers that route on path only (no host check)
    for c in report.components:
        if not c.exported or not c.filters:
            continue
        if not any(f.is_browsable for f in c.filters):
            continue
        n = _dispatches_on_path_only(c.name, smali_roots)
        if n:
            report.path_only_handlers.append({"name": c.name, "path_reads": n})

    # raw setting hits as findings
    findings: List[dict] = []
    for h in smali_hits:
        rule = next(r for r in R.SETTING_RULES if r.id == h.rule_id)
        if rule.setting and h.literal is False:
            continue  # hardening applied, not a finding
        findings.append(
            {
                "severity": rule.severity,
                "rule": rule.id,
                "title": f"{rule.title}"
                + (f" ({h.literal})" if h.literal is not None else " (argument unresolved)"),
                "location": f"{h.file}:{h.line} ({h.method})",
                "evidence": h.snippet,
                "detail": rule.description,
            }
        )

    # Java-only surface. jadx recovers constructs smali scanning can miss
    # (obfuscated wrappers, nested lambdas, third-party code), so surface settings
    # and JS bridges that no smali hit already reported.
    covered = set()
    for h in smali_hits:
        covered.add((h.class_name, h.rule_id))
    for host in report.hosts:
        for setting, val in host.settings.items():
            if setting == "mixed_content_mode":
                if str(val) in ("0", "ALWAYS_ALLOW"):
                    findings.append(
                        {
                            "severity": "HIGH",
                            "rule": "WV-SET-009",
                            "title": f"{host.name}: mixed content mode ALWAYS_ALLOW",
                            "location": host.name,
                            "evidence": f"setMixedContentMode({val})",
                            "detail": next(
                                r.description for r in R.SETTING_RULES if r.id == "WV-SET-009"
                            ),
                        }
                    )
                continue
            rule = next((r for r in R.SETTING_RULES if r.setting == setting), None)
            if rule is None or val is not True:
                continue
            if (host.name, rule.id) in covered:
                continue
            findings.append(
                {
                    "severity": rule.severity,
                    "rule": rule.id,
                    "title": f"{rule.title} ({val})",
                    "location": host.name,
                    "evidence": f"{setting.split('_')[-1]} -> {val}",
                    "detail": rule.description,
                }
            )
        for b in host.bridges:
            findings.append(
                {
                    "severity": "INFO",
                    "rule": "WV-SINK-004",
                    "title": f"JS bridge `{b.name}` exposed by {host.name}",
                    "location": f"{host.name}:{b.line}",
                    "evidence": f"addJavascriptInterface({b.exposed_object}, \"{b.name}\")"
                    + (f"  methods={b.methods}" if b.methods else ""),
                    "detail": next(
                        r.description for r in R.SINK_RULES if r.id == "WV-SINK-004"
                    ),
                }
            )
    report.findings = findings

    report.native_webview_libs = scan_native(sorted(apk_dir.glob("*.apk")))

    # correlated findings appended
    report.findings.extend(build_findings(report))
    report.findings = dedupe_findings(report.findings)
    report.findings.sort(key=lambda f: R.severity_rank(f["severity"]))
    return report


def dedupe_findings(findings: List[dict]) -> List[dict]:
    """Collapse findings that describe the same issue at the same location.

    Anchored raw setting hits live at file:line, while correlated findings live
    at a class. Two deep-link filters on the same component produce the same
    finding, so key on (rule, location, title) and keep the highest severity.
    """
    seen: Dict[tuple, dict] = {}
    for f in findings:
        key = (f["rule"], f.get("location", ""), f["title"])
        prev = seen.get(key)
        if prev is None or R.severity_rank(f["severity"]) < R.severity_rank(prev["severity"]):
            seen[key] = f
    return list(seen.values())
