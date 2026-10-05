# AGENTS.md

Repository-specific context for agents working on `webbrowservulntest`.

## What this repo is

A static Android WebView attack-surface scanner (`webrecon/`) plus a worked
analysis of Apple Music. It is defensive security tooling: it reads APKs and
writes reports, never exploits.

## Environment

- No `/dev/kvm` -> **no Android emulator**. Do not try to boot one; it hangs or
  fails. All analysis is static.
- Toolchain is installed by `./install_sdk.sh`: JDK 21, `apktool`, `aapt`,
  `jadx` (in `/opt/jadx`), `androguard` (pip).
- Network egress works; APKPure (`d.apkpure.com`) is the working APK mirror
  (Aptoide/ApkCombo are unreliable for this app).

## Build / test

```bash
python3 -m unittest discover -s tests -v     # no APK needed, uses a synthetic fixture
```

## Analyzing an APK

```bash
python3 -m webrecon.cli samples/apple_music.xapk -o analysis/webrecon
```

Layout of the output/working directory:

- `<out>/work/` - decompiled tree (`AndroidManifest.xml`, `smali*/`, `java/`).
  These can be symlinks; `analyze()` follows them.
- `<out>/apk/`   - extracted base + split APKs.
- `<out>/report.{md,json}` - results.

To reuse a decompile across runs, symlink `smali*`, `java`, `res` and
`AndroidManifest.xml` into `<out>/work` and pass `--skip-decompile`.

## Code layout

- `webrecon/rules.py` - all detection rules (severity, MASVS/MASTG mapping).
  Add new detections here.
- `webrecon/scanner.py` - pipeline: unpack -> decompile -> manifest -> smali ->
  java -> correlate -> findings. `analyze()` is the testable seam.
- `webrecon/report.py` - Markdown renderer.
- `webrecon/cli.py` - argument parsing.

## Gotchas

- This runtime restarts under memory pressure, and a restart wipes `/usr` and
  `/tmp` but preserves `/workspace`. Install the toolchain into
  `/workspace/toolchain` (`jdk/`, `jadx/`, `apktool.jar`, `bin/apktool`,
  `bin/jadx`, `venv/`) rather than relying on `install_sdk.sh`, then run with
  `PATH=/workspace/toolchain/bin:$PATH` and
  `/workspace/toolchain/venv/bin/python`. `/workspace/run_one.sh <name> <file>`
  does this for one app.
- Run **one** app per `webrecon` invocation in the background and poll. Large
  XAPKs (BAND, 225 MB) OOM-killed the container twice when run concurrently;
  `du -sh` on the venv/analysis sizes before adding parallelism.
- `xapk` is a misnomer for some mirrors' plain APKs and vice versa. Confirm with
  `zipfile`/`unzip -l` before scanning: a `.xapk` with a top-level
  `AndroidManifest.xml` is really an APK and must be renamed (`webrecon` reports
  "no .apk inside" otherwise).
- `apktool`'s decoded `AndroidManifest.xml` **drops versionCode/versionName and
  uses-sdk**. `parse_manifest()` merges `androguard`'s binary-manifest decode for
  those fields and keeps apktool for the component tree and symbolic
  `@xml/...` refs. Do not "simplify" this to one source.
- smali literal recovery walks registers within the enclosing `.method`. For
  `invoke-static {v0}` the boolean is the only register; for `invoke-virtual
  {p0, v1}` it is the last register. Both shapes use the *last* register.
- Findings are de-duplicated on `(rule, location, title)`; raw setting hits are
  anchored at `file:line`, correlated findings at a class name.
- A `false` literal for a security setting (`setAllowFileAccess(false)`, etc.) is
  correct hardening and must NOT be reported as a finding.

## Style

- Python 3, stdlib + androguard only. Keep imports at the top of modules.
- Prefer clear dataclasses over dicts for report structures.
- Comments explain non-obvious invariants only; do not narrate the code.
