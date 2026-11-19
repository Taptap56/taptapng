# TaptapX agent guide

## Scope

New Android app (Kotlin, Views + Material Components, VpnService).
UI mirrors v2rayNG 2.3.15 exactly (same layout/screens/components/
theme); only the content differs (in-app protocols: SSH, later
VMess/VLESS/Trojan/SS + SlowDNS/DNSTT + Onering + Pemicu). No
xray-core is bundled. v1.0.1 rebuilt the UI from Compose to Views
(XML layouts + RecyclerView + AppCompat/Material, no Compose at
all) because Views is what keeps the APK small (XVEON-style).

## Rules

- Stage task paths explicitly. Never `git add .`, `git add -A`, or
  `git commit -a`.
- Kotlin/Java production code: add/update a JVM test that asserts the
  changed behavior, then run `:app:testDebugUnitTest` and
  `:app:compileDebugKotlin` (in CI; Gradle is blocked in this VM).
- Resources, manifest, Gradle, or dependencies: run
  `:app:assembleRelease` (in CI). Release is R8-minified and signed
  with the debug keystore; keep the proguard rules for Gson/JSch/
  ZXing/VpnService up to date when the model or engines change.
- QR scan uses the framework Camera1 API + ZXing core (no CameraX —
  size). Do not add CameraX without checking the APK size impact.
- Never log credentials, private keys, or full proxy URLs.
- Never rename/delete a persisted field (ProfileItem / profiles.json)
  without a backward-compatible migration + a regression test reading
  the preceding format.
- Report any required check that did not run under `Not run`, with its
  command and reason. A compile or assembled APK does not verify
  runtime behavior.
- Do not modify existing projects/APKs (TaptapNG, v2rayNG, TB/TC).
