# TaptapX ProGuard/R8 rules (release build).
# R8 must not break: Gson (ProfileItem/ProfileStore), JSch, ZXing,
# the VpnService, or the preference/settings keys.

-keepattributes Signature, *Annotation*

# Gson: the profile model is serialized by field name; keep it whole,
# plus the TypeToken subclass used by ProfileStore.load().
-keep class com.taptap.x.data.ProfileItem { *; }
-keep class com.taptap.x.data.ConfigType { *; }
-keepclassmembers enum com.taptap.x.data.ConfigType { *; }
-keep class com.taptap.x.data.ProfileStore { *; }
-keep class * extends com.google.gson.reflect.TypeToken
-keep class com.google.gson.reflect.TypeToken { *; }

# JSch (mwiede fork, package com.jcraft.jsch): algorithms are loaded
# by reflection; keep the whole package.
-keep class com.jcraft.jsch.** { *; }
-keep class com.github.mwiede.jsch.** { *; }

# JSch optional dependencies (not bundled, not needed on Android —
# JSch falls back to its own logger/crypto when they are absent).
# Without these, R8 fails on "missing class" for: SLF4J, Log4j2,
# BouncyCastle (optional ciphers), JNA (Windows Pageant agent),
# JGSS (GSSAPI auth), junixsocket (AF_UNIX agent forwarding).
-dontwarn org.slf4j.**
-dontwarn org.apache.logging.log4j.**
-dontwarn org.bouncycastle.**
-dontwarn com.sun.jna.**
-dontwarn org.ietf.jgss.**
-dontwarn org.newsclub.net.unix.**

# ZXing: readers/writers are instantiated by name.
-keep class com.google.zxing.** { *; }

# Android entry points referenced from the manifest.
-keep class com.taptap.x.TaptapXApp { *; }
-keep class com.taptap.x.service.TaptapVpnService { *; }
-keep class com.taptap.x.service.BootReceiver { *; }
