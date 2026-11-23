# TaptapNG ProGuard/R8 rules (release build).
# R8 must not break: Gson (ProfileItem/ProfileStore), JSch, ZXing,
# the VpnService, or the preference/settings keys.

-keepattributes Signature, *Annotation*

# Gson: the profile model is serialized by field name; keep it whole,
# plus the TypeToken subclass used by ProfileStore.load().
-keep class com.taptap.ng.data.ProfileItem { *; }
-keep class com.taptap.ng.data.ConfigType { *; }
-keepclassmembers enum com.taptap.ng.data.ConfigType { *; }
-keep class com.taptap.ng.data.ProfileStore { *; }
# v1.0.18 (START GAGAL ClassCastException, M7): the groups model
# needs the same treatment. Without these keeps R8 strips the
# generic Signature from GroupsConfig's list fields, so Gson reads
# every group as a LinkedTreeMap and the first typed access
# (GroupsStore.pruneMissingProfiles, outside load()'s runCatching)
# throws "LinkedTreeMap cannot be cast to ProxyGroup" on every
# start after the first (groups.json only exists from start #2).
# -keepattributes Signature above only helps classes that are kept.
-keep class com.taptap.ng.data.GroupsConfig { *; }
-keep class com.taptap.ng.data.GroupsStore { *; }
-keep class com.taptap.ng.core.ProxyGroup { *; }
-keep class com.taptap.ng.core.RouteRule { *; }
-keep class com.taptap.ng.core.ProxyGroupType { *; }
-keep class com.taptap.ng.core.RouteRuleType { *; }
-keepclassmembers enum com.taptap.ng.core.ProxyGroupType { *; }
-keepclassmembers enum com.taptap.ng.core.RouteRuleType { *; }
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
-keep class com.taptap.ng.TaptapNGApp { *; }
-keep class com.taptap.ng.service.TaptapVpnService { *; }
-keep class com.taptap.ng.service.BootReceiver { *; }
