plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.taptap.ng"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.taptap.ng"
        minSdk = 24
        targetSdk = 37
        versionCode = 9
        versionName = "1.0.8"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Release signing (v1.0.2): a STABLE keystore stored as GitHub
    // Actions secrets (KEYSTORE_BASE64 / KEYSTORE_PASSWORD / KEY_ALIAS /
    // KEY_PASSWORD, repo Taptap56/taptapng) — v1.0.0/v1.0.1 were signed
    // by the debug keystore Gradle generates fresh on every CI runner,
    // so every build had a different signature and v1.0.1 could not
    // overwrite v1.0.0 on the phone ("tidak konsisten dengan tanda
    // tangan APK yang diinstal", 2026-11-21). The keystore file is
    // decoded by the workflow into $RUNNER_TEMP and passed here via
    // environment variables; the keystore itself is NEVER committed.
    // Without the env vars the build falls back to the debug keystore
    // (local builds still work) — the workflow fails fast when the
    // secret is absent, so a CI build can never silently ship a
    // debug-signed APK again. Keystore: ~/workspace/build/
    // taptapng-release.keystore (alias taptapng, RSA 2048, valid to
    // 2054-04-08; password lives ONLY in the GitHub secrets).
    val releaseKeystorePath = System.getenv("TAPTAPNG_KEYSTORE_PATH")
    val releaseKeystorePassword = System.getenv("TAPTAPNG_KEYSTORE_PASSWORD")
    val releaseKeyAlias = System.getenv("TAPTAPNG_KEY_ALIAS")
    val releaseKeyPassword = System.getenv("TAPTAPNG_KEY_PASSWORD")
    signingConfigs {
        if (releaseKeystorePath != null && File(releaseKeystorePath).exists() &&
            !releaseKeystorePassword.isNullOrBlank() &&
            !releaseKeyAlias.isNullOrBlank() &&
            !releaseKeyPassword.isNullOrBlank()
        ) {
            create("release") {
                storeFile = file(releaseKeystorePath)
                storePassword = releaseKeystorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            // Release + R8: the APK must stay small (XVEON-style).
            // Signed with the stable release keystore when the CI
            // secrets are present (see above); debug keystore only
            // as a local fallback — never for a shipped build.
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.findByName("release")
                ?: signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    buildFeatures {
        buildConfig = true
    }

    testOptions {
        unitTests.all {
            it.useJUnitPlatform()
            // v1.0.15: show test stdout in the CI log, so the
            // throughput tests' printed MB/s (grep THROUGHPUT) is
            // readable from `gh run view --log` — Gradle otherwise
            // captures println into the XML reports only.
            it.testLogging { showStandardStreams = true }
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.material)
    implementation(libs.androidx.recyclerview)
    implementation(libs.androidx.preference.ktx)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.lifecycle.runtime.ktx)

    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.gson)

    // SSH (in-app, pure Java) — proof-of-concept protocol for Phase 1.
    // Same approach as XVEON: JSch, no native core.
    implementation(libs.jsch)

    // Onering (M4, v1.0.23): Bouncy Castle TLS client (see libs.versions.toml
    // for why BC is the only way to send the custom 0xff00 extension).
    implementation(libs.bctls)

    // QR code scan/generate: ZXing core only (no CameraX — CameraX
    // would add megabytes; the scanner uses the framework Camera1 API).
    implementation(libs.zxing.core)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    // In-process SSH server for the end-to-end SSH unit test.
    testImplementation(libs.sshd.core)
}
