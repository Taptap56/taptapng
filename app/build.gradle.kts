plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.taptap.x"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.taptap.x"
        minSdk = 24
        targetSdk = 37
        versionCode = 33
        versionName = "1.0.32"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            // Release + R8: the APK must stay small (XVEON-style).
            // Signed with the debug keystore so the CI-built APK is
            // installable on the phone (no release keystore exists yet).
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.getByName("debug")
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
