package com.taptap.ng

import android.app.Application
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.util.Log
import com.google.android.material.color.DynamicColors
import com.taptap.ng.core.DialLog
import com.taptap.ng.core.proto.FragmentConfig
import com.taptap.ng.core.proto.Transport
import com.taptap.ng.data.SettingsStore
import java.util.Locale

class TaptapNGApp : Application() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(wrapLocale(base))
    }

    override fun onCreate() {
        super.onCreate()
        AppContext.init(this)
        // v1.0.6, fix E: dial stages go to logcat (tag TaptapNG-Dial)
        // as well as to the in-app ring buffer.
        DialLog.logcatSink = { tag, msg -> Log.d(tag, msg) }
        val settings = SettingsStore(this)
        // v1.0.5, group A: core log level gates DialLog verbosity.
        DialLog.applyLevel(settings.coreLogLevel)
        // v1.0.5 (Fragment): the dial reads the live settings on
        // every Transport.open, so toggling Fragment applies
        // without restarting the app or the VPN.
        Transport.fragmentConfigProvider = {
            val s = SettingsStore(this)
            if (s.fragmentEnabled) {
                FragmentConfig.fromSettings(
                    s.fragmentPackets,
                    s.fragmentLength,
                    s.fragmentInterval,
                    s.fragmentMaxSplit,
                )
            } else {
                null
            }
        }
        settings.applyThemeMode()
        if (settings.dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            DynamicColors.applyToActivitiesIfAvailable(this)
        }
    }

    companion object {
        /** Wrap a context with the stored language ("auto" = system). */
        fun wrapLocale(context: Context): Context {
            val lang = context.getSharedPreferences(
                SettingsStore.PREFS_NAME, Context.MODE_PRIVATE
            ).getString(SettingsStore.KEY_LANGUAGE, "auto") ?: "auto"
            if (lang == "auto") return context
            val locale = Locale(lang)
            Locale.setDefault(locale)
            val config = Configuration(context.resources.configuration)
            config.setLocale(locale)
            return context.createConfigurationContext(config)
        }
    }
}

/** Minimal application-context holder (Phase 1; no MMKV yet). */
object AppContext {
    lateinit var app: Application
        private set

    fun init(application: Application) {
        app = application
    }
}
