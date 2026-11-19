package com.taptap.x

import android.app.Application
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.util.Log
import com.google.android.material.color.DynamicColors
import com.taptap.x.core.DialLog
import com.taptap.x.data.SettingsStore
import java.util.Locale

class TaptapXApp : Application() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(wrapLocale(base))
    }

    override fun onCreate() {
        super.onCreate()
        AppContext.init(this)
        // v1.0.6, fix E: dial stages go to logcat (tag TaptapX-Dial)
        // as well as to the in-app ring buffer.
        DialLog.logcatSink = { tag, msg -> Log.d(tag, msg) }
        val settings = SettingsStore(this)
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
