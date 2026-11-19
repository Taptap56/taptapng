package com.taptap.x

import android.app.Application

class TaptapXApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AppContext.init(this)
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
