package com.taptap.x.ui.settings

import android.content.Context
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.ListPreference
import androidx.preference.PreferenceFragmentCompat
import com.taptap.x.R
import com.taptap.x.TaptapXApp
import com.taptap.x.data.SettingsStore

/**
 * Settings screen with Views (PreferenceFragmentCompat), mirroring
 * v2rayNG's SettingsActivity groups that apply to TaptapX: UI, VPN,
 * local proxy, DNS, advanced. Theme + language apply immediately.
 */
class SettingsActivity : AppCompatActivity() {

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(TaptapXApp.wrapLocale(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.settings_container, SettingsFragment())
                .commit()
        }
    }

    class SettingsFragment : PreferenceFragmentCompat() {

        override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
            preferenceManager.sharedPreferencesName = SettingsStore.PREFS_NAME
            setPreferencesFromResource(R.xml.preferences, rootKey)

            findPreference<ListPreference>(SettingsStore.KEY_UI_MODE_NIGHT)
                ?.setOnPreferenceChangeListener { _, newValue ->
                    val store = SettingsStore(requireContext())
                    store.uiModeNight = newValue as String
                    store.applyThemeMode()
                    requireActivity().recreate()
                    true
                }

            findPreference<ListPreference>(SettingsStore.KEY_LANGUAGE)
                ?.setOnPreferenceChangeListener { _, newValue ->
                    SettingsStore(requireContext()).language = newValue as String
                    requireActivity().recreate()
                    true
                }
        }
    }
}
