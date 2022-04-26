/*
 * Copyright © 2017-2021 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.MenuItem
import androidx.fragment.app.commit
import androidx.lifecycle.lifecycleScope
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.wireguard.android.HWApplication
import com.wireguard.android.R
import com.wireguard.android.backend.WgQuickBackend
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.android.util.AdminKnobs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Interface for changing application-global persistent settings.
 */
class SettingsActivity : ThemeChangeAwareActivity() {
    private val TAG = "WireGuard/SettingsActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (supportFragmentManager.findFragmentById(android.R.id.content) == null) {
            supportFragmentManager.commit {
                add(android.R.id.content, SettingsFragment())
            }
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    class SettingsFragment : PreferenceFragmentCompat() {
        override fun onCreatePreferences(savedInstanceState: Bundle?, key: String?) {
            preferenceManager.preferenceDataStore = PreferencesPreferenceDataStore(lifecycleScope, HWApplication.getPreferencesDataStore())
            addPreferencesFromResource(R.xml.preferences)
            //preferenceScreen.initialExpandedChildrenCount = 4
            preferenceScreen.initialExpandedChildrenCount = 6
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val darkTheme = preferenceManager.findPreference<Preference>("dark_theme")
                darkTheme?.parent?.removePreference(darkTheme)
                --preferenceScreen.initialExpandedChildrenCount
            }
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                val remoteApps = preferenceManager.findPreference<Preference>("allow_remote_control_intents")
                remoteApps?.parent?.removePreference(remoteApps)
            }
            if (AdminKnobs.disableConfigExport) {
                val zipExporter = preferenceManager.findPreference<Preference>("zip_exporter")
                zipExporter?.parent?.removePreference(zipExporter)
            }
            val wgQuickOnlyPrefs = arrayOf(
                    preferenceManager.findPreference("tools_installer"),
                    preferenceManager.findPreference("restore_on_boot"),
                    preferenceManager.findPreference<Preference>("multiple_tunnels")
            ).filterNotNull()
            wgQuickOnlyPrefs.forEach { it.isVisible = false }
            lifecycleScope.launch {
                if (HWApplication.getBackend() is WgQuickBackend) {
                    ++preferenceScreen.initialExpandedChildrenCount
                    wgQuickOnlyPrefs.forEach { it.isVisible = true }
                } else {
                    wgQuickOnlyPrefs.forEach { it.parent?.removePreference(it) }
                }
            }
            preferenceManager.findPreference<Preference>("log_viewer")?.setOnPreferenceClickListener {
                startActivity(Intent(requireContext(), LogViewerActivity::class.java))
                true
            }
            /* Custom change begin */
            preferenceManager.findPreference<Preference>("key_option")?.setOnPreferenceClickListener {
                startActivity(Intent(requireContext(), LogViewerActivity::class.java))
                true
            }
            /* Custom change end */
            val kernelModuleEnabler = preferenceManager.findPreference<Preference>("kernel_module_enabler")
            if (WgQuickBackend.hasKernelSupport()) {
                lifecycleScope.launch {
                    if (HWApplication.getBackend() !is WgQuickBackend) {
                        try {
                            withContext(Dispatchers.IO) { HWApplication.getRootShell().start() }
                        } catch (_: Throwable) {
                            kernelModuleEnabler?.parent?.removePreference(kernelModuleEnabler)
                        }
                    }
                }
            } else {
                kernelModuleEnabler?.parent?.removePreference(kernelModuleEnabler)
            }
        }

        /* Custom change begin */
        /*override fun onResume() {
            super.onResume()
            //unregister the preferenceChange listener
            preferenceScreen.sharedPreferences?.registerOnSharedPreferenceChangeListener(this)
        }

        override fun onSharedPreferenceChanged(
            sharedPreferences: SharedPreferences?,
            key: String?
        ) {
            Log.i("onSharedPreferenceChanged", "Preferences changed.")
            val category = findPreference("key_option") as PreferenceCategory?
            val keystorePref = findPreference<Preference>("key_option_keystore")
            val hsmPref = findPreference<Preference>("key_option_hsm")
            val prefs = PreferencesPreferenceDataStore(lifecycleScope, Application.getPreferencesDataStore())
            if(prefs.getBoolean("use_hsm", false)) {
                preferenceManager.findPreference<Preference>("key_option_hsm")?.setOnPreferenceClickListener {
                    startActivity(Intent(requireContext(), HSMActivity::class.java))
                    true
                }
                category?.removePreference(hsmPref!!)
                category?.addPreference(keystorePref!!)
            } else {
                preferenceManager.findPreference<Preference>("key_option_keystore")?.setOnPreferenceClickListener {
                    startActivity(Intent(requireContext(), LogViewerActivity::class.java))
                    true
                }
                category?.removePreference(keystorePref!!)
                category?.addPreference(hsmPref!!)
            }
        }
        override fun onPause() {
            super.onPause()
            //unregister the preference change listener
            preferenceScreen.sharedPreferences?.unregisterOnSharedPreferenceChangeListener(this)
        }*/
        /* Custom change end */
    }
}

