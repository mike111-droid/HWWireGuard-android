/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard

import android.content.Context
import android.util.Log
import com.wireguard.android.Application
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.android.util.applicationScope
import com.wireguard.crypto.Key
import com.wireguard.hwwireguard.HWHSMManager
import com.wireguard.hwwireguard.HWHardwareBackedKey
import com.wireguard.hwwireguard.HWRatchetManager
import com.wireguard.hwwireguard.HWTimestamp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Class for monitoring the tunnels and changing PSKs according to selected version.
 */
class HWMonitor(context: Context) {
    companion object {
        private const val TAG = "WireGuard/Monitor"
    }
    private var run: AtomicBoolean = AtomicBoolean(false);
    private var oldTimestamp: String? = null
    private val context: Context = context

    fun startMonitor() {
        Log.i(TAG, "inside startMonitor")
        run.set(true)
        applicationScope.launch(Dispatchers.Default) {
            while(run.get()) {
                for(tunnel in Application.getTunnelManager().getTunnels()) {
                    monitor(tunnel)
                }
                delay(3000)
            }
        }
    }

    fun stopMonitor() {
        Log.i(TAG, "inside stopMonitor")
        run.set(false)
    }

    private suspend fun ratchet(key: Key) : Key {
        val ratchetManager =
            HWRatchetManager()
        return ratchetManager.ratchet(key)
    }

    private suspend fun monitor(tunnel: ObservableTunnel) {
        Log.i(TAG, "Checking tunnel: $tunnel")
        val timestamp = HWTimestamp().timestamp
        if(timestamp != oldTimestamp) {
            /* PSK needs to be reloaded with new timestamp */
            val pref = PreferencesPreferenceDataStore(applicationScope, Application.getPreferencesDataStore())
            val hwbacked = pref.getString("dropdown", "none")
            if(hwbacked == "SmartCardHSM") {
                Log.i(TAG, "Using SmartCard-HSM...")
                val hsmManager =
                    HWHSMManager(context)
                val newPSK = hsmManager.hsmOperation(HWHardwareBackedKey.KeyType.RSA,"123456", timestamp, 0x3)
                val config = tunnel.config ?: return
                for((counter, peer) in config.peers.withIndex()) {
                    Log.i(
                        TAG,
                        "psk before: " + Application.getBackend().getStatistics(tunnel).presharedKey[peer.publicKey]!!.toBase64()
                    )
                    config.peers[counter].setPreSharedKey(newPSK)
                    Application.getBackend().addConf(config)
                    Log.i(
                        TAG,
                        "psk after: " + Application.getBackend().getStatistics(tunnel).presharedKey[peer.publicKey]!!.toBase64()
                    )
                }
            }else if(hwbacked == "AndroidKeyStore"){
                Log.i(TAG, "Using AndroidKeyStore...")
            }
        }
        oldTimestamp = timestamp
    }
}