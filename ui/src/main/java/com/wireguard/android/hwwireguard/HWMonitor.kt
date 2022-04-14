/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard

import android.app.Activity
import android.content.Context
import android.util.Log
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.wireguard.android.Application
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.android.util.applicationScope
import com.wireguard.config.Config
import com.wireguard.crypto.Key
import com.wireguard.hwwireguard.HWHSMManager
import com.wireguard.hwwireguard.HWHardwareBackedKey
import com.wireguard.hwwireguard.HWKeyStoreManager
import com.wireguard.hwwireguard.HWRatchetManager
import com.wireguard.hwwireguard.HWTimestamp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean


/**
 * Class for monitoring the tunnels and changing PSKs according to selected version.
 */
class HWMonitor(context: Context, activity: Activity) {
    companion object {
        private const val TAG = "WireGuard/Monitor"
    }
    private var run: AtomicBoolean = AtomicBoolean(false);
    private var oldTimestamp: String? = null
    private val context: Context = context
    private val activity: Activity = activity

    fun startMonitor() {
        Log.i(TAG, "inside startMonitor")
        run.set(true)
        activity.applicationScope.launch {
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
        /* not necessary */
        //oldTimestamp = null
        run.set(false)
    }

    private fun hsmOperation(timestamp: String, tunnel: ObservableTunnel) {
        val edittext = EditText(context);
        val alertDialogBuilder: AlertDialog.Builder = AlertDialog.Builder(context)
        alertDialogBuilder.setMessage("Enter the PIN of the SmartCard-HSM in order to use it.")
        alertDialogBuilder.setTitle("Authenticate yourself")
        alertDialogBuilder.setNegativeButton("Cancel") {dialog, _ ->
            dialog.cancel()
        }
        alertDialogBuilder.setView(edittext)
        alertDialogBuilder.setPositiveButton("Enter") { _, _ ->
            Toast.makeText(context, "Your pin is: " + edittext.text.toString(), Toast.LENGTH_SHORT).show()
            val pin = edittext.text.toString()
            Log.i(TAG, "Pin is $pin")
            val hsmManager = HWHSMManager(context)
            val newPSK = hsmManager.hsmOperation(HWHardwareBackedKey.KeyType.RSA, pin, timestamp, 0x3)
            val config = tunnel.config ?: return@setPositiveButton
            loadNewPSK(tunnel, config, newPSK)
        }
        val alertDialog: AlertDialog = alertDialogBuilder.create()
        alertDialog.show()
    }

    private fun keyStoreOperation(timestamp: String, tunnel: ObservableTunnel) {
        val keyStoreManager = HWKeyStoreManager(context)
    }

    private fun loadNewPSK(tunnel: ObservableTunnel, config: Config, newPSK: Key) {
        activity.applicationScope.launch {
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
        }
    }

    private suspend fun monitor(tunnel: ObservableTunnel) {
        Log.i(TAG, "Checking tunnel: $tunnel")
        val timestamp = HWTimestamp().timestamp
        /* Check if timestamp changed */
        if(timestamp != oldTimestamp) {
            /* PSK needs to be reloaded with new timestamp */
            val pref = PreferencesPreferenceDataStore(
                applicationScope,
                Application.getPreferencesDataStore()
            )
            val hwbacked = pref.getString("dropdown", "none")
            if (hwbacked == "SmartCardHSM") {
                Log.i(TAG, "Using SmartCard-HSM...")
                hsmOperation(timestamp, tunnel)
            } else if (hwbacked == "AndroidKeyStore") {
                Log.i(TAG, "Using AndroidKeyStore...")
                keyStoreOperation(timestamp, tunnel)
            }
            oldTimestamp = timestamp
        }
        /* Check if six failed handshakes -> reset */

        /* Check if successful handshake */
    }

    private fun ratchet(key: Key) : Key {
        val ratchetManager =
            HWRatchetManager()
        return ratchetManager.ratchet(key)
    }
}