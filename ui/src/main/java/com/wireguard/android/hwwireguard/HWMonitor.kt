/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard

import android.app.Activity
import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.util.Log
import android.widget.EditText
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.core.app.NotificationCompat
import androidx.fragment.app.Fragment
import com.google.android.material.snackbar.Snackbar
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.activity.MainActivity
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.android.util.BiometricAuthenticator
import com.wireguard.android.util.applicationScope
import com.wireguard.config.Config
import com.wireguard.crypto.Key
import com.wireguard.hwwireguard.HWHSMManager
import com.wireguard.hwwireguard.HWHardwareBackedKey
import com.wireguard.hwwireguard.HWKeyStoreManager
import com.wireguard.hwwireguard.HWTimestamp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean


/**
 * Class for monitoring the tunnels and changing PSKs according to selected version.
 */
class HWMonitor(context: Context, activity: Activity, fragment: Fragment) {
    companion object {
        private const val TAG = "WireGuard/Monitor"
    }
    private var run: AtomicBoolean = AtomicBoolean(false);
    private var oldTimestamp: String? = null
    private val context: Context = context
    private val activity: Activity = activity
    private val fragment: Fragment = fragment

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
        oldTimestamp = null
        run.set(false)
    }

    private fun hsmOperation(timestamp: String, tunnel: ObservableTunnel) {
        val edittext = EditText(context)
        edittext.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        edittext.transformationMethod = PasswordTransformationMethod.getInstance()
        val alertDialogBuilder: AlertDialog.Builder = AlertDialog.Builder(context)
        alertDialogBuilder.setMessage("Enter the PIN of the SmartCard-HSM in order to use it.")
        alertDialogBuilder.setTitle("Authenticate yourself")
        alertDialogBuilder.setNegativeButton("Cancel") {dialog, _ ->
            dialog.cancel()
        }
        alertDialogBuilder.setView(edittext)
        alertDialogBuilder.setPositiveButton("Enter") { _, _ ->
            val pin = edittext.text.toString()
            val hsmManager = HWHSMManager(context)
            val newPSK = hsmManager.hsmOperation(HWHardwareBackedKey.KeyType.RSA, pin, timestamp, 0x3)
            val config = tunnel.config ?: return@setPositiveButton
            loadNewPSK(tunnel, config, newPSK)
        }
        val alertDialog: AlertDialog = alertDialogBuilder.create()
        alertDialog.show()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if(!isAppInForeground()) {
                addNotification()
            }
        }
    }

    private fun isAppInForeground(): Boolean {
        val application = context
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val runningProcessList = activityManager.runningAppProcesses
        if (runningProcessList != null) {
            val myApp = runningProcessList.find { it.processName == application.packageName }
            ActivityManager.getMyMemoryState(myApp)
            return myApp?.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
        }
        return false
    }

    @RequiresApi(Build.VERSION_CODES.O)
    fun addNotification() {
        Log.i(TAG, "Started addNotification")
        val mBuilder = NotificationCompat.Builder(context, "notify_001")
        val ii = Intent(
            context,
            MainActivity::class.java
        )
        val pendingIntent = PendingIntent.getActivity(context, 0, ii, 0)

        val bigText = NotificationCompat.BigTextStyle()
        bigText.bigText("Enter the pin again otherwise the VPN will stop.")
        bigText.setBigContentTitle("Enter pin")
        bigText.setSummaryText("Enter the pin again otherwise the VPN will stop.")

        mBuilder.setContentIntent(pendingIntent)
        mBuilder.setSmallIcon(R.mipmap.ic_launcher_round)
        mBuilder.setContentTitle("Enter pin")
        mBuilder.setContentText("Enter the pin again otherwise the VPN will stop.")
        mBuilder.priority = Notification.PRIORITY_MAX
        mBuilder.setStyle(bigText)
        mBuilder.setAutoCancel(true)

        val mNotificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channelId = "Your_channel_id"
            val channel = NotificationChannel(
                channelId,
                "Channel human readable title",
                NotificationManager.IMPORTANCE_HIGH
            )
            mNotificationManager.createNotificationChannel(channel)
            mBuilder.setChannelId(channelId)
        }

        mNotificationManager.notify(0, mBuilder.build())
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun keyStoreOperation(timestamp: String, tunnel: ObservableTunnel) {
        BiometricAuthenticator.authenticate(R.string.biometric_prompt_key, fragment) {
            when (it) {
                // When we have successful authentication, or when there is no biometric hardware available.
                is BiometricAuthenticator.Result.Success, is BiometricAuthenticator.Result.HardwareUnavailableOrDisabled -> {
                    val keyStoreManager = HWKeyStoreManager(context)
                    for(key in keyStoreManager.getKeyList()) {
                        Log.i(TAG, "key: ${key.label}")
                    }
                    val newPSK = keyStoreManager.keyStoreOperation(HWHardwareBackedKey.KeyType.RSA, "rsa_key", timestamp)
                    val config = tunnel.config ?: return@authenticate
                    loadNewPSK(tunnel, config, newPSK)
                }
                is BiometricAuthenticator.Result.Failure -> {
                    Snackbar.make(
                        activity.findViewById(android.R.id.content),
                        it.message,
                        Snackbar.LENGTH_SHORT
                    ).show()
                }
                is BiometricAuthenticator.Result.Cancelled -> {}
            }
        }
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

    private fun monitor(tunnel: ObservableTunnel) {
        Log.i(TAG, "Checking tunnel: $tunnel")
        val timestamp = HWTimestamp().timestamp
        /* Check if timestamp changed */
        if(timestamp != oldTimestamp) {
            /* PSK needs to be reloaded with new timestamp */
            val pref = PreferencesPreferenceDataStore(
                applicationScope,
                Application.getPreferencesDataStore()
            )
            val hwBackend = pref.getString("dropdown", "none")
            if (hwBackend == "SmartCardHSM") {
                Log.i(TAG, "Using SmartCard-HSM...")
                hsmOperation(timestamp, tunnel)
            } else if (hwBackend == "AndroidKeyStore") {
                Log.i(TAG, "Using AndroidKeyStore...")
                if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    keyStoreOperation(timestamp, tunnel)
                }else{
                    Toast.makeText(context, "Android version not high enough for key usage.", Toast.LENGTH_LONG).show()
                    Log.i(TAG, "Android version not high enough for key usage.")
                }
            }
            oldTimestamp = timestamp
        }
        /* Check if six failed handshakes -> reset */

        /* Check if successful handshake */
    }
}