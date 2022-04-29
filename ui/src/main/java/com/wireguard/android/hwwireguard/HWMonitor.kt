/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard

import android.annotation.SuppressLint
import android.app.Activity
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
import com.wireguard.android.HWApplication
import com.wireguard.android.R
import com.wireguard.android.activity.MainActivity
import com.wireguard.android.hwwireguard.util.HWBiometricAuthenticator
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.android.util.applicationScope
import com.wireguard.config.Config
import com.wireguard.crypto.Key
import com.wireguard.hwwireguard.HWHSMManager
import com.wireguard.hwwireguard.HWHardwareBackedKey
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
        const val NOTIFICATION_ID = 0
    }

    private var run: AtomicBoolean = AtomicBoolean(false)
    private var oldTimestamp: String? = null
    var newTimestamp: String? = null
    val mContext: Context = context
    private val mActivity: Activity = activity
    val mFragment: Fragment = fragment
    var startBiometricPrompt: Boolean = false
    var mTunnel: ObservableTunnel? = null

    fun startMonitor() {
        Log.i(TAG, "inside startMonitor")
        run.set(true)
        mActivity.applicationScope.launch {
            while(run.get()) {
                monitor(mTunnel!!)
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
        val edittext = EditText(mContext)
        edittext.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        edittext.transformationMethod = PasswordTransformationMethod.getInstance()
        val alertDialogBuilder: AlertDialog.Builder = AlertDialog.Builder(mContext)
        alertDialogBuilder.setMessage("Enter the PIN of the SmartCard-HSM in order to use it.")
        alertDialogBuilder.setTitle("Authenticate yourself")
        alertDialogBuilder.setNegativeButton("Cancel") {dialog, _ ->
            dialog.cancel()
        }
        alertDialogBuilder.setView(edittext)
        alertDialogBuilder.setPositiveButton("Enter") { _, _ ->
            val pin = edittext.text.toString()
            val hsmManager = HWHSMManager(mContext)
            val newPSK = hsmManager.hsmOperation(HWHardwareBackedKey.KeyType.RSA, pin, timestamp, 0x3)
            val config = tunnel.config ?: return@setPositiveButton
            loadNewPSK(tunnel, config, newPSK)
            val notificationManager =
                mContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager?
            notificationManager!!.cancel(NOTIFICATION_ID)
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
        return HWApplication.isActivityVisible()
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    @RequiresApi(Build.VERSION_CODES.O)
    fun addNotification() {
        Log.i(TAG, "Started addNotification")
        val mBuilder = NotificationCompat.Builder(mContext, "notify_001")
        val intent = Intent(mContext, MainActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK;
        intent.action = Intent.ACTION_MAIN;
        intent.addCategory(Intent.CATEGORY_LAUNCHER);
        val pendingIntent = PendingIntent.getActivity(
            mContext, 0,
            intent, PendingIntent.FLAG_UPDATE_CURRENT
        )

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
        mBuilder.setVisibility(NotificationCompat.VISIBILITY_PUBLIC)

        val mNotificationManager =
            mContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

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

        mNotificationManager.notify(NOTIFICATION_ID, mBuilder.build())
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun keyStoreOperation(timestamp: String, tunnel: ObservableTunnel) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if(!isAppInForeground()) {
                addNotification()
                startBiometricPrompt = true
            }else{
                HWBiometricAuthenticator.keyStoreOperation(timestamp, "rsa_key", tunnel, this)
                val notificationManager =
                    mContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager?
                notificationManager!!.cancel(NOTIFICATION_ID)
            }
        }
    }

    fun loadNewPSK(tunnel: ObservableTunnel, config: Config, newPSK: Key) {
        mActivity.applicationScope.launch {
            for((counter, peer) in config.peers.withIndex()) {
                Log.i(
                    TAG,
                    "psk before: " + HWApplication.getBackend().getStatistics(tunnel).presharedKey[peer.publicKey]!!.toBase64()
                )
                config.peers[counter].setPreSharedKey(newPSK)
                HWApplication.getBackend().addConf(config)
                Log.i(
                    TAG,
                    "psk after: " + HWApplication.getBackend().getStatistics(tunnel).presharedKey[peer.publicKey]!!.toBase64()
                )
            }
        }
    }

    private fun monitor(tunnel: ObservableTunnel) {
        Log.i(TAG, "Checking tunnel: $tunnel")
        newTimestamp = HWTimestamp().timestamp
        /* Check if timestamp changed */
        if(newTimestamp != oldTimestamp) {
            /* PSK needs to be reloaded with new timestamp */
            val pref = PreferencesPreferenceDataStore(
                applicationScope,
                HWApplication.getPreferencesDataStore()
            )
            val hwBackend = pref.getString("dropdown", "none")
            if (hwBackend == "SmartCardHSM") {
                Log.i(TAG, "Using SmartCard-HSM...")
                hsmOperation(newTimestamp!!, tunnel)
            } else if (hwBackend == "AndroidKeyStore") {
                Log.i(TAG, "Using AndroidKeyStore...")
                if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    keyStoreOperation(newTimestamp!!, tunnel)
                }else{
                    Toast.makeText(mContext, "Android version not high enough for key usage.", Toast.LENGTH_LONG).show()
                    Log.i(TAG, "Android version not high enough for key usage.")
                }
            }
            oldTimestamp = newTimestamp
        }
        /* Check if six failed handshakes -> reset */

        /* Check if successful handshake */
    }
}