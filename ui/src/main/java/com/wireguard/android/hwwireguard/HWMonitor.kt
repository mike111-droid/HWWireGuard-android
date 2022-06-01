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
import androidx.biometric.BiometricPrompt
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.wireguard.android.HWApplication
import com.wireguard.android.R
import com.wireguard.android.activity.MainActivity
import com.wireguard.android.hwwireguard.crypto.HWHSMManager
import com.wireguard.android.hwwireguard.crypto.HWHardwareBackedKey
import com.wireguard.android.hwwireguard.crypto.HWKeyStoreManager
import com.wireguard.android.hwwireguard.crypto.HWTimestamp
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.android.util.applicationScope
import com.wireguard.config.Config
import com.wireguard.crypto.Key
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMCardService
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import opencard.core.service.SmartCard
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
    /* Tunnel can only be set once */
    private var mTunnel: ObservableTunnel? = null
    /* isTunnelSet makes sure that mTunnel is only set once */
    private var isTunnelSet: Boolean = false
    /* SmartCardHSMCardService is necessary for all interactions with HSM */
    var smartCardService: SmartCardHSMCardService? = null
    /* Variable to safe preference of current tunnel */
    lateinit var mPref: PreferencesPreferenceDataStore

    /**
     * Function to start the monitor process. Is stop with AtomicBoolean run. mTunnel must be set before.
     */
    fun startMonitor() {
        Log.i(TAG, "inside startMonitor")
        mPref = PreferencesPreferenceDataStore(
            applicationScope,
            HWApplication.getPreferencesDataStore()
        )
        mActivity.applicationScope.launch {
            try {
                authenticate()
                /* Wait for authentication */
                while(!run.get()) {
                    delay(1000)
                }
                /* Start monitor process that updates PSK with every changing timestamp */
                while(run.get()) {
                    monitor()
                    delay(3000)
                }
            /* Catch all expression that might be thrown by the SmartCard-HSM */
            } catch (e: Exception) {
                Log.i(TAG, Log.getStackTraceString(e));
            } finally {
                /* Make sure to shutdown SmartCard-HSM */
                val hwBackend = mPref.getString("dropdown", "none")
                if (hwBackend == "SmartCardHSM") {
                    try {
                        Log.i(TAG, "Shutting down.")
                        SmartCard.shutdown()
                    } catch (e: Exception) {
                        Log.i(TAG, Log.getStackTraceString(e))
                    }
                }
            }
        }
    }

    /**
     * Function to authenticate either AndroidKeyStores or SmartCard-HSM.
     */
    private fun authenticate() {
        val hwBackend = mPref.getString("dropdown", "none")
        if (hwBackend == "SmartCardHSM") {
            /* Create session for HSM operations */
            val hsmManager = HWHSMManager(mContext)
            smartCardService = hsmManager.smartCardHSMCardService
            smartCardService?.let { authenticateHSM(it, hsmManager) }
        }else if(hwBackend == "AndroidKeyStore") {
            authenticateKeyStore()
        }
    }
    /**
     * Function to authenticate AndroidKeyStore.
     */
    private fun authenticateKeyStore() {
        val authCallback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.w(TAG, "onAuthenticationError $errorCode $errString")
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                run.set(true)
                Log.d(TAG, "onAuthenticationSucceeded " + result.cryptoObject)
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.w(TAG, "onAuthenticationFailed")
            }
        }
        val prompt = BiometricPrompt(
            mFragment,
            ContextCompat.getMainExecutor(mContext),
            authCallback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock your device to use KeyStore keys")
            .setConfirmationRequired(true)
            .setDeviceCredentialAllowed(true)
            .build()
        prompt.authenticate(promptInfo)
    }
    /**
     * Function to enter pin to SmartCardHSMCardService so Session is started which is used for all HSM operations.
     * The session is ended with the closing of the tunnel.
     */
    private fun authenticateHSM(schsmcs: SmartCardHSMCardService, hsmManager: HWHSMManager) {
        /* Open Dialog window for Pin */
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
        /* On positive button press of dialog the timestamp is signed with HSM and newPSK loaded into backend with Pin from edittext */
        alertDialogBuilder.setPositiveButton("Enter") { _, _ ->
            val pin = edittext.text.toString()
            /* Verify Pin for SmartCard-HSM */
            hsmManager.checkPin(pin, schsmcs)
            /* Set run to true so monitoring starts */
            run.set(true)
            /* Delete pin notification if user goes to app without using notification */
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

    /**
     * Function to stop monitor process.
     */
    fun stopMonitor() {
        Log.i(TAG, "inside stopMonitor")
        /* Reset oldTimestamp to null in case tunnel is turned on again */
        oldTimestamp = null
        /* Set run to false so while-loop in startMonitor() is ended */
        run.set(false)
    }

    /**
     * Function to monitor for new timestamp. If new timestamp then calculate newPSK and load it to backend.
     */
    private suspend fun monitor() {
        newTimestamp = HWTimestamp().timestamp.toString()
        /* Check if timestamp changed */
        if(newTimestamp != oldTimestamp) {
            /* Check which mode is selected in preferences */
            val hwBackend = mPref.getString("dropdown", "none")
            /* Check which mode is selected */
            if (hwBackend == "SmartCardHSM") {
                Log.i(TAG, "Using SmartCard-HSM...")
                /* reload PSK with newTimestamp signed by SmartCard-HSM */
                hsmOperation(newTimestamp!!)
            } else if (hwBackend == "AndroidKeyStore") {
                Log.i(TAG, "Using AndroidKeyStore...")
                /* Check for minimum version to run app */
                if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    /* reload PSK with newTimestamp signed by Android KeyStore */
                    keyStoreOperation(newTimestamp!!)
                }else{
                    Toast.makeText(mContext, "Android version not high enough for key usage.", Toast.LENGTH_LONG).show()
                    Log.i(TAG, "Android version not high enough for key usage.")
                }
            }
            /* update reference timestamp */
            oldTimestamp = newTimestamp
        }
    }

    /**
     * Function to update PSK with new timestamp by using SmartCard-HSM.
     */
    private fun hsmOperation(timestamp: String) {
        val hsmManager = HWHSMManager(mContext)
        /* Use SmartCardHSMCardService to perform operation on SmartCard-HSM */
        val newPSK = hsmManager.hsmOperation(HWHardwareBackedKey.KeyType.RSA, smartCardService, timestamp, 0x3)
        /* Load newPSK into GoBackend */
        val config = mTunnel!!.config ?: return
        loadNewPSK(config, newPSK)
    }

    /**
     * Function to update PSK with new timestamp by using Android KeyStore.
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private suspend fun keyStoreOperation(timestamp: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            /* if app is in background -> Notification is sent and startBiometricPrompt set to true
            * setBiometricPrompt is checked in onResume() of BaseFragment where keyStoreOperation is called */
            if(!isAppInForeground()) {
                addNotification()
                startBiometricPrompt = true
            /* if app is in foreground -> keyStoreOperation direct */
            }else{
                val keyStoreManager = HWKeyStoreManager(mContext)
                //Debug.startMethodTracing("demo.trace")
                val newPSK = keyStoreManager.keyStoreOperation(timestamp, "rsa_key", mTunnel!!, this)
                //Debug.stopMethodTracing()
                val config = mTunnel!!.getConfigAsync()
                /* delay to make sure that config is loaded */
                // TODO: find better solution
                delay(500)
                if(newPSK != null) {
                    loadNewPSK(config, newPSK)
                }
                /* Delete pin notification */
                val notificationManager =
                    mContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager?
                notificationManager!!.cancel(NOTIFICATION_ID)
            }
        }
    }

    /**
     * Function to load PSK into backend for all peers.
     * addConf is function in BackendGo that calls custom function in api-android.go in cpp folder of tunnel.
     */
    fun loadNewPSK(config: Config, newPSK: Key) {
        mActivity.applicationScope.launch {
            for((counter, peer) in config.peers.withIndex()) {
                Log.i(TAG, "PSK before: " + HWApplication.getBackend().getStatistics(mTunnel!!).presharedKey[peer.publicKey]!!.toBase64())
                config.peers[counter].setPreSharedKey(newPSK)
                HWApplication.getBackend().addConf(config)
                Log.i(TAG, "PSK after: " + HWApplication.getBackend().getStatistics(mTunnel!!).presharedKey[peer.publicKey]!!.toBase64())
            }
        }
    }

    /**
     * Function to show notification to authenticate user (SmartCard-HSM with Pin, KeyStores with BiometricPrompt)
     */
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


    /**
     * Function to check if app is in background. HWApplication.isActivityVisible() is defined in HWApplication class.
     */
    private fun isAppInForeground(): Boolean {
        return HWApplication.isActivityVisible()
    }

    /**
     * Function to set tunnel. Only can set once because of isTunnelSet boolean.
     */
    fun setTunnel(tunnel: ObservableTunnel) {
        if(!isTunnelSet) {
            mTunnel = tunnel
            isTunnelSet = true
        }
    }

    /**
     * Function to get tunnel because its private to protect it from setting.
     */
    fun getTunnel() : ObservableTunnel? {
        return mTunnel
    }
}