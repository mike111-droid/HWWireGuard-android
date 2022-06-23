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
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.util.Log
import android.widget.EditText
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
import com.wireguard.config.Peer
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

    /* Atomic boolean to stay the same across multiple process and control monitor process */
    private var run: AtomicBoolean = AtomicBoolean(false)
    /* Variable to save old timestamp for comparison */
    private var mOldTimestamp: String? = null
    /* mContext, mActivity, mFragment
    * Necessary variables to perform certain UI interactions */
    val mContext: Context = context
    private val mActivity: Activity = activity
    val mFragment: Fragment = fragment
    /* Variable to lookup which tunnel this monitor observes */
    private var mTunnel: ObservableTunnel? = null
    @kotlin.jvm.JvmField
    var startBiometricPrompt: Boolean = false
    /* isTunnelSet makes sure that mTunnel is only set once */
    private var isTunnelSet: Boolean = false
    /* SmartCardHSMCardService is necessary for all interactions with HSM */
    private var smartCardService: SmartCardHSMCardService? = null
    /* Hardware backend (either AndroidKeyStore or SmartCard-HSM */
    var mHWBackend = PreferencesPreferenceDataStore(applicationScope, HWApplication.getPreferencesDataStore()).getString("dropdown", "none")
    /* Key algorithm (either RSA or AES) */
    var mKeyAlgo = PreferencesPreferenceDataStore(applicationScope, HWApplication.getPreferencesDataStore()).getString("dropdownAlgorithms", "RSA")
    /* List of peers that still need to have keyStoreOperation performed for them because authentication expired */
    val missingPeerOperationsKeyStore: HashMap<Peer?, String> = HashMap()
    /* Shutdown lock so access to backend does not happen when shutdown */
    var shutdownLock: AtomicBoolean = AtomicBoolean(false)

    /* Added member variables for Version 2 */
    /* List with lastHandshakeTime of peer */
    var mLastHandshakeTime: HashMap<Key, Int> = HashMap()
    /* save current initPSK */
    lateinit var initPSK: Key
    /* Boolean to check if already ratcheted within the 20 handshake cycle */
    var alreadyResetOnce = false
    var alreadyResetTwice = false
    

    /**
     * Function to start the monitor process. Is stop with AtomicBoolean run. mTunnel must be set before.
     */
    fun startMonitor() {
        Log.i(TAG, "inside startMonitor")
        mActivity.applicationScope.launch {
            try {
                authenticate()
                while(!run.get()) {
                    delay(1000)
                }
                /* Start monitor process that updates PSK with every changing timestamp */
                Log.i(TAG, "Starting Monitor...")
                while(run.get()) {
                    monitor()
                }
                /* Reset oldTimestamp to null in case tunnel is turned on again */
                mOldTimestamp = null
            /* Catch all expression that might be thrown by the SmartCard-HSM */
            } catch (e: Exception) {
                Log.i(TAG, Log.getStackTraceString(e))
            } finally {
                /* Make sure to shutdown SmartCard-HSM */
                if (mHWBackend == "SmartCardHSM") {
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
        /* Check which hardware backend */
        if (mHWBackend == "SmartCardHSM") {
            /* Create session for HSM operations */
            val hsmManager = HWHSMManager(mContext)
            smartCardService = hsmManager.smartCardHSMCardService
            /* Authenticate for SmartCard-HSM */
            smartCardService?.let { authenticateHSM(it, hsmManager) }
        }else if(mHWBackend == "AndroidKeyStore") {
            /* Authenticate for Android KeyStore */
            authenticateKeyStore()
        }
    }
    /**
     * Function to authenticate AndroidKeyStore.
     */
    private fun authenticateKeyStore() {
        /* Define callback actions for different authentication results */
        val authCallback = object : BiometricPrompt.AuthenticationCallback() {
            /* Error case */
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.w(TAG, "onAuthenticationError $errorCode $errString")
            }
            /* Success case -> set run to true (to break wait loop) */
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                run.set(true)
                Log.d(TAG, "onAuthenticationSucceeded " + result.cryptoObject)
            }
            /* Error case */
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.w(TAG, "onAuthenticationFailed")
            }
        }
        val prompt = BiometricPrompt(mFragment, ContextCompat.getMainExecutor(mContext), authCallback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock your device to use KeyStore keys")
            .setConfirmationRequired(true)
            .setDeviceCredentialAllowed(true)
            .build()
        /* Display authentication prompt */
        prompt.authenticate(promptInfo)
    }
    /**
     * Function to authenticate SmartCard-HSM.
     * Authentication via HSM PIN in a alert dialog prompt.
     * The session is ended with the closing of the tunnel.
     */
    private fun authenticateHSM(schsmcs: SmartCardHSMCardService, hsmManager: HWHSMManager) {
        /* Get alertDialogBuilder for user authentication with PIN */
        val alertDialogBuilder = getHSMAlertDialogBuilderHSM(schsmcs, hsmManager)
        /* If app is not in foreground add notification */
        val alertDialog: AlertDialog = alertDialogBuilder.create()
        /* Show alert dialog */
        alertDialog.show()
    }
    /**
     * Function to get AlertDialogBuilder for HSM authentication.
     */
    private fun getHSMAlertDialogBuilderHSM(schsmcs: SmartCardHSMCardService, hsmManager: HWHSMManager): AlertDialog.Builder {
        /* Construct alert dialog */
        val edittext = EditText(mContext)
        edittext.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        edittext.transformationMethod = PasswordTransformationMethod.getInstance()
        /* Get AlertDialogBuilder with mContext */
        val alertDialogBuilder: AlertDialog.Builder = AlertDialog.Builder(mContext)
        /* Set displayed text and textedit */
        alertDialogBuilder.setMessage("Enter the PIN of the SmartCard-HSM in order to use it.")
        alertDialogBuilder.setTitle("Authenticate yourself")
        alertDialogBuilder.setView(edittext)
        /* Action for cancel button. Closes dialog. */
        alertDialogBuilder.setNegativeButton("Cancel") {dialog, _ ->
            dialog.cancel()
        }
        /* Action for enter button. Login to SmartCard-HSM and set run to true (to break wait loop) */
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
        return alertDialogBuilder
    }

    /**
     * Function to stop monitor process.
     */
    fun stopMonitor() {
        Log.i(TAG, "inside stopMonitor")
        /* Set run to false so while-loop in startMonitor() is ended */
        run.set(false)
    }

    /**
     * Function to monitor for new timestamp. If new timestamp then calculate newPSK and load it to backend.
     * With every successful handshake the psk is ratcheted.
     */
    private suspend fun monitor() {
        /* Delay to minimize CPU usage (do not need checks every second) */
        delay(4000)
        /* Get current timestamp */
        val currentTimestamp = HWTimestamp().timestamp.toString()
        /* Check if timestamp changed */
        if(currentTimestamp != mOldTimestamp) {
            Log.i(TAG, "newTimestamp is a different one from oldTimestamp...")
            /* Check which mode is selected */
            if (mHWBackend == "SmartCardHSM") {
                Log.i(TAG, "Using SmartCard-HSM...")
                /* reload PSK with newTimestamp signed by SmartCard-HSM */
                hsmOperation(currentTimestamp, null)
            } else if (mHWBackend == "AndroidKeyStore") {
                Log.i(TAG, "Using AndroidKeyStore...")
                /* Check for minimum version to run app */
                /* reload PSK with newTimestamp signed by Android KeyStore */
                keyStoreOperation(currentTimestamp, null)
            }
            /* update reference timestamp */
            mOldTimestamp = currentTimestamp
        }
        monitorV2Extension()
    }

    /**
     * Function to check if handshake was successful.
     * -> if yes: ratchet with oldPSK
     * -> if no: continue
     * Function also checks how many failed handshakes.
     * -> if 6 failed: reset with initPSK
     * -> if 13 failed: reset with currentTimestamp
     */
    private suspend fun monitorV2Extension() {
        /* Get statistics from WireGuardGo backend */
        val config = mTunnel!!.config ?: return
        if(!run.get()) return
        shutdownLock.set(true)
        val stats = HWApplication.getBackend().getStatistics(mTunnel)
        shutdownLock.set(false)
        val lastHandshakeTime = stats.lastHandshakeTime
        /* Iterate through peers to check if successful handshake occurred */
        for (peer in config.peers) {
            if (mLastHandshakeTime[peer.publicKey] == null) {
                mLastHandshakeTime[peer.publicKey] = 0
            }
            /* Check if LastHandshakeTime changed */
            if (lastHandshakeTime[peer.publicKey] != mLastHandshakeTime[peer.publicKey]) {
                /* Handshake was successful (change saved mLastHandshakeTime and ratchet) */
                lastHandshakeTime[peer.publicKey]?.let { mLastHandshakeTime.put(peer.publicKey, it) }
                Log.i(TAG, "handshake was successful... Do ratchet...")
                ratchetOption2(config, peer)
            }
            /* Check failed handshake attempts */
            val handshakeAttempts = stats.handshakeAttempts[peer.publicKey]
            handleFailedHandshake(handshakeAttempts, config, peer)
        }
    }

    /**
     * Function to handle failed handshakes.
     * -> if 6 failed: reset with initPSK
     * -> if 13 failed: reset with currentTimestamp
     */
    private fun handleFailedHandshake(handshakeAttempts: Int?, config: Config, peer: Peer?) {
        if (handshakeAttempts != null) {
            /* mod 20 in case handshakeAttempts go higher than 20 */
            val handshakeAttemptsMod = handshakeAttempts.mod(20)
            if (handshakeAttemptsMod == 0) {
                alreadyResetOnce = false
                alreadyResetTwice = false
            }
            /* if handshakeAttempt%20==6 => reset PSK with saved initPSK */
            if (handshakeAttemptsMod == 6 && !alreadyResetOnce) {
                /* Reset PSK for exact peer */
                Log.i(TAG, "We are out of sync. So reset oldTimestamp")
                Log.i(TAG, "initPSK: ${initPSK.toBase64()}")
                loadNewPSK(config, initPSK, peer)
                alreadyResetOnce = true
            }
            /* if handshakeAttempt%20==13 => reset PSK with newly calculated PSK from current timestamp (in case saved initPSK is false) */
            if (handshakeAttemptsMod == 13 && !alreadyResetTwice) {
                val currentTimestamp = HWTimestamp().timestamp.toString()
                if (mHWBackend == "SmartCardHSM") {
                    Log.i(TAG, "Resetting using SmartCard-HSM...")
                    /* reload PSK with newTimestamp signed by SmartCard-HSM */
                    hsmOperation(currentTimestamp, peer)
                } else if (mHWBackend == "AndroidKeyStore") {
                    Log.i(TAG, "Resetting using AndroidKeyStore...")
                    /* reload PSK with newTimestamp signed by Android KeyStore */
                    keyStoreOperation(currentTimestamp, peer)
                }
                alreadyResetTwice = true
                /* update reference timestamp for all peers */
                mOldTimestamp = currentTimestamp
            }
        }
    }

    /**
     * Function to ratchet PSK for specific peer.
     */
    private fun ratchetOption2(config: Config, peer: Peer) {
        for((counter, peerIteration) in config.peers.withIndex()) {
            /* find specific peer */
            if(peerIteration == peer) {
                val psk = config.peers[counter].preSharedKey.get()
                if(mHWBackend == "SmartCardHSM") {
                    Log.i(TAG, "Using SmartCard-HSM...")
                    /* reload PSK with newTimestamp signed by SmartCard-HSM */
                    hsmOperation(psk.toBase64(), peerIteration)
                }else if(mHWBackend == "AndroidKeyStore") {
                    Log.i(TAG, "Using AndroidKeyStore...")
                    /* reload PSK with newTimestamp signed by Android KeyStore */
                    keyStoreOperation(psk.toBase64(), peerIteration)
                }
            }
        }
    }

    /**
     * Function to update PSK with new timestamp by using SmartCard-HSM.
     * SmartCard-HSM does not need notification because PIN is valid for the whole time.
     */
    private fun hsmOperation(timestamp: String, peer: Peer?) {
        val hsmManager = HWHSMManager(mContext)
        /* Check which algorithm to use (RSA or AES) */
        val newPSK: Key = if(mKeyAlgo == "RSA") {
            /* Use RSA */
            hsmManager.hsmOperation(HWHardwareBackedKey.KeyType.RSA, smartCardService, timestamp, 0x3)
        }else{
            /* Use AES */
            hsmManager.hsmOperation(HWHardwareBackedKey.KeyType.AES, smartCardService, timestamp, 0x1)
        }
        /* Load newPSK into GoBackend */
        Log.i(TAG, "newPSK is ${newPSK.toBase64()}")
        val config = mTunnel!!.config ?: return
        loadNewPSK(config, newPSK, peer)
        /* only if peer null was newPSK triggered by timestamp */
        if(peer == null) {
            initPSK = newPSK
        }

    }

    /**
     * Function to update PSK with new timestamp by using Android KeyStore.
     * Android KeyStore needs notifications because in order to use key, biometric authentication must have been used in the last 6 hours.
     */
    fun keyStoreOperation(timestamp: String, peer: Peer?) {
        /* Check for minimum version to run app */
        val keyStoreManager = HWKeyStoreManager()
        /* Check which algorithm to use (RSA or AES) */
        val newPSK: Key? = if (mKeyAlgo == "RSA") {
            /* Use RSA */
            keyStoreManager.keyStoreOperation(timestamp, "rsa_key", mTunnel!!, this, peer)
        } else {
            /* Use AES */
            keyStoreManager.keyStoreOperation(timestamp, "aes_key", mTunnel!!, this, peer)
        }
        /* Get config so we can set new PSK and load config into WireGuardGo Backend */
        val config = mTunnel!!.config ?: return
        /* Make sure newPSK is not null (newPSK can be null if keyStoreOperationWithBio was used which automatically loads newPSK) */
        if (newPSK != null) {
            loadNewPSK(config, newPSK, peer)
            /* Delete pin notification */
            val notificationManager =
                mContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager?
            notificationManager!!.cancel(NOTIFICATION_ID)
            /* only if peer null was newPSK triggered by timestamp */
            if(peer == null) {
                initPSK = newPSK
            }
        }
    }

    /**
     * Function to load PSK into backend for all peers.
     * addConf is function in BackendGo that calls custom function in api-android.go in cpp folder of tunnel.
     */
    fun loadNewPSK(config: Config, newPSK: Key,  peer: Peer?) {
        mActivity.applicationScope.launch {
            for((counter, peerIterate) in config.peers.withIndex()) {
                if(!run.get()) return@launch
                shutdownLock.set(true)
                Log.i(TAG, "PSK before: " + HWApplication.getBackend().getStatistics(mTunnel!!).presharedKey[peerIterate.publicKey]!!.toBase64())
                if(peer == null) {
                    config.peers[counter].setPreSharedKey(newPSK)
                    HWApplication.getBackend().loadConf(config)
                }
                if(peer == peerIterate) {
                    config.peers[counter].setPreSharedKey(newPSK)
                    HWApplication.getBackend().loadPSK(config)
                }
                Log.i(TAG, "PSK after: " + HWApplication.getBackend().getStatistics(mTunnel!!).presharedKey[peerIterate.publicKey]!!.toBase64())
                shutdownLock.set(false)
                if(!run.get()) return@launch
            }
        }
    }

    /**
     * Function to show notification to authenticate user (SmartCard-HSM with Pin, KeyStores with BiometricPrompt)
     */
    @SuppressLint("UnspecifiedImmutableFlag")
    fun addNotification() {
        Log.i(TAG, "Started addNotification")
        val mBuilder = getNotificationBuilder()
        /* Create notification channel */
        val mNotificationManager =
            mContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channelId = "Your_channel_id"
        val channel = NotificationChannel(
            channelId,
            "Channel human readable title",
            NotificationManager.IMPORTANCE_HIGH
        )
        mNotificationManager.createNotificationChannel(channel)
        mBuilder.setChannelId(channelId)
        /* Display notification */
        mNotificationManager.notify(NOTIFICATION_ID, mBuilder.build())
    }

    private fun getNotificationBuilder() : NotificationCompat.Builder {
        /* Create NotificationBuilder */
        val mBuilder = NotificationCompat.Builder(mContext, "notify_001")
        /* Create intent to perform when notification clicked */
        val intent = Intent(mContext, MainActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        intent.action = Intent.ACTION_MAIN
        intent.addCategory(Intent.CATEGORY_LAUNCHER)
        val pendingIntent = PendingIntent.getActivity(
            mContext, 0,
            intent, PendingIntent.FLAG_UPDATE_CURRENT
        )
        /* Create notification text */
        val bigText = NotificationCompat.BigTextStyle()
        bigText.bigText("Enter the pin again otherwise the VPN will stop.")
        bigText.setBigContentTitle("Enter pin")
        bigText.setSummaryText("Enter the pin again otherwise the VPN will stop.")
        /* Set settings of notification */
        mBuilder.setContentIntent(pendingIntent)
        mBuilder.setSmallIcon(R.mipmap.ic_launcher_round)
        mBuilder.setContentTitle("Enter pin")
        mBuilder.setContentText("Enter the pin again otherwise the VPN will stop.")
        mBuilder.priority = Notification.PRIORITY_MAX
        mBuilder.setStyle(bigText)
        mBuilder.setAutoCancel(true)
        mBuilder.setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
        return mBuilder
    }

    /**
     * Function to check if app is in background. HWApplication.isActivityVisible() is defined in HWApplication class.
     */
    fun isAppInForeground(): Boolean {
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
