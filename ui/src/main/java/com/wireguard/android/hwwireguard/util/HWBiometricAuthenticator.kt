/*
 * Copyright © 2017-2021 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard.util

import android.os.AsyncTask
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.wireguard.android.hwwireguard.HWMonitor
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.hwwireguard.HWKeyStoreManager
import java.security.KeyStore
import java.security.Signature
import java.util.concurrent.Executors
import javax.crypto.Cipher


object HWBiometricAuthenticator {
    private const val TAG = "WireGuard/HWBiometricAuthenticator"

    fun keyStoreOperation(
            input: String,
            alias: String,
            tunnel: ObservableTunnel,
            monitor: HWMonitor
    ) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val keyEntry: KeyStore.Entry = keyStore.getEntry(alias, null)
        val authCallback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                //Looper.prepare()
                Log.w(TAG, "onAuthenticationError $errorCode $errString")
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                //Looper.prepare()
                Log.d(TAG, "onAuthenticationSucceeded " + result.cryptoObject)
                var result: ByteArray?
                if(keyEntry is KeyStore.PrivateKeyEntry) {
                    Log.i(TAG, "Using RSA...")
                    val signature = Signature.getInstance("SHA256WithRSA")
                    signature.initSign(keyEntry.privateKey)
                    result = signature.run {
                        update(input.toByteArray())
                        sign()
                    }
                }else if(keyEntry is KeyStore.SecretKeyEntry) {
                    Log.i(TAG, "Using AES...")
                    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, keyEntry.secretKey)
                    result = cipher.run {
                        doFinal(input.toByteArray())
                    }
                }else{
                    Log.i(TAG, "Key is not compatible with RSA or AES...")
                    result = null
                }
                if(result == null) return
                val config = tunnel.config ?: return
                monitor.loadNewPSK(tunnel, config, HWKeyStoreManager.bytesToKey(HWKeyStoreManager.sha256(result)))
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                //Looper.prepare()
                Log.w(TAG, "onAuthenticationFailed")
            }
        }
        val prompt = BiometricPrompt(
            monitor.mFragment,
            ContextCompat.getMainExecutor(monitor.mContext),
            authCallback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock your device to use KeyStore keys")
            .setConfirmationRequired(true)
            .setDeviceCredentialAllowed(true)
            .build()
        prompt.authenticate(promptInfo)
    }
}
