/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard.crypto

import android.content.Context
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.wireguard.android.hwwireguard.HWMonitor
import com.wireguard.android.model.ObservableTunnel
import java.security.KeyStore
import java.security.Signature
import javax.crypto.Cipher

/**
 * Class to hold keyStoreOperation with BiometricPrompt.
 */
class HWBiometricAuthenticator {
    /**
     * Function to perform keyStoreOperation for HWWireGuard with BiometricPrompt.
     */
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
                Log.w(TAG, "onAuthenticationError $errorCode $errString")
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
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
                val newPSK = HWKeyStoreManager.bytesToKey(HWKeyStoreManager.sha256(result))
                monitor.initPSK = newPSK
                Log.i(TAG, "Loading PSK " + newPSK.toBase64())
                monitor.loadNewPSK(config, newPSK)
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
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

    companion object {
        private const val TAG = "WireGuard/HWBiometricAuthenticator"
    }
}
