/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * This class is supposed to manage the AndroidKeyStore Operations.
 * It can take an initial value and return a PSK in Base64 as String.
 */

package com.wireguard.crypto;

import android.os.Build;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyStoreManager {
    private static final String TAG = "WireGuard/KeyStoreManager";
    public KeyStoreManager() { }

    /**
     * Function to add new AES key to AndroidKeyStore.
     *
     * @param   key: String with key in Base64 format.
     * @param alias: Alias of key.
     * @return     : True for success. False for failure.
     */
    public boolean addKeyStoreKeyAES(String alias, String key) {
        /* Import AES key into KeyStore */
        byte[] importKeyBytes = Base64.decode(key, Base64.DEFAULT);
        SecretKey importKey = new SecretKeySpec(importKeyBytes, 0, importKeyBytes.length, "AES");
        Log.i(TAG, "Key: " + Base64.encodeToString(importKey.getEncoded(), Base64.DEFAULT));
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.setEntry(
                    alias,
                    new KeyStore.SecretKeyEntry(importKey),
                    new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setRandomizedEncryptionRequired(false)
                            .build());
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
        return true;
    }

    /**
     * Function to add new RSA key to AndroidKeyStore.
     *
     * @param privKey: String of private key (RSA).
     * @param  pubKey: String of public key (RSA).
     * @param   alias: Alias of key.
     * @return       : Ture for success. False for failure.
     */
    public boolean addKeyStoreKeyRSA(String alias, String privKey, String pubKey) {
        // TODO: Implement (PROBLEM: CertificateChain necessary -> needs to be generated)
        return false;
    }

    /**
     * Function to remove key from AndroidKeyStore.
     *
     * @param alias: Alias of key.
     * @return     : True for success. False for failure.
     */
    public boolean deleteKey(String alias) {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry(alias);
            return true;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
    }

    /**
     * Function to return key with init as initial value (Using AES CBC).
     *
     * @param alias: String with alias of key from AndroidKeyStore that should be used.
     * @param    iv: String with IV for AES CBC (needs to be the same for both WireGuard-Peers.
     * @param  init: String with init value.
     * @return     : Key that can be used as new PSK.
     */
    public Key keyStoreOperationAESCBC(String alias, String iv, String init) {
        KeyStore keystore;
        try {
            /* Get correct key from AndroidKeyStore */
            keystore = KeyStore.getInstance("AndroidKeyStore");
            keystore.load(null);
            java.security.Key key = keystore.getKey(alias, null);

            /* Prepare cipher */
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            Log.i("MAIN_ACTIVITY", "Using IV: " + Base64.encodeToString(cipher.getIV(), Base64.DEFAULT));

            /* Encrypt init with AES_CBC*/
            byte[] initBytes = init.getBytes("UTF-8");
            MessageDigest sha256 = MessageDigest.getInstance("SHA256");
            sha256.update(initBytes);
            byte[] digestBytes = sha256.digest();
            byte[] pskBytes = cipher.doFinal(digestBytes);

            /* Return new PSK */
            return Key.fromBase64(Base64.encodeToString(pskBytes, Base64.DEFAULT));
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | KeyFormatException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }

    /**
     * Function to return key with init as initial value (Using AES ECB).
     *
     * @param alias: String with alias of key from AndroidKeyStore that should be used.
     * @param  init: String with init value.
     * @return     : Key that can be used as new PSK.
     */
    public Key keyStoreOperationAESECB(String alias, String init) {
        KeyStore keystore;
        try {
            /* Get correct key from AndroidKeyStore */
            keystore = KeyStore.getInstance("AndroidKeyStore");
            keystore.load(null);
            java.security.Key key = keystore.getKey(alias, null);

            /* Prepare cipher */
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            /* Encrypt init with AES_CBC*/
            byte[] initBytes = init.getBytes("UTF-8");
            MessageDigest sha256 = MessageDigest.getInstance("SHA256");
            sha256.update(initBytes);
            byte[] digestBytes = sha256.digest();
            byte[] pskBytes = cipher.doFinal(digestBytes);

            /* Return new PSK */
            return Key.fromBase64(Base64.encodeToString(pskBytes, Base64.DEFAULT));
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | KeyFormatException | InvalidKeyException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }

    /**
     * Function to return key with init as initial value (using RSA Signatur).
     *
     * @param alias: String with alias of key from AndroidKeyStore that should be used.
     * @param  init: String with init value.
     * @return     : Key that can be used as new PSK.
     */
    public Key keyStoreOperationRSA(String alias, String init) {
        KeyStore keyStore = null;
        Key key = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyStore.Entry entry = keyStore.getEntry(alias, null);
            PrivateKey privKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            byte[] data = init.getBytes("UTF8");
            Signature sig = Signature.getInstance("SHA256WithRSA");
            sig.initSign(privKey);
            sig.update(data);
            byte[] pskBytes = sig.sign();
            return Key.fromBase64(Base64.encodeToString(pskBytes, Base64.DEFAULT));
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException | InvalidKeyException | SignatureException | KeyFormatException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }

    /**
     * Function to return all keys in AndroidKeyStore that can be used.
     *
     * @return: HashMap of all keys with their entry.
     */
    public HashMap<String, String> getAndroidKeyStoreKeys() {
        HashMap<String, String> keys = new HashMap();
        KeyStore keystore = null;
        try {
            /* Get alias of all keys */
            keystore = KeyStore.getInstance("AndroidKeyStore");
            keystore.load(null);
            Enumeration<String> enumeration = keystore.aliases();
            while(enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                Log.i(TAG, "alias name: " + alias);
                KeyStore.Entry entry = keystore.getEntry(alias, null);
                Log.i(TAG, entry.toString());
                /* Process keys into customKeyStore */
                keys.put(alias, entry.toString());
            }
            return keys;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }

    /**
     * Function to return which key is selected.
     * @return: String with alias of key that is selected.
     */
    public String getSelectedKey(){
        // TODO: Implement
        return null;
    }
}
