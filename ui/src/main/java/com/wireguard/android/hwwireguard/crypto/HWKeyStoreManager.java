/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard.crypto;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Environment;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;

import com.wireguard.android.hwwireguard.HWMonitor;
import com.wireguard.android.model.ObservableTunnel;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import androidx.annotation.NonNull;

/**
 * TODO: Not all characters are allowed for key labels/alias -> make sure to filter them at UI
 * This class offers:
 *      1. Crypto-Operations with AndroidKeyStore (AES enc and RSA sign)
 *      2. keyList to save HardwareBackedKeys (label/alias, type, slot=always 0 because not necessary)
 *      3. selectedKeyLabel to identify one AndroidKeyStore key to use in operations (provides Getter and Setter Method)
 *      4. Operations to store/load keyList and selectedKeyLabel into file HSMKeys.txt
 */
public class HWKeyStoreManager {
    /**
     * HWBiometricAuthenticator has keyStoreOperation function with BiometricPrompt.
     */
    public HWBiometricAuthenticator biometricAuthenticator = new HWBiometricAuthenticator();
    private static final String TAG = "WireGuard/KeyStoreManager";
    private final Context context;

    public HWKeyStoreManager(final Context context) {
        this.context = context;
    }

    /**
     * Function to remove key from AndroidKeyStore.
     * @param alias: Alias of key.
     */
    public void deleteKey(final String alias) {
        /* Handle KeyStore */
        try {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry(alias);
        } catch (final KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    /**
     * Function to add new AES key to AndroidKeyStore.
     * @param keyFile: File name with AES key encoded in Base64.
     * @param   alias: Alias of key.
     */
    public boolean addKeyStoreKeyAES(final String alias, final String keyFile) {
        /* Import AES key into KeyStore from file */
        try {
            final String pathKey = Environment.getExternalStorageDirectory() + File.separator + "Download" + File.separator + keyFile;
            Log.i(TAG, "Using this path for key: " + pathKey);
            final byte[] fileContent = Files.readAllBytes(Paths.get(pathKey));
            final byte[] importKeyBytes = Base64.decode(fileContent, Base64.DEFAULT);
            final SecretKey importKey = new SecretKeySpec(importKeyBytes, 0, importKeyBytes.length, "AES");
            addAESKeyToAndroidKeyStore(alias, importKey);
            return true;
        } catch (final KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
    }

    /**
     * Function to add SecretKey to KeyStore.
     * @param alias    : String with alias of key.
     * @param importKey: SecretKey.
     */
    private void addAESKeyToAndroidKeyStore(final String alias, final SecretKey importKey) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.setEntry(
                alias,
                new KeyStore.SecretKeyEntry(importKey),
                new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(false)
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(6*60*60)
                        .build());
    }

    /**
     * Function to add new RSA key to AndroidKeyStore.
     * @param crtFile: Name of file in Downloads with pem or der certificate.
     * @param keyFile: Name of file in Downloads in PKCS#8 form.
     * @param   alias: Alias of key.
     */
    public boolean addKeyStoreKeyRSA(final String alias, final String crtFile, final String keyFile) {
        try {
            /* Get certificate in pem format and create Certificate */
            final Certificate cert = getCertificate(crtFile);

            /* Get private key */
            final PrivateKey privateKey = getPrivateKey(keyFile);

            /* add private key with cert to AndroidKeyStore Entries */
            addRSAKeyToAndroidKeyStore(alias, cert, privateKey);
            return true;
        } catch (final IOException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException e) {
            Log.i(TAG, "Failed to add key to AndroidKeyStores.");
            return false;
        }
    }

    /**
     * Function to get RSA PrivateKey from keyFile in Download folder.
     * @param keyFile: String with name of keyFile.
     * @return       : PrivateKey.
     */
    private PrivateKey getPrivateKey(final String keyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        final String pathKey = Environment.getExternalStorageDirectory() + File.separator + "Download" + File.separator + keyFile;
        Log.i(TAG, "Using this path for private key: " + pathKey);
        final byte[] fileContentKey = Files.readAllBytes(Paths.get(pathKey));
        final PrivateKey privateKey =
                KeyFactory.getInstance("RSA").generatePrivate(
                        new PKCS8EncodedKeySpec(fileContentKey));
        return privateKey;
    }

    /**
     * Function to get RSA Certificate from crtFile in Download folder.
     * @param crtFile: String with name of crtFile.
     * @return       : Certificate.
     */
    private Certificate getCertificate(final String crtFile) throws IOException, CertificateException {
        final String pathCrt = Environment.getExternalStorageDirectory() + File.separator + "Download" + File.separator + crtFile;
        Log.i(TAG, "Using this path for cert: " + pathCrt);
        final byte[] fileContentCrt = Files.readAllBytes(Paths.get(pathCrt));
        final Certificate cert =
                CertificateFactory.getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(fileContentCrt));
        return cert;
    }

    /**
     * Function to add entry to KeyStore. PrivateKey and Certificate required.
     * @param alias     : String with alias/name of key.
     * @param cert      : Certificate.
     * @param privateKey: PrivateKey.
     */
    private void addRSAKeyToAndroidKeyStore(final String alias, final Certificate cert, final PrivateKey privateKey) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        ks.setEntry(
                alias,
                new KeyStore.PrivateKeyEntry(privateKey, new Certificate[] {cert}),
                new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(6*60*60)
                        .build());
    }

    // TODO: clean up catch clause
    /**
     * Function for keyStoreOperation.
     * @param input  : Timestamp/Init that will be signed/encrypted.
     * @param alias  : String with name of key to use.
     * @param tunnel : Tunnel that PSK will be changed.
     * @param monitor: Monitor for access to biometricAuthenticator functions.
     * @return       : Key with new PSK if no BiometricPrompt. Null if BiometricPrompt.
     */
    public Key keyStoreOperation(String input, String alias, ObservableTunnel tunnel, HWMonitor monitor) {
        try {
            Key newPSK = keyStoreOperationNoBio(input, alias, tunnel, monitor);
            return newPSK;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException | KeyFormatException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | SignatureException e) {
            Log.i(TAG, "We have to use withBio");
            keyStoreOperationWithBio(input, alias, tunnel, monitor);
            return null;
        }
    }

    /**
     * Function that calls BiometricPrompt (which automatically loads new PSK into backend)
     */
    public void keyStoreOperationWithBio(String input, String alias, ObservableTunnel tunnel, HWMonitor monitor) {
        biometricAuthenticator.keyStoreOperation(input, alias, tunnel, monitor);
    }

    /**
     * Function to perform the AndroidKeyStore operation (AES_ECB or RSA).
     * @param alias  : Alias of key to use.
     * @param init   : Input to sign or encrypt.
     * @return       : Key for newPSK.
     */
    public Key keyStoreOperationNoBio(final String init, final String alias, final ObservableTunnel tunnel, final HWMonitor monitor) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyFormatException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {
        Key newPSK = null;
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.Entry keyEntry = keyStore.getEntry(alias, null);
        if(keyEntry instanceof KeyStore.SecretKeyEntry) {
            newPSK =  aesOperation(keyEntry, init.getBytes(StandardCharsets.UTF_8));
        } else if(keyEntry instanceof KeyStore.PrivateKeyEntry) {
            newPSK =  rsaOperation(keyEntry, init.getBytes(StandardCharsets.UTF_8));
        }
        if(newPSK == null) {
            Log.i(TAG, "newPSK is null... something is wrong with AndroidKeyStore Entries.");
        }
        return newPSK;
    }

    /**
     * Function to perform the RSA operation.
     * @param keyEntry : KeyEntry to use.
     * @param initBytes: Init to be signed.
     * @return         : Key for newPSK.
     */
    @NonNull private Key rsaOperation(final KeyStore.Entry keyEntry, final byte[] initBytes) throws NoSuchAlgorithmException, InvalidKeyException, KeyStoreException, UnrecoverableEntryException, SignatureException, KeyFormatException {
        final Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initSign(((KeyStore.PrivateKeyEntry) keyEntry).getPrivateKey());

        /* Sign initBytes with SHA256WithRSA */
        sig.update(initBytes);
        byte[] signature = sig.sign();
        return bytesToKey(sha256(signature));
    }

    /**
     * Function to perform
     * @param keyEntry
     * @param initBytes
     * @return
     */
    @NonNull private Key aesOperation(final KeyStore.Entry keyEntry, final byte[] initBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, KeyFormatException, IllegalBlockSizeException, BadPaddingException {
        @SuppressLint("GetInstance") final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, ((KeyStore.SecretKeyEntry) keyEntry).getSecretKey());
        byte[] digest = sha256(initBytes);

        /* Encrypt with AES */
        return bytesToKey(sha256(cipher.doFinal(digest)));
    }

    /**
     * Function transforms byte[] of key in hex to type Key.
     * @param bytes: Byte array with key.
     * @return     : Key.
     */
    public static Key bytesToKey(final byte[] bytes) throws KeyFormatException {
        final StringBuilder strSig = new StringBuilder();
        for (final byte aByte : bytes) {
            strSig.append(String.format("%02x", aByte));
        }
        return Key.fromHex(strSig.toString());
    }

    /**
     * Function perform sha256 operation on data.
     * @param data: Byte array for input.
     * @return    : Byte array with output.
     */
    public static byte[] sha256(final byte[] data) throws NoSuchAlgorithmException {
        final MessageDigest sha256 = MessageDigest.getInstance("SHA256");
        sha256.update(data);
        return sha256.digest();
    }
}
