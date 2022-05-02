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
import com.wireguard.android.hwwireguard.crypto.HWHardwareBackedKey.HardwareType;
import com.wireguard.android.hwwireguard.crypto.HWHardwareBackedKey.KeyType;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
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
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

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
 *      1. Crypto-Operations with AndroidKeyStore (AES_ECB enc and RSA sign)
 *      2. keyList to save HardwareBackedKeys (label/alias, type, slot=always 0 because not necessary)
 *      3. selectedKeyLabel to identify one AndroidKeyStore key to use in operations (provides Getter and Setter Method)
 *      4. Operations to store/load keyList and selectedKeyLabel into file HSMKeys.txt
 */
public class HWKeyStoreManager {
    public HWBiometricAuthenticator biometricAuthenticator;
    private static final String TAG = "WireGuard/KeyStoreManager";
    private String selectedKeyLabel = "UNSELECTED";
    private final List<HWHardwareBackedKey> keyList;
    private final Context context;

    public HWKeyStoreManager(final Context context) throws IOException {
        this.context = context;
        keyList = new ArrayList<>();
        loadKeys();
    }

    /**
     * Function to set which key is selected for operation.
     * // TODO: Prevent delimiter char '=' from being in Alias (and UNSELECTED)
     *
     */
    private void setSelectedKeyLabel(String alias) {
        selectedKeyLabel = alias;
        try{
            storeKeys();
        } catch (final IOException e) {
            Log.i(TAG, "Failed to store updated keyList into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    /**
     * Function to return which key is selected.
     *
     * @return: String with alias of key that is selected.
     */
    public String getSelectedKey(){
        return selectedKeyLabel;
    }

    /**
     * Function to parse key in String format.
     *
     * @param keyStoreKey: String with key.
     * @return           : HSMKey.
     */
    private static HWHardwareBackedKey parseKey(final String keyStoreKey) {
        final String[] split = keyStoreKey.split(",");
        final String label = split[0].split("=")[1];
        final byte slot = Byte.parseByte(split[1].split("=")[1]);
        final KeyType type = KeyType.valueOf(split[2].split("=")[1]);
        return new HWHardwareBackedKey(HardwareType.KEYSTORE, label, slot, type);
    }

    /**
     * Function to load the HSM keys saved into keyList.
     *
     */
    private void loadKeys() throws IOException {
        final StringBuilder stringBuilder = new StringBuilder();
        String line;
        final BufferedReader in;
        try {
            in = new BufferedReader(new FileReader(new File(context.getFilesDir(), "KeyStoreKeys.txt")));
        }catch(final FileNotFoundException e){
            Log.i(TAG, "File KeyStoreKeys.txt not found.");
            Log.e(TAG, Log.getStackTraceString(e));
            return;
        }
        int lineCounter = 0;
        while((line = in.readLine()) != null) {
            lineCounter++;
            /* Last line contains selectedKeyLabel */
            if(line.contains("selectedKeyLabel=")) {
                break;
            }
            stringBuilder.append(line);
        }
        /* Check that list is not empty */
        if(lineCounter > 1) {
            /* List has keys */
            assert line != null;
            setSelectedKeyLabel(line.split("=")[1]);
            final String[] split = stringBuilder.toString().split("\n");
            for(final String key: split) {
                keyList.add(parseKey(key));
            }
        }else{
            /* List is empty. Make sure selectedKey is UNSELECTED. */
            setSelectedKeyLabel("UNSELECTED");
            storeKeys();
        }
        in.close();
    }

    /**
     * Function to store the AndroidKeyStore keys into a file that later is used to load them again.
     *
     */
    private void storeKeys() throws IOException {
        final StringBuilder writeStr = new StringBuilder();
        for(final HWHardwareBackedKey key: keyList) {
            writeStr.append(key.toString());
        }
        writeStr.append("selectedKeyLabel=").append(selectedKeyLabel);
        final File path = context.getFilesDir();
        final File file = new File(path, "KeyStoreKeys.txt");
        try (final FileOutputStream stream = new FileOutputStream(file)) {
            stream.write(writeStr.toString().getBytes());
        }
    }

    /**
     * Function to remove key from AndroidKeyStore.
     *
     * @param alias: Alias of key.
     * @return     : True for success. False for failure.
     */
    public boolean deleteKey(final String alias) {
        /* Handle KeyStore */
        try {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry(alias);
        } catch (final KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }

        /* Handle keyList */
        final HWHardwareBackedKey key = getKeyFromAlias(alias);
        if(key != null) {
            keyList.remove(key);
        }else{
            Log.i(TAG, "Key alias not found in keyList.");
            return false;
        }
        try {
            storeKeys();
            return true;
        } catch (final IOException e) {
            Log.i(TAG, "Failed to store updated keyList into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
    }

    /**
     * Function to get key from alias/label.
     *
     * @param alias: Alias of key we are looking for.
     * @return     : First _HardwareBackedKey with same label/alias.
     */
    public HWHardwareBackedKey getKeyFromAlias(String alias) {
        for(final HWHardwareBackedKey key: keyList) {
            if(key.getLabel().equals(alias)) {
                return key;
            }
        }
        return null;
    }

    /**
     * Function to return the keyList.
     * @return: keyList.
     */
    public List<HWHardwareBackedKey> getKeyList() {
        return keyList;
    }

    /**
     * Function to return all keys in AndroidKeyStore that can be used.
     *
     * @return: HashMap of all keys with their entry.
     */
    public static HashMap<String, String> getAndroidKeyStoreKeys() {
        try {
            /* Get alias of all keys */
            final KeyStore keystore = KeyStore.getInstance("AndroidKeyStore");
            keystore.load(null);
            final Enumeration<String> enumeration = keystore.aliases();
            final HashMap keys = new HashMap();
            while(enumeration.hasMoreElements()) {
                final String alias = enumeration.nextElement();
                Log.i(TAG, "alias name: " + alias);
                final KeyStore.Entry entry = keystore.getEntry(alias, null);
                Log.i(TAG, entry.toString());
                /* Process keys into customKeyStore */
                keys.put(alias, entry.toString());
            }
            return keys;
        } catch (final KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }

    // TODO: combine to one function addKeyStoreKey
    /**
     * Function to add new AES key to AndroidKeyStore.
     * // TODO: Prevent delimiter char '=' from being in Alias (and UNSELECTED)
     *
     * @param   key: String with key in Base64 format.
     * @param alias: Alias of key.
     * @return     : True for success. False for failure.
     */
    public boolean addKeyStoreKeyAES(final String alias, final String key) {
        /* Import AES key into KeyStore */
        final byte[] importKeyBytes = Base64.decode(key, Base64.DEFAULT);
        final SecretKey importKey = new SecretKeySpec(importKeyBytes, 0, importKeyBytes.length, "AES");
        try {
            addAESKeyToAndroidKeyStore(alias, importKey);
        } catch (final KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
        /* add key keyList but check if key label already exists
         * -> if yes update key (do not add to keyList) */
        final Iterable<HWHardwareBackedKey> keyListCopy = new ArrayList<>(keyList);
        for(final HWHardwareBackedKey k : keyListCopy) {
            if(k.getLabel().equals(alias)){
                keyList.remove(k);
            }
        }
        keyList.add(new HWHardwareBackedKey(HardwareType.KEYSTORE, alias, (byte) 0x0, KeyType.AES));
        try {
            storeKeys();
        } catch (final IOException e) {
            Log.i(TAG, "Failed to store updated keyList into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return true;
    }

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
                        .build());
    }

    /**
     * Function to add new RSA key to AndroidKeyStore.
     * // TODO: Prevent delimiter char '=' from being in Alias (and UNSELECTED)
     *
     * @param crtFile: Name of file in Downloads with pem or der certificate.
     * @param keyFile: Name of file in Downloads in PKCS#8 form.
     * @param   alias: Alias of key.
     * @return       : Ture for success. False for failure.
     */
    public boolean addKeyStoreKeyRSA(final String alias, final String crtFile, final String keyFile) {
        try {
            /* Get certificate in pem format and create Certificate */
            final Certificate cert = getCertificate(crtFile);

            /* Get private key */
            final PrivateKey privateKey = getPrivateKey(keyFile);

            /* add private key with cert to AndroidKeyStore Entries */
            addRSAKeyToAndroidKeyStore(alias, cert, privateKey);
        } catch (final IOException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            Log.i(TAG, "Failed to add key to AndroidKeyStores.");
            return false;
        }

        /* add key keyList but check if key label already exists
         * -> if yes update key (remove and add) */
        final Iterable<HWHardwareBackedKey> keyListCopy = new ArrayList<>(keyList);
        for(final HWHardwareBackedKey k : keyListCopy) {
            if(k.getLabel().equals(alias)){
                keyList.remove(k);
            }
        }
        keyList.add(new HWHardwareBackedKey(HardwareType.KEYSTORE, alias, (byte) 0x0, KeyType.RSA));

        /* Store keys of keyList in KeyStoreKeys.txt file */
        try {
            storeKeys();
        } catch (final IOException e) {
            Log.i(TAG, "Failed to store updated keyList into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return false;
    }

    private PrivateKey getPrivateKey(final String keyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        final String pathKey = Environment.getExternalStorageDirectory() + File.separator + "Download" + File.separator + keyFile;
        Log.i(TAG, "Using this path for private key: " + pathKey);
        final byte[] fileContentKey = Files.readAllBytes(Paths.get(pathKey));
        final PrivateKey privateKey =
                KeyFactory.getInstance("RSA").generatePrivate(
                        new PKCS8EncodedKeySpec(fileContentKey));
        return privateKey;
    }

    private Certificate getCertificate(final String crtFile) throws IOException, CertificateException {
        final String pathCrt = Environment.getExternalStorageDirectory() + File.separator + "Download" + File.separator + crtFile;
        Log.i(TAG, "Using this path for cert: " + pathCrt);
        final byte[] fileContentCrt = Files.readAllBytes(Paths.get(pathCrt));
        final Certificate cert =
                CertificateFactory.getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(fileContentCrt));
        return cert;
    }

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
                        .setUserAuthenticationValidityDurationSeconds(10)
                        .build());
    }

    public Key keyStoreOperationWithBio(String input, String alias, ObservableTunnel tunnel, HWMonitor monitor) {

        return null;
    }

    // TODO: clean up catch clause
    /**
     * Function to perform the AndroidKeyStore operation (AES_ECB or RSA).
     *
     * @param keyType : Allowed AES or RSA. AES leads to AES_ECB.
     * @param alias  : Alias of key to use.
     * @param init   : Input to sign or encrypt.
     * @return       : Key for newPSK.
     */
    public Key keyStoreOperationNoBio(final KeyType keyType, final String alias, final String init) {
        try {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final byte[] initBytes = init.getBytes(StandardCharsets.UTF_8);

            if(keyType == KeyType.AES) {
                return aesOperation(alias, keyStore, initBytes);
            }else if(keyType == KeyType.RSA) {
                return rsaOperation(alias, keyStore, initBytes);
            }else{
                return null;
            }
        } catch (final KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | KeyFormatException | IllegalBlockSizeException | BadPaddingException | UnrecoverableEntryException | SignatureException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }

    @NonNull private Key rsaOperation(final String alias, final KeyStore keyStore, final byte[] initBytes) throws NoSuchAlgorithmException, InvalidKeyException, KeyStoreException, UnrecoverableEntryException, SignatureException, KeyFormatException {
        final Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initSign(((KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null)).getPrivateKey());

        /* Sign initBytes with SHA256WithRSA */
        sig.update(initBytes);
        byte[] signature = sig.sign();
        return bytesToKey(sha256(signature));
    }

    // TODO: Encrypt not yet implemented
    @NonNull private Key aesOperation(final String alias, final KeyStore keyStore, final byte[] initBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, KeyStoreException, UnrecoverableKeyException, KeyFormatException, IllegalBlockSizeException, BadPaddingException {
        @SuppressLint("GetInstance") final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keyStore.getKey(alias, null));
        byte[] digest = sha256(initBytes);

        /* Encrypt with AES */
        return bytesToKey(sha256(cipher.doFinal(digest)));
    }

    /**
     * Function transforms byte[] of key in hex to type Key.
     *
     * @param bytes: Byte array with key.
     * @return     : Key.
     */
    public static Key bytesToKey(final byte[] bytes) throws KeyFormatException {
        final StringBuilder strSig = new StringBuilder();
        for (final byte aByte : bytes) {
            strSig.append(String.format("%02x", aByte));
        }
        Log.i(TAG, "psk: " + strSig);
        return Key.fromHex(strSig.toString());
    }

    /**
     * Function perform sha256 operation on data.
     *
     * @param data: Byte array for input.
     * @return    : Byte array with output.
     */
    public static byte[] sha256(final byte[] data) throws NoSuchAlgorithmException {
        final MessageDigest sha256 = MessageDigest.getInstance("SHA256");
        sha256.update(data);
        return sha256.digest();
    }
}
