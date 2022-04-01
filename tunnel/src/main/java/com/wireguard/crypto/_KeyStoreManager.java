/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * This class is supposed to manage the AndroidKeyStore Operations.
 * It can take an initial value and return a PSK in Base64 as String.
 */

package com.wireguard.crypto;

import android.content.Context;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;

import com.wireguard.crypto._HardwareBackedKey.HardwareType;
import com.wireguard.crypto._HardwareBackedKey.KeyType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
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
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * TODO: Not all characters are allowed for key labels/alias -> make sure to filter them at UI
 * This class offers:
 *      1. Crypto-Operations with AndroidKeyStore (AESCBC/AESECB enc and RSA sign)
 *      2. keyList to save HardwareBackedKeys (label/alias, type, slot=always 0 because not necessary)
 *      3. selectedKeyLabel to identify one AndroidKeyStore key to use in operations (provides Getter and Setter Method)
 *      4. Operations to store/load keyList and selectedKeyLabel into file HSMKeys.txt
 */
public class _KeyStoreManager {
    private static final String TAG = "WireGuard/KeyStoreManager";
    private String selectedKeyLabel = "NOTSELECTED";
    public List<_HardwareBackedKey> keyList;
    private Context context;
    public _KeyStoreManager(Context context) throws IOException {
        this.context = context;
        keyList = new ArrayList<>();
        loadKeys();
    }

    /**
     * Function to set which key is selected for operation.
     * // TODO: Prevent delimiter char '=' from being in Alias (and NOTSELECTED)
     *
     * @param label: Label/Alias of key.
     */
    public void setSelectedKeyLabel(String label) {
        selectedKeyLabel = label;
        try{
            storeKeys();
        } catch (IOException e) {
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
    public _HardwareBackedKey parseKey(String keyStoreKey) {
        String[] split = keyStoreKey.split(",");
        String label = split[0].split("=")[1];
        byte slot = Byte.valueOf(split[1].split("=")[1]);
        _HardwareBackedKey.KeyType type = _HardwareBackedKey.KeyType.valueOf(split[2].split("=")[1]);
        return new _HardwareBackedKey(HardwareType.KEYSTORE, label, slot, type);
    }

    /**
     * Function to load the HSM keys saved into keyList.
     *
     */
    public void loadKeys() throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        String line;
        BufferedReader in;
        try {
            in = new BufferedReader(new FileReader(new File(context.getFilesDir(), "KeyStoreKeys.txt")));
        }catch(FileNotFoundException e){
            Log.i(TAG, "File KeyStoreKeys.txt not found.");
            Log.e(TAG, Log.getStackTraceString(e));
            return;
        }
        int lineCounter = 0;
        while((line = in.readLine()) != null) {
            lineCounter++;
            /* Last line contains selectedKeyLabel */
            if(line.indexOf("selectedKeyLabel=") != -1) {
                break;
            }
            stringBuilder.append(line);
        }
        /* Check is list is empty */
        if(lineCounter > 1) {
            selectedKeyLabel = line.split("=")[1];
            String[] split = stringBuilder.toString().split("\n");
            for(String key: split) {
                keyList.add(parseKey(key));
            }
        }else{
            /* List is empty. Make sure selectedKey is NOTSELECTED. */
            setSelectedKeyLabel("NOTSELECTED");
            storeKeys();
        }
        in.close();
    }

    /**
     * Function to store the AndroidKeyStore keys into a file that later is used to load them again.
     *
     */
    public void storeKeys() throws IOException {
        String writeStr = new String();
        for(_HardwareBackedKey key: keyList) {
            writeStr += key.toString();
        }
        writeStr += "selectedKeyLabel=" + selectedKeyLabel;
        File path = context.getFilesDir();
        File file = new File(path, "KeyStoreKeys.txt");
        FileOutputStream stream = new FileOutputStream(file);
        try {
            stream.write(writeStr.getBytes());
        } finally {
            stream.close();
        }
    }

    /**
     * Function to add new AES key to AndroidKeyStore.
     * // TODO: Prevent delimiter char '=' from being in Alias (and NOTSELECTED)
     *
     * @param   key: String with key in Base64 format.
     * @param alias: Alias of key.
     * @return     : True for success. False for failure.
     */
    public boolean addKeyStoreKeyAESECB(String alias, String key) {
        /* Import AES key into KeyStore */
        byte[] importKeyBytes = Base64.decode(key, Base64.DEFAULT);
        SecretKey importKey = new SecretKeySpec(importKeyBytes, 0, importKeyBytes.length, "AES");
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.setEntry(
                    alias,
                    new KeyStore.SecretKeyEntry(importKey),
                    new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setRandomizedEncryptionRequired(false)
                            .build());
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
        /* add key keyList but check if key label alread exists
         * -> if yes update key (do not add to keyList) */
        List<_HardwareBackedKey> keyListCopy = new ArrayList<>(keyList);
        for(_HardwareBackedKey k : keyListCopy) {
            if(k.getLabel().equals(alias)){
                keyList.remove(k);
            }
        }
        keyList.add(new _HardwareBackedKey(HardwareType.KEYSTORE, alias, (byte) 0x0, KeyType.AESCBC));
        try {
            storeKeys();
        } catch (IOException e) {
            Log.i(TAG, "Failed to store updated keyList into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return true;
    }

    /**
     * Function to add new AES key to AndroidKeyStore.
     * // TODO: Prevent delimiter char '=' from being in Alias (and NOTSELECTED)
     *
     * @param   key: String with key in Base64 format.
     * @param alias: Alias of key.
     * @return     : True for success. False for failure.
     */
    public boolean addKeyStoreKeyAESCBC(String alias, String key) {
        /* Import AES key into KeyStore */
        byte[] importKeyBytes = Base64.decode(key, Base64.DEFAULT);
        SecretKey importKey = new SecretKeySpec(importKeyBytes, 0, importKeyBytes.length, "AES");
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
        /* add key keyList but check if key label alread exists
        * -> if yes update key (do not add to keyList) */
        List<_HardwareBackedKey> keyListCopy = new ArrayList<>(keyList);
        for(_HardwareBackedKey k : keyListCopy) {
            if(k.getLabel().equals(alias)){
                keyList.remove(k);
            }
        }
        keyList.add(new _HardwareBackedKey(HardwareType.KEYSTORE, alias, (byte) 0x0, KeyType.AESCBC));
        try {
            storeKeys();
        } catch (IOException e) {
            Log.i(TAG, "Failed to store updated keyList into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return true;
    }

    /**
     * Function to add new RSA key to AndroidKeyStore.
     * // TODO: Prevent delimiter char '=' from being in Alias (and NOTSELECTED)
     *
     * @param privKey: String of private key (RSA).
     * @param  pubKey: String of public key (RSA).
     * @param   alias: Alias of key.
     * @return       : Ture for success. False for failure.
     */
    public boolean addKeyStoreKeyRSA(String alias, String privKey, String pubKey) {
        // TODO: Implement (PROBLEM: CertificateChain necessary -> needs to be generated)

        try {
            storeKeys();
        } catch (IOException e) {
            Log.i(TAG, "Failed to store updated keyList into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return false;
    }

    /**
     * Function to remove key from AndroidKeyStore.
     *
     * @param alias: Alias of key.
     * @return     : True for success. False for failure.
     */
    public boolean deleteKey(String alias) {
        /* Handle keyList */
        _HardwareBackedKey key = getKeyFromAlias(alias);
        if(key != null) {
            keyList.remove(key);
        }else{
            Log.i(TAG, "Key alias not found in keyList.");
            return false;
        }
        try {
            storeKeys();
        } catch (IOException e) {
            Log.i(TAG, "Failed to store updated keyList into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }

        /* Handle KeyStore */
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
     * Function to get key from alias/label.
     *
     * @param alias: Alias of key we are looking for.
     * @return     : First _HardwareBackedKey with same label/alias.
     */
    public _HardwareBackedKey getKeyFromAlias(String alias) {
        for(_HardwareBackedKey key: keyList) {
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
    public List<_HardwareBackedKey> getKeyList() {
        return keyList;
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
}
