/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.hwwireguard;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;

import com.wireguard.hwwireguard.HWHardwareBackedKey.HardwareType;
import com.wireguard.hwwireguard.HWHardwareBackedKey.KeyType;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;

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
import java.security.InvalidAlgorithmParameterException;
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
public class HWKeyStoreManager {
    private static final String TAG = "WireGuard/KeyStoreManager";
    private String selectedKeyLabel = "NOTSELECTED";
    public List<HWHardwareBackedKey> keyList;
    private Context context;
    public HWKeyStoreManager(Context context) throws IOException {
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
    public HWHardwareBackedKey parseKey(String keyStoreKey) {
        String[] split = keyStoreKey.split(",");
        String label = split[0].split("=")[1];
        byte slot = Byte.valueOf(split[1].split("=")[1]);
        HWHardwareBackedKey.KeyType type = HWHardwareBackedKey.KeyType.valueOf(split[2].split("=")[1]);
        return new HWHardwareBackedKey(HardwareType.KEYSTORE, label, slot, type);
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
        for(HWHardwareBackedKey key: keyList) {
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

    // TODO: combine to one function addKeyStoreKey
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
        List<HWHardwareBackedKey> keyListCopy = new ArrayList<>(keyList);
        for(HWHardwareBackedKey k : keyListCopy) {
            if(k.getLabel().equals(alias)){
                keyList.remove(k);
            }
        }
        keyList.add(new HWHardwareBackedKey(HardwareType.KEYSTORE, alias, (byte) 0x0, KeyType.AESCBC));
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
        try {
            importAESKeyIntoKeyStore(alias, key);
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            Log.i(TAG, "Failed to add key to AndroidKeyStores.");
        }

        /* add key keyList but check if key label already exists
        * -> if yes update key (do not add to keyList) */
        List<HWHardwareBackedKey> keyListCopy = new ArrayList<>(keyList);
        for(HWHardwareBackedKey k : keyListCopy) {
            if(k.getLabel().equals(alias)){
                keyList.remove(k);
            }
        }
        keyList.add(new HWHardwareBackedKey(HardwareType.KEYSTORE, alias, (byte) 0x0, KeyType.AESCBC));
        try {
            storeKeys();
        } catch (IOException e) {
            Log.i(TAG, "Failed to store updated keyList into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return true;
    }

    /**
     * Function to import AES key into AndroidKeyStore.
     *
     * @param alias: Alias of key.
     * @param key  : Base64 encode AES key as String.
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    private void importAESKeyIntoKeyStore(final String alias, final String key) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        byte[] importKeyBytes = Base64.decode(key, Base64.DEFAULT);
        SecretKey importKey = new SecretKeySpec(importKeyBytes, 0, importKeyBytes.length, "AES");
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.setEntry(
                alias,
                new KeyStore.SecretKeyEntry(importKey),
                new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(false)
                        .build());
    }


    /**
     * Function to add new RSA key to AndroidKeyStore.
     * // TODO: Prevent delimiter char '=' from being in Alias (and NOTSELECTED)
     *
     * @param crtFile: Name of file in Downloads with pem or der certificate.
     * @param keyFile: Name of file in Downloads in PKCS#8 form.
     * @param   alias: Alias of key.
     * @return       : Ture for success. False for failure.
     */
    public boolean addKeyStoreKeyRSA(String alias, String crtFile, String keyFile) {
        try {
            /* Get certificate in pem format and create Certificate */
            String pathCrt = Environment.getExternalStorageDirectory() + File.separator + "Download" + File.separator + crtFile;
            Log.i(TAG, "Using this path for cert: " + pathCrt);
            byte[] fileContentCrt = Files.readAllBytes(Paths.get(pathCrt));
            Certificate cert =
                    CertificateFactory.getInstance("X.509").generateCertificate(
                            new ByteArrayInputStream(fileContentCrt));

            /* Get private key*/
            String pathKey = Environment.getExternalStorageDirectory() + File.separator + "Download" + File.separator + keyFile;
            Log.i(TAG, "Using this path for private key: " + pathKey);
            byte[] fileContentKey = Files.readAllBytes(Paths.get(pathKey));
            PrivateKey privateKey =
                    KeyFactory.getInstance("RSA").generatePrivate(
                            new PKCS8EncodedKeySpec(fileContentKey));

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                ks.setEntry(
                        alias,
                        new KeyStore.PrivateKeyEntry(privateKey, new Certificate[] {cert}),
                        new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                                .build());
            }
        } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            Log.i(TAG, "Failed to add key to AndroidKeyStores.");
            return false;
        }

        /* add key keyList but check if key label already exists
         * -> if yes update key (remove and add) */
        List<HWHardwareBackedKey> keyListCopy = new ArrayList<>(keyList);
        for(HWHardwareBackedKey k : keyListCopy) {
            if(k.getLabel().equals(alias)){
                keyList.remove(k);
            }
        }
        keyList.add(new HWHardwareBackedKey(HardwareType.KEYSTORE, alias, (byte) 0x0, KeyType.RSA));

        /* Store keys of keyList in KeyStoreKeys.txt file */
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
        HWHardwareBackedKey key = getKeyFromAlias(alias);
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
    public HWHardwareBackedKey getKeyFromAlias(String alias) {
        for(HWHardwareBackedKey key: keyList) {
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

    // TODO: clean up catch clause

    /**
     * Function to perform the AndroidKeyStore operation (AES_ECB or RSA).
     *
     * @param keyType: Allowed AES or RSA. AES leads to AES_ECB.
     * @param alias  : Alias of key to use.
     * @param init   : Input to sign or encrypt.
     * @return       : Key for newPSK.
     * @exception NoSuchAlgorithmException: KeyTypes AESECB and AESCBC are not allowed.
     */
    public Key keyStoreOperation(KeyType keyType, String alias, String init) {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            byte[] initBytes = init.getBytes("UTF8");

            if(keyType == KeyType.AES) {
                Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, keyStore.getKey(alias, null));
                MessageDigest sha256 = MessageDigest.getInstance("SHA256");

                /* Encrypt SHA256(initBytes) with AES_ECB */
                sha256.update(initBytes);
                byte[] digestBytes = sha256.digest();
                return Key.fromBase64(Base64.encodeToString(cipher.doFinal(digestBytes), Base64.DEFAULT));
            }else if(keyType == KeyType.RSA) {
                Signature sig = Signature.getInstance("SHA256WithRSA");
                sig.initSign(((KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null)).getPrivateKey());

                /* Sign initBytes with SHA256WithRSA */
                sig.update(initBytes);
                return Key.fromBase64(Base64.encodeToString(sig.sign(), Base64.DEFAULT));
            }else{
                throw new NoSuchAlgorithmException("This function only allows RSA and AES (AESECB)...");
            }
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | KeyFormatException | UnrecoverableEntryException | SignatureException e) {
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
}
