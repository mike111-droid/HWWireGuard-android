/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * This class is supposed to manage the SmartCard-HSM by CardContact Systems GmbH.
 * It can take an initial value and return a PSK in Base64 as String.
 */

package com.wireguard.crypto;

import android.content.Context;
import android.util.Log;

import com.wireguard.android.backend.Backend;
import com.wireguard.crypto._HardwareBackedKey.HardwareType;
import com.wireguard.crypto._HardwareBackedKey.KeyType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import de.cardcontact.opencard.android.swissbit.SBMicroSDCardTerminalFactory;
import de.cardcontact.opencard.factory.SmartCardHSMCardServiceFactory;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMCardService;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMKey;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMRSAKey;
import de.cardcontact.opencard.utils.StreamingAPDUTracer;
import opencard.core.service.CardRequest;
import opencard.core.service.CardServiceException;
import opencard.core.service.CardServiceFactory;
import opencard.core.service.CardServiceRegistry;
import opencard.core.service.SmartCard;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CardTerminalRegistry;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;


/**
 * Necessary Class for SmartCard-HSM interaction.
 */
class LogCatOutputStream_ extends OutputStream {
    @Override
    public synchronized void write(byte[] buffer, int offset, int len) {
        Log.i("SmartCard-HSM", new String(buffer, offset, len));
    }

    @Override
    public void write(int oneByte) throws IOException {
    }
}

/**
 * TODO: Not all characters are allowed for key labels/alias -> make sure to filter them at UI
 * This class offers:
 *      1. Crypto-Operations with SmartCard-HSM (AES___ enc and RSA sign)
 *      2. keyList to save HardwareBackedKeys (label/alias, type, slot)
 *      3. selectedKeyLabel to identify one SmartCard-HSM key to use in operations (provides Getter and Setter Method)
 *      4. Operations to store/load keyList and selectedKeyLabel into file HSMKeys.txt
 */
public class _HSMManager {
    private static final String TAG = "WireGuard/HSMManager";
    private String selectedKeyLabel = "NOTSELECTED";
    public List<_HardwareBackedKey> keyList;
    private Context context;
    public _HSMManager(Context context) throws IOException {
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
     * @param hsmKey: String with key.
     * @return      : HSMKey.
     */
    public _HardwareBackedKey parseKey(String hsmKey) {
        String[] split = hsmKey.split(",");
        String label = split[0].split("=")[1];
        byte slot = Byte.valueOf(split[1].split("=")[1]);
        _HardwareBackedKey.KeyType type = _HardwareBackedKey.KeyType.valueOf(split[2].split("=")[1]);
        return new _HardwareBackedKey(HardwareType.HSM, label, slot, type);
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
            in = new BufferedReader(new FileReader(new File(context.getFilesDir(), "HSMKeys.txt")));
        }catch(FileNotFoundException e){
            Log.i(TAG, "File HSMKey.txt not found.");
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
     * Function to store the HSM keys into a file that later is used to load them again.
     *
     */
    public void storeKeys() throws IOException {
        String writeStr = new String();
        for(_HardwareBackedKey key: keyList) {
            writeStr += key.toString();
        }
        writeStr += "selectedKeyLabel=" + selectedKeyLabel;
        File path = context.getFilesDir();
        File file = new File(path, "HSMKeys.txt");
        FileOutputStream stream = new FileOutputStream(file);
        try {
            stream.write(writeStr.getBytes());
        } finally {
            stream.close();
        }
    }

    /**
     * Function to add key to keyList.
     * // TODO: Prevent delimiter char '=' from being in Alias (and NOTSELECTED)
     *
     * @param key: Key to be added.
     */
    public void addKey(_HardwareBackedKey key) {
        /* add key keyList but check if key label already exists
         * -> if yes update key (remove old one and add new one) */
        List<_HardwareBackedKey> keyListCopy = new ArrayList<>(keyList);
        for(_HardwareBackedKey k : keyListCopy) {
            if(k.getLabel().equals(key.getLabel())){
                keyList.remove(k);
            }
        }
        keyList.add(key);
        try {
            storeKeys();
        } catch (IOException e) {
            Log.i(TAG, "Failed to store into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    /**
     * Function to delete key from keyList.
     *
     * @param label: Key to be deleted.
     */
    public void deleteKey(String label) {
        _HardwareBackedKey key = getKeyFromAlias(label);
        if(key != null) {
            keyList.remove(key);
        }else{
            Log.i(TAG, "Key alias not found in keyList.");
            return;
        }
        try {
            storeKeys();
        } catch (IOException e) {
            Log.i(TAG, "Failed to store updated keyList into HSMKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
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
     * Function to perform either AES or RSA operation on the HSM.
     *
     * @param keyType: Specifies whether to use KeyType.AES or KeyType.RSA.
     * @param pin
     * @param init
     * @param keyID
     * @return
     */
    public Key hsmOperation(_HardwareBackedKey.KeyType keyType, String pin, String init, byte keyID) throws NoSuchAlgorithmException{
        Key newPSK = null;
        try {
            /* Startup */
            Log.i(TAG, "OCF startup...");
            SmartCard.startup();
            Log.i(TAG, "Creating card terminal registry...");
            CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();

            /* Add SwissBit card terminal to registry */
            SBMicroSDCardTerminalFactory sbcardf = new SBMicroSDCardTerminalFactory(context);
            sbcardf.createCardTerminals(ctr, null);

            /* Creating service registry */
            Log.i(TAG, "Creating card service registry...");
            CardServiceRegistry csr = CardServiceRegistry.getRegistry();

            /* Adding card service */
            Log.i(TAG, "Adding SmartCard-HSM card service...");
            CardServiceFactory csf = new SmartCardHSMCardServiceFactory();
            csr.add(csf);

            Log.i(TAG, "Creating card request...");
            CardRequest cr = new CardRequest(CardRequest.ANYCARD, null, SmartCardHSMCardService.class);
            SmartCard sc = SmartCard.waitForCard(cr);
            if (sc == null) {
                Log.i("SmartCard-HSM", "Could not get smart card...");
                return null;
            }

            sc.setAPDUTracer(new StreamingAPDUTracer(new PrintStream(new LogCatOutputStream_())));
            Log.i(TAG, "Card found");

            Log.i(TAG, "Trying to create card service...");
            SmartCardHSMCardService schsmcs = (SmartCardHSMCardService) sc.getCardService(SmartCardHSMCardService.class, true);

            /* Verify the PIN */
            Log.i(TAG, "Verifying PIN...");
            if(!schsmcs.verifyPassword(null, 0, pin.getBytes())) {
                Log.i(TAG, "PIN is incorrect. More than 3 false pins lead to locked devices!");
                return null;
            }

            /* init to bytes */
            byte[] data = init.getBytes();
            StringBuilder tmp2 = new StringBuilder();
            for (byte aByte : data) {
                tmp2.append(String.format("%02x", aByte));
            }
            Log.i(TAG, "data: " + tmp2.toString());

            /* Hashing of data */
            MessageDigest sha256 = MessageDigest.getInstance("SHA256");
            sha256.update(data);
            byte[] digest = sha256.digest();
            Log.i(TAG, "sha256.digest: " + digest.toString());

            /* HSM Operation */
            byte[] res = null;
            if(keyType == KeyType.AES) {
                /* AES on HSM */
                res = hsmOperationAES(schsmcs, digest, keyID);
            }else if(keyType == KeyType.RSA){
                /* RSA on HSM */
                res = hsmOperationRSA(schsmcs, digest, keyID);
            }else{
                // TODO: Check if exception ends program...
                throw new NoSuchAlgorithmException("keyType " + keyType + " is not supported on SmartCard-HSM.");
            }

            /* Hash result */
            sha256.update(res);
            byte[] psk = sha256.digest();
            StringBuilder strSig = new StringBuilder();
            for (byte aByte : psk) {
                strSig.append(String.format("%02x", aByte));
            }
            Log.i(TAG, "psk: " + strSig.toString());
            newPSK = Key.fromHex(strSig.toString());
        } catch (Exception e) {
            Log.i(TAG, Log.getStackTraceString(e));
            return null;
        } finally {
            try {
                SmartCard.shutdown();
                return newPSK;
            } catch (Exception e) {
                Log.i(TAG, Log.getStackTraceString(e));
                return newPSK;
            }
        }
    }

    /**
     * Function to perform the RSA operation on the HSM. Only keys with length 2048 allowed.
     *
     * @param schsmcs: SmartCardHSMCardService that is needed for signHash function.
     * @param digest : Byte array used as input (hash of init)
     * @param keyID  : Slot of key to be used.
     * @return       : Byte array with signature.
     * @throws CardServiceException : Exception of SmartCardHSMCardService.
     * @throws CardTerminalException: Exception of SmartCardHSMCardService.
     */
    public byte[] hsmOperationRSA(SmartCardHSMCardService schsmcs, byte[] digest, byte keyID) throws CardServiceException, CardTerminalException {
        /* RSA operation on HSM */
        SmartCardHSMRSAKey rsa2048Key = new SmartCardHSMRSAKey(keyID, "RSA-v1-5-SHA-256", (short) 2048);
        byte[] sig = schsmcs.signHash(rsa2048Key, "SHA256withRSA", "PKCS1_V15", digest);
        return sig;
    }

    /**
     * Function to perform the AES operation on the HSM. Only keys with length 256 allowed.
     *
     * @param schsmcs: SmartCardHSMCardService that is needed for sendCommandAPDU function.
     * @param digest : Byte array used as input (hash of init)
     * @param keyID  : Slot of key to be used.
     * @return       : Byte array with signature.
     * @throws CardServiceException : Exception of SmartCardHSMCardService.
     * @throws CardTerminalException: Exception of SmartCardHSMCardService.
     */
    public byte[] hsmOperationAES(SmartCardHSMCardService schsmcs, byte[] digest, byte keyID) throws CardServiceException, CardTerminalException {
        /* AES operation on HSM. APDU package according to documentation. */
        SmartCardHSMKey aesKey = new SmartCardHSMKey(keyID, "AES_KEY", (short) 256, "AES");
        int length = digest.length;
        CommandAPDU com = new CommandAPDU(9 + length);
        com.append((byte) -128);
        com.append((byte) 120);
        int keyNo = aesKey.getKeyRef();
        Log.i(TAG, "keyNo: " + keyNo);
        com.append((byte) keyNo);
        com.append((byte) 16);
        com.append((byte) 0);
        com.append((byte) (length >> 8));
        com.append((byte) length);
        com.append(digest);
        com.append((byte) 0);
        com.append((byte) 0);
        Log.i(TAG, "com: " + com.getBytes());
        ResponseAPDU rsp = schsmcs.sendCommandAPDU(com);
        byte[] enc = rsp.data();
        return enc;
    }
}
