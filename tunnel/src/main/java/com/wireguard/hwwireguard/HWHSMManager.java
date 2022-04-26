/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.hwwireguard;

import android.content.Context;
import android.util.Log;

import com.wireguard.crypto.KeyFormatException;
import com.wireguard.hwwireguard.HWHardwareBackedKey.HardwareType;
import com.wireguard.hwwireguard.HWHardwareBackedKey.KeyType;
import com.wireguard.crypto.Key;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import androidx.annotation.Nullable;
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
import opencard.core.util.OpenCardPropertyLoadingException;

/**
 * TODO: Not all characters are allowed for key labels/alias -> make sure to filter them at UI
 * This class offers:
 *      1. Crypto-Operations with SmartCard-HSM (AES___ enc and RSA sign)
 *      2. keyList to save HardwareBackedKeys (label/alias, type, slot)
 *      3. selectedKeyLabel to identify one SmartCard-HSM key to use in operations (provides Getter and Setter Method)
 *      4. Operations to store/load keyList and selectedKeyLabel into file HSMKeys.txt
 */
public class HWHSMManager {
    public static final byte[] BYTES = new byte[0];
    private static final String TAG = "WireGuard/HSMManager";
    private String selectedKeyLabel = "UNSELECTED";
    private final List<HWHardwareBackedKey> keyList;
    private final Context context;

    public HWHSMManager(final Context context) throws IOException {
        this.context = context;
        keyList = new ArrayList<>();
        loadKeys();
    }

    // TODO: Prevent delimiter char '=' from being in Alias (and UNSELECTED)
    /**
     * Function to set which key is selected for operation. Needs to be called outside of this class (user select).
     *
     * @param alias: String with key alias.
     *
     */
    void setSelectedKeyLabel(final String alias) {
        selectedKeyLabel = alias;
        try{
            storeKeys();
        } catch (final IOException e) {
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
    private static HWHardwareBackedKey parseKey(final String hsmKey) {
        final String[] split = hsmKey.split(",");
        final String label = split[0].split("=")[1];
        final byte slot = Byte.parseByte(split[1].split("=")[1]);
        final HWHardwareBackedKey.KeyType type = HWHardwareBackedKey.KeyType.valueOf(split[2].split("=")[1]);
        return new HWHardwareBackedKey(HardwareType.HSM, label, slot, type);
    }

    /**
     * Function to load the HSM keys saved into keyList.
     *
     */
    private void loadKeys() throws IOException {
        /* Read file to String line */
        final StringBuilder stringBuilder = new StringBuilder();
        String line;
        final BufferedReader in;
        try {
            in = new BufferedReader(new FileReader(new File(context.getFilesDir(), "HSMKeys.txt")));
        }catch(final FileNotFoundException e){
            Log.i(TAG, "File HSMKey.txt not found.");
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
        /* handle lines from HSMKeys.txt file */
        handleKeyListFileInput(stringBuilder, line, lineCounter);
        in.close();
    }

    private void handleKeyListFileInput(final StringBuilder stringBuilder, final String line, final int lineCounter) throws IOException {
        if(lineCounter > 1) {
            /* List has keys */
            final String[] split = stringBuilder.toString().split("\n");
            for(final String key: split) {
                keyList.add(parseKey(key));
            }
            assert line != null;
            setSelectedKeyLabel(line.split("=")[1]);
        }else{
            /* List is empty. Make sure selectedKey is UNSELECTED. */
            setSelectedKeyLabel("UNSELECTED");
            storeKeys();
        }
    }

    /**
     * Function to store the HSM keys into a file that later is used to load them again.
     *
     */
    private void storeKeys() throws IOException {
        final StringBuilder writeStr = new StringBuilder();
        for(final HWHardwareBackedKey key: keyList) {
            writeStr.append(key.toString());
        }
        writeStr.append("selectedKeyLabel=").append(selectedKeyLabel);
        final FileOutputStream streamHSMKeys = new FileOutputStream(new File(context.getFilesDir(), "HSMKeys.txt"));
        streamHSMKeys.write(writeStr.toString().getBytes());
        streamHSMKeys.close();
    }

    /**
     * Function to add key to keyList.
     * // TODO: Prevent delimiter char '=' from being in Alias (and UNSELECTED)
     *
     * @param key: Key to be added.
     */
    public void addKey(final HWHardwareBackedKey key) {
        /* add key keyList but check if key label already exists
         * -> if yes update key (remove old one and add new one) */
        final Iterable<HWHardwareBackedKey> keyListCopy = new ArrayList<>(keyList);
        for(final HWHardwareBackedKey k : keyListCopy) {
            if(k.getLabel().equals(key.getLabel())){
                keyList.remove(k);
            }
        }
        keyList.add(key);
        try {
            storeKeys();
        } catch (final IOException e) {
            Log.i(TAG, "Failed to store into KeyStoreKeys.txt file.");
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    /**
     * Function to delete key from keyList.
     *
     * @param label: Key to be deleted.
     */
    public void deleteKey(final String label) {
        final HWHardwareBackedKey key = getKeyFromAlias(label);
        if(key != null) {
            keyList.remove(key);
        }else{
            Log.i(TAG, "Key alias not found in keyList.");
            return;
        }
        try {
            storeKeys();
        } catch (final IOException e) {
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
    private HWHardwareBackedKey getKeyFromAlias(final String alias) {
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
     * Function to perform either AES or RSA operation on the HSM.
     *
     * @param keyType: Specifies whether to use KeyType.AES or KeyType.RSA.
     * @param pin    : String with pin for HSM.
     * @param init   : Input data.
     * @param keyID  : Slot ID of the key to use.
     * @return       : New PSK key.
     */
    public Key hsmOperation(final HWHardwareBackedKey.KeyType keyType, final String pin, final String init, final byte keyID) {
        try {
            /* Startup card and get SmartCardHSMCardService */
            final SmartCardHSMCardService schsmcs = getSmartCardHSMCardService();
            if (schsmcs == null) return null;

            /* Verify the PIN */
            checkPin(pin, schsmcs);

            /* init to bytes */
            final byte[] data = init.getBytes();

            /* Hashing of data */
            final byte[] digest = sha256(data);
            Log.i(TAG, "sha256.digest: " + Arrays.toString(digest));

            /* HSM Operation */
            byte[] res = BYTES;
            if(keyType == KeyType.AES) {
                /* AES on HSM */
                res = hsmOperationAES(schsmcs, digest, keyID);
            }else if(keyType == KeyType.RSA){
                /* RSA on HSM */
                res = hsmOperationRSA(schsmcs, digest, keyID);
            }

            /* Hash result */
            final byte[] psk = sha256(res);
            return bytesToKey(psk);
        } catch (final Exception e) {
            Log.i(TAG, Log.getStackTraceString(e));
            return null;
        } finally {
            try {
                SmartCard.shutdown();
            } catch (final Exception e) {
                Log.i(TAG, Log.getStackTraceString(e));
            }
        }
    }

    /**
     * Function transforms byte[] of key in hex to type Key.
     *
     * @param bytes: Byte array with key.
     * @return     : Key.
     */
    private static Key bytesToKey(final byte[] bytes) throws KeyFormatException {
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
    private static byte[] sha256(final byte[] data) throws NoSuchAlgorithmException {
        final MessageDigest sha256 = MessageDigest.getInstance("SHA256");
        sha256.update(data);
        return sha256.digest();
    }

    /**
     * Function to check pin of SmartCard-HSM.
     *
     * @param pin    : String with pin for SmartCard-HSM.
     * @param schsmcs: SmartCardHSMCardService for operations on SmartCard-HSM.
     */
    private static void checkPin(final String pin, final SmartCardHSMCardService schsmcs) throws Exception {
        Log.i(TAG, "Verifying PIN...");
        if(!schsmcs.verifyPassword(null, 0, pin.getBytes())) {
            Log.i(TAG, "PIN is incorrect. More than 3 false pins lead to locked devices!");
            throw new Exception("Wrong PIN.");
        }
    }

    @Nullable private SmartCardHSMCardService getSmartCardHSMCardService() throws OpenCardPropertyLoadingException, ClassNotFoundException, CardServiceException, CardTerminalException {
        /* Startup */
        Log.i(TAG, "OCF startup...");
        SmartCard.startup();
        Log.i(TAG, "Creating card terminal registry...");
        final CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();

        /* Add SwissBit card terminal to registry */
        final SBMicroSDCardTerminalFactory sbcardf = new SBMicroSDCardTerminalFactory(context);
        sbcardf.createCardTerminals(ctr, null);

        /* Creating service registry */
        Log.i(TAG, "Creating card service registry...");
        final CardServiceRegistry csr = CardServiceRegistry.getRegistry();

        /* Adding card service */
        Log.i(TAG, "Adding SmartCard-HSM card service...");
        final CardServiceFactory csf = new SmartCardHSMCardServiceFactory();
        csr.add(csf);

        Log.i(TAG, "Creating card request...");
        final CardRequest cr = new CardRequest(CardRequest.ANYCARD, null, SmartCardHSMCardService.class);
        final SmartCard sc = SmartCard.waitForCard(cr);
        if (sc == null) {
            Log.i("SmartCard-HSM", "Could not get smart card...");
            return null;
        }

        sc.setAPDUTracer(new StreamingAPDUTracer(new PrintStream(new HWLogCatOutputStream())));
        Log.i(TAG, "Card found");

        Log.i(TAG, "Trying to create card service...");
        return (SmartCardHSMCardService) sc.getCardService(SmartCardHSMCardService.class, true);
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
    private byte[] hsmOperationRSA(SmartCardHSMCardService schsmcs, byte[] digest, byte keyID) throws CardServiceException, CardTerminalException {
        /* RSA operation on HSM */
        SmartCardHSMRSAKey rsa2048Key = new SmartCardHSMRSAKey(keyID, "RSA-v1-5-SHA-256", (short) 2048);
        return schsmcs.signHash(rsa2048Key, "SHA256withRSA", "PKCS1_V15", digest);
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
    private byte[] hsmOperationAES(SmartCardHSMCardService schsmcs, byte[] digest, byte keyID) throws CardServiceException, CardTerminalException {
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
        Log.i(TAG, "com: " + Arrays.toString(com.getBytes()));
        final ResponseAPDU rsp = schsmcs.sendCommandAPDU(com);
        return rsp.data();
    }
}
