/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * This class is supposed to manage the SmartCard-HSM by CardContact Systems GmbH.
 * It can take an initial value and return a PSK in Base64 as String.
 */

package com.wireguard.crypto;

import android.app.Application;
import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import de.cardcontact.opencard.android.swissbit.SBMicroSDCardTerminalFactory;
import de.cardcontact.opencard.factory.SmartCardHSMCardServiceFactory;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMCardService;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMRSAKey;
import de.cardcontact.opencard.utils.StreamingAPDUTracer;
import opencard.core.service.CardRequest;
import opencard.core.service.CardServiceFactory;
import opencard.core.service.CardServiceRegistry;
import opencard.core.service.SmartCard;
import opencard.core.terminal.CardTerminalRegistry;
import opencard.core.util.HexString;

class LogCatOutputStream extends OutputStream {
    @Override
    public synchronized void write(byte[] buffer, int offset, int len) {
        Log.i("SmartCard-HSM", new String(buffer, offset, len));
    }

    @Override
    public void write(int oneByte) throws IOException {
    }
}

public class HSMManager {
    private static final String TAG = "WireGuard/HSMManager";
    public List<HSMKey> keyList;
    private Context context;
    public HSMManager(Context context){
        this.context = context;
        keyList = new ArrayList<HSMKey>();
    }

    /**
     * Function to parse key in String format.
     *
     * @param hsmKey: String with key.
     * @return      : HSMKey.
     */
    public HSMKey parseKey(String hsmKey) {
        String[] split = hsmKey.split(",");
        String label = split[0].split("=")[1];
        byte slot = Byte.valueOf(split[1].split("=")[1]);
        HSMKey.KeyType type = HSMKey.KeyType.valueOf(split[2].split("=")[1]);
        boolean selected = Boolean.valueOf(split[3].split("=")[1]);
        return new HSMKey(label, slot, type, selected);
    }

    /**
     * Function to load the HSM keys saved into keyList.
     *
     */
    public void loadKeys() throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        String line;
        BufferedReader in = new BufferedReader(new FileReader(new File(context.getFilesDir(), "HSMKeys.txt")));
        while((line = in.readLine()) != null) {
            stringBuilder.append(line);
        }
        String[] split = stringBuilder.toString().split("\n");
        for(String key: split) {
            keyList.add(parseKey(key));
        }
        in.close();
    }

    /**
     * Function to store the HSM keys into a file that later is used to load them again.
     *
     */
    public void storeKeys() throws IOException {
        String writeStr = new String();
        for(HSMKey key: keyList) {
            writeStr += key.toString();
        }
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
     *
     * @param key: Key to be added.
     */
    public void addKey(HSMKey key) {
        /* Check that only one key is selected */
        keyList.add(key);
    }

    /**
     * Function to delete key from keyList.
     *
     * @param key: Key to be deleted.
     */
    public void deleteKey(HSMKey key) {
        keyList.remove(key);
    }

    /**
     * Function to return the keyList.
     * @return: keyList.
     */
    public List<HSMKey> getKeyList() {
        return keyList;
    }

    /**
     * Function to return key with init as initial value (Using RSA)
     *
     * @param     pin: String with pin value for HSM (is checked at the start but should be correct otherwise HSM might lock)
     * @param    init: String with init value
     * @param   keyID: Byte with the slot number of which key should be used (Needs to be set by user)
     * @return       : Key that can be used as new PSK
     */
    public Key hsmOperationRSA(String pin, String init, byte keyID) {
        Key newPSK = null;
        try {
            /* Startup */
            Log.i(TAG, "OCF startup...");
            SmartCard.startup();
            Log.i(TAG, "Creating card terminal registry...");
            CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();

            /* Add SwissBit card terminal to regiatry */
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

            sc.setAPDUTracer(new StreamingAPDUTracer(new PrintStream(new LogCatOutputStream())));
            Log.i(TAG, "Card found");

            Log.i(TAG, "Trying to create card service...");
            SmartCardHSMCardService schsmcs = (SmartCardHSMCardService) sc.getCardService(SmartCardHSMCardService.class, true);

            /* Verify the PIN */
            Log.i(TAG, "Verifying PIN...");
            if(!schsmcs.verifyPassword(null, 0, pin.getBytes())) {
                Log.i(TAG, "PIN is incorrect. More than 3 false pins lead to locked devices!");
                return null;
            }

            /* HSM Operation */
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

            /* RSA operation on HSM */
            SmartCardHSMRSAKey rsa2048Key = new SmartCardHSMRSAKey( keyID, "RSA-v1-5-SHA-256", (short) 2048);
            byte[] sig = schsmcs.signHash(rsa2048Key, "SHA256withRSA", "PKCS1_V15", digest);
            sha256.update(sig);
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
     * Function to return key with init as initial value (Using RSA)
     *
     * @param context: Context of activity from where this function is called (necessary for SBMicroSDCardTerminalFactory)
     * @param     pin: String with pin value for HSM (is checked at the start but should be correct otherwise HSM might lock)
     * @param    init: String with init value
     * @param   keyID: Byte with the slot number of which key should be used (Needs to be set by user)
     * @return       : Key that can be used as new PSK
     */
    public Key hsmOperationAES(Context context, String pin, String init, byte keyID) {
        // TODO: Implement
        return null;
    }
}
