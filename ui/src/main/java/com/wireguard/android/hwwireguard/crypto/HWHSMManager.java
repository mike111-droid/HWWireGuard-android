/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard.crypto;

import android.content.Context;
import android.util.Log;

import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;
import com.wireguard.android.hwwireguard.crypto.HWHardwareBackedKey.HardwareType;
import com.wireguard.android.hwwireguard.crypto.HWHardwareBackedKey.KeyType;

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
 * This class offers:
 *      - Crypto-Operations with SmartCard-HSM (AES enc and RSA sign)
 */
public class HWHSMManager {
    public static final byte[] BYTES = new byte[0];
    private static final String TAG = "WireGuard/HSMManager";
    private final Context context;

    public HWHSMManager(final Context context) throws IOException {
        this.context = context;
    }

    /**
     * Function to perform either AES or RSA operation on the HSM.
     * @param keyType: Specifies whether to use KeyType.AES or KeyType.RSA.
     * @param init   : Input data.
     * @param keyID  : Slot ID of the key to use.
     * @return       : New PSK key.
     */
    public Key hsmOperation(final KeyType keyType, final SmartCardHSMCardService schsmcs, final String init, final byte keyID) {
        try {
            /* Startup card and get SmartCardHSMCardService */
            if (schsmcs == null) return null;

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
        }
    }

    /**
     * Function transforms byte[] of key in hex to type Key.
     * @param bytes: Byte array with key.
     * @return     : Key.
     */
    public Key bytesToKey(final byte[] bytes) throws KeyFormatException {
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
    public byte[] sha256(final byte[] data) throws NoSuchAlgorithmException {
        final MessageDigest sha256 = MessageDigest.getInstance("SHA256");
        sha256.update(data);
        return sha256.digest();
    }

    /**
     * Function to check pin of SmartCard-HSM.
     * @param pin    : String with pin for SmartCard-HSM.
     * @param schsmcs: SmartCardHSMCardService for operations on SmartCard-HSM.
     */
    public void checkPin(final String pin, final SmartCardHSMCardService schsmcs) throws Exception {
        Log.i(TAG, "Verifying PIN...");
        if(!schsmcs.verifyPassword(null, 0, pin.getBytes())) {
            Log.i(TAG, "PIN is incorrect. More than 3 false pins lead to locked devices!");
            throw new Exception("Wrong PIN.");
        }
    }

    /**
     * Function to return SmartCardHSMService.
     */
    @Nullable public SmartCardHSMCardService getSmartCardHSMCardService() throws OpenCardPropertyLoadingException, ClassNotFoundException, CardServiceException, CardTerminalException {
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
     * @param schsmcs: SmartCardHSMCardService that is needed for signHash function.
     * @param digest : Byte array used as input (hash of init)
     * @param keyID  : Slot of key to be used.
     * @return       : Byte array with signature.
     */
    public byte[] hsmOperationRSA(SmartCardHSMCardService schsmcs, byte[] digest, byte keyID) throws CardServiceException, CardTerminalException {
        /* RSA operation on HSM */
        SmartCardHSMRSAKey rsa2048Key = new SmartCardHSMRSAKey(keyID, "RSA-v1-5-SHA-256", (short) 2048);
        return schsmcs.signHash(rsa2048Key, "SHA256withRSA", "PKCS1_V15", digest);
    }

    /**
     * Function to perform the AES operation on the HSM. Only keys with length 256 allowed.
     * @param schsmcs: SmartCardHSMCardService that is needed for sendCommandAPDU function.
     * @param digest : Byte array used as input (hash of init)
     * @param keyID  : Slot of key to be used.
     * @return       : Byte array with signature.
     */
    private byte[] hsmOperationAES(SmartCardHSMCardService schsmcs, byte[] digest, byte keyID) throws CardServiceException, CardTerminalException {
        /* 0x10 is AES CBC Encrypt */
        return schsmcs.deriveSymmetricKey(keyID, (byte) 0x10, digest);
        /* AES operation on HSM. APDU package according to documentation. */
        /*SmartCardHSMKey aesKey = new SmartCardHSMKey(keyID, "AES_KEY", (short) 256, "AES");
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
        return rsp.data();*/
    }
}
