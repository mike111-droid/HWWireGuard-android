/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * This class is supposed to perform the Ratchet Operation (SHA256) on a given Key and return the new PSK
 * as Key Datatype.
 */

package com.wireguard.crypto;

import android.util.Log;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class RatchetManager {
    private static final String TAG = "WireGuard/RatchetManager";
    public RatchetManager() { }

    /**
     * Function to return new key from hashed old key.
     * Was tested and produces the same result as in WireGuardHSM-linux.
     *
     * @param key: Old key that will be hashed.
     * @return   : New key. If exception occurred key=null.
     */
    public Key ratchet(Key key) {
        String str = key.toBase64();
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            Log.i(TAG, Log.getStackTraceString(e));
            return null;
        }
        byte[] hash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
        Key ret = null;
        try {
            ret = Key.fromHex(toHexString(hash));
        } catch (KeyFormatException e) {
            Log.i(TAG, Log.getStackTraceString(e));
            return null;
        }
        return ret;
    }

    /**
     * Function to return String of hex from byte array.
     * @param hash: Byte array
     * @return    : String
     */
    private static String toHexString(byte[] hash) {
        // Convert byte array into signum representation
        BigInteger number = new BigInteger(1, hash);

        // Convert message digest into hex value
        StringBuilder hexString = new StringBuilder(number.toString(16));

        // Pad with leading zeros
        while (hexString.length() < 32) {
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }
}
