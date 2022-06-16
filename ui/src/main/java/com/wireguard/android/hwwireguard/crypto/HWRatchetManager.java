/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard.crypto;

import android.util.Log;

import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Class to perform RatchetOperation. newPSK = SHA256(oldPSK)
 */
public class HWRatchetManager {
    private static final String TAG = "WireGuard/RatchetManager";

    /**
     * Function to return new key from hashed old key.
     * Was tested and produces the same result as in WireGuardHSM-linux.
     *
     * @param key: Old key that will be hashed.
     * @return   : New key. If exception occurred key=null.
     */
    public Key ratchet(final Key key) {
        final String str = key.toBase64();
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (final NoSuchAlgorithmException e) {
            Log.i(TAG, Log.getStackTraceString(e));
            return null;
        }
        final byte[] hash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
        Key ret;
        try {
            ret = Key.fromHex(toHexString(hash));
        } catch (final KeyFormatException e) {
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
    private static String toHexString(final byte[] hash) {
        final BigInteger value = new BigInteger(1, hash);

        final StringBuilder hexString = new StringBuilder(value.toString(16));

        while (hexString.length() < 32) {
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }
}
