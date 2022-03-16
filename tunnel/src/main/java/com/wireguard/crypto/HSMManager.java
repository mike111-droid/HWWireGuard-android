/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * This class is supposed to manage the SmartCard-HSM by CardContact Systems GmbH.
 * It can take an initial value and return a PSK in Base64 as String.
 */

package com.wireguard.crypto;

public class HSMManager {

    private static final String TAG = "WireGuard/HSMManager";

    public HSMManager() {
        super();
    }

    /**
     * Function to return key with init as initial value
     *
     * @param init: String with init value
     * @return    : Key that can be used as new PSK
     */
    public Key hsmOperation(String init) {
        // TODO: Implement this function
        return null;
    }
}
