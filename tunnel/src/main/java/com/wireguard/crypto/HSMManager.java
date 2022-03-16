/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * This class is supposed to manage the SmartCard-HSM by CardContact Systems GmbH.
 * It can take an initial value and return a PSK in Base64 as String.
 */

package com.wireguard.crypto;

import android.content.Context;
import android.content.SharedPreferences;

public class HSMManager {

    private static final String TAG = "WireGuard/HSMManager";

    public HSMManager() {
        super();
    }

    /**
     * Function to return key with init as initial value
     *
     * @param context: Context of activity from where this function is called (necessary for SBMicroSDCardTerminalFactory)
     * @param     pin: String with pin value for HSM (is checked at the start but should be correct otherwise HSM might lock)
     * @param    init: String with init value
     * @return       : Key that can be used as new PSK
     */
    public Key hsmOperation(Context context, String pin, String init) {
        // TODO: Implement this function

        return null;
    }
}
