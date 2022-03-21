/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.crypto;

import java.text.SimpleDateFormat;

public class Timestamp {
    java.sql.Timestamp timestamp;
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd.HH");
    Timestamp() { }

    /**
     * Function to return timestamp in the format "yyyy.MM.dd.HH"
     *
     * @return: String of timestamp in format
     */
    public String getTimestamp() {
        timestamp = new java.sql.Timestamp(System.currentTimeMillis());
        return sdf.format(timestamp).toString();
    }
}
