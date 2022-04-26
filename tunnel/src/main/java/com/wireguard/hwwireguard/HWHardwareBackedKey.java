/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.hwwireguard;

/**
 * The class offers:
 *      1. Attributes for both SmartCard-HSM and AndroidKeyStore keys (label, slot(only relevant to SmartCard-HSM), type)
 *      2. Enums HardwareType (KEYSTORE, HSM) and KeyType (AESCBC, AESECB, RSA for AndroidKeyStore AND AES, RSA for SmartCard-HSM)
 *      3. Getter methods, Constructor acts as Setter, toString() for saving.
 */
public class HWHardwareBackedKey {
    private HardwareType hardwareType;
    private String label;
    private byte slot;
    private KeyType type;

    public enum HardwareType {
        KEYSTORE,
        HSM
    }

    public enum KeyType {
        AES,
        RSA
    }

    /**
     * Constructor with necessary attributes.
     *
     * @param hardwareType
     * @param label
     * @param slot
     * @param type
     */
    public HWHardwareBackedKey(HardwareType hardwareType, String label, byte slot, KeyType type) {
        this.hardwareType = hardwareType;
        this.label = label;
        this.slot = slot;
        this.type = type;
    }

    public HardwareType getHardwareType() { return hardwareType; }

    public String getLabel() {
        return label;
    }

    public byte getSlot() {
        return slot;
    }

    public KeyType getType() {
        return type;
    }

    @Override public String toString() {
        return "label=" + label + ',' +
                "slot=" + slot + ',' +
                "type=" + type + ',' + '\n';
    }
}
