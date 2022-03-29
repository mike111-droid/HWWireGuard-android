/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.crypto;

import androidx.annotation.NonNull;



public class HSMKey {
    private String label;
    private byte slot;
    private KeyType type;
    private boolean selected;

    public enum KeyType {
        AES,
        RSA
    }

    /**
     * Constructor with necessary attributes.
     *
     * @param label
     * @param slot
     * @param type
     * @param selected
     */
    public HSMKey(String label, byte slot, KeyType type, boolean selected) {
        this.label = label;
        this.slot = slot;
        this.type = type;
        this.selected = selected;
    }

    public String getLabel() {
        return label;
    }

    public byte getSlot() {
        return slot;
    }

    public KeyType getType() {
        return type;
    }

    public boolean getSelected() {
        return selected;
    }

    @Override public String toString() {
        return "label=" + label + ',' +
                "slot=" + slot + ',' +
                "type=" + type + ',' +
                "selected=" + selected + '\n';
    }
}
