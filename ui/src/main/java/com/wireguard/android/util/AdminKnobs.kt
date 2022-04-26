/*
 * Copyright © 2017-2021 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.util

import android.content.RestrictionsManager
import androidx.core.content.getSystemService
import com.wireguard.android.HWApplication

object AdminKnobs {
    private val restrictions: RestrictionsManager? = HWApplication.get().getSystemService()
    val disableConfigExport: Boolean
        get() = restrictions?.applicationRestrictions?.getBoolean("disable_config_export", false)
                ?: false
}
