/*
 * Copyright © 2017-2021 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.app.NotificationManager
import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.databinding.DataBindingUtil
import androidx.databinding.ViewDataBinding
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.snackbar.Snackbar
import com.wireguard.android.HWApplication
import com.wireguard.android.R
import com.wireguard.android.activity.BaseActivity
import com.wireguard.android.activity.BaseActivity.OnSelectedTunnelChangedListener
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.databinding.TunnelDetailFragmentBinding
import com.wireguard.android.databinding.TunnelListItemBinding
import com.wireguard.android.hwwireguard.HWMonitor
import com.wireguard.android.hwwireguard.crypto.HWBiometricAuthenticator
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.applicationScope
import com.wireguard.android.hwwireguard.crypto.HWKeyStoreManager
import com.wireguard.crypto.Key
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Base class for fragments that need to know the currently-selected tunnel. Only does anything when
 * attached to a `BaseActivity`.
 */
abstract class BaseFragment : Fragment(), OnSelectedTunnelChangedListener {
    private var pendingTunnel: ObservableTunnel? = null
    private var pendingTunnelUp: Boolean? = null
    private val permissionActivityResultLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val tunnel = pendingTunnel
        val checked = pendingTunnelUp
        if (tunnel != null && checked != null)
            setTunnelStateWithPermissionsResult(tunnel, checked)
        pendingTunnel = null
        pendingTunnelUp = null
    }
    /* Custom change begin */
    private lateinit var monitor: HWMonitor
    override fun onCreate(savedInstanceState: Bundle?) {
        monitor = HWMonitor(requireContext(), requireActivity(), this)
        super.onCreate(savedInstanceState)
    }

    override fun onResume() {
        super.onResume()
        Log.i(TAG, "onResume called...")
        if(monitor.startBiometricPrompt) {
            val keyStoreOperation =  HWKeyStoreManager(requireContext())
            var newPSK = keyStoreOperation.keyStoreOperation(monitor.newTimestamp!!, "rsa_key", monitor.getTunnel()!!, monitor)
            if(newPSK != null) {
                monitor.initPSK = newPSK
            }
            monitor.startBiometricPrompt = false
            val notificationManager =
                requireContext().getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager?
            notificationManager!!.cancel(HWMonitor.NOTIFICATION_ID)
        }
    }
    /* Custom change end */

    protected var selectedTunnel: ObservableTunnel?
        get() = (activity as? BaseActivity)?.selectedTunnel
        protected set(tunnel) {
            (activity as? BaseActivity)?.selectedTunnel = tunnel
        }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        (activity as? BaseActivity)?.addOnSelectedTunnelChangedListener(this)
    }

    override fun onDetach() {
        (activity as? BaseActivity)?.removeOnSelectedTunnelChangedListener(this)
        super.onDetach()
    }

    fun setTunnelState(view: View, checked: Boolean) {
        val tunnel = when (val binding = DataBindingUtil.findBinding<ViewDataBinding>(view)) {
            is TunnelDetailFragmentBinding -> binding.tunnel
            is TunnelListItemBinding -> binding.item
            else -> return
        } ?: return
        val activity = activity ?: return
        activity.lifecycleScope.launch {
            if (HWApplication.getBackend() is GoBackend) {
                val intent = GoBackend.VpnService.prepare(activity)
                if (intent != null) {
                    pendingTunnel = tunnel
                    pendingTunnelUp = checked
                    permissionActivityResultLauncher.launch(intent)
                    return@launch
                }
            }

            /* Custom change begin */
            val keyStoreManager = HWKeyStoreManager(context)
            keyStoreManager.deleteKey("rsa_key")
            keyStoreManager.addKeyStoreKeyRSA("rsa_key", "crt.pem", "private_key.der")

            if(PreferencesPreferenceDataStore(applicationScope, HWApplication.getPreferencesDataStore()).getString("dropdown", "none") != "none") {
                if(checked) {
                    Log.i(TAG, "Tunnel state is up, so we start the Monitor.")
                    monitor.setTunnel(tunnel)
                    monitor.startMonitor()
                } else {
                    Log.i(TAG, "Tunnel state is down, so we stop the Monitor.")
                    monitor.stopMonitor()
                    /* reset monitor */
                    monitor = HWMonitor(requireContext(), requireActivity(), monitor.mFragment)
                }
            }else{
                if(checked) {
                    val config = tunnel.getConfigAsync()
                    delay(1000)
                    HWApplication.getBackend().addConf(config)
                }
            }
            /* Custom change end */
            setTunnelStateWithPermissionsResult(tunnel, checked)
        }
    }

    private fun setTunnelStateWithPermissionsResult(tunnel: ObservableTunnel, checked: Boolean) {
        val activity = activity ?: return
        activity.lifecycleScope.launch {
            try {
                tunnel.setStateAsync(Tunnel.State.of(checked))
            } catch (e: Throwable) {
                val error = ErrorMessages[e]
                val messageResId = if (checked) R.string.error_up else R.string.error_down
                val message = activity.getString(messageResId, error)
                val view = view
                if (view != null)
                    Snackbar.make(view, message, Snackbar.LENGTH_LONG)
                            .setAnchorView(view.findViewById(R.id.create_fab))
                            .show()
                else
                    Toast.makeText(activity, message, Toast.LENGTH_LONG).show()
                Log.e(TAG, message, e)
            }
        }
    }

    companion object {
        private const val TAG = "WireGuard/BaseFragment"
    }
}
