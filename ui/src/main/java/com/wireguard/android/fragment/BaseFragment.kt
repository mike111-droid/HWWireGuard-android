/*
 * Copyright © 2017-2021 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.content.Context
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.databinding.DataBindingUtil
import androidx.databinding.ViewDataBinding
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.snackbar.Snackbar
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.activity.BaseActivity
import com.wireguard.android.activity.BaseActivity.OnSelectedTunnelChangedListener
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.databinding.TunnelDetailFragmentBinding
import com.wireguard.android.databinding.TunnelListItemBinding
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.util.ErrorMessages
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
            if (Application.getBackend() is GoBackend) {
                val intent = GoBackend.VpnService.prepare(activity)
                if (intent != null) {
                    pendingTunnel = tunnel
                    pendingTunnelUp = checked
                    permissionActivityResultLauncher.launch(intent)
                    return@launch
                }
            }
            setTunnelStateWithPermissionsResult(tunnel, checked)
            val config = tunnel.getConfigAsync()
            delay(1000)
            /* Custom change begin */
            for ((counter, peer) in config.peers.withIndex()) {
                Log.i(
                    TAG,
                    "psk1: " + Application.getBackend().getStatistics(tunnel).presharedKey[peer.publicKey]!!.toBase64()
                )
                /* Change psk */
                config.peers[counter].setPreSharedKey(Key.fromBase64("6LGnM3Hz2zi2BJiz5iyIHbgg/FCU38JzVuxxyQsQkR0="))
                //Application.getBackend().setState(tunnel, tunnel.state, config)
                Application.getBackend().addConf(config)
                //delay(500)
                Log.i(
                    TAG,
                    "psk2: " + Application.getBackend().getStatistics(tunnel).presharedKey[peer.publicKey]!!.toBase64()
                )
                config.peers[counter].setPreSharedKey(Key.fromBase64("or/ZJXL3mejqaF+5TyGpYhr02ceXgE15Ysqt2Xia81o="))
                //Application.getBackend().setState(tunnel, tunnel.state, config)
                Application.getBackend().addConf(config)
                //delay(500)
                Log.i(
                    TAG,
                    "endPSK: " + Application.getBackend().getStatistics(tunnel).presharedKey[peer.publicKey]!!.toBase64()
                )
            }
            /* Custom change end */
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
