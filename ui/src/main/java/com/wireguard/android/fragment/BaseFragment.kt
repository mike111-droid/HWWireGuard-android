/*
 * Copyright © 2017-2021 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.databinding.DataBindingUtil
import androidx.databinding.ViewDataBinding
import androidx.datastore.preferences.core.intPreferencesKey
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
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.applicationScope
import com.wireguard.crypto.Key
import com.wireguard.crypto._HSMManager
import com.wireguard.crypto._HardwareBackedKey
import com.wireguard.crypto._RatchetManager
import com.wireguard.crypto._Timestamp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.coroutineContext

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

    override fun onCreate(savedInstanceState: Bundle?) {
        monitor = Monitor(requireContext())
        super.onCreate(savedInstanceState)
    }
    private lateinit var monitor: Monitor

    // TODO: Question - atomic boolean for cross coroutine communication?
    /**
     * Class for monitoring the tunnels and changing PSKs according to selected version.
     */
    class Monitor(context: Context) {
        companion object {
            private const val TAG = "WireGuard/Monitor"
        }
        private var run: AtomicBoolean = AtomicBoolean(false);
        private var oldTimestamp: String? = null
        private val context: Context = context

        fun startMonitor() {
            Log.i(TAG, "inside startMonitor")
            run.set(true)
            applicationScope.launch(Dispatchers.Default) {
                while(run.get()) {
                    for(tunnel in Application.getTunnelManager().getTunnels()) {
                        monitor(tunnel)
                    }
                    delay(3000)
                }
            }
        }

        fun stopMonitor() {
            Log.i(TAG, "inside stopMonitor")
            run.set(false)
        }

        private suspend fun ratchet(key: Key) : Key {
            val ratchetManager = _RatchetManager()
            return ratchetManager.ratchet(key)
        }

        private suspend fun monitor(tunnel: ObservableTunnel) {
            Log.i(TAG, "Checking tunnel: $tunnel")
            val timestamp = _Timestamp().timestamp
            //Log.i(TAG, "timestamp: $timestamp")
            //Log.i(TAG, "oldTimestamp: $oldTimestamp")
            if(timestamp != oldTimestamp) {
                /* PSK needs to be reloaded with new timestamp */
                val pref = PreferencesPreferenceDataStore(applicationScope, Application.getPreferencesDataStore())
                val useHSM = pref.getBoolean("use_hsm", false)
                if(useHSM) {
                    Log.i(TAG, "Using SmartCard-HSM...")
                    val hsmManager = _HSMManager(context)
                    val newPSK = hsmManager.hsmOperation(_HardwareBackedKey.KeyType.RSA,"123456", timestamp, 0x3)
                    val config = tunnel.config ?: return
                    for((counter, peer) in config.peers.withIndex()) {
                        Log.i(
                            TAG,
                            "psk before: " + Application.getBackend().getStatistics(tunnel).presharedKey[peer.publicKey]!!.toBase64()
                        )
                        config.peers[counter].setPreSharedKey(newPSK)
                        Application.getBackend().addConf(config)
                        Log.i(
                            TAG,
                            "psk after: " + Application.getBackend().getStatistics(tunnel).presharedKey[peer.publicKey]!!.toBase64()
                        )
                    }
                }else{
                    Log.i(TAG, "Using AndroidKeyStore...")
                }
            }
            oldTimestamp = timestamp
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
            if (Application.getBackend() is GoBackend) {
                val intent = GoBackend.VpnService.prepare(activity)
                if (intent != null) {
                    pendingTunnel = tunnel
                    pendingTunnelUp = checked
                    permissionActivityResultLauncher.launch(intent)
                    return@launch
                }
            }
            /* Custom change begin */
            if(checked) {
                Log.i(TAG, "Tunnel state is up, so we start the Monitor.")
                monitor.startMonitor()
            }else{
                Log.i(TAG, "Tunnel state is down, so we stop the Monitor.")
                monitor.stopMonitor()
            }
            /* Custom change end */
            setTunnelStateWithPermissionsResult(tunnel, checked)
            /* Custom change begin */
            /*if(checked) {
                Log.i(TAG, "Tunnel state is up, so we start the Monitor.")
                monitor.startMonitor()
            }else{
                Log.i(TAG, "Tunnel state is down, so we stop the Monitor.")
                monitor.stopMonitor()
            }*/
            /*for ((counter, peer) in config.peers.withIndex()) {
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
            }*/
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
