/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.activity

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.databinding.LogViewerActivityBinding
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.crypto.HSMKey
import com.wireguard.crypto.HSMManager

class KeyOptionActivity : AppCompatActivity() {
    private lateinit var binding: LogViewerActivityBinding
    private val TAG = "WireGuard/HSMActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = LogViewerActivityBinding.inflate(layoutInflater)
        setContentView(R.layout.key_option_activity)
        // showing the back button in action bar
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar!!.title = "Key Option"
        val preferenceManager = PreferencesPreferenceDataStore(lifecycleScope, Application.getPreferencesDataStore())
        val useHSM = preferenceManager.getBoolean("use_hsm", false)
        var keyListString: MutableList<String> = mutableListOf()
        Log.i(TAG, "useHSM is ${useHSM}.")
        if(useHSM) {
            val hsmManager = HSMManager(applicationContext)
            hsmManager.loadKeys()
            val keyList: MutableList<HSMKey>? = hsmManager.getKeyList()
            for(key in keyList!!){
                keyListString.add(key.toString())
            }
        } else {
            // TODO: Implement for AndroidKeyStores
        }
        var l: ListView = findViewById(R.id.list)
        val arr: ArrayAdapter<String> = ArrayAdapter<String>(
            this,
            R.layout.hsm_key_list_item,
            keyListString
        )
        l.adapter = arr
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                finish()
                true
            }
            R.id.menu_action_edit -> {
                Toast.makeText(applicationContext,"Editing key options",Toast.LENGTH_SHORT).show()
                val intent = Intent(this, KeyEditActivity::class.java)
                startActivity(intent)
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.tunnel_detail, menu)
        return true
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressed()
        return true
    }
}