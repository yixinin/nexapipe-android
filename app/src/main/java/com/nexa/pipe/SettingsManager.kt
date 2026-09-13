package com.nexa.pipe

import android.content.Context
import android.content.SharedPreferences
import com.nexa.pipe.ui.NodeConfig
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.decodeFromString

class SettingsManager(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("NexaPipeSettings", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    private companion object {
        const val KEY_NODES = "nodes"
        const val KEY_RELAY_MODE = "relay_mode"
        const val KEY_RELAY_URL = "relay_url"
        const val KEY_FORCE_RELAY = "force_relay"
        const val KEY_2FA_ENABLED = "two_factor_enabled"
        const val KEY_2FA_CLIENT_ID = "two_factor_client_id"
        const val KEY_2FA_SECRET = "two_factor_secret"
        const val KEY_2FA_ALGORITHM = "two_factor_algorithm"
    }

    fun saveNodes(nodes: List<NodeConfig>) {
        val jsonStr = json.encodeToString(nodes)
        prefs.edit().putString(KEY_NODES, jsonStr).apply()
    }

    fun loadNodes(): List<NodeConfig> {
        val jsonStr = prefs.getString(KEY_NODES, "")
        if (jsonStr.isNullOrEmpty()) {
            return emptyList()
        }
        return try {
            json.decodeFromString(jsonStr)
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Saves the relay configuration. */
    fun saveRelayConfig(relayMode: String, relayUrl: String, forceRelay: Boolean) {
        prefs.edit()
            .putString(KEY_RELAY_MODE, relayMode)
            .putString(KEY_RELAY_URL, relayUrl)
            .putBoolean(KEY_FORCE_RELAY, forceRelay)
            .apply()
    }

    /** Loads the relay mode; defaults to "pinned" (pinned to aps1-1). */
    fun loadRelayMode(): String {
        return prefs.getString(KEY_RELAY_MODE, "pinned") ?: "pinned"
    }

    /** Loads the custom relay URL. */
    fun loadRelayUrl(): String {
        return prefs.getString(KEY_RELAY_URL, "") ?: ""
    }

    /** Loads whether relaying is forced (direct connections disabled). */
    fun loadForceRelay(): Boolean {
        return prefs.getBoolean(KEY_FORCE_RELAY, false)
    }

    /** Saves the 2FA configuration. */
    fun saveTwoFactorConfig(
        enabled: Boolean,
        clientId: String,
        secret: String,
        algorithm: String
    ) {
        prefs.edit()
            .putBoolean(KEY_2FA_ENABLED, enabled)
            .putString(KEY_2FA_CLIENT_ID, clientId)
            .putString(KEY_2FA_SECRET, secret)
            .putString(KEY_2FA_ALGORITHM, algorithm)
            .apply()
    }

    /** Loads whether 2FA is enabled; defaults to false. */
    fun loadTwoFactorEnabled(): Boolean {
        return prefs.getBoolean(KEY_2FA_ENABLED, false)
    }

    /** Loads the 2FA client ID. */
    fun loadTwoFactorClientId(): String {
        return prefs.getString(KEY_2FA_CLIENT_ID, "") ?: ""
    }

    /** Loads the 2FA TOTP secret (Base32). */
    fun loadTwoFactorSecret(): String {
        return prefs.getString(KEY_2FA_SECRET, "") ?: ""
    }

    /** Loads the 2FA algorithm; defaults to sha1. */
    fun loadTwoFactorAlgorithm(): String {
        return prefs.getString(KEY_2FA_ALGORITHM, "sha1") ?: "sha1"
    }
}
