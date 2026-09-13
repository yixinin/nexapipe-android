package com.nexa.pipe.ui

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nexa.pipe.IrohProxy
import com.nexa.pipe.PermissionManager
import com.nexa.pipe.SettingsManager
import com.nexa.pipe.vpn.NexaVpnService
import com.nexa.pipe.vpn.UnderlyingNetworkSelector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress

import kotlinx.serialization.Serializable

@Serializable
data class NodeConfig(
    val nodeId: String,
    val domains: List<String> = emptyList()
)

class VpnViewModel : ViewModel() {
    private val TAG = "VpnViewModel"
    private var settingsManager: SettingsManager? = null

    val isVpnRunning = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isIrohStarted = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isConnecting = kotlinx.coroutines.flow.MutableStateFlow(false)
    val endpointId = kotlinx.coroutines.flow.MutableStateFlow("")
    val nodes = kotlinx.coroutines.flow.MutableStateFlow(mutableListOf<NodeConfig>())
    val logMessages = kotlinx.coroutines.flow.MutableStateFlow(mutableListOf<String>())
    val errorMessage = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)
    val connectionStatusText = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)
    val vpnPermissionGranted = kotlinx.coroutines.flow.MutableStateFlow(false)
    val notificationPermissionGranted = kotlinx.coroutines.flow.MutableStateFlow(false)

    // Relay configuration
    val relayMode = kotlinx.coroutines.flow.MutableStateFlow("pinned") // "pinned", "default", "disabled", "custom"
    val relayUrl = kotlinx.coroutines.flow.MutableStateFlow("")
    val forceRelay = kotlinx.coroutines.flow.MutableStateFlow(false)

    // 2FA configuration
    val twoFactorEnabled = kotlinx.coroutines.flow.MutableStateFlow(false)
    val twoFactorClientId = kotlinx.coroutines.flow.MutableStateFlow("")
    val twoFactorSecret = kotlinx.coroutines.flow.MutableStateFlow("")
    val twoFactorAlgorithm = kotlinx.coroutines.flow.MutableStateFlow("sha1") // "sha1", "sha256", "sha512"

    // Serialize connect/disconnect so concurrent native calls cannot race.
    private val connectionMutex = Mutex()
    // Keeps a handle on the connect coroutine so disconnect can cancel it
    // (JNI cannot be interrupted, but the next suspension point throws
    // CancellationException).
    private var connectJob: Job? = null

    companion object {
        // Timeout and retry parameters for a single connect attempt. iroh bind
        // can take up to 30s on a weak network, so the budget is generous.
        private const val MAX_CONNECT_ATTEMPTS = 3
        private const val ATTEMPT_TIMEOUT_MS = 60_000L
        private const val DISCONNECT_MUTEX_TIMEOUT_MS = 70_000L
        private val BACKOFF_MS = longArrayOf(0, 1_000, 2_000)
        // Local proxy listening port (only used to warm up preConnect; in TUN
        // mode data does not flow through the local proxy).
        // startProxyWithRetries increments it automatically on a port conflict.
        private const val LOCAL_PROXY_PORT = 8080
    }

    fun initSettings(context: android.content.Context) {
        if (settingsManager == null) {
            settingsManager = SettingsManager(context)
        }
    }

    fun loadSettings() {
        settingsManager?.let { manager ->
            val loadedNodes = manager.loadNodes()
            nodes.value = loadedNodes.toMutableList()
            relayMode.value = manager.loadRelayMode()
            relayUrl.value = manager.loadRelayUrl()
            forceRelay.value = manager.loadForceRelay()
            twoFactorEnabled.value = manager.loadTwoFactorEnabled()
            twoFactorClientId.value = manager.loadTwoFactorClientId()
            twoFactorSecret.value = manager.loadTwoFactorSecret()
            twoFactorAlgorithm.value = manager.loadTwoFactorAlgorithm()
            addLog("Settings loaded: ${loadedNodes.size} nodes, relay=${relayMode.value}")
        }
    }

    private fun saveSettings() {
        settingsManager?.let { manager ->
            manager.saveNodes(nodes.value)
            manager.saveRelayConfig(relayMode.value, relayUrl.value, forceRelay.value)
            manager.saveTwoFactorConfig(
                twoFactorEnabled.value,
                twoFactorClientId.value,
                twoFactorSecret.value,
                twoFactorAlgorithm.value
            )
        }
    }

    fun updateRelayConfig(mode: String, url: String, force: Boolean) {
        relayMode.value = mode
        relayUrl.value = url
        forceRelay.value = force
        saveSettings()
        addLog("Relay config updated: mode=${mode}, force=${force}")
    }

    fun updateTwoFactorConfig(enabled: Boolean, clientId: String, secret: String, algorithm: String) {
        twoFactorEnabled.value = enabled
        twoFactorClientId.value = clientId
        twoFactorSecret.value = secret
        twoFactorAlgorithm.value = algorithm
        saveSettings()
        addLog("2FA config updated: enabled=${enabled}, client=${clientId}, algorithm=${algorithm}")
    }

    fun addLog(message: String) {
        Log.d(TAG, message)
        viewModelScope.launch {
            logMessages.value.add(message)
            if (logMessages.value.size > 100) {
                logMessages.value.removeFirst()
            }
            logMessages.value = logMessages.value.toMutableList()
        }
    }

    fun startIroh() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                ensureIrohStarted()
            } catch (e: Exception) {
                addLog("Error starting iroh: ${e.message}")
                errorMessage.value = e.message ?: "Unknown error"
            }
        }
    }

    /**
     * Starts the iroh endpoint if it is not up yet. nativeStartIroh already has
     * a 30s timeout on the Rust side. Throwing means failure; the caller
     * decides whether to retry.
     */
    private suspend fun ensureIrohStarted() {
        if (isIrohStarted.value) return
        addLog("Starting iroh first...")
        val id = IrohProxy.nativeStartIroh()
        if (id != null) {
            endpointId.value = id
            isIrohStarted.value = true
            addLog("Iroh started: $id")
        } else {
            throw Exception("Failed to start iroh")
        }
    }

    /**
     * Reads the system DNS server list from ConnectivityManager and returns it
     * as a comma-separated string of IPs.
     *
     * By default iroh fails to read the system DNS on Android through JNI
     * ("Null pointer in call_method obj argument") and falls back to Google DNS
     * (8.8.8.8/8.8.4.4), which is unreliable behind restrictive networks and
     * leaves the backend unreachable. Instead, Kotlin reads the system DNS
     * straight from ConnectivityManager.getLinkProperties().dnsServers and
     * hands it to nativeSetDnsServers on the Rust side, so iroh uses a custom
     * DnsResolver instead of the broken JNI path.
     *
     * A connected Wi-Fi network is always preferred; cellular is only picked
     * when no usable Wi-Fi exists. Only that network's DNS is read, so Wi-Fi
     * and cellular DNS are never mixed. If the system DNS list is empty (an
     * edge case), fall back to public DNS servers that are widely reachable
     * from mainland China (AliDNS 223.5.5.5, 114DNS 114.114.114.114).
     */
    private fun getSystemDnsServers(context: Context): String {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return ""
        val selectedNetwork = UnderlyingNetworkSelector.selectPreferredNetwork(cm)
        val servers = UnderlyingNetworkSelector
            .dnsServers(cm, selectedNetwork)
            .toCollection(linkedSetOf())
        if (servers.isNotEmpty()) {
            addLog(
                "Using ${UnderlyingNetworkSelector.transportName(cm, selectedNetwork)} DNS: $servers"
            )
        }

        // Last-resort fallback: public DNS servers commonly reachable from
        // mainland China. AliDNS + 114DNS cover the common cases.
        if (servers.isEmpty()) {
            addLog("No system DNS found, falling back to public DNS (223.5.5.5, 114.114.114.114)")
            servers.add("223.5.5.5")
            servers.add("114.114.114.114")
        }

        return servers.joinToString(",")
    }

    /**
     * Pre-resolves the IPs of the iroh infrastructure domains and injects them
     * into the OverrideResolver on the Rust side.
     *
     * The Great Firewall (GFW) drops UDP DNS responses for iroh.link domains,
     * so iroh's internal hickory resolver times out on dns.iroh.link and
     * *.relay.n0.iroh.link. Those domains are pre-resolved here with the system
     * DNS (InetAddress, which may go through DoT / Private DNS and bypass the
     * GFW) and returned as "domain=ip1,ip2;domain2=ip3" for connect() to pass
     * to nativeSetDnsOverride. The OverrideResolver then returns the
     * pre-resolved IPs directly for these domains, so pkarr resolve (HTTPS to
     * dns.iroh.link/pkarr/<z32>) and the relay connection succeed.
     */
    private suspend fun resolveIrohDnsOverrides(): String {
        // DNS origin and default relay servers used by iroh presets::N0.
        val domains = listOf(
            "dns.iroh.link",
            "use1-1.relay.n0.iroh.link",
            "usw1-1.relay.n0.iroh.link",
            "euc1-1.relay.n0.iroh.link",
            "aps1-1.relay.n0.iroh.link",
        )

        val overrides = kotlinx.coroutines.coroutineScope {
            domains.map { domain ->
                async(Dispatchers.IO) {
                    try {
                        val addrs = InetAddress.getAllByName(domain)
                        val ips = addrs.mapNotNull { it.hostAddress }
                        if (ips.isNotEmpty()) {
                            addLog("Resolved iroh domain $domain -> $ips")
                            "$domain=${ips.joinToString(",")}"
                        } else {
                            addLog("Failed to resolve iroh domain $domain (no IPs)")
                            null
                        }
                    } catch (e: Exception) {
                        addLog("Failed to resolve iroh domain $domain: ${e.message}")
                        null
                    }
                }
            }.awaitAll()
        }

        val result = overrides.filterNotNull().joinToString(";")
        addLog("iroh DNS overrides: $result")
        return result
    }

    /**
     * Clears and re-adds the domain -> node mappings. Returns the list of all
     * domains that have to be proxied; throws when there is no mapping at all.
     */
    private suspend fun addDomainMappings(): List<String> {
        IrohProxy.nativeClearNodes()
        var hasDomainMappings = false
        for (node in nodes.value) {
            if (node.domains.isNotEmpty()) {
                for (domain in node.domains) {
                    addLog("Adding domain mapping: '$domain' -> nodeId: ${node.nodeId}")
                    val result = IrohProxy.nativeAddDomainMapping(domain, node.nodeId)
                    if (result != 0) {
                        addLog("Failed to add domain mapping: $domain")
                    } else {
                        hasDomainMappings = true
                    }
                }
            }
        }
        if (!hasDomainMappings) {
            throw Exception("No domain mappings configured. Please add nodes with domains.")
        }
        return nodes.value.flatMap { it.domains }
    }

    /**
     * Starts the local proxy. nativeStopProxy runs first (Rust releases the
     * listening port deterministically, no delay needed), then it retries up to
     * 10 times with an incrementing port. Returns the port actually in use.
     */
    private suspend fun startProxyWithRetries(basePort: Int): Int {
        addLog("Starting proxy...")
        IrohProxy.nativeStopProxy()
        var result = -1
        var actualPort = basePort
        for (attempt in 0..9) {
            actualPort = basePort + attempt
            addLog("Trying to start proxy on port $actualPort...")
            result = IrohProxy.nativeStartProxy(actualPort)
            if (result == 0) break
            addLog("Failed to start proxy on port $actualPort, retrying...")
            delay(200)
        }
        if (result != 0) {
            throw Exception("Failed to start proxy on ports $basePort..${basePort + 9}")
        }
        addLog("Proxy started on port $actualPort")
        return actualPort
    }

    /**
     * Releases every tunnel resource: nativeDestroy (stops the local proxy and
     * drops the iroh endpoint) + resets the state + stops the VPN service.
     * Key point: isIrohStarted is reset to false and nativeDestroy clears the
     * endpoint, so the next connect runs nativeStartIroh again and builds a
     * brand new tunnel instead of reusing the old endpoint.
     * Note: nativeDestroy is used here rather than nativeStopProxy - the latter
     * only stops the proxy and keeps the endpoint, which is what
     * startProxyWithRetries needs when it rebinds the port.
     */
    private suspend fun releaseAllResources(context: Context) {
        try {
            IrohProxy.nativeDestroy()
        } catch (e: Exception) {
            addLog("releaseAllResources: nativeDestroy failed: ${e.message}")
        }
        isIrohStarted.value = false
        endpointId.value = ""
        try {
            val intent = Intent(context, NexaVpnService::class.java).apply {
                action = NexaVpnService.ACTION_STOP
            }
            context.startService(intent)
        } catch (_: Exception) {}
        isVpnRunning.value = false
    }

    fun connect(context: Context) {
        if (isConnecting.value) return
        connectJob = viewModelScope.launch(Dispatchers.IO) {
            // Mutually exclusive with disconnect; abandon this connect if a
            // disconnect is already in progress.
            if (!connectionMutex.tryLock()) {
                addLog("connect: disconnect in progress, aborting")
                return@launch
            }

            // If the VPN is already believed to be running (stale state after
            // activity recreation, or a repeated tap), tear the old tunnel down
            // cleanly first. Otherwise nativeStopProxy stops the TUN proxy while
            // the service skips ACTION_START ("VPN already running, skipping"),
            // leaving a dead tunnel that looks like a disconnect after connecting.
            if (isVpnRunning.value) {
                addLog("connect: VPN already running, stopping it before reconnecting")
                releaseAllResources(context)
            }

            try {
                isConnecting.value = true
                errorMessage.value = null
                connectionStatusText.value = null

                if (!IrohProxy.isNativeLoaded()) {
                    throw Exception("Native library not loaded. Please check if libnexapipe_client.so is properly included in the APK.")
                }
                val vpnPermissionGranted = VpnService.prepare(context) == null
                if (!vpnPermissionGranted) {
                    throw Exception("VPN permission not granted. Please grant VPN permission first.")
                }

                val basePort = LOCAL_PROXY_PORT
                var lastError: Exception? = null

                // Retry loop: every attempt has an overall timeout of
                // ATTEMPT_TIMEOUT_MS; on timeout or failure all resources are
                // released before the next attempt.
                for (attempt in 1..MAX_CONNECT_ATTEMPTS) {
                    try {
                        withTimeout(ATTEMPT_TIMEOUT_MS) {
                            // Inject the system DNS into iroh so it does not
                            // fall back to Google DNS after the JNI system-DNS
                            // read fails on Android (unreliable behind
                            // restrictive networks, backends unreachable).
                            // Re-read on every retry because the network may
                            // have changed after releaseAllResources.
                            val dnsServers = getSystemDnsServers(context)
                            if (dnsServers.isNotEmpty()) {
                                addLog("Injecting system DNS servers: $dnsServers")
                                IrohProxy.nativeSetDnsServers(dnsServers)
                            }
                            // Pre-resolve the iroh infrastructure domains
                            // (dns.iroh.link + relays) to work around the GFW
                            // dropping iroh.link UDP DNS responses. Re-resolved
                            // on every retry.
                            val dnsOverrides = resolveIrohDnsOverrides()
                            if (dnsOverrides.isNotEmpty()) {
                                IrohProxy.nativeSetDnsOverride(dnsOverrides)
                            }
                            // Configure the relay mode
                            IrohProxy.nativeSetRelayConfig(relayMode.value, relayUrl.value)
                            // Configure the 2FA credentials (must be injected
                            // before nativeStartProxy)
                            if (twoFactorEnabled.value) {
                                IrohProxy.nativeSetTwoFactor(
                                    twoFactorClientId.value,
                                    twoFactorSecret.value,
                                    twoFactorAlgorithm.value
                                )
                            }
                            ensureIrohStarted()
                            val allDomains = addDomainMappings()
                            startProxyWithRetries(basePort)

                            // Pre-connect: warm up iroh connections directly on the Rust side
                            // and cache them in the shared connection pool. Unlike HTTP-based
                            // warm-up through the local proxy, this does not depend on backends
                            // answering plain HTTP requests, and it does not consume pooled
                            // connections, so warm-up is reliable.
                            // Pre-connect runs as part of the overall connecting flow;
                            // the UI keeps showing "Connecting..." (no separate status).
                            addLog("Pre-connecting to backends (native warm-up)...")
                            val preConnectedCount = IrohProxy.nativePreconnect()
                            if (preConnectedCount > 0) {
                                addLog("Pre-connect completed: $preConnectedCount backend(s) warmed")
                                delay(1000)
                            } else {
                                addLog("Pre-connect failed or no backend warmed ($preConnectedCount), starting VPN anyway")
                            }
                        }

                        // Success: start the VPN foreground service.
                        val allDomains = nodes.value.flatMap { it.domains }
                        val intent = Intent(context, NexaVpnService::class.java).apply {
                            action = NexaVpnService.ACTION_START
                            putStringArrayListExtra(NexaVpnService.EXTRA_DOMAINS, ArrayList(allDomains))
                        }
                        context.startForegroundService(intent)
                        isVpnRunning.value = true
                        addLog("VPN connected successfully (attempt $attempt/$MAX_CONNECT_ATTEMPTS)")
                        return@launch
                    } catch (e: TimeoutCancellationException) {
                        // withTimeout expired: retryable.
                        addLog("Attempt $attempt/$MAX_CONNECT_ATTEMPTS timed out after ${ATTEMPT_TIMEOUT_MS}ms")
                        lastError = e
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        // Deliberate cancellation from disconnect: do not
                        // retry, propagate to exit the loop.
                        throw e
                    } catch (e: Exception) {
                        addLog("Attempt $attempt/$MAX_CONNECT_ATTEMPTS failed: ${e.message}")
                        lastError = e
                    }

                    if (attempt < MAX_CONNECT_ATTEMPTS) {
                        addLog("Releasing all resources before retry...")
                        releaseAllResources(context)
                        delay(BACKOFF_MS[attempt])
                    }
                }
                errorMessage.value = lastError?.message ?: "All connection attempts failed"
                addLog("All $MAX_CONNECT_ATTEMPTS attempts failed")
            } finally {
                isConnecting.value = false
                connectionStatusText.value = null
                connectionMutex.unlock()
            }
        }
    }

    fun disconnect(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            // Cancel the in-flight connect: JNI cannot be interrupted, but the
            // next suspension point throws CancellationException and it exits.
            connectJob?.cancel()

            // Wait for connect to release the mutex (its finally block unlocks
            // it). The budget is slightly larger than a single connect timeout.
            val locked = withTimeoutOrNull(DISCONNECT_MUTEX_TIMEOUT_MS) {
                connectionMutex.withLock {
                    releaseAllResources(context)
                }
            }
            if (locked == null) {
                // Edge case: connect is still stuck in JNI past the budget.
                // There is no deadlock on the Rust side anymore, so force the
                // release.
                addLog("disconnect: could not acquire mutex within ${DISCONNECT_MUTEX_TIMEOUT_MS}ms, forcing release")
                releaseAllResources(context)
            }
            addLog("VPN disconnected")
        }
    }

    fun checkVpnPermission(context: Context): Boolean {
        val granted = VpnService.prepare(context) == null
        vpnPermissionGranted.value = granted
        return granted
    }

    fun checkNotificationPermission(context: Context): Boolean {
        val granted = PermissionManager.checkNotificationPermission(context)
        notificationPermissionGranted.value = granted
        return granted
    }

    fun refreshPermissions(context: Context) {
        checkVpnPermission(context)
        checkNotificationPermission(context)
    }

    fun addNode(nodeId: String) {
        if (nodeId.isNotEmpty() && !nodes.value.any { it.nodeId == nodeId }) {
            nodes.value.add(NodeConfig(nodeId))
            nodes.value = nodes.value.toMutableList()
            saveSettings()
        }
    }

    fun removeNode(nodeId: String) {
        nodes.value.removeAll { it.nodeId == nodeId }
        nodes.value = nodes.value.toMutableList()
        saveSettings()
        if (isIrohStarted.value) {
            IrohProxy.nativeRemoveNode(nodeId)
            addLog("Removed node: $nodeId")
        }
    }

    fun addDomainToNode(nodeId: String, domain: String) {
        if (domain.isNotEmpty()) {
            val nodeIndex = nodes.value.indexOfFirst { it.nodeId == nodeId }
            if (nodeIndex != -1) {
                val node = nodes.value[nodeIndex]
                if (!node.domains.contains(domain)) {
                    val newDomains = node.domains.toMutableList().apply { add(domain) }
                    val newNode = node.copy(domains = newDomains)
                    val newNodes = nodes.value.toMutableList().apply { set(nodeIndex, newNode) }
                    nodes.value = newNodes
                    saveSettings()
                }
            }
        }
    }

    fun removeDomainFromNode(nodeId: String, domain: String) {
        val nodeIndex = nodes.value.indexOfFirst { it.nodeId == nodeId }
        if (nodeIndex != -1) {
            val node = nodes.value[nodeIndex]
            if (node.domains.contains(domain)) {
                val newDomains = node.domains.toMutableList().apply { remove(domain) }
                val newNode = node.copy(domains = newDomains)
                val newNodes = nodes.value.toMutableList().apply { set(nodeIndex, newNode) }
                nodes.value = newNodes
                saveSettings()
            }
        }
    }

    fun clearLogs() {
        logMessages.value.clear()
        logMessages.value = logMessages.value.toMutableList()
    }

    /**
     * Syncs the ViewModel's isVpnRunning with the actual NexaVpnService state.
     *
     * Scenario: after the Activity/ViewModel is recreated (partial process
     * restore, developer options, ...), isVpnRunning defaults to false while
     * the VPN service may still be running in the foreground. Calling this
     * aligns the UI state with the real service state, so the UI cannot show
     * "Disconnected" while the tunnel is actually usable.
     */
    fun syncVpnServiceState() {
        if (!isVpnRunning.value && !isConnecting.value && NexaVpnService.isServiceActive) {
            isVpnRunning.value = true
            addLog("Synced UI state: VPN service is active")
        }
    }
}
