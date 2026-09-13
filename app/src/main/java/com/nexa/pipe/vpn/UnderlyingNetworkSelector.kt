package com.nexa.pipe.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities

/**
 * Selects the physical network used by Nexa's VPN and exposes its DNS servers.
 *
 * A VPN must name its actual egress network with setUnderlyingNetworks().  Do
 * not use callback delivery order here: when Wi-Fi and cellular are both up,
 * Android is free to report cellular first.  Nexa deliberately prefers Wi-Fi
 * whenever it is connected and usable, then falls back to cellular.
 */
object UnderlyingNetworkSelector {
    @Suppress("DEPRECATION")
    fun selectPreferredNetwork(connectivityManager: ConnectivityManager): Network? {
        var cellular: Network? = null

        for (network in connectivityManager.allNetworks) {
            val capabilities = connectivityManager.getNetworkCapabilities(network) ?: continue
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            ) {
                continue
            }

            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return network
            }
            if (cellular == null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                cellular = network
            }
        }

        return cellular
    }

    fun dnsServers(connectivityManager: ConnectivityManager, network: Network?): List<String> {
        if (network == null) return emptyList()

        return connectivityManager.getLinkProperties(network)
            ?.dnsServers
            ?.mapNotNull { it.hostAddress }
            ?.distinct()
            .orEmpty()
    }

    fun transportName(connectivityManager: ConnectivityManager, network: Network?): String = when {
        network == null -> "none"
        connectivityManager.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "Wi-Fi"
        connectivityManager.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
        else -> "unknown"
    }
}
