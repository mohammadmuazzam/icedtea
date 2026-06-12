package com.peachtea.model;

import java.net.Inet4Address;

public class Host {
    private final Inet4Address ipv4;
    private final String macAddress;  // Formatted as "XX:XX:XX:XX:XX:XX"
    private final String hostname;    // Device network name (e.g., "Mohammad-PC")
    private boolean isTarget;         // For marking if this specific device is being spoofed

    // Robust constructor requiring core structural network data
    public Host(Inet4Address ipv4, String macAddress, String hostname) {
        this.ipv4 = ipv4;
        this.macAddress = (macAddress != null) ? macAddress.toUpperCase().trim() : "UNKNOWN";
        this.hostname = (hostname != null && !hostname.isEmpty()) ? hostname : "Unknown Device";
        this.isTarget = false;
    }

    // --- Getters & Setters ---
    public Inet4Address getIpv4() { 
        return ipv4; 
    }

    public String getIpv4AsString() {
        return ipv4.getHostAddress();
    }

    public String getMacAddress() { 
        return macAddress; 
    }

    public String getHostname() {
        return hostname;
    }

    public boolean isTarget() {
        return isTarget;
    }

    public void setTarget(boolean isTarget) {
        this.isTarget = isTarget;
    }

    // Clean data string override for printing directly to your UI lists or logs
    @Override
    public String toString() {
        return String.format("%s (%s) - MAC: %s", getIpv4AsString(), hostname, macAddress);
    }
}