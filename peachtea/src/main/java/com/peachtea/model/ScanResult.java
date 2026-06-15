package com.peachtea.model;

import java.util.List;

public class ScanResult 
{
    public final String gatewayIp;
    public final List<String> discoveredIps;

    public ScanResult(String gatewayIp, List<String> discoveredIps) 
    {
        this.gatewayIp = gatewayIp;
        this.discoveredIps = discoveredIps;
    }
}