package com.peachtea.controller;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import com.peachtea.model.Engine;

public class NetworkScanner 
{
    private static final int TIMEOUT_MS = 500;
    private static final int THREAD_POOL_SIZE = 50;

    private final EngineController engineController;
    private String gatewayIp;
    private long subnetMask = -1L;
    private long localIp = -1L;
    private final List<String> discoveredIps = new ArrayList<>();

    public NetworkScanner(EngineController engineController) 
    {
        this.engineController = engineController;
    }

    public void scan(Runnable progressCallback, Consumer<String> logCallback) throws Exception 
    {
        gatewayIp = null;
        discoveredIps.clear();

        if (localIp == -1 || subnetMask == -1)
            throw new IllegalStateException("Network info not fetched. Call fetchNetworkInfo() first.");

        if ((localIp >> 24) == 127)
            throw new IllegalStateException("Interface is loopback. Select a real network interface.");

        if (subnetMask == 0)
            throw new IllegalStateException("Illegal subnet mask of 0. Cannot scan. Is this the correct interface?");

        long networkBase = localIp & subnetMask;
        long broadcast   = networkBase | (~subnetMask & 0xFFFFFFFFL);

        String detectedGateway = detectGateway();
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

        logCallback.accept("Gateway: " + detectedGateway);
        logCallback.accept("localIp: " + longToIp(localIp));
        logCallback.accept("subnetMask: " + longToIp(subnetMask));
        logCallback.accept("networkBase: " + longToIp(networkBase));
        logCallback.accept("broadcast: " + longToIp(broadcast));

        for (long i = networkBase + 1; i < broadcast; i++) 
        {
            final String ip = longToIp(i);
            executor.submit(() -> 
            {
                try 
                {
                    //#logCallback.accept("Testing for: " + ip);
                    InetAddress addr = InetAddress.getByName(ip);
                    if (addr.isReachable(TIMEOUT_MS)) 
                    {
                        logCallback.accept("Found: " + ip);

                        synchronized (discoveredIps) 
                        {
                            if (ip.equals(detectedGateway)) 
                                gatewayIp = ip;
                            else 
                                discoveredIps.add(ip);
                        }
                    }
                } 
                catch (IOException ignored) {}

                if (progressCallback != null) 
                    progressCallback.run();
            });
        }

        executor.shutdown();
        executor.awaitTermination(60, TimeUnit.SECONDS);
    }

    public void fetchNetworkInfo() throws Exception 
    {
        localIp    = engineController.query(Engine.Flag.LOCALIP);
        subnetMask = engineController.query(Engine.Flag.SUBNET);
    }

    public String getGatewayIp()           { return gatewayIp; }
    public List<String> getDiscoveredIps() { return new ArrayList<>(discoveredIps); }
    public long getSubnetMask()            { return subnetMask; }
    public long getLocalIp()               { return localIp; }

    private String detectGateway() 
    {
        try 
        {
            Process p = new ProcessBuilder("ip", "route", "show", "default").start();
            String output = new String(p.getInputStream().readAllBytes()).trim();
            for (String line : output.split("\n")) 
            {
                if (line.contains("dev " + engineController.getInterface())) 
                {
                    String[] parts = line.split("\\s+");
                    for (int i = 0; i < parts.length - 1; i++) 
                    {
                        if (parts[i].equals("via")) return parts[i + 1];
                    }
                }
            }
        } 
        catch (IOException ignored) {}
        return null;
    }

    private String longToIp(long ip) 
    {
        return String.format("%d.%d.%d.%d",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8)  & 0xFF,
                ip        & 0xFF);
    }
}