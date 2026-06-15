package com.peachtea.controller;

import java.util.function.Consumer;

import com.peachtea.model.ScanResult;

public class ScanController 
{
    // ─── Private fields ───────────────────────────────────────
    private final EngineController engineController;

    // ─── Constructor ──────────────────────────────────────────
    public ScanController(EngineController engineController) 
    {
        this.engineController = engineController;
    }

    // ─── Public ───────────────────────────────────────────────
    public void startScan(Runnable onProgress, Consumer<String> onLog,
                          Consumer<String> onError, Consumer<ScanResult> onComplete,
                          Runnable onFinally) 
    {
        new Thread(() -> 
        {
            try 
            {
                NetworkScanner scanner = new NetworkScanner(engineController);
                if (!ProcessHelper.isSudoAvailable()) 
                {
                    onError.accept("sudo password required. Please enter it in the terminal, then try again.");
                }

                onLog.accept("Fetching network info...");
                scanner.fetchNetworkInfo();

                if (scanner.getLocalIp() == 0) 
                {
                    onError.accept("Interface has no IP. Is it connected to a network?");
                    return;
                }

                onLog.accept("Starting network scan...");
                scanner.scan(onProgress, onLog);

                String gatewayIp = scanner.getGatewayIp();
                java.util.List<String> discovered = scanner.getDiscoveredIps();

                if (gatewayIp == null) 
                {
                    onError.accept("Scan complete but gateway not found. Cannot proceed.");
                    return;
                }

                if (discovered.isEmpty()) 
                {
                    onError.accept("Scan complete but no hosts found. Cannot proceed.");
                    return;
                }

                onLog.accept("Gateway: " + gatewayIp);
                onLog.accept("Hosts found: " + discovered.size());
                discovered.forEach(ip -> onLog.accept("  " + ip));

                onComplete.accept(new ScanResult(gatewayIp, discovered));
            } 
            catch (Exception ex) 
            {
                onError.accept("Scan failed: " + ex.getMessage());
            } 
            finally 
            {
                onFinally.run();
            }
        }).start();
    }
}