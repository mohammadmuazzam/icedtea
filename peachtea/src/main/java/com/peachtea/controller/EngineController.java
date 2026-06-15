package com.peachtea.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import com.peachtea.model.Engine;

public class EngineController 
{
    private final Engine engine = Engine.getInstance();

    // ─── Public ───────────────────────────────────────────────

    public long query(Engine.Flag flag) throws Exception 
    {
        return engine.query(flag);
    }

    public String getInterface() 
    {
        return engine.getInterface();
    }

    public void startSpoofingAndSniffing(String gatewayIp, List<String> discoveredIps,
            String outputFileName, Consumer<String> onLog, Consumer<String> onError) 
    {
        if (engine.isRunning()) 
        {
            onError.accept("Native engine is already actively running!");
            return;
        }

        try 
        {
            engine.validateBinary();
        } 
        catch (IllegalStateException e) 
        {
            onError.accept("CRITICAL: " + e.getMessage());
            return;
        }

        if (!ProcessHelper.isSudoAvailable()) 
        {
            onError.accept("sudo password required. Please enter it in the terminal, then try again.");
        }

        new Thread(() -> 
        {
            try 
            {
                List<String> command = new ArrayList<>();
                command.add("sudo");
                command.add(engine.getBinaryPath());
                command.add("--interface");
                command.add(engine.getInterface());
                command.add(Engine.Flag.RUN.value);
                command.add(outputFileName);
                command.add(gatewayIp);
                command.addAll(discoveredIps);

                onLog.accept("Launching: " + String.join(" ", command));

                ProcessBuilder pb = new ProcessBuilder(command);
                pb.redirectErrorStream(true);
                engine.setNativeProcess(pb.start());

                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(engine.getNativeProcess().getInputStream()))) 
                {
                    String line;
                    while ((line = reader.readLine()) != null) 
                    {
                        onLog.accept(line.isBlank() ? "\n" : "[Engine] " + line);
                    }
                } 
                catch (IOException ignored) {}

                int exitCode = engine.getNativeProcess().waitFor();
                onLog.accept("Engine terminated with exit code: " + exitCode);

            } 
            catch (Exception e) 
            {
                onError.accept("Failed to communicate with C++ core: " + e.getMessage());
            }
        }).start();
    }

    public void stopEngine(Consumer<String> onLog) 
    {
        if (engine.isRunning()) 
        {
            onLog.accept("Terminating Engine...");
            engine.stop(onLog);
        }
    }
}