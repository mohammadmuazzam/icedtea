package com.peachtea.model;

import java.io.File;
import java.io.IOException;
import java.util.function.Consumer;

public class Engine 
{
    private static Engine instance;

    private final String binaryPath;
    private String networkInterface;
    private Process nativeProcess;

    private Engine() 
    {
        this.binaryPath = System.getProperty("user.dir") + "/peachtea/bin/icedTea";
    }

    public static Engine getInstance() 
    {
        if (instance == null) instance = new Engine();
        return instance;
    }

    public void setInterface(String networkInterface) 
    {
        this.networkInterface = networkInterface;
    }

    public String getInterface() 
    {
        return networkInterface;
    }

    public boolean isRunning() 
    {
        return nativeProcess != null && nativeProcess.isAlive();
    }

    public File getBinaryFile() 
    {
        return new File(binaryPath);
    }

    public String getBinaryPath() 
    {
        return binaryPath;
    }

    public Process getNativeProcess() 
    {
        return nativeProcess;
    }

    public void setNativeProcess(Process process) 
    {
        this.nativeProcess = process;
    }

    public enum Flag 
    {
        SUBNET("--subnet"),
        LOCALIP("--localip"),
        RUN("--run");

        public final String value;
        Flag(String value) { this.value = value; }
    }

    /** Calls the binary with a single flag, returns uint32 output as long. */
    public long query(Flag flag) throws Exception 
    {
        Process p = new ProcessBuilder("sudo", binaryPath, "--interface", networkInterface, flag.value)
                .redirectErrorStream(true)
                .start();
        String output = new String(p.getInputStream().readAllBytes()).trim();
        p.waitFor();
        if (output.isEmpty()) throw new IllegalStateException("Binary returned nothing for flag: " + flag.value);
        return Long.parseLong(output);
    }

    public void validateBinary() 
    {
        File binary = new File(binaryPath);
        if (!binary.exists())
            throw new IllegalStateException("Binary not found: " + binaryPath);
        if (!binary.canExecute())
            throw new IllegalStateException("Binary not executable: " + binaryPath + " — run: chmod +x icedTea");
    }

    public void stop(Consumer<String> onLog) 
    {
        if (isRunning()) 
        {
            long pid = nativeProcess.pid();
            try 
            {
                new ProcessBuilder("kill", "-TERM", String.valueOf(pid)).start();
            } 
            catch (IOException e) 
            {
                nativeProcess.destroy(); // fallback
            }
        }
    }
}