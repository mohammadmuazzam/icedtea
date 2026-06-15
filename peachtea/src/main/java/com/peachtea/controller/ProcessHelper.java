package com.peachtea.controller;

public class ProcessHelper 
{
    public static boolean isSudoAvailable() 
    {
        try 
        {
            Process p = new ProcessBuilder("sudo", "-n","true")
                    .redirectErrorStream(true)
                    .start();
            return p.waitFor() == 0;
        } 
        catch (Exception e) 
        {
            return false;
        }
    }
}
