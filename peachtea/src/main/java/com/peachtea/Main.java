package com.peachtea;

import javax.swing.SwingUtilities;

import com.formdev.flatlaf.FlatDarkLaf;
import com.peachtea.ui.MainDashboard;

public class Main {
    public static void main(String[] args) {
        //* using flatdarklaf for modern feel */
        try
        {
            FlatDarkLaf.setup();
        } 
        catch (Exception e) 
        {
            System.err.println("Failed to initialize FlatLaf look and feel theme.");
        }

        SwingUtilities.invokeLater(() -> 
        {
            System.out.println("Opening MainDashboard framework...");
            MainDashboard dashboard = new MainDashboard();
            dashboard.setVisible(true);
        });
    }
}