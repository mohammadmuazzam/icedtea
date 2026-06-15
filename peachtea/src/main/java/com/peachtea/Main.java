package com.peachtea;

import javax.swing.SwingUtilities;

import com.formdev.flatlaf.FlatDarkLaf;
import com.peachtea.ui.InterfacePicker;
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

        SwingUtilities.invokeLater(() -> {
            InterfacePicker picker = new InterfacePicker();
            picker.setVisible(true);

            String iface = picker.getSelectedInterface();
            if (iface == null) {
                System.err.println("No interface selected. Exiting.");
                System.exit(0);
            }

            MainDashboard dashboard = new MainDashboard(iface);
            dashboard.setVisible(true);
        });
    }
}