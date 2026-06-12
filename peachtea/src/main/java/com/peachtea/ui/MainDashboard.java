package com.peachtea.ui;

import javax.swing.JFrame;

public class MainDashboard extends JFrame {
    
    public MainDashboard() {
        setTitle("Network Infiltrator");
        setSize(750, 650);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        
        //TODO: rethink this
        // 2. Inject your modular layout panel canvas
        ScanPanel scanPanel = new ScanPanel();
        add(scanPanel);
    }
}