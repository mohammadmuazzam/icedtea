package com.peachtea.ui;

import javax.swing.JFrame;

import com.peachtea.controller.EngineController;
import com.peachtea.model.ScanResult;

public class MainDashboard extends JFrame 
{
    private EngineController engineController;

    public MainDashboard(String networkInterface) 
    {
        setTitle("IcedTea");
        setSize(750, 650);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        ScanPanel scanPanel = new ScanPanel(networkInterface, this::showSpoofPanel);
        this.engineController = scanPanel.getEngineController();
        add(scanPanel);
    }

    private void showSpoofPanel(ScanResult result) 
    {
        getContentPane().removeAll();
        add(new SpoofPanel(result, engineController));
        revalidate();
        repaint();
    }
}