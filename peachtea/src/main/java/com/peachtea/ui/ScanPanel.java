package com.peachtea.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

public class ScanPanel extends JPanel {
    private JTextArea logConsole;
    private JButton scanButton;
    private JTextField subnetField;
    private JProgressBar progressBar;

    public ScanPanel() {
        setupPanelProperties();
        setupLogConsole();
        setupControlDashboard();
    }

    private void setupPanelProperties() {
        setLayout(new BorderLayout(15, 15));
        setBorder(new EmptyBorder(20, 20, 20, 20));
    }

    private void setupLogConsole() {
        logConsole = new JTextArea(12, 40);
        logConsole.setEditable(false);
        logConsole.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logConsole.setBackground(new Color(30, 30, 30)); 
        logConsole.setForeground(new Color(0, 255, 0));  
        logConsole.setText("System Idle. Ready to perform network audit.\n");
        
        JScrollPane scrollPane = new JScrollPane(logConsole);
        scrollPane.setBorder(BorderFactory.createTitledBorder("System Logs / Error Output"));
        add(scrollPane, BorderLayout.NORTH);
    }

    private void setupControlDashboard() {
        JPanel centerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Subnet Input Field
        JLabel label = new JLabel("Target Subnet Range:");
        label.setFont(new Font("SansSerif", Font.BOLD, 14));
        gbc.gridx = 0; gbc.gridy = 0;
        centerPanel.add(label, gbc);

        subnetField = new JTextField("192.168.1.");
        subnetField.setFont(new Font("SansSerif", Font.PLAIN, 14));
        gbc.gridx = 1; gbc.gridy = 0;
        gbc.weightx = 1.0;
        centerPanel.add(subnetField, gbc);

        // Scan Activation Button
        scanButton = new JButton("SCAN NETWORK");
        scanButton.setFont(new Font("SansSerif", Font.BOLD, 16));
        scanButton.setPreferredSize(new Dimension(200, 50));
        scanButton.addActionListener(e -> triggerNetworkScan());
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 0;
        centerPanel.add(scanButton, gbc);
        
        // Operational Progress Bar
        progressBar = new JProgressBar(0, 254);
        progressBar.setStringPainted(true);
        gbc.gridx = 0; gbc.gridy = 2;
        centerPanel.add(progressBar, gbc);

        add(centerPanel, BorderLayout.CENTER);
    }

    private void triggerNetworkScan() {
        String baseSubnet = subnetField.getText().trim();
        
        if (baseSubnet.isEmpty() || !baseSubnet.endsWith(".")) {
            logError("Invalid Subnet Format! Target must end with a dot (e.g., '192.168.1.')");
            return;
        }

        logMessage("Initializing asynchronous multi-threaded subnet sweep on " + baseSubnet + "0/24...");
        scanButton.setEnabled(false);
        progressBar.setValue(0);
    }

    public void logMessage(String msg) {
        SwingUtilities.invokeLater(() -> {
            logConsole.setForeground(new Color(0, 255, 0));
            logConsole.append("[INFO] " + msg + "\n");
        });
    }

    public void logError(String err) {
        SwingUtilities.invokeLater(() -> {
            logConsole.setForeground(Color.RED);
            logConsole.append("[ERROR] " + err + "\n");
        });
    }
    
    public void updateProgress(int value) {
        SwingUtilities.invokeLater(() -> progressBar.setValue(value));
    }
}