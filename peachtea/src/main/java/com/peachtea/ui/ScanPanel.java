package com.peachtea.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import com.peachtea.controller.EngineController;
import com.peachtea.controller.ScanController;
import com.peachtea.model.Engine;
import com.peachtea.model.ScanResult;

public class ScanPanel extends JPanel 
{
    // ─── Private fields ───────────────────────────────────────
    private final LogConsole logConsole;
    private JButton scanButton;
    private JProgressBar progressBar;
    private JComboBox<String> interfaceDropdown;

    private final EngineController engineController;
    private final ScanController scanController;
    private final Consumer<ScanResult> onScanComplete;

    // ─── Constructor ──────────────────────────────────────────
    public ScanPanel(String networkInterface, Consumer<ScanResult> onScanComplete) 
    {
        Engine.getInstance().setInterface(networkInterface);
        this.engineController = new EngineController();
        this.scanController = new ScanController(engineController);
        this.onScanComplete = onScanComplete;
        this.logConsole = new LogConsole("System Logs / Error Output", "System Idle. Ready to perform network audit.");

        setLayout(new BorderLayout(15, 15));
        setBorder(new EmptyBorder(20, 20, 20, 20));

        add(logConsole, BorderLayout.NORTH);
        setupControlDashboard();
    }

    // ─── Public ───────────────────────────────────────────────
    public EngineController getEngineController() 
    {
        return engineController;
    }

    public void logMessage(String msg) 
    {
        logConsole.logMessage(msg);
    }

    public void logError(String err) 
    {
        logConsole.logError(err);
    }

    public void updateProgress(int value) 
    {
        SwingUtilities.invokeLater(() -> progressBar.setValue(value));
    }

    // ─── Private ──────────────────────────────────────────────
    private String[] getNetworkInterfaces() 
    {
        try 
        {
            Process p = new ProcessBuilder("ip", "-o", "link", "show")
                    .redirectErrorStream(true)
                    .start();
            String output = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return java.util.Arrays.stream(output.split("\n"))
                    .map(line -> line.split(":")[1].trim())
                    .filter(name -> !name.equals("lo"))
                    .toArray(String[]::new);
        } 
        catch (IOException | InterruptedException e) 
        {
            return new String[]{ Engine.getInstance().getInterface() };
        }
    }

    private void setupControlDashboard() 
    {
        JPanel centerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Interface label
        JLabel ifaceLabel = new JLabel("Interface:");
        ifaceLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        centerPanel.add(ifaceLabel, gbc);

        // Interface dropdown
        interfaceDropdown = new JComboBox<>(getNetworkInterfaces());
        interfaceDropdown.setSelectedItem(Engine.getInstance().getInterface());
        interfaceDropdown.setFont(new Font("Monospaced", Font.PLAIN, 13));
        interfaceDropdown.addActionListener(e -> 
        {
            String selected = (String) interfaceDropdown.getSelectedItem();
            if (selected != null) 
            {
                Engine.getInstance().setInterface(selected);
                logMessage("Interface changed to: " + selected);
            }
        });
        gbc.gridx = 1; gbc.gridy = 0;
        centerPanel.add(interfaceDropdown, gbc);

        // Scan button
        scanButton = new JButton("SCAN NETWORK");
        scanButton.setFont(new Font("SansSerif", Font.BOLD, 16));
        scanButton.setPreferredSize(new Dimension(200, 50));
        scanButton.addActionListener(e -> triggerNetworkScan());
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2;
        centerPanel.add(scanButton, gbc);

        // Progress bar
        progressBar = new JProgressBar(0, 254);
        progressBar.setStringPainted(true);
        gbc.gridx = 0; gbc.gridy = 2;
        centerPanel.add(progressBar, gbc);

        add(centerPanel, BorderLayout.CENTER);
    }

    private void triggerNetworkScan() 
    {
        scanButton.setEnabled(false);
        progressBar.setValue(0);
        AtomicInteger progress = new AtomicInteger(0);

        scanController.startScan(
            () -> updateProgress(progress.incrementAndGet()),
            msg -> logMessage(msg),
            err -> logError(err),
            onScanComplete,
            () -> SwingUtilities.invokeLater(() -> scanButton.setEnabled(true))
        );
    }
}