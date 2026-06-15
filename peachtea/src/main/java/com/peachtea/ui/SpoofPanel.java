package com.peachtea.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import com.peachtea.controller.EngineController;
import com.peachtea.model.ScanResult;

public class SpoofPanel extends JPanel 
{
    // ─── Private fields ───────────────────────────────────────
    private final LogConsole logConsole;
    private JButton actionButton;
    private JLabel timerLabel;
    private JTextField filenameField;

    private final ScanResult scanResult;
    private final EngineController engineController;
    private final List<JCheckBox> checkBoxes = new ArrayList<>();

    private Timer clock;
    private int elapsedSeconds = 0;
    private boolean isSpoofing = false;

    // ─── Constructor ──────────────────────────────────────────
    public SpoofPanel(ScanResult scanResult, EngineController engineController) 
    {
        this.scanResult = scanResult;
        this.engineController = engineController;
        this.logConsole = new LogConsole("Engine Output", "Awaiting spoof command...");

        setLayout(new BorderLayout(15, 15));
        setBorder(new EmptyBorder(20, 20, 20, 20));

        setupHeader();
        setupCenter();
        setupBottom();
    }

    //* ─── Public ───────────────────────────────────────────────
    public void logMessage(String msg) 
    {
        logConsole.logMessage(msg);
    }

    public void logError(String err) 
    {
        logConsole.logError(err);
    }

    //* ─── Private ──────────────────────────────────────────────
    private void setupHeader() 
    {
        JLabel header = new JLabel("Gateway: " + scanResult.gatewayIp + " — Select targets to spoof");
        header.setFont(new Font("SansSerif", Font.BOLD, 14));
        add(header, BorderLayout.NORTH);
    }

    private void setupCenter() 
    {
        JPanel centerPanel = new JPanel(new BorderLayout(10, 10));

        JPanel checkboxPanel = new JPanel(new GridLayout(0, 1, 5, 5));
        checkboxPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

        for (String ip : scanResult.discoveredIps) 
        {
            String label = ip.equals(scanResult.gatewayIp) ? ip + "  (Gateway)" : ip;
            JCheckBox cb = new JCheckBox(label);
            cb.setFont(new Font("Monospaced", Font.PLAIN, 13));
            checkBoxes.add(cb);
            checkboxPanel.add(cb);
        }

        JScrollPane hostScroll = new JScrollPane(checkboxPanel);
        hostScroll.setBorder(BorderFactory.createTitledBorder("Discovered Hosts"));
        hostScroll.setPreferredSize(new Dimension(400, 200));
        centerPanel.add(hostScroll, BorderLayout.NORTH);

        centerPanel.add(logConsole, BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);
    }

    private void setupBottom() 
    {
        JPanel bottomPanel = new JPanel(new BorderLayout(10, 10));

        JPanel controlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        controlRow.add(new JLabel("Output file:"));

        filenameField = new JTextField("capture.pcap", 15);
        filenameField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        controlRow.add(filenameField);

        timerLabel = new JLabel("00:00:00");
        timerLabel.setFont(new Font("Monospaced", Font.BOLD, 14));
        timerLabel.setForeground(Color.GRAY);
        controlRow.add(timerLabel);

        bottomPanel.add(controlRow, BorderLayout.NORTH);

        actionButton = new JButton("SPOOF SELECTED");
        actionButton.setFont(new Font("SansSerif", Font.BOLD, 16));
        actionButton.addActionListener(e -> handleActionButton());
        bottomPanel.add(actionButton, BorderLayout.SOUTH);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void handleActionButton() 
    {
        if (isSpoofing) stopSpoofing();
        else startSpoofing();
    }

    private void startSpoofing() 
    {
        List<String> selected = new ArrayList<>();
        for (JCheckBox cb : checkBoxes) 
        {
            if (cb.isSelected()) 
                selected.add(cb.getText().replace("  (Gateway)", "").trim());
        }

        if (selected.isEmpty()) 
        {
            logError("No hosts selected.");
            return;
        }

        String filename = filenameField.getText().trim();
        if (filename.isEmpty()) 
            filename = "capture.pcap";

        isSpoofing = true;
        actionButton.setText("STOP SPOOF/SNIFF");
        filenameField.setEnabled(false);
        checkBoxes.forEach(cb -> cb.setEnabled(false));

        startClock();
        logMessage("Starting spoofing on " + selected.size() + " hosts...");

        engineController.startSpoofingAndSniffing(
            scanResult.gatewayIp, selected, filename,
            msg -> logMessage(msg),
            err -> logError(err)
        );
    }

    private void stopSpoofing() 
    {
        engineController.stopEngine(msg -> logMessage(msg));
        isSpoofing = false;
        stopClock();

        actionButton.setText("SPOOF SELECTED");
        filenameField.setEnabled(true);
        checkBoxes.forEach(cb -> cb.setEnabled(true));
        //#logMessage("Sniffing stopped. Saving to " + filenameField.getText().trim());
    }

    private void startClock() 
    {
        elapsedSeconds = 0;
        timerLabel.setForeground(new Color(0, 200, 0));
        clock = new Timer();
        clock.scheduleAtFixedRate(new TimerTask() 
        {
            @Override
            public void run() 
            {
                elapsedSeconds++;
                int h = elapsedSeconds / 3600;
                int m = (elapsedSeconds % 3600) / 60;
                int s = elapsedSeconds % 60;
                SwingUtilities.invokeLater(() -> 
                    timerLabel.setText(String.format("%02d:%02d:%02d", h, m, s)));
            }
        }, 1000, 1000);
    }

    private void stopClock() 
    {
        if (clock != null) 
        {
            clock.cancel();
            clock = null;
        }
        SwingUtilities.invokeLater(() -> timerLabel.setForeground(Color.GRAY));
    }
}