package com.peachtea.ui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

public class InterfacePicker extends JDialog {

    private String selectedInterface = null;

    public InterfacePicker() {
        setTitle("Select Network Interface");
        setModal(true);
        setSize(350, 200);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        String[] interfaces = getInterfaces();
        if (interfaces.length == 0) {
            JOptionPane.showMessageDialog(null, "No network interfaces found.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JComboBox<String> combo = new JComboBox<>(interfaces);
        JButton confirmButton = new JButton("Confirm");

        confirmButton.addActionListener(e -> {
            selectedInterface = (String) combo.getSelectedItem();
            dispose();
        });

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Network Interface:"), gbc);

        gbc.gridx = 1;
        panel.add(combo, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2;
        panel.add(confirmButton, gbc);

        add(panel);
    }

    private String[] getInterfaces() {
        try {
            // Use 'ip link show' to list interfaces, one per line
            Process p = new ProcessBuilder("ip", "-o", "link", "show")
                    .redirectErrorStream(true)
                    .start();

            String output = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();

            // Each line: "1: lo: ..." — extract the name before the colon
            return java.util.Arrays.stream(output.split("\n"))
                    .map(line -> line.split(":")[1].trim())
                    .filter(name -> !name.equals("lo"))
                    .toArray(String[]::new);

        } catch (IOException | InterruptedException e) {
            return new String[0];
        }
    }

    /** @return selected interface name, or null if dismissed */
    public String getSelectedInterface() {
        return selectedInterface;
    }
}