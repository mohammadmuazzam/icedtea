package com.peachtea.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public class LogConsole extends JPanel 
{
    // ─── Private fields ───────────────────────────────────────
    private final JTextPane textPane;

    // ─── Constructor ──────────────────────────────────────────
    public LogConsole(String title, String initialMessage) 
    {
        setLayout(new BorderLayout());

        textPane = new JTextPane();
        textPane.setEditable(false);
        textPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        textPane.setBackground(new Color(30, 30, 30));
        textPane.setPreferredSize(new Dimension(700, 400));

        JScrollPane scrollPane = new JScrollPane(textPane);
        scrollPane.setBorder(BorderFactory.createTitledBorder(title));

        add(scrollPane, BorderLayout.CENTER);
        logMessage(initialMessage);
    }

    // ─── Public ───────────────────────────────────────────────
    public void logMessage(String msg) 
    {
        appendLog("[INFO] " + msg, new Color(0, 255, 0));
    }

    public void logError(String err) 
    {
        appendLog("[ERROR] " + err, Color.RED);
    }

    public void log(String msg) 
    {
        appendLog(msg, new Color(0, 255, 0));
    }

    // ─── Private ──────────────────────────────────────────────
    private void appendLog(String msg, Color color) 
    {
        SwingUtilities.invokeLater(() -> 
        {
            StyledDocument doc = textPane.getStyledDocument();
            SimpleAttributeSet style = new SimpleAttributeSet();
            StyleConstants.setForeground(style, color);
            try 
            {
                doc.insertString(doc.getLength(), msg + "\n", style);
            } 
            catch (Exception ignored) {}
        });
    }
}