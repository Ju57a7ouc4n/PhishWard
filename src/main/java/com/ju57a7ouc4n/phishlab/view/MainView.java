
/*
 * PhishWard - A proactive phishing and threat analysis tool.
 * Copyright (C) 2026 ju57a7ouc4n
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.ju57a7ouc4n.phishlab.view;

import javax.swing.*;

import com.ju57a7ouc4n.phishlab.controller.PhishWardController;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import java.util.Queue;

/**
 * Main Graphical User Interface (GUI) for PhishWard.
 * Implements the visual skeleton (View) without the business logic.
 *
 * @author ju57a7ouc4n
 * @version 1.0
 */
public class MainView extends JFrame {
    private JTextField urlField;
    private JButton analyzeBtn;
    private JTextArea consoleArea;
    private JLabel scoreLabel;
    private JButton whitelistBtn;
    private JButton blacklistBtn;
    private PhishWardController controller;
    private JTextField apiKeyField;
    private final Queue<String> messageQueue = new LinkedList<>();
    private boolean isTyping = false;
    private int pendingScore = 0;
    private Color pendingColor = Color.GRAY;
    private boolean scoreNeedsUpdate = false;

    public MainView() {
        setTitle("PhishWard - Threat Analysis Engine");
        setSize(800, 500);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));
        initUI();
        createMenuBar();
    }

    private void initUI() {
        JPanel northContainer = new JPanel(new GridLayout(2, 1, 0, 5)); 
        northContainer.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        JPanel urlRow = new JPanel(new BorderLayout(5, 5));
        urlField = new JTextField();
        analyzeBtn = new JButton("Analyze URL");
        analyzeBtn.setActionCommand("ANALYZE");
        urlField.setFont(new Font("Consolas", Font.PLAIN, 14));
        urlRow.add(new JLabel("Target URL:      "), BorderLayout.WEST);
        urlRow.add(urlField, BorderLayout.CENTER);
        urlRow.add(analyzeBtn, BorderLayout.EAST);
        JPanel apiRow = new JPanel(new BorderLayout(5, 5));
        apiKeyField = new JTextField(); 
        apiKeyField.setFont(new Font("Consolas", Font.PLAIN, 14));
        apiKeyField.setToolTipText("Optional: Enter your PhishTank API Key to bypass rate limits.");
        apiRow.add(new JLabel("PhishTank API Key: "), BorderLayout.WEST);
        apiRow.add(apiKeyField, BorderLayout.CENTER);
        northContainer.add(urlRow);
        northContainer.add(apiRow);
        add(northContainer, BorderLayout.NORTH);
        consoleArea = new JTextArea();
        consoleArea.setEditable(false);
        consoleArea.setBackground(new Color(30, 30, 30));
        consoleArea.setForeground(new Color(0, 255, 0));
        consoleArea.setFont(new Font("Consolas", Font.PLAIN, 13));
        consoleArea.append("[*] PhishWard Engine Initialized.\n");
        consoleArea.append("[*] Ready for target input...\n\n");
        JScrollPane scrollPane = new JScrollPane(consoleArea);
        scrollPane.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
        add(scrollPane, BorderLayout.CENTER);
        JPanel southPanel = new JPanel(new BorderLayout(10, 10));
        southPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        scoreLabel = new JLabel("Threat Score: Awaiting Analysis...", SwingConstants.CENTER);
        scoreLabel.setFont(new Font("Arial", Font.BOLD, 14));
        JPanel actionButtonsPanel = new JPanel(new FlowLayout());
        whitelistBtn = new JButton("Add to Whitelist");
        whitelistBtn.setActionCommand("WHITELIST");
        blacklistBtn = new JButton("Add to Blacklist");
        blacklistBtn.setActionCommand("BLACKLIST");
        whitelistBtn.setEnabled(false);
        blacklistBtn.setEnabled(false);
        actionButtonsPanel.add(whitelistBtn);
        actionButtonsPanel.add(blacklistBtn);
        southPanel.add(scoreLabel, BorderLayout.NORTH);
        southPanel.add(actionButtonsPanel, BorderLayout.CENTER);
        add(southPanel, BorderLayout.SOUTH);
    }

    private void createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        JMenu menu = new JMenu("About");
        JMenuItem helpItem = new JMenuItem("Help / Engine Workflow");
        JMenuItem creditsItem = new JMenuItem("Credits & Support");
        helpItem.addActionListener(e -> showHelp());
        creditsItem.addActionListener(e -> showCredits());
        menu.add(helpItem);
        menu.add(creditsItem);
        menuBar.add(menu);
        setJMenuBar(menuBar);
    }

    private void showHelp() {
        String helpText = "How to use PhishWard:\n\n"
                + "To begin, enter the target URL into the input field and click the 'Analyze URL' button.\n\n"
                + "The interface will lock temporarily while the Analysis Engine runs in a secure background thread. This ensures the application remains responsive during network requests.\n\n"
                + "First, the engine checks your local SQLite database. It verifies if the domain already exists in your personal Whitelist or Blacklist to provide an immediate assessment.\n\n"
                + "Next, it initiates active network reconnaissance. The tool resolves the target's IP address and extracts HTTP server headers to detect missing security policies, such as HSTS or CSP, and flags suspicious session cookies.\n\n"
                + "Finally, the engine queries global OSINT feeds via the PhishTank API. It cross-references the domain against a continuously updated registry of known malicious phishing campaigns.\n\n"
                + "All findings are aggregated into a final Threat Score out of 100. The detailed breakdown is printed to the console, empowering you to add the domain to your local lists based on the gathered intelligence.\n\n"
                + "Disclaimer: PhishWard is strictly an advisory tool and is not a substitute for standard security practices. The engine is subject to both false positives and false negatives, particularly with zero-day phishing campaigns. The final responsibility for interacting with any digital asset rests entirely with the user.";
        
        JOptionPane.showMessageDialog(this, helpText, "Engine Workflow & Help", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showCredits() {
        JPanel panel = new JPanel(new BorderLayout(0, 15));
        String creditsText = "PhishWard v1.0\n"
                + "Developed by Augusto Sulsente (ju57a7ouc4n).\n\n"
                + "I firmly believe that cybersecurity tools must be free, auditable, and completely open-source. True digital defense should be accessible to anyone who needs it.\n\n"
                + "You cannot claim to be protected if the very tools securing your systems are secretly harvesting and selling your personal data. PhishWard is built on absolute transparency and will always remain a free, open-source project.\n\n"
                + "If you find this tool valuable and wish to support its continued development, you can contribute via Bitcoin:";
        JTextArea textArea = new JTextArea(creditsText);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setOpaque(false);
        JButton copyBtcBtn = new JButton("Copy BTC Wallet to Clipboard");
        copyBtcBtn.addActionListener(e -> {
            String btcWallet = "bc1qv5m6ydtdx3et3dys8kwk5m59jr5p4r3vqn760u";
            StringSelection selection = new StringSelection(btcWallet);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, null);
            copyBtcBtn.setText("Wallet Copied!");
        });
        panel.add(textArea, BorderLayout.CENTER);
        panel.add(copyBtcBtn, BorderLayout.SOUTH);
        panel.setPreferredSize(new Dimension(450, 300));
        JOptionPane.showMessageDialog(this, panel, "About & Support", JOptionPane.PLAIN_MESSAGE);
    }

    /**
     * Links the View's buttons to the Controller's listener.
     * @param listener The Controller implementing ActionListener.
     */
    public void setControllerListener(PhishWardController c) {
        analyzeBtn.addActionListener(c);
        whitelistBtn.addActionListener(c);
        blacklistBtn.addActionListener(c);
    }

    public String getTargetUrl() {
        return urlField.getText().trim();
    }

    public void appendToConsole(String text) {
        messageQueue.add(text + "\n");
        if (!isTyping) {
            processQueue();
        }
    }
    private void processQueue() {
        if (messageQueue.isEmpty()) {
            isTyping = false;
            if (scoreNeedsUpdate) {
                updateScoreLabelNow(pendingScore, pendingColor);
                scoreNeedsUpdate = false;
                setListButtonsEnabled(true);
                setUiLocked(false);
            }
            return;
        }
        isTyping = true;
        String nextMessage = messageQueue.poll();
        Timer timer = new Timer(30, new ActionListener() {
            int charIndex = 0;
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                if (charIndex < nextMessage.length()) {
                    consoleArea.append(String.valueOf(nextMessage.charAt(charIndex)));
                    consoleArea.setCaretPosition(consoleArea.getDocument().getLength());
                    charIndex++;
                } else {
                    ((Timer)e.getSource()).stop();
                    processQueue(); 
                }
            }
        });
        timer.start();
    }

    public void setUiLocked(boolean locked) {
        analyzeBtn.setEnabled(!locked);
    }

    public void setListButtonsEnabled(boolean enabled) {
        whitelistBtn.setEnabled(enabled);
        blacklistBtn.setEnabled(enabled);
    }

    public void updateScoreLabel(int score, Color color) {
        this.pendingScore = score;
        this.pendingColor = color;
        this.scoreNeedsUpdate = true;
        if (!isTyping) {
            updateScoreLabelNow(score, color);
            scoreNeedsUpdate = false;
        }
    }
    
    private void updateScoreLabelNow(int score, Color color) {
        scoreLabel.setText("Threat Score: " + score + "/100");
        scoreLabel.setForeground(color);
    }
    
    /**
     * Opens a pop-up dialog asking the user for a justification.
     * * @return The entered string, or null if the user cancels the dialog.
     */
    public String getReason() {
        return JOptionPane.showInputDialog(
            this,
            "Enter the reason for blacklisting this domain:",
            "Blacklist Reason Required",
            JOptionPane.WARNING_MESSAGE
        );
    }
    
    /**
     * Displays a critical error pop-up dialog to the user.
     *
     * @param title   The title of the error window.
     * @param message The detailed error description.
     */
    public void showErrorDialog(String title, String message) {
        JOptionPane.showMessageDialog(
            this,
            message,
            title,
            JOptionPane.ERROR_MESSAGE
        );
    }
    
    public void setController(PhishWardController c) {
    	this.controller = c;
    	this.setControllerListener(this.controller);
    }
    
    public String getApiKey() {
        return apiKeyField.getText().trim();
    }
}