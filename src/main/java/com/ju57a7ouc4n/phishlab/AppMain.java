package com.ju57a7ouc4n.phishlab;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import com.ju57a7ouc4n.phishlab.controller.PhishWardController;
import com.ju57a7ouc4n.phishlab.view.MainView;

/**
 * Main entry point for the PhishWard application.
 * Bootstraps the MVC architecture and launches the GUI safely.
 *
 * @author ju57a7ouc4n
 * @version 1.0
 */
public class AppMain {
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            System.err.println("[!] Failed to initialize System Look and Feel.");
        }
        SwingUtilities.invokeLater(() -> {
        	PhishWardController controller = new PhishWardController();
            MainView view = new MainView();
            view.setController(controller);
            controller.setView(view);
            view.setVisible(true);
        });
    }
}