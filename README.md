# PhishWard 🛡️ - Threat Analysis Engine

Developed by **Augusto Sulsente (ju57a7ouc4n)**.

PhishWard is a proactive, open-source cybersecurity tool designed to provide real-time intelligence on suspicious URLs. Built on the philosophy that **security tools must be free, auditable, and transparent**, PhishWard empowers users to analyze threats without becoming the product themselves.

Unlike corporate security tools, PhishWard does not harvest your data. It is a local-first engine that provides a detailed technical breakdown of why a site might be dangerous.

## 🧠 The Philosophy: Open Source & Privacy
In an era of "security-as-a-service" where tools secretly sell user telemetry, PhishWard stands for:
- **Zero Data Harvesting:** No telemetry, no background tracking.
- **Auditability:** Every line of code is open for review.
- **Accessibility:** Professional-grade analysis for everyone, for free.

## ⚙️ Analysis Pipeline
The engine follows a rigorous multi-stage workflow to determine a **Threat Score (0-100)**:

1.  **Local Intelligence:** Checks a local SQLite database for user-defined Whitelists or Blacklists.
2.  **Network Reconnaissance:** * Resolves the target IP address.
    * Analyzes HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type).
    * Detects suspicious session or tracking cookies.
3.  **Global OSINT:** Queries the PhishTank API to cross-reference known malicious campaigns.
4.  **Score Aggregation:** Weights all findings to provide an advisory threat level.

## ⚠️ Disclaimer

PhishWard is an advisory tool. Cybersecurity is an evolving field, and no engine can guarantee 100% detection of zero-day threats. Always practice safe browsing habits.
