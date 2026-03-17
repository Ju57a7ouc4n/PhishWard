
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

package com.ju57a7ouc4n.phishlab.engine;

import java.util.ArrayList;

import com.ju57a7ouc4n.phishlab.model.dao.DatabaseManager;
import com.ju57a7ouc4n.phishlab.model.entities.AnalysisResult;
import com.ju57a7ouc4n.phishlab.model.entities.Rule;
import com.ju57a7ouc4n.phishlab.model.entities.RuleType;
import com.ju57a7ouc4n.phishlab.model.entities.UrlTarget;
import com.ju57a7ouc4n.phishlab.model.events.AnalysisProgressListener;
import com.ju57a7ouc4n.phishlab.model.events.ErrorListener;
import com.ju57a7ouc4n.phishlab.model.events.UserHandledError;
import com.ju57a7ouc4n.phishlab.model.network.HttpAnalyzer;
import com.ju57a7ouc4n.phishlab.model.network.PhishTankClient;

public class AnalysisEngine implements ErrorListener, AnalysisProgressListener{
    public HttpAnalyzer httpAnalyzer;
    public PhishTankClient phishTankClient;
    private AnalysisProgressListener progressListener;
    private ArrayList<ErrorListener> listeners;
    public DatabaseManager manager;
    private static AnalysisEngine instance = null;
    private String apiKey = "";
    
    private AnalysisEngine() {
        this.httpAnalyzer = new HttpAnalyzer();
        this.phishTankClient = new PhishTankClient();
        this.listeners = new ArrayList<>();
        this.manager = DatabaseManager.getInstance();
        this.httpAnalyzer.addErrorListener(this);
        this.manager.addErrorListener(this);
        this.phishTankClient.addErrorListener(this);
        this.phishTankClient.setProgressListener(this);
        this.httpAnalyzer.setProgressListener(this);
    }
    
    public static AnalysisEngine getInstance() {
    	if(instance == null)
    		instance = new AnalysisEngine();
    	return instance;
    }
    
    public void setProgressListener(AnalysisProgressListener listener) {
        this.progressListener = listener;
    }

    private void notifyProgress(String message) {
        if (this.progressListener != null) {
            this.progressListener.onProgressUpdate(message);
        }
        try {
            Thread.sleep(600); 
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Executes the complete analysis pipeline for a given URL.
     * Pure data processing, completely decoupled from the GUI.
     *
     * @param rawUrl The raw string input provided by the user.
     * @return An AnalysisResult object containing the threat score and evidence.
     */
    public AnalysisResult processUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            this.notifyError("Error", "No Target URL provided.", new IllegalArgumentException("Null or empty URL"));
            return null;
        }
        notifyProgress("\n=========================================");
        notifyProgress("[*] Target acquired: " + rawUrl);
        notifyProgress("[*] Launching analysis pipeline in background...");
        UrlTarget target = new UrlTarget(rawUrl);
        AnalysisResult result = new AnalysisResult(target);
        if (!target.isValid()) {
            notifyProgress("[!] Invalid URL format. Analysis aborted.");
            result.addThreatScore(0, "Invalid URL format. Analysis aborted.");
            return result; 
        }
        notifyProgress("[*] Checking local database cache...");
        Rule foundRule = this.manager.findRuleByIndicator(target.getDomain());
        
        if (foundRule != null) {
            if (foundRule.getListType() == RuleType.WHITELIST) {
                notifyProgress("[-] Target matched in local Whitelist.");
                result.addThreatScore(0, "URL Appears in Local Whitelist.");
            } else {
                notifyProgress("[!] Target matched in local Blacklist.");
                result.addThreatScore(100, "URL Appears in Local Blacklist.");
            }
            result.setFoundInLocalList(true);
            return result;
        }
        else {
        	notifyProgress("[+] Can't Find Target in Local Database.");
        }
        notifyProgress("[*] Resolving IP and fetching HTTP headers...");
        result.setResolvedIp(this.httpAnalyzer.resolveIp(target));
        result.setHeaders(this.httpAnalyzer.fetchHeaders(target));
        boolean hasHsts = false;
        boolean hasXFrame = false;
        boolean hasCsp = false;
        boolean hasXContentType = false;
        boolean injectsCookies = false;
        for (String key : result.getHeaders().keySet()) {
            String lowerKey = key.toLowerCase();
            if (lowerKey.equals("strict-transport-security")) hasHsts = true;
            else if (lowerKey.equals("x-frame-options")) hasXFrame = true;
            else if (lowerKey.equals("content-security-policy")) hasCsp = true;
            else if (lowerKey.equals("x-content-type-options")) hasXContentType = true;
            else if (lowerKey.equals("set-cookie")) injectsCookies = true;
        }
        if (!hasHsts) result.addThreatScore(15, "Missing Strict-Transport-Security (HSTS) header.");
        if (!hasXFrame) result.addThreatScore(10, "Missing X-Frame-Options header.");
        if (!hasCsp) result.addThreatScore(10, "Missing Content-Security-Policy (CSP) header.");
        if (!hasXContentType) result.addThreatScore(5, "Missing X-Content-Type-Options header.");
        if (injectsCookies) {
            result.setSetsCookies(true);
            result.addThreatScore(10, "Server injects tracking or session cookies (Set-Cookie).");
        }
        notifyProgress("[*] Querying global OSINT feeds (PhishTank API)...");
        if (this.phishTankClient.isPhishing(target,this.apiKey)) {
            notifyProgress("[!] Target reported as malicious in PhishTank.");
            result.addThreatScore(80, "Reported in Phishtank.");
        }
        return result;
    }   
    
	public void addErrorListener(ErrorListener listener) {
		this.listeners.add(listener);
	}

	public void notifyError(String title, String message, Exception e) {
		UserHandledError error = new UserHandledError(title,message,e);
		for(int i=0;i<this.listeners.size();i++) {
			this.listeners.get(i).anErrorOcurred(error);
		}
	}

	@Override
	public void anErrorOcurred(UserHandledError error) {
		/**/
	}
	
	/**
     * Adds a specific domain to the local database (Whitelist or Blacklist).
     * Acts as a bridge between the Controller and the Data Access layer.
     *
     * @param domain The exact domain string to be registered.
     * @param type   The RuleType enum (WHITELIST or BLACKLIST).
     * @param reason The justification provided by the user.
     */
    public void addDomainToList(String domain, RuleType type, String reason) {
        if (domain == null || domain.trim().isEmpty()) {
            notifyError("Invalid Input", "Cannot add an empty domain to the list.", new IllegalArgumentException());
            return;
        }
        try {
            Rule newRule = new Rule(domain.trim(), type, reason);
            this.manager.insertRule(newRule);
            notifyProgress("[-] Successfully added '" + domain + "' to " + type.toString() + ".");
        } catch (Exception e) {
            this.notifyError("Database Error", "Failed to save the rule: " + e.getMessage(), e);
        }
    }
	
    public void setApiKey(String apiKey) {
    	this.apiKey = apiKey;
    }

	@Override
	public void onProgressUpdate(String message) {
		this.notifyProgress(message);
	}
}
