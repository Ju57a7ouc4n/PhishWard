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

package com.ju57a7ouc4n.phishlab.model.entities;

import java.util.HashMap;
import java.util.Map;

/**
 * Dynamic container for the investigation state.
 * Accompanies the URL through all phases of the analysis pipeline (Local, OSINT, Active),
 * accumulating evidence, HTTP headers, and calculating the final threat score.
 *
 * @author ju57a7ouc4n
 * @version 1.0
 */

public class AnalysisResult {
	private UrlTarget target;
	private boolean foundInLocalList;
	private boolean hasRedirect;
	private boolean setsCookies;
	private String redirectUrl;
	private String osintReport;
	private Map<String, String> headers;
	private String resolvedIp;
	private int threatScore;
	private StringBuilder scoreBreakdown;
	
	/**
	* Initializes a new analysis report linked to a specific target.
	* Prepares internal data collections and sets default values prior to 
	* the execution of the intelligence gathering phases.
	*
	* @param target The validated object containing the URL to investigate.
	*/
	
	public AnalysisResult(UrlTarget target) {
		super();
		this.target = target;
		this.foundInLocalList = false;
		this.hasRedirect = false;
		this.setsCookies = false;
		this.redirectUrl = "None";
		this.headers = new HashMap<>();
		this.osintReport = "N/A";
		this.resolvedIp = "N/A";
		this.threatScore = 0;
		this.scoreBreakdown = new StringBuilder("--- Analysis Details --- \n");
	}
	
	/**
	* Inserts or updates an HTTP header in the server response evidence map.
	*
	* @param key The name of the header (e.g., "Server", "X-Frame-Options").
	* @param value The value returned by the server for that header.
	*/
	
	public void addHeader(String key, String value) {
		this.headers.put(key, value);
	}
	
	/**
	* Increments the total risk score of the target and logs the justification.
	* Implements a logical constraint to ensure the final score never exceeds 
	* the maximum limit of 100 points.
	*
	* @param points Amount of risk points to add based on the severity of the finding.
	* @param reason Detailed description of the detected anomaly justifying the score.
	*/
	
	public void addThreatScore(int points, String reason) {
		if(this.threatScore + points >= 100)
			this.threatScore = 100;
		else
			this.threatScore+=points;
		this.scoreBreakdown.append("[+" + points + "] " + reason + "\n");
	}

	public UrlTarget getTarget() {
		return target;
	}

	public void setTarget(UrlTarget target) {
		this.target = target;
	}

	public boolean isFoundInLocalList() {
		return foundInLocalList;
	}

	public void setFoundInLocalList(boolean foundInLocalList) {
		this.foundInLocalList = foundInLocalList;
	}

	public String getOsintReport() {
		return osintReport;
	}

	public void setOsintReport(String osintReport) {
		this.osintReport = osintReport;
	}

	public Map<String, String> getHeaders() {
		return headers;
	}

	public void setHeaders(Map<String, String> headers) {
		this.headers = headers;
	}

	public String getResolvedIp() {
		return resolvedIp;
	}

	public void setResolvedIp(String resolvedIp) {
		this.resolvedIp = resolvedIp;
	}

	public int getThreatScore() {
		return threatScore;
	}

	public StringBuilder getScoreBreakdown() {
		return scoreBreakdown;
	}

	public boolean isHasRedirect() {
		return hasRedirect;
	}

	public void setHasRedirect(boolean hasRedirect) {
		this.hasRedirect = hasRedirect;
	}

	public boolean isSetsCookies() {
		return setsCookies;
	}

	public void setSetsCookies(boolean setsCookies) {
		this.setsCookies = setsCookies;
	}

	public String getRedirectUrl() {
		return redirectUrl;
	}

	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}
	
	
}
