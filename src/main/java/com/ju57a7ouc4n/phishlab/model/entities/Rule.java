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

/**
 * Entity (POJO) representing an individual record in the local SQLite database.
 * Stores filtering rule information, including the target indicator, 
 * its list type, the reason for its creation, and the timestamp.
 *
 * @author ju57a7ouc4n
 * @version 1.0
 */

public class Rule {
	int id;
	String indicator;
	RuleType listType;
	String reason;
	long timestamp;
	
	/**
	 * Default constructor.
	 * Strictly required by persistence frameworks (JDBC) to instantiate 
	 * the object before populating it with data retrieved from SQLite.
	 */
	
	public Rule() {
		super();
	}
	
	/**
	 * Main constructor for creating new rules from the user interface.
	 * Automatically assigns the current system timestamp.
	 *
	 * @param indicator The IP address or domain to register.
	 * @param listType The type of rule (WHITELIST or BLACKLIST).
	 * @param reason Brief justification provided by the user for creating the rule.
	 */
	
	public Rule(String indicator, RuleType listType, String reason) {
		super();
		this.indicator = indicator;
		this.listType = listType;
		this.reason = reason;
		this.timestamp = System.currentTimeMillis();
	}
	
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getIndicator() {
		return indicator;
	}
	public void setIndicator(String indicator) {
		this.indicator = indicator;
	}
	public RuleType getListType() {
		return listType;
	}
	public void setListType(RuleType listType) {
		this.listType = listType;
	}
	public String getReason() {
		return reason;
	}
	public void setReason(String reason) {
		this.reason = reason;
	}
	public long getTimestamp() {
		return timestamp;
	}
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}
	
	
	
}
