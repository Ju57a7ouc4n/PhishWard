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

package com.ju57a7ouc4n.phishlab.model.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import com.ju57a7ouc4n.phishlab.model.entities.Rule;
import com.ju57a7ouc4n.phishlab.model.entities.RuleType;
import com.ju57a7ouc4n.phishlab.model.events.ErrorListener;
import com.ju57a7ouc4n.phishlab.model.events.UserHandledError;

/**
 * Data Access Object (DAO) responsible for executing CRUD operations 
 * on the 'rules' table within the SQLite database.
 * Isolates the application logic from the underlying persistence mechanism.
 *
 * @author ju57a7ouc4n
 * @version 1.0
 */

public class RuleDAO {
	private ArrayList<ErrorListener> listeners;
	
	public RuleDAO() {
		super();
		this.listeners = new ArrayList<>();
	}
	
	/**
	 * Persists a new Rule object into the database.
	 * Uses a PreparedStatement to safely bind the entity's attributes to the SQL query,
	 * preventing SQL injection attacks.
	 *
	 * @param rule The fully populated Rule entity to be inserted.
	 * @return true if the insertion was successful, false if a database error occurred 
	 * or if a unique constraint was violated.
	 */
	
	public boolean insertRule(Rule rule) {
		String sql = "INSERT INTO rules (indicator, listType, reason, timestamp) VALUES (?, ?, ?, ?)";
		try(Connection conn = DatabaseManager.getInstance().getConnection();
				PreparedStatement pstmt = conn.prepareStatement(sql);){
			pstmt.setString(1, rule.getIndicator());
			pstmt.setString(2, rule.getListType().name());
			pstmt.setString(3, rule.getReason());
			pstmt.setLong(4, rule.getTimestamp());
			pstmt.executeUpdate();
			return true;
		}
		catch(SQLException e) {
			this.notifyError("Save Error", "Can't Insert Rule in Database.", e);
			return false;
		}
	}
	
	/**
	 * Queries the database to find an existing rule that matches the specified indicator.
	 * If a match is found, it maps the SQL ResultSet row back into a Java Rule entity.
	 *
	 * @param indicator The exact URL, domain, or IP address to search for.
	 * @return A fully populated Rule object if a match is found; null otherwise.
	 */
	
	public Rule findRuleByIndicator(String indicator) {
		String sql = "SELECT id, indicator, listType, reason, timestamp FROM rules WHERE indicator = ?";
		try (Connection conn = DatabaseManager.getInstance().getConnection();
			     PreparedStatement pstmt = conn.prepareStatement(sql)) {
			pstmt.setString(1, indicator);
			ResultSet rs = pstmt.executeQuery();
			if (rs.next()) {
				Rule foundRule = new Rule();
				foundRule.setId(rs.getInt("id"));
				foundRule.setIndicator(rs.getString("indicator"));
				foundRule.setReason(rs.getString("reason"));
				foundRule.setTimestamp(rs.getLong("timestamp"));
				foundRule.setListType(RuleType.valueOf(rs.getString("listType")));
				return foundRule;
			}
			return null;
		} catch (SQLException e) {
			this.notifyError("Lecture Error", "Can't Find Indicator.", e);
			return null;
		}
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
}