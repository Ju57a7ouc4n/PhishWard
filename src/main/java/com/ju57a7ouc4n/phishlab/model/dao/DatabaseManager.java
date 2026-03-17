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
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

import com.ju57a7ouc4n.phishlab.model.entities.Rule;
import com.ju57a7ouc4n.phishlab.model.entities.RuleType;
import com.ju57a7ouc4n.phishlab.model.events.*;

/**
 * Utility class responsible for managing the JDBC connection to the local SQLite database.
 * Handles the creation of the database file and the initialization of the required tables.
 * This class uses static methods to provide a global connection point for the application.
 *
 * @author ju57a7ouc4n
 * @version 1.0
 */

public class DatabaseManager{
	private static final String DB_URL = "jdbc:sqlite:phishlab.db";
	private static DatabaseManager instance = null;
	private ArrayList<ErrorListener> listeners;
	
	
	private DatabaseManager() {
		super();
		this.listeners = new ArrayList<>();
		initializeDatabase();
	}
	
	public static DatabaseManager getInstance() {
		if(instance == null)
			instance = new DatabaseManager();
		return instance;
	}
	
	/**
	 * Establishes and returns a new active connection to the SQLite local file.
	 * The caller is responsible for closing the connection after use to prevent memory leaks.
	 *
	 * @return A valid, open {@link java.sql.Connection} object.
	 * @throws SQLException If a database access error occurs or the driver is not found.
	 */
	
	public Connection getConnection() throws SQLException{
		return DriverManager.getConnection(DB_URL);
	}
	
	public void initializeDatabase() {
		try(Connection conn = this.getConnection();
			Statement stmt = conn.createStatement();) {
			String sql = "CREATE TABLE IF NOT EXISTS rules (\n"
	                   + "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
	                   + "    indicator TEXT NOT NULL UNIQUE,\n"
	                   + "    listType TEXT NOT NULL,\n"
	                   + "    reason TEXT,\n"
	                   + "    timestamp INTEGER\n"
	                   + ");";
	        stmt.execute(sql);
		}
		catch(SQLException e) {
			notifyError("Database Error", "Can't Initialize \"rules\" table.", e);
		}
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
			try (ResultSet rs = pstmt.executeQuery()) {
				if (rs.next()) {
					Rule foundRule = new Rule();
					foundRule.setId(rs.getInt("id"));
					foundRule.setIndicator(rs.getString("indicator"));
					foundRule.setReason(rs.getString("reason"));
					foundRule.setTimestamp(rs.getLong("timestamp"));
					foundRule.setListType(RuleType.valueOf(rs.getString("listType")));
					return foundRule;
				}
			}
		} catch (SQLException e) {
			this.notifyError("Database Error", "SQL Failure: " + e.getMessage(), e);
		}
		return null;
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
