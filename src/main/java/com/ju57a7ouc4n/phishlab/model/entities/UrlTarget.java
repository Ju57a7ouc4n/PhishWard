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
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Immutable data transfer object that processes and isolates the components 
 * of the URL entered by the user. Acts as an initial sanitization layer.
 *
 * @author ju57a7ouc4n
 * @version 1.0
 */

public class UrlTarget {
	String rawUrl;
	String domain;
	String protocol;
	boolean isValid;
	
	/**
	* Processes the raw string entered by the user and extracts the protocol 
	* and domain using {@link java.net.URI}. If the syntax is invalid, the object 
	* is internally marked as invalid to abort the analysis early.
	*
	* @param rawUrl The exact text string entered by the user to be analyzed.
	*/
	
	public UrlTarget(String rawUrl) {
		super();
		this.rawUrl=rawUrl;
		try {
			URI aux = new URI(rawUrl);
			this.isValid = true;
			this.domain = aux.getHost();
			this.protocol = aux.getScheme();
		} catch (URISyntaxException e) {
			this.isValid = false;
			this.domain = "INVALID";
			this.protocol = "INVALID";
		}
	}
	
	public String getRawUrl() {
		return this.rawUrl;
	}

	public String getDomain() {
		return this.domain;
	}

	public String getProtocol() {
		return this.protocol;
	}

	public boolean isValid() {
		return this.isValid;
	}
	
}
