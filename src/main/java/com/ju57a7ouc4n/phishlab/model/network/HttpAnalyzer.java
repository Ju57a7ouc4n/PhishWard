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

package com.ju57a7ouc4n.phishlab.model.network;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.ju57a7ouc4n.phishlab.model.entities.UrlTarget;
import com.ju57a7ouc4n.phishlab.model.events.ErrorListener;
import com.ju57a7ouc4n.phishlab.model.events.UserHandledError;

import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Component responsible for establishing active HTTP connections to the target.
 * Extracts server headers and resolves DNS to obtain the underlying IP address.
 * Utilizes OkHttp for robust and timed-out network operations.
 *
 * @author ju57a7ouc4n
 * @version 1.0
 */

public class HttpAnalyzer {
	private final OkHttpClient client;
	private ArrayList<ErrorListener> listeners;
	
	public HttpAnalyzer() {
		this.client = new OkHttpClient().newBuilder()
				.followRedirects(false)
				.followSslRedirects(false)
				.connectTimeout(5, TimeUnit.SECONDS)
	            .readTimeout(5, TimeUnit.SECONDS)
	            .build();
		this.listeners = new ArrayList<>();
	}
	
	public String resolveIp(UrlTarget target) {
	    try {
	        InetAddress address = InetAddress.getByName(target.getDomain());
	        return address.getHostAddress(); 
	    } catch (UnknownHostException e) {
	        this.notifyError("DNS Error", "Can't resolve IP Domain: " + target.getDomain(), e);
	        return "Unknown";
	    }
	}
	
	public Map<String, String> fetchHeaders(UrlTarget target) {
	    Map<String, String> headerMap = new HashMap<>();
	    Request request = new Request.Builder()
	        .url(target.getRawUrl())
	        .head()
	        .build();
	    try (Response response = client.newCall(request).execute()) {
	        Headers responseHeaders = response.headers();
	        for (String name : responseHeaders.names()) {
	            headerMap.put(name, responseHeaders.get(name));
	        }
	        headerMap.put("HTTP-Status-Code", String.valueOf(response.code()));
	    } catch (IOException e) {
	        this.notifyError("Connection", "Cannnot Obtain Headers From: " + target.getRawUrl(), e);
	    }
	    return headerMap;
	}
	
	public void addErrorListener(ErrorListener listener) {
	    this.listeners.add(listener);
	}

	private void notifyError(String title, String message, Exception e) {
	    UserHandledError error = new UserHandledError(title, message, e);
	    for (ErrorListener listener : this.listeners) {
	        listener.anErrorOcurred(error); 
	    }
	}
}
