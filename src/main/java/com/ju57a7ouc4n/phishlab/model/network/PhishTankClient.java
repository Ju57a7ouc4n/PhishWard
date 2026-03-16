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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.ju57a7ouc4n.phishlab.model.entities.UrlTarget;
import com.ju57a7ouc4n.phishlab.model.events.ErrorListener;
import com.ju57a7ouc4n.phishlab.model.events.UserHandledError;

import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
public class PhishTankClient {
	private static final String API_URL = "https://checkurl.phishtank.com/checkurl/";
    private final OkHttpClient client;
    private List<ErrorListener> listeners;

    public PhishTankClient() {
        this.listeners = new ArrayList<>();
        this.client = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build();
    }
    
    public boolean isPhishing(UrlTarget target) {
        RequestBody formBody = new FormBody.Builder()
            .add("url", target.getRawUrl())
            .add("format", "json")
            .build();
        Request request = new Request.Builder()
            .url(API_URL)
            .post(formBody)
            .build();
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Código HTTP de error: " + response.code());
            }
            String responseData = response.body().string();
            JsonObject jsonObject = JsonParser.parseString(responseData).getAsJsonObject();
            if (jsonObject.has("results")) {
                JsonObject results = jsonObject.getAsJsonObject("results");
                return results.get("valid").getAsBoolean();
            }
            return false;
        } catch (Exception e) {
            this.notifyError("OSINT Fail", "PhishTank Consulting Error: " + target.getDomain(), e);
            return false; 
        }
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
