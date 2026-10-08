package com.csqtt.vkauth;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.net.Uri;
import android.graphics.Color;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class MainActivity extends Activity {
    private static final String AUTH_URL = "https://oauth.vk.ru/authorize?client_id=7793118&scope=1073737727&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&display=page&response_type=token&revoke=1&v=5.199";
    private static final String SCHEME = "csqtt-vk";
    private static final String HOST = "login";
    private static final String[] BLANK_HOSTS = {"oauth.vk.ru", "oauth.vk.com"};
    private static final String BLANK_PATH = "/blank.html";
    private static final long SESSION_TIMEOUT_MS = 5 * 60 * 1000L;

    private WebView webView;
    private TextView status;
    private String callbackUrl;
    private String state;
    private int pass;
    private boolean finished;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private Runnable timeout;
    private Runnable poller;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        handleIntent(getIntent());
    }

    @Override protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.WHITE);
        status = new TextView(this);
        status.setText("CSQTT VK Auth\nОжидание авторизации…");
        status.setTextSize(16);
        status.setTextColor(Color.DKGRAY);
        status.setPadding(32, 32, 32, 20);
        root.addView(status, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        webView = new WebView(this);
        root.addView(webView, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void startWebView() {
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setUserAgentString("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true);
        webView.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) { return inspectUrl(request.getUrl().toString()); }
            @Override public boolean shouldOverrideUrlLoading(WebView view, String url) { return inspectUrl(url); }
            @Override public void onPageStarted(WebView view, String url, android.graphics.Bitmap favicon) { inspectUrl(url); }
            @Override public void onPageFinished(WebView view, String url) { inspectUrl(url); }
        });
        webView.loadUrl(AUTH_URL);
        startPolling();
    }

    private boolean isBlankHost(String host) {
        if (host == null) return false;
        for (String h : BLANK_HOSTS) if (h.equalsIgnoreCase(host)) return true;
        return false;
    }

    private void startPolling() {
        if (poller != null) handler.removeCallbacks(poller);
        poller = new Runnable() {
            @Override public void run() {
                if (finished || webView == null) return;
                String url = webView.getUrl();
                if (url != null) inspectUrl(url);
                if (!finished) handler.postDelayed(this, 750L);
            }
        };
        handler.postDelayed(poller, 750L);
    }

    private boolean inspectUrl(String url) {
        if (finished || url == null) return false;
        Uri u;
        try { u = Uri.parse(url); } catch (Exception e) { return false; }
        if (!isBlankHost(u.getHost()) || !BLANK_PATH.equalsIgnoreCase(u.getPath())) return false;
        String fragment = u.getEncodedFragment();
        if (fragment == null || fragment.isEmpty()) return true;
        String token = param(fragment, "access_token");
        if (token != null && !token.isEmpty()) {
            postToken(token, valueOrEmpty(param(fragment, "user_id")));
            return true;
        }
        if (fragment.contains("payload=")) {
            if (pass == 0) {
                pass = 1;
                setStatus("VK вернул промежуточный токен. Повторяем авторизацию…");
                handler.postDelayed(() -> { if (!finished) webView.loadUrl(AUTH_URL); }, 1500L);
            } else {
                fail("VK второй раз вернул silent token — вечный токен не получен");
            }
            return true;
        }
        String error = param(fragment, "error_description");
        if (error == null) error = param(fragment, "error");
        if (error != null) fail("VK: " + error);
        return true;
    }

    private void handleIntent(android.content.Intent intent) {
        Uri u = intent == null ? null : intent.getData();
        if (u == null || !SCHEME.equalsIgnoreCase(u.getScheme()) || !HOST.equalsIgnoreCase(u.getHost())) {
            setStatus("Откройте авторизацию из веб-панели CSQTT-Keenetic.");
            return;
        }
        callbackUrl = u.getQueryParameter("callback");
        state = u.getQueryParameter("state");
        if (!validCallback(callbackUrl) || state == null || state.length() < 16 || state.length() > 256) {
            fail("Некорректные callback/state");
            return;
        }
        finished = false;
        pass = 0;
        setStatus("Открываю авторизацию VK…");
        if (timeout != null) handler.removeCallbacks(timeout);
        timeout = () -> { if (!finished) fail("Тайм-аут авторизации VK"); };
        handler.postDelayed(timeout, SESSION_TIMEOUT_MS);
        startWebView();
    }

    private boolean validCallback(String value) {
        if (value == null || value.length() > 2048) return false;
        try {
            Uri u = Uri.parse(value);
            String scheme = u.getScheme();
            return ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                    && "/api/vk/token".equals(u.getPath()) && u.getHost() != null;
        } catch (Exception e) { return false; }
    }

    private static String param(String fragment, String key) {
        if (fragment == null) return null;
        for (String part : fragment.split("&")) {
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            if (!key.equals(part.substring(0, eq))) continue;
            try { return Uri.decode(part.substring(eq + 1)); } catch (Exception e) { return part.substring(eq + 1); }
        }
        return null;
    }

    private static String valueOrEmpty(String s) { return s == null ? "" : s; }

    private void postToken(String token, String userId) {
        if (finished) return;
        finished = true;
        if (timeout != null) handler.removeCallbacks(timeout);
        setStatus("Токен получен. Передаю его в Keenetic…");
        new Thread(() -> {
            HttpURLConnection c = null;
            try {
                c = (HttpURLConnection) new URL(callbackUrl).openConnection();
                c.setRequestMethod("POST");
                c.setConnectTimeout(10000);
                c.setReadTimeout(10000);
                c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                c.setRequestProperty("Accept", "application/json");
                JSONObject body = new JSONObject();
                body.put("token", token);
                body.put("user_id", userId);
                body.put("state", state);
                byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
                try (OutputStream out = c.getOutputStream()) { out.write(bytes); }
                int code = c.getResponseCode();
                BufferedReader reader = new BufferedReader(new InputStreamReader(code >= 400 ? c.getErrorStream() : c.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) response.append(line);
                boolean ok = code >= 200 && code < 300;
                runOnUiThread(() -> {
                    if (ok) {
                        setStatus("Готово ✓\nVK авторизация передана в CSQTT-Keenetic.");
                        Toast.makeText(this, "VK авторизация завершена", Toast.LENGTH_SHORT).show();
                        handler.postDelayed(this::finish, 900L);
                    } else {
                        finished = false;
                        setStatus("Keenetic не принял токен. HTTP " + code + "\n" + response);
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> { finished = false; setStatus("Не удалось передать токен в Keenetic:\n" + e.getMessage()); });
            } finally { if (c != null) c.disconnect(); }
        }).start();
    }

    private void fail(String message) {
        finished = true;
        if (timeout != null) handler.removeCallbacks(timeout);
        setStatus("Ошибка: " + message);
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }

    private void setStatus(String value) { if (status != null) status.setText(value); }
    @Override protected void onDestroy() { if (timeout != null) handler.removeCallbacks(timeout); if (poller != null) handler.removeCallbacks(poller); if (webView != null) webView.destroy(); super.onDestroy(); }
}
