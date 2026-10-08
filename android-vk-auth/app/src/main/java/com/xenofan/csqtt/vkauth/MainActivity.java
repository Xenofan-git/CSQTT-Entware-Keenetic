package com.xenofan.csqtt.vkauth;

import android.app.Activity;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final String CLIENT_ID = "7793118";
    private static final String SCOPE = "1073737727";
    private static final String REDIRECT_URI = "https://oauth.vk.ru/blank.html";
    private static final String AUTH_URL =
            "https://oauth.vk.ru/authorize?" +
            "client_id=" + CLIENT_ID +
            "&scope=" + SCOPE +
            "&redirect_uri=" + Uri.encode(REDIRECT_URI) +
            "&display=page&response_type=token&revoke=1&v=5.199";

    private WebView webView;
    private TextView status;
    private String callbackUrl;
    private String state;
    private int pass = 0;
    private boolean finished = false;

    private static final String DESKTOP_UA =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.WHITE);

        status = new TextView(this);
        status.setText("CSQTT VK Auth\nГотов к авторизации");
        status.setTextColor(Color.DKGRAY);
        status.setTextSize(16);
        status.setPadding(24, 20, 24, 20);
        root.addView(status, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        webView = new WebView(this);
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setUserAgentString(DESKTOP_UA);

        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true);

        webView.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, String url) {
                inspectUrl(url);
                return false;
            }

            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
                inspectUrl(req.getUrl().toString());
                return false;
            }

            @Override public void onPageStarted(WebView view, String url, android.graphics.Bitmap favicon) {
                inspectUrl(url);
            }

            @Override public void onPageFinished(WebView view, String url) {
                inspectUrl(url);
            }
        });

        root.addView(webView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);
    }

    private void handleIntent(android.content.Intent intent) {
        Uri data = intent == null ? null : intent.getData();
        if (data == null) {
            status.setText("CSQTT VK Auth\nНажмите «Войти» в панели Keenetic.");
            return;
        }
        if (!"csqtt-vk".equalsIgnoreCase(data.getScheme()) ||
                !"login".equalsIgnoreCase(data.getHost())) {
            return;
        }

        callbackUrl = data.getQueryParameter("callback");
        state = data.getQueryParameter("state");
        if (callbackUrl == null || callbackUrl.trim().isEmpty() ||
                state == null || state.trim().isEmpty()) {
            status.setText("Ошибка: отсутствуют callback/state.");
            return;
        }

        status.setText("CSQTT VK Auth\nОткройте VK и войдите в аккаунт…");
        startAuth();
    }

    private void startAuth() {
        if (finished) return;
        pass = 0;
        loadAuthPage();
    }

    private void loadAuthPage() {
        if (finished) return;
        status.setText(pass == 0
                ? "CSQTT VK Auth\nАвторизация VK…"
                : "CSQTT VK Auth\nVK уже авторизован — получаем постоянный токен…");
        webView.loadUrl(AUTH_URL);
    }

    private void inspectUrl(String url) {
        if (finished || url == null) return;
        Uri u;
        try { u = Uri.parse(url); } catch (Exception e) { return; }

        if (!"oauth.vk.ru".equalsIgnoreCase(u.getHost()) &&
            !"oauth.vk.com".equalsIgnoreCase(u.getHost())) return;
        if (!"/blank.html".equalsIgnoreCase(u.getPath())) return;

        String fragment = u.getEncodedFragment();
        if (fragment == null || fragment.isEmpty()) return;

        String token = param(fragment, "access_token");
        if (token != null && !token.isEmpty()) {
            String userId = valueOrEmpty(param(fragment, "user_id"));
            String expires = valueOrEmpty(param(fragment, "expires_in"));
            finishWithToken(token, userId, expires);
            return;
        }

        if (fragment.contains("payload=")) {
            if (pass == 0) {
                pass = 1;
                status.setText("CSQTT VK Auth\nПолучен silent token. Повторяем вход…");
                webView.postDelayed(this::loadAuthPage, 1200);
            } else {
                finishWithError("VK снова вернул silent token вместо access_token.");
            }
            return;
        }

        if (fragment.contains("error=")) {
            finishWithError("VK OAuth: " + valueOrEmpty(param(fragment, "error_description")));
        }
    }

    private String param(String fragment, String key) {
        String q = fragment.startsWith("#") ? fragment.substring(1) : fragment;
        for (String pair : q.split("&")) {
            int p = pair.indexOf('=');
            if (p <= 0) continue;
            String k = pair.substring(0, p);
            if (!key.equals(k)) continue;
            try {
                return Uri.decode(pair.substring(p + 1));
            } catch (Exception ignored) {
                return pair.substring(p + 1);
            }
        }
        return null;
    }

    private String valueOrEmpty(String v) {
        return v == null ? "" : v;
    }

    private void finishWithToken(String token, String userId, String expires) {
        if (finished) return;
        finished = true;
        status.setText("CSQTT VK Auth\nТокен получен. Передаём его на Keenetic…");
        postToken(callbackUrl, state, token, userId, expires);
    }

    private void finishWithError(String message) {
        if (finished) return;
        finished = true;
        status.setText("CSQTT VK Auth\n" + message);
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }

    private void postToken(String callback, String stateValue, String token,
                            String userId, String expires) {
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                JSONObject body = new JSONObject();
                body.put("token", token);
                body.put("user_id", userId);
                try { body.put("expires_in", Long.parseLong(expires)); }
                catch (Exception e) { body.put("expires_in", 0); }
                body.put("state", stateValue);

                conn = (HttpURLConnection) new URL(callback).openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(20000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                conn.setRequestProperty("Accept", "application/json");
                conn.setRequestProperty("User-Agent", "CSQTT-VK-Auth/1.0");

                byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
                conn.setFixedLengthStreamingMode(bytes.length);
                try (OutputStream out = conn.getOutputStream()) {
                    out.write(bytes);
                }

                int code = conn.getResponseCode();
                runOnUiThread(() -> {
                    if (code >= 200 && code < 300) {
                        status.setText("CSQTT VK Auth\n✓ Токен автоматически передан в Keenetic.");
                        Toast.makeText(this, "VK авторизация завершена", Toast.LENGTH_SHORT).show();
                        finish();
                    } else {
                        status.setText("CSQTT VK Auth\nKeenetic вернул HTTP " + code);
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> status.setText(
                        "CSQTT VK Auth\nНе удалось передать токен: " + e.getMessage()));
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }
}
