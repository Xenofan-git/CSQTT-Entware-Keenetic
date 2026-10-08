#include <wpe/webkit.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#define VK_AUTH_URL "https://oauth.vk.ru/authorize?client_id=7793118&scope=1073737727&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&display=page&response_type=token&revoke=1&v=5.199"
#define POLL_MS 500
#define TIMEOUT_SECONDS 300

typedef struct {
    GMainLoop *loop;
    WebKitWebView *view;
    guint poll_id;
    guint timeout_id;
    guint silent_restarts;
    gboolean finished;
} App;

static gchar *auth_dir(const gchar *suffix)
{
    const gchar *root = g_getenv("CSQTT_WPE_HOME");
    if (!root || !*root) root = g_build_filename(g_get_home_dir(), ".csqtt", NULL);
    gchar *out = g_build_filename(root, suffix, NULL);
    if (root != g_getenv("CSQTT_WPE_HOME")) g_free((gchar *)root);
    return out;
}

static gchar *token_path(void)
{
    const gchar *path = g_getenv("CSQTT_WPE_TOKEN_FILE");
    if (path && *path) return g_strdup(path);
    return auth_dir("vk-token.json");
}

static gchar *param_from_query(const gchar *query, const gchar *key)
{
    if (!query) return NULL;
    gchar **parts = g_strsplit(query, "&", -1);
    gchar *out = NULL;
    for (gsize i = 0; parts[i]; i++) {
        gchar **kv = g_strsplit(parts[i], "=", 2);
        if (kv[0] && kv[1] && g_strcmp0(kv[0], key) == 0) {
            out = g_uri_unescape_string(kv[1], NULL);
            g_strfreev(kv);
            break;
        }
        g_strfreev(kv);
    }
    g_strfreev(parts);
    return out;
}

static gboolean blank_redirect(const gchar *uri)
{
    if (!uri) return FALSE;
    GUri *u = g_uri_parse(uri, G_URI_FLAGS_NONE, NULL);
    if (!u) return FALSE;
    gboolean ok =
        (g_strcmp0(g_uri_get_host(u), "oauth.vk.ru") == 0 ||
         g_strcmp0(g_uri_get_host(u), "oauth.vk.com") == 0) &&
        g_strcmp0(g_uri_get_path(u), "/blank.html") == 0;
    g_uri_unref(u);
    return ok;
}

static gchar *access_token_from_uri(const gchar *uri)
{
    if (!blank_redirect(uri)) return NULL;
    const gchar *hash = strchr(uri, '#');
    if (!hash) return NULL;
    return param_from_query(hash + 1, "access_token");
}

static gboolean silent_token_from_uri(const gchar *uri)
{
    const gchar *hash = uri ? strchr(uri, '#') : NULL;
    if (!hash) return FALSE;
    gchar *fragment = g_uri_unescape_string(hash + 1, NULL);
    if (!fragment) return FALSE;
    gboolean result =
        strstr(fragment, "payload=") != NULL &&
        strstr(fragment, "silent_token") != NULL;
    g_free(fragment);
    return result;
}

static void stop_app(App *app, gboolean success)
{
    if (app->finished) return;
    app->finished = TRUE;
    if (app->poll_id) g_source_remove(app->poll_id);
    if (app->timeout_id) g_source_remove(app->timeout_id);
    if (!success)
        g_printerr("wpe-auth: VK token was not obtained\n");
    g_main_loop_quit(app->loop);
}

static gboolean timeout_cb(gpointer data)
{
    stop_app(data, FALSE);
    return G_SOURCE_REMOVE;
}

static gboolean restart_oauth(gpointer data)
{
    App *app = data;
    if (!app->finished)
        webkit_web_view_load_uri(app->view, VK_AUTH_URL);
    return G_SOURCE_REMOVE;
}

static gboolean poll_cb(gpointer data)
{
    App *app = data;
    const gchar *uri = webkit_web_view_get_uri(app->view);
    if (!uri) return G_SOURCE_CONTINUE;

    gchar *token = access_token_from_uri(uri);
    if (token && *token) {
        gchar *dir = auth_dir("");
        gchar *path = token_path();
        g_mkdir_with_parents(dir, 0700);

        GDateTime *now = g_date_time_new_now_utc();
        gchar *saved_at = g_date_time_format(now, "%Y-%m-%dT%H:%M:%SZ");
        gchar *escaped = g_strescape(token, NULL);
        gchar *json = g_strdup_printf(
            "{\n  \"Token\": \"%s\",\n  \"SavedAt\": \"%s\"\n}\n",
            escaped, saved_at);

        FILE *fp = fopen(path, "w");
        if (!fp) {
            g_printerr("wpe-auth: cannot save %s: %s\n", path, g_strerror(errno));
            stop_app(app, FALSE);
        } else {
            fchmod(fileno(fp), 0600);
            fputs(json, fp);
            fclose(fp);
            g_print("WPE_AUTH_STATUS=access_token_detected\n");
            g_print("WPE_AUTH_TOKEN_FILE=%s\n", path);
            stop_app(app, TRUE);
        }

        g_free(json);
        g_free(escaped);
        g_free(saved_at);
        g_date_time_unref(now);
        g_free(path);
        g_free(dir);
        g_free(token);
        return G_SOURCE_REMOVE;
    }

    if (blank_redirect(uri) && silent_token_from_uri(uri)) {
        if (app->silent_restarts >= 1) {
            g_printerr("wpe-auth: silent_token remained after retry\n");
            stop_app(app, FALSE);
            return G_SOURCE_REMOVE;
        }

        app->silent_restarts++;
        g_print("WPE_AUTH_STATUS=silent_token_retry\n");
        webkit_web_view_load_uri(app->view, "https://vk.com/");
        return G_SOURCE_CONTINUE;
    }

    if (blank_redirect(uri) &&
        (strstr(uri, "#error=") || strstr(uri, "?error="))) {
        stop_app(app, FALSE);
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

static void load_changed(WebKitWebView *view, WebKitLoadEvent event, gpointer data)
{
    App *app = data;
    if (event != WEBKIT_LOAD_FINISHED) return;

    const gchar *uri = webkit_web_view_get_uri(view);
    if (uri && g_str_has_prefix(uri, "https://vk.com/") &&
        app->silent_restarts > 0 && !app->finished)
        g_timeout_add(2000, restart_oauth, app);
}

int main(void)
{
    if (!g_getenv("WPE_PLATFORM"))
        g_setenv("WPE_PLATFORM", "headless", TRUE);

    gchar *profile_dir = auth_dir("profile");
    gchar *data_dir = g_build_filename(profile_dir, "data", NULL);
    gchar *cache_dir = g_build_filename(profile_dir, "cache", NULL);

    g_mkdir_with_parents(data_dir, 0700);
    g_mkdir_with_parents(cache_dir, 0700);

    WebKitNetworkSession *session =
        webkit_network_session_new(data_dir, cache_dir);

    WebKitSettings *settings = webkit_settings_new();
    webkit_settings_set_enable_javascript(settings, TRUE);
    webkit_settings_set_enable_webgl(settings, FALSE);
    webkit_settings_set_enable_media_stream(settings, FALSE);

    App app = {0};
    app.loop = g_main_loop_new(NULL, FALSE);
    app.view = WEBKIT_WEB_VIEW(g_object_new(
        WEBKIT_TYPE_WEB_VIEW,
        "network-session", session,
        "settings", settings,
        NULL));

    g_signal_connect(app.view, "load-changed",
                     G_CALLBACK(load_changed), &app);

    g_print("wpe-auth: WPE_PLATFORM=%s\n", g_getenv("WPE_PLATFORM"));
    g_print("wpe-auth: persistent profile=%s\n", profile_dir);
    g_print("wpe-auth: LaLune VK OAuth flow started\n");

    app.poll_id = g_timeout_add(POLL_MS, poll_cb, &app);
    app.timeout_id = g_timeout_add_seconds(TIMEOUT_SECONDS, timeout_cb, &app);
    webkit_web_view_load_uri(app.view, VK_AUTH_URL);
    g_main_loop_run(app.loop);

    g_clear_object(&app.view);
    g_clear_object(&settings);
    g_clear_object(&session);
    g_main_loop_unref(app.loop);
    g_free(data_dir);
    g_free(cache_dir);
    g_free(profile_dir);
    return app.finished ? 0 : 1;
}
