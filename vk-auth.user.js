// ==UserScript==
// @name         CSQTT-Keenetic VK Auto Auth
// @namespace    https://github.com/Xenofan-git/CSQTT-Keenetic
// @version      1.4.0
// @description  Automatically captures VK implicit OAuth URL on blank.html and sends the token to CSQTT-Keenetic.
// @match        https://oauth.vk.ru/blank.html*
// @match        https://oauth.vk.com/blank.html*
// @run-at       document-start
// @noframes
// @grant        none
// ==/UserScript==

(() => {
  "use strict";

  // VK implicit OAuth returns access_token in the URL fragment.
  // A normal page on another origin cannot read that fragment, so this
  // userscript must run on VK's blank.html page.
  const params = new URLSearchParams(location.hash.replace(/^#/, ""));
  const token = params.get("access_token") || "";
  const userId = params.get("user_id") || "";
  const expiresIn = params.get("expires_in") || "0";
  const state = params.get("state") || "";
  const error = params.get("error") || "";

  if (error) {
    document.documentElement.innerHTML =
      "<body style='font-family:system-ui;padding:24px;background:#111;color:#eee'>" +
      "<h2 style='color:#ff7777'>CSQTT VK: ошибка авторизации</h2><p>" +
      String(params.get("error_description") || error).replace(/[<>&]/g, "") +
      "</p></body>";
    return;
  }

  if (!token || !state) {
    // This can also be a normal visit to blank.html. Do nothing.
    return;
  }

  function decodeBase64Url(value) {
    let s = value.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bytes = Uint8Array.from(atob(s), ch => ch.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }

  let rawState;
  try {
    rawState = decodeBase64Url(state);
  } catch (_) {
    return;
  }

  const separator = rawState.indexOf("|");
  if (separator <= 0) return;

  const callback = rawState.slice(0, separator);
  if (!/^https?:\/\/[^|]+\/api\/vk\/token$/i.test(callback)) return;

  // The first field in state is the CSQTT capture callback (HTTPS through KeenDNS, HTTP for direct LAN access). The second field
  // is the panel URL used by the callback server for the automatic return.
  // Use a real form POST so no CORS permission is required.
  const form = document.createElement("form");
  form.method = "POST";
  form.action = callback;
  form.style.display = "none";

  const fields = {
    token,
    user_id: userId,
    expires_in: expiresIn,
    state,
  };

  for (const [name, value] of Object.entries(fields)) {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    form.appendChild(input);
  }

  (document.documentElement || document.body).appendChild(form);
  form.submit();
})();
