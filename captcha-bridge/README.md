# CSQTT VK CAPTCHA Bridge

Optional Manifest V3 helper for the CSQTT manual CAPTCHA fallback.

It runs only on VK identity pages, observes captchaNotRobot.check, extracts response.success_token, and posts it to the waiting CSQTT panel at /api/captcha/result.

If the bridge is not installed, the CSQTT CAPTCHA page provides a manual result field.

## Install

Desktop Chrome/Chromium: enable Developer mode and load this directory as an unpacked extension.

Android: use a browser that supports the extension mechanism.