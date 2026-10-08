# CSQTT ARM64/Entware integration matrix

## Pinned provenance

- CSQTT-Keenetic base: `a7ea295cb8360367ae4ede70f37d87e136eb323b`
- LaLune upstream reference: `Endlad2/LaLune @ e4a6d08b63aef6025bf8ad8f77da660ea552e04b`
- LaLune-NanoPi-ARM64 reference: `8d1e095a58419723adea5f8040eb17d0c67496d4`
- WPE-Auth-Entware current auth ref: `a42c81c53fbd6d6e789384877bf48d01dc74875f`
- Proven CSQTT server dataplane: `XXcipherX/csqtt-server @ 0a1e789fdc05442705aa0c5f3b7ab5e91984436a`

| Area | CSQTT-Keenetic | LaLune | LaLune-NanoPi-ARM64 | WPE-Auth-Entware | Action |
|---|---|---|---|---|---|
| Web panel/UI | Existing CSQTT web panel | Flutter/LaLune UI | Headless API/panel skeleton | None | KEEP CSQTT UI |
| CSQTT core/dataplane | Native manager + ARM64 client workflow | Bundled client/deploy references | Packages CSQTT 2.1.9 assets | None | KEEP CSQTT 2.1.9 |
| TUN/SCM_RIGHTS | Implemented | Linux backend reference | Gateway/TUN lifecycle | None | KEEP + harden |
| VK calls | calls.start/forceFinish | Mature VK lifecycle | Gateway VK API | None | MERGE into CSQTT |
| VK OAuth | Existing callback/manual token | Full OAuth/session | Headless hooks | WPE OAuth | MERGE behind CSQTT API |
| VK cookies/session | Limited | Persistent browser/session | Reference | Persistent WebKit profile | TAKE LaLune/WPE |
| silent_token | No | Implemented | Reference | Implement | TAKE LaLune behavior |
| Smart CAPTCHA | Config only | Automatic + WebView | CAPTCHA bridge/API | Browser runtime | MERGE |
| Manual CAPTCHA UI | Not yet | WebView | API pattern | None | ADD to CSQTT panel |
| CAPTCHA result transport | Rust core stdin accepts CAPTCHA_RESULT | Internal channel | API pattern | None | KEEP core protocol |
| ARM64/Entware build | Existing Go build | Linux ARM64 | Proven ARM64 CI | Entware WPE build | UNIFY checks |
| Process supervisor | Basic | Linux lifecycle | Gateway skeleton | Standalone helper | MERGE selected patterns |
| Deploy/update | Existing deploy.go | DeployManager | ARM64 DeployManager | None | TAKE lifecycle patterns |
| Routing/policy | Keenetic-specific | LaLune-specific | LaLune-specific | None | DO NOT IMPORT |
| WireGuard | Keenetic-specific | LaLune-specific | Gateway-specific | None | DO NOT IMPORT |
| Secrets | Config/env | LaLune config | Gateway token | Token file | CSQTT-owned 0600 |
| CI | Rust client | Go/Flutter | Native ARM64 | WPE cross/Entware | UNIFY checks |

## Transfer rules
- KEEP: CSQTT remains authoritative.
- MERGE: adapt implementation to CSQTT interfaces.
- TAKE: reuse proven ARM64/build/runtime components.
- DO NOT IMPORT: LaLune VPN/routing/UI architecture.

## CAPTCHA target
1. CSQTT core runs its automatic CAPTCHA chain.
2. Core emits `CAPTCHA_SOLVE|mode|redirect_uri|session_token` when interactive input is required.
3. CSQTT manager exposes the pending session through the existing CSQTT web panel.
4. Panel opens the VK CAPTCHA URL in a real browser window.
5. Optional VK-only bridge captures `success_token` and posts `/api/captcha/result`.
6. User can paste the result manually if the bridge is unavailable.
7. Manager writes `CAPTCHA_RESULT|<token>` to the running client stdin.
8. Tunnel continues without restarting the client.