# CSQTT-Entware-Keenetic — Keenetic ARM64/Entware

Linux/Entware-менеджер для существующего нативного `csqtt-client` CSQTT 2.1.9.

## Что уже делает

- создаёт Linux TUN `csqtt0` через `/dev/net/tun` + `TUNSETIFF`;
- использует `IFF_TUN | IFF_NO_PI`;
- устанавливает MTU 1300;
- запускает существующий Rust `client` без его модификации;
- подключается к abstract Unix socket `@csqtt_tun_uds`;
- передаёт TUN FD через `SCM_RIGHTS` тем же способом, что Android-клиент;
- ждёт ACK `0x01`;
- включает `CSQTT_EVENTS=1`;
- разбирает `TUNCONF` и назначает серверный IPv4 на `csqtt0` как `/32`;
- автоматически создаёт и сохраняет `device_id/generation/salt` в `state.json`;
- поддерживает режим `vk_hash_mode=auto_api`: получает VK call/hash через `api.vk.ru`, передаёт hash в существующий Rust client и завершает созданные VK Calls при остановке;
- использует ту же логику количества Auto API calls, что Android CSQTT 2.1.9;
- поддерживает `vk_access_token` в конфиге или переменную окружения `CSQTT_VK_ACCESS_TOKEN`.

## Deploy сервера из Web Panel

Панель умеет разворачивать отдельный CSQTT Server на VPS без ручной установки.

- существующий Android CSQTT endpoint не изменяется;
- для Keenetic по умолчанию используется отдельный UDP 46010;
- WEB-панель сервера по умолчанию 46012/tcp;
- панель определяет архитектуру VPS (amd64, arm64, armv7);
- скачивает официальный CSQTT-universal.apk нужной версии и извлекает из него тот же deploy.sh и Linux server binary, которые используются Android-приложением;
- передаёт их на VPS по SSH/SCP;
- запускает официальный systemd deploy/redeploy с проверкой TUN, NAT, firewall, порта и стабильности сервиса;
- после успешного deploy может автоматически переключить локальный Keenetic client на новый host:46010.

Пароли SSH/VPS не сохраняются в конфигурацию CSQTT; они используются только во время операции deploy.

## CAPTCHA fallback

- основной режим остаётся автоматическим (`captcha_mode=auto`);
- CSQTT 2.1.9 уже выполняет автоматическую цепочку CAPTCHA и при необходимости выводит `CAPTCHA_SOLVE|mode|redirect_uri|session_token`;
- ARM64-менеджер перехватывает это событие и не перезапускает клиент;
- Web Panel `/captcha` открывает реальную VK CAPTCHA в отдельном окне;
- установленный `captcha-bridge/` может автоматически передать `success_token` обратно;
- если bridge недоступен, результат можно передать вручную через поле панели;
- менеджер отправляет результат в работающий Rust client как `CAPTCHA_RESULT|<token>`;
- отмена передаётся как `CAPTCHA_RESULT|error:cancelled`.

## Что пока НЕ делает

- не меняет default route;
- не делает policy routing;
- не включает весь LAN в туннель;
- не реализует полноценную авторизацию Web Panel;
- не включает WPE browser runtime в основной бинарник менеджера: WPE остаётся отдельным auth-компонентом;
- не заменяет CSQTT Web Panel интерфейсом LaLune;
- не реализует HydraRoute failover.

Это намеренно: сначала проверяем настоящий Rust-транспорт CSQTT на Keenetic. Маршрутизация и полноценное управление будут отдельными этапами.

## Установка на Entware

Скопировать новый `CSQTT-Entware-Keenetic` и существующий ARM64 `client` в `/opt/etc/csqtt/`.

```sh
mkdir -p /opt/etc/csqtt
chmod 755 /opt/etc/csqtt/CSQTT-Entware-Keenetic
chmod 755 /opt/etc/csqtt/client
```

Создать `/opt/etc/csqtt/config.json` по `config.example.json`.

Для Auto API нужен действующий VK access token. Его не следует публиковать в GitHub или отправлять в чат; можно задать его в `config.json` либо через `CSQTT_VK_ACCESS_TOKEN`.

Перед первым запуском проверить:

```sh
uname -m
ls -l /dev/net/tun
command -v ip || true
ls -l /opt/sbin/ip /opt/bin/ip 2>/dev/null || true
```

Запуск:

```sh
/opt/etc/csqtt/CSQTT-Entware-Keenetic -config /opt/etc/csqtt/config.json
```

При первом запуске менеджер сам создаст `/opt/etc/csqtt/state.json` с уникальными параметрами устройства.

## Важно

Для запуска нужны root-права и доступ к `/dev/net/tun`.

На первом тесте НЕ добавлять default route через `csqtt0`. Маршрутизация будет добавлена отдельным этапом после проверки TUN/CSQTT.

## Сборка

Проверено:

```text
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test ./...   # host test
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'
```

Цель: ARM64 / Entware `aarch64-k3.10`.

## Unified ARM64 branch

Ветка `arm64-entware-unified` объединяет CSQTT как основной проект с выбранными Linux/ARM64 элементами LaLune-NanoPi-ARM64 и WPE-Auth-Entware. Матрица переноса находится в `ARM64_INTEGRATION_MATRIX.md`.

LaLune UI, VPN routing, WireGuard и policy routing в эту ветку не импортируются.


Локальный ARM64 binary `CSQTT-Entware-Keenetic` собран статически. На x86-хосте ARM64 test binary запускать нельзя, поэтому cross-`go test` не используется как runtime-тест.
