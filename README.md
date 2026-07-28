# tor-bundle-windows

Однофайловый Tor-бандл для Windows: SOCKS5+HTTP-прокси, постоянный
Hidden Service, DNS через Tor, поддержка мостов — всё в одном exe,
без установки отдельного Tor или дополнительных программ.

**[Скачать последнюю сборку](https://github.com/spicicpein/tor-bundle-windows/releases/download/latest/tor-bundle-windows.exe)**

## Возможности

- Tor-ядро встроено внутрь exe (cgo, статическая линковка) — не отдельный процесс
- Локальный SOCKS5 + HTTP(CONNECT) прокси на одном порту (авто-определение протокола)
- Hidden Service с постоянным `.onion`-адресом, несколько портов на одном адресе
- Встроенный DNS-сервер с опциональным резолвингом через Tor
- Мосты (obfs4, webtunnel): вручную в конфиге или автоматически через свой `bridge_source`
- Установка как служба Windows (`-service install`), с настраиваемым именем
- Все рабочие файлы — в папке `slake` рядом с exe, никаких скрытых мест

## Быстрый старт

1. Скачайте `tor-bundle-windows.exe`, положите в любую папку
2. Запустите — рядом появится папка `slake` с `config.json`
3. При необходимости отредактируйте `config.json` (см. ниже) и перезапустите

## config.json

```json
{
  "listen_address": "127.0.0.1",
  "proxy_port": 9050,
  "onion_services": [
    { "onion_port": 22, "forward_to": "127.0.0.1:22" }
  ],
  "bridges": [],
  "bridge_source": { "urls": [] },
  "dns": { "enabled": false, "over_tor": true }
}
```

| Поле | Что значит |
|---|---|
| `listen_address` | `127.0.0.1` — только этот компьютер, `0.0.0.0` — доступно с других устройств в сети |
| `proxy_port` | один порт для SOCKS5 и HTTP-прокси сразу |
| `onion_services` | список `{onion_port, forward_to}` — сколько угодно портов на одном `.onion`-адресе |
| `bridges` | строки мостов, если сеть блокирует Tor напрямую — см. [HELP-bridges.txt](HELP-bridges.txt) |
| `bridge_source.urls` | адрес(а) собственного сборщика мостов, автоматический фолбэк |
| `dns.enabled` / `dns.over_tor` | встроенный DNS-сервер (порт 53) и резолвинг через Tor |

Про мосты подробно, с примерами под каждый тип — в
[HELP-bridges.txt](HELP-bridges.txt).

## Служба Windows

Из консоли **от имени администратора**:

```
tor-bundle-windows.exe -service install -service-name "MyService" -service-description "..."
tor-bundle-windows.exe -service start
tor-bundle-windows.exe -service stop
tor-bundle-windows.exe -service uninstall
```

## Проверка сборщика мостов

```
tor-bundle-windows.exe -check-bridges
```

Проверяет `bridge_source.urls`, ничего не запуская.

## Как это собрано

CI ([`.github/workflows/build.yml`](.github/workflows/build.yml)) на каждый
пуш: подтягивает официальный `lyrebird.exe` из Tor Expert Bundle,
кросс-компилирует под Windows через cgo/mingw-w64, публикует релиз.
Форк [go-libtor](https://github.com/spicicpein/go-libtor) содержит фикс
для сборки под современный mingw-w64 (устранена коллизия заголовков
`event2/rpc.h` с системным `rpc.h`).

Известное ограничение: встроенное ядро Tor основано на версии 0.4.6.10
(2022) — это цена настоящего единого процесса без отдельного tor.exe;
подробности выбора обсуждались в разработке.
