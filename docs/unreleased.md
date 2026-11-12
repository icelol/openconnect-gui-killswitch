# Released in v1.2.2 / Выпущено в v1.2.2

## Network safety audit — 2026-11-02

- Keep explicit macOS OFF usable with corrupt recovery metadata; preserve
  unknown PF references without disabling the system firewall.
- Bound Windows DNS UDP/TCP fallback by one total lookup deadline.
- Cancel unfinished authentication when its GUI owner disappears.
- Keep the OpenConnect command producer nonblocking; coalesce commands and
  retry cancellation asynchronously under backpressure.
- Hide unsupported legacy secret/profile options in the service GUI and avoid
  persisting new unused secrets.
- Add regression tests, a DNS mutation/fuzz target, a Russian operation/recovery
  guide and an audit report with remaining limitations.

These fixes are included in v1.2.2. Earlier v1.2.1 files keep their original hashes and source tag.

## Аудит сетевой безопасности — 02.11.2026

Исправлены отказ OFF при повреждённом состоянии macOS, продление ожидания DNS
в Windows, незавершённый вход после закрытия GUI и блокирующий командный канал
VPN. Редактор больше не предлагает неподдерживаемое сохранение секретов.

[Устройство и ручное отключение](killswitch-operation.ru.md) ·
[Проверки, ограничения и следующие шаги](network-security-review.ru.md).

Исправления включены в установщики v1.2.2.
