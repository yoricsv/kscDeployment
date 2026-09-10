#!/usr/bin/env bash
#
# Установка Агента администрирования KSC на Debian.
#
# Установка выполняется в два этапа: развёртывание пакета и постустановочная
# настройка postinstall.pl, которая записывает адрес Сервера и создаёт
# подключение. Без второго этапа Агент установлен, но не работает.
#
# Использование:
#   sudo ./10_install-netagent.sh /path/klnagent64_*.deb
#   sudo ./10_install-netagent.sh /path/klnagent64_*.deb --interactive

. "$(dirname "$0")/common.sh"
require_root

DEB="${1:-}"
MODE="${2:---auto}"
ANSWERS='/tmp/klnagent-answers.txt'

[ -n "$DEB" ] || die 'Укажите путь к пакету: sudo ./10_install-netagent.sh /path/klnagent64_<ver>_amd64.deb'
[ -f "$DEB" ] || die "Пакет не найден: $DEB"

log '=== Установка Агента администрирования ==='
check_server_name || log 'Продолжение возможно, но Агент не подключится без разрешения имени Сервера.' WARN
check_server_port

# ------------------------------------------------------------------ Уже установлен?

if dpkg -s klnagent64 >/dev/null 2>&1; then
    log 'Агент уже установлен.' WARN
    log "Смена Сервера: ${NAGENT_DIR}/bin/klmover -address ${KSC_FQDN}" WARN
    exit 0
fi

# ------------------------------------------------------------------ Установка пакета

log "Установка пакета $(basename "$DEB")..."
dpkg -i "$DEB" || {
    log 'dpkg сообщил о неудовлетворённых зависимостях, попытка их установки...' WARN
    apt-get install -f -y || die 'Не удалось удовлетворить зависимости. В изолированном контуре подключите локальное зеркало.'
}
log 'Пакет установлен.' OK

# ------------------------------------------------------------------ Постустановочная настройка

if [ "$MODE" = '--interactive' ]; then
    log 'Запуск интерактивной настройки. Значения для ввода:'
    log "  адрес Сервера ........ ${KSC_FQDN}"
    log "  порт ................. ${KSC_PORT_SSL}"
    log '  использовать SSL ..... да'
    "${NAGENT_DIR}/lib/bin/setup/postinstall.pl"
else
    # Файл ответов создаётся во временном каталоге и удаляется после установки:
    # он содержит параметры подключения и не должен оставаться на узле.
    trap 'rm -f "$ANSWERS"' EXIT
    cat > "$ANSWERS" <<EOF
KLNAGENT_SERVER=${KSC_FQDN}
KLNAGENT_SERVER_PORT=${KSC_PORT_SSL}
KLNAGENT_SERVER_SSL_PORT=${KSC_PORT_SSL}
KLNAGENT_USE_SSL=1
KLNAGENT_GW_MODE=0
EULA_AGREED=yes
PRIVACY_POLICY_AGREED=yes
EOF
    chmod 600 "$ANSWERS"
    log 'Постустановочная настройка (неинтерактивно)...'
    "${NAGENT_DIR}/lib/bin/setup/postinstall.pl" --autoinstall="$ANSWERS" \
        || die "Настройка завершилась ошибкой. Повторите интерактивно: sudo $0 $DEB --interactive"
fi

# ------------------------------------------------------------------ Служба

systemctl enable klnagent64 >/dev/null 2>&1 || true
systemctl restart klnagent64 || die 'Служба klnagent64 не запустилась. Журнал: journalctl -u klnagent64'
sleep 5
systemctl is-active --quiet klnagent64 && log 'Служба klnagent64 запущена.' OK || die 'Служба klnagent64 не активна.'

# ------------------------------------------------------------------ Правила межсетевого экрана

# Сервер инициирует подключение к Агенту на 15000/udp (команда «пробуждения»).
# Если на узле используется nftables/ufw — правило добавляется только для адреса Сервера.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'active'; then
    ufw allow from "${KSC_IP}" to any port "${KSC_PORT_SRV2AGENT}" proto udp comment 'KSC server to agent'
    log "ufw: разрешён ${KSC_PORT_SRV2AGENT}/udp с ${KSC_IP}" OK
else
    log "Межсетевой экран узла: правило для ${KSC_PORT_SRV2AGENT}/udp с ${KSC_IP} добавьте вручную (см. hardening/harden.sh)." WARN
fi

# ------------------------------------------------------------------ Проверка связи

log '--- Проверка подключения к Серверу ---'
"${NAGENT_DIR}/bin/klnagchk" -sendhb -nowait 2>&1 | sed 's/^/  /' || log 'klnagchk вернул ошибку — разберите вывод выше.' WARN

log '=== Агент установлен. Следующий шаг: 20_install-kesl.sh ===' OK
log 'Проверьте появление узла в консоли KSC (Обнаружение устройств → Нераспределённые устройства).'
