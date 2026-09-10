#!/usr/bin/env bash
#
# Установка Kaspersky Endpoint Security для Linux (KESL).
#
# Порядок обязателен: сначала Агент администрирования, затем KESL, иначе
# приложение не будет управляться Сервером и лицензия не применится
# автоматически. Лицензия и параметры защиты назначаются политикой из KSC —
# локально они не задаются, чтобы исключить расхождение с политикой.
#
# Использование:
#   sudo ./20_install-kesl.sh /path/kesl_<ver>_amd64.deb
#   sudo ./20_install-kesl.sh /path/kesl_<ver>_amd64.deb --interactive

. "$(dirname "$0")/common.sh"
require_root

DEB="${1:-}"
MODE="${2:---auto}"
ANSWERS='/tmp/kesl-answers.txt'

[ -n "$DEB" ] || die 'Укажите путь к пакету: sudo ./20_install-kesl.sh /path/kesl_<ver>_amd64.deb'
[ -f "$DEB" ] || die "Пакет не найден: $DEB"

log '=== Установка Kaspersky Endpoint Security для Linux ==='

# Управление KESL выполняется через Агент: без него узел не получит политику.
dpkg -s klnagent64 >/dev/null 2>&1 || die 'Агент администрирования не установлен. Сначала выполните 10_install-netagent.sh.'
systemctl is-active --quiet klnagent64 || log 'Служба Агента не активна: KESL установится, но политику не получит.' WARN

if dpkg -s kesl >/dev/null 2>&1; then
    log 'KESL уже установлен.' WARN
    "${KESL_DIR}/bin/kesl-control" --get-app-info 2>/dev/null | sed 's/^/  /' || true
    exit 0
fi

# ------------------------------------------------------------------ Установка

log "Установка пакета $(basename "$DEB")..."
dpkg -i "$DEB" || {
    apt-get install -f -y || die 'Не удалось удовлетворить зависимости.'
}

if [ "$MODE" = '--interactive' ]; then
    log 'Запуск интерактивной настройки kesl-setup.pl.'
    log 'Ключевые ответы: лицензию не вводить (назначается политикой KSC), KSN — отключить (изолированный контур).'
    "${KESL_DIR}/bin/kesl-setup.pl"
else
    trap 'rm -f "$ANSWERS"' EXIT
    # Параметры соответствуют изолированному аттестованному контуру:
    # участие в KSN исключено, обновление — только из хранилища Сервера KSC.
    cat > "$ANSWERS" <<'EOF'
EULA_AGREED=yes
PRIVACY_POLICY_AGREED=yes
USE_KSN=no
SERVICE_LOCALE=ru_RU.UTF-8
INSTALL_LICENSE=
UPDATE_EXECUTE=no
UPDATER_SOURCE=SCServer
ENABLE_GUI=no
KSC_MODE=yes
EOF
    chmod 600 "$ANSWERS"
    log 'Настройка (неинтерактивно)...'
    "${KESL_DIR}/bin/kesl-setup.pl" --autoinstall="$ANSWERS" \
        || die "Настройка завершилась ошибкой. Повторите интерактивно: sudo $0 $DEB --interactive"
fi

# ------------------------------------------------------------------ Проверка

systemctl enable kesl >/dev/null 2>&1 || true
systemctl restart kesl || die 'Служба kesl не запустилась. Журнал: journalctl -u kesl'
sleep 5

log '--- Состояние приложения ---'
"${KESL_DIR}/bin/kesl-control" --get-app-info 2>&1 | sed 's/^/  /' || true

log '=== KESL установлен ===' OK
log 'Дальнейшие действия выполняются в KSC: назначить узел в группу, применить политику и лицензию,'
log 'запустить задачу обновления баз и полную проверку. Локальные настройки будут перезаписаны политикой.'
