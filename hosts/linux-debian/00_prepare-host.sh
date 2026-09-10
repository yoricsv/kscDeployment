#!/usr/bin/env bash
#
# Подготовка узла Debian к установке Агента администрирования и KESL.
#
# Выполняет проверки, без которых установка завершается ошибкой или Агент
# не подключается к Серверу: разрешение имени, доступность порта, наличие
# заголовков ядра и компилятора (нужны для сборки модуля перехвата KESL,
# если не используется fanotify), свободное место, время.
#
# Использование:  sudo ./00_prepare-host.sh

. "$(dirname "$0")/common.sh"
require_root

log '=== Подготовка узла Debian ==='
check_debian

# ------------------------------------------------------------------ Сеть

log '--- Сетевые проверки ---'
ip -4 addr show scope global | awk '/inet /{print "  адрес: "$2" ("$NF")"}'

# Статическая адресация обязательна: перечень узлов ведётся вручную,
# смена адреса нарушает соответствие узла записи в KSC и правилам МЭ.
if grep -rqs 'dhcp' /etc/network/interfaces /etc/network/interfaces.d/ 2>/dev/null; then
    log 'В /etc/network/interfaces обнаружено получение адреса по DHCP. Требуется статическая адресация.' WARN
fi
if command -v nmcli >/dev/null 2>&1 && nmcli -t -f ipv4.method con show --active 2>/dev/null | grep -q auto; then
    log 'NetworkManager: активное соединение использует автоматическую адресацию. Требуется статическая.' WARN
fi

check_server_name || true
check_server_port

# ------------------------------------------------------------------ Время

log '--- Синхронизация времени ---'
if command -v timedatectl >/dev/null 2>&1; then
    timedatectl status | sed 's/^/  /'
    if ! timedatectl status | grep -qE 'synchronized: yes|синхронизированы: да'; then
        log 'Время не синхронизировано. Расхождение более 5 минут нарушает проверку сертификата Агента.' WARN
        log "Настройте systemd-timesyncd на контроллеры домена: 10.20.30.10, 10.20.30.11" WARN
    fi
fi

# ------------------------------------------------------------------ Ресурсы

log '--- Ресурсы ---'
avail_opt="$(df -BG --output=avail /opt 2>/dev/null | tail -1 | tr -dc '0-9')"
avail_var="$(df -BG --output=avail /var 2>/dev/null | tail -1 | tr -dc '0-9')"
log "  свободно в /opt: ${avail_opt} ГБ (требуется не менее 2 ГБ)"
log "  свободно в /var: ${avail_var} ГБ (требуется не менее 4 ГБ: базы и журналы)"
[ "${avail_opt:-0}" -ge 2 ] || log 'Недостаточно места в /opt.' WARN
[ "${avail_var:-0}" -ge 4 ] || log 'Недостаточно места в /var.' WARN
log "  ОЗУ: $(free -m | awk '/Mem:/{print $2" МБ"}')"

# ------------------------------------------------------------------ Зависимости

log '--- Зависимости ---'
# perl нужен для postinstall.pl, which/procps используются сценариями установки.
DEPS='perl which procps'
MISSING=''
for p in $DEPS; do
    dpkg -s "$p" >/dev/null 2>&1 || MISSING="$MISSING $p"
done

# Заголовки ядра требуются, если KESL собирает модуль перехвата.
# На современных ядрах используется fanotify, тогда заголовки не нужны,
# но их наличие снимает риск отказа установки.
if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
    log "Заголовки ядра для $(uname -r) отсутствуют." WARN
    MISSING="$MISSING linux-headers-$(uname -r)"
fi

if [ -n "$MISSING" ]; then
    log "Не установлены пакеты:$MISSING" WARN
    log "В изолированном контуре установите их из локального зеркала:  apt-get install -y$MISSING" WARN
else
    log 'Все зависимости присутствуют.' OK
fi

# ------------------------------------------------------------------ Конфликтующее ПО

log '--- Проверка конфликтующего ПО ---'
for pkg in clamav clamav-daemon sophos-av; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        log "Обнаружено средство антивирусной защиты: $pkg. Одновременная работа двух средств не допускается." WARN
    fi
done

# ------------------------------------------------------------------ Каталоги

mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"

log '=== Подготовка завершена. Следующий шаг: 10_install-netagent.sh ===' OK
