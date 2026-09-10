#!/usr/bin/env bash
#
# Приёмочная проверка узла Debian: Агент администрирования и KESL.
# Формирует отчёт, пригодный для приложения к акту ввода в эксплуатацию.
#
# Использование:  sudo ./30_test-agent.sh

. "$(dirname "$0")/common.sh"
require_root

PASS=0; FAIL=0; WARNC=0
REPORT="${LOG_DIR}/acceptance-$(hostname -s)-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$LOG_DIR"

check() {   # check "описание" "ожидание" команда...
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        printf '  [ OK ]   %s\n' "$desc" | tee -a "$REPORT"; PASS=$((PASS+1))
    else
        printf '  [ FAIL ] %s\n' "$desc" | tee -a "$REPORT"; FAIL=$((FAIL+1))
    fi
}
note() { printf '  [ ii ]   %s\n' "$1" | tee -a "$REPORT"; }
warn() { printf '  [ WARN ] %s\n' "$1" | tee -a "$REPORT"; WARNC=$((WARNC+1)); }

{
    echo "Приёмочная проверка узла: $(hostname -f)"
    echo "Дата: $(date '+%d.%m.%Y %H:%M:%S')"
    echo "Сервер администрирования: ${KSC_FQDN} (${KSC_IP})"
    echo '--------------------------------------------------------------'
} > "$REPORT"

echo "Приёмочная проверка узла $(hostname -f)"
echo '--------------------------------------------------------------'

# ------------------------------------------------------------------ Система

note "ОС: $(. /etc/os-release; echo "$PRETTY_NAME")"
note "Ядро: $(uname -r)"
note "Адреса: $(ip -4 -o addr show scope global | awk '{print $4}' | tr '\n' ' ')"

# ------------------------------------------------------------------ Связь с Сервером

check "Имя Сервера ${KSC_FQDN} разрешается" getent hosts "$KSC_FQDN"
check "Порт ${KSC_PORT_SSL}/tcp Сервера доступен" timeout 5 bash -c "</dev/tcp/${KSC_FQDN}/${KSC_PORT_SSL}"

# ------------------------------------------------------------------ Агент

check 'Пакет klnagent64 установлен' dpkg -s klnagent64
check 'Служба klnagent64 активна' systemctl is-active --quiet klnagent64
check 'Служба klnagent64 включена в автозагрузку' systemctl is-enabled --quiet klnagent64

if [ -x "${NAGENT_DIR}/bin/klnagchk" ]; then
    OUT="$("${NAGENT_DIR}/bin/klnagchk" -sendhb -nowait 2>&1 || true)"
    echo "$OUT" | sed 's/^/    /' >> "$REPORT"
    if echo "$OUT" | grep -qiE 'succe|успеш|connected|соединение установлено'; then
        printf '  [ OK ]   Соединение с Сервером подтверждено (klnagchk)\n' | tee -a "$REPORT"; PASS=$((PASS+1))
    else
        printf '  [ FAIL ] Соединение с Сервером не подтверждено, см. вывод klnagchk в отчёте\n' | tee -a "$REPORT"; FAIL=$((FAIL+1))
    fi
fi

# ------------------------------------------------------------------ KESL

if dpkg -s kesl >/dev/null 2>&1; then
    check 'Служба kesl активна' systemctl is-active --quiet kesl

    if [ -x "${KESL_DIR}/bin/kesl-control" ]; then
        APPINFO="$("${KESL_DIR}/bin/kesl-control" --get-app-info 2>&1 || true)"
        echo "$APPINFO" | sed 's/^/    /' >> "$REPORT"

        BASES="$(echo "$APPINFO" | grep -iE 'Bases date|Дата выпуска баз' | head -1 | cut -d: -f2- | xargs || true)"
        [ -n "$BASES" ] && note "Дата баз: ${BASES}"

        LIC="$("${KESL_DIR}/bin/kesl-control" -L --query 2>&1 || true)"
        if echo "$LIC" | grep -qiE 'expiration|Дата окончания'; then
            note "Лицензия: $(echo "$LIC" | grep -iE 'expiration|Дата окончания' | head -1 | xargs)"
        else
            warn 'Лицензия не активирована — назначьте ключ политикой KSC.'
        fi

        if echo "$APPINFO" | grep -qiE 'File_Threat_Protection.*Started|Постоянная защита.*Запущена'; then
            printf '  [ OK ]   Постоянная защита файлов запущена\n' | tee -a "$REPORT"; PASS=$((PASS+1))
        else
            warn 'Постоянная защита файлов не запущена — проверьте политику и поддержку ядра.'
        fi
    fi
else
    warn 'KESL не установлен: узел контролируется, но не защищён (только инвентаризация).'
fi

# ------------------------------------------------------------------ Межсетевой экран

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q active; then
    if ufw status | grep -q "${KSC_IP}"; then
        printf '  [ OK ]   ufw: разрешён доступ с Сервера %s\n' "$KSC_IP" | tee -a "$REPORT"; PASS=$((PASS+1))
    else
        warn "ufw активен, но правило для Сервера ${KSC_IP} отсутствует: команды Сервера не дойдут."
    fi
fi

# ------------------------------------------------------------------ Итог

{
    echo '--------------------------------------------------------------'
    echo "Успешно: ${PASS}   Отказ: ${FAIL}   Предупреждений: ${WARNC}"
} | tee -a "$REPORT"

echo "Отчёт: ${REPORT}"
[ "$FAIL" -eq 0 ] || exit 1
