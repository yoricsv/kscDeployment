#!/usr/bin/env bash
# Общие переменные и функции для сценариев Debian.
# Подключается директивой:  . "$(dirname "$0")/common.sh"
#
# Значения должны совпадать с common/config.ps1. При изменении адресации
# правьте оба файла — единого источника нет намеренно, чтобы сценарии Linux
# не зависели от наличия PowerShell.

set -euo pipefail

# ------------------------------------------------------------------ Параметры

KSC_DOMAIN="${KSC_DOMAIN:-domain.local}"
KSC_HOST="${KSC_HOST:-ksc}"
KSC_FQDN="${KSC_FQDN:-${KSC_HOST}.${KSC_DOMAIN}}"
KSC_IP="${KSC_IP:-10.20.30.20}"
KSC_PORT_SSL="${KSC_PORT_SSL:-13000}"
KSC_PORT_SRV2AGENT="${KSC_PORT_SRV2AGENT:-15000}"
KSC_SUBNET="${KSC_SUBNET:-10.20.30.0/24}"
KSC_RDS="${KSC_RDS:-10.20.30.15}"

NAGENT_DIR='/opt/kaspersky/klnagent64'
KESL_DIR='/opt/kaspersky/kesl'
LOG_DIR='/var/log/ksc-deployment'

# ------------------------------------------------------------------ Функции

log() {
    local level="${2:-INFO}"
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local color=''
    case "$level" in
        OK)    color='\033[0;32m' ;;
        WARN)  color='\033[0;33m' ;;
        ERROR) color='\033[0;31m' ;;
    esac
    printf '%b[%s] [%s] %s\033[0m\n' "$color" "$ts" "$level" "$1"
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    printf '[%s] [%s] %s\n' "$ts" "$level" "$1" >> "$LOG_DIR/deploy.log" 2>/dev/null || true
}

die() { log "$1" ERROR; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die 'Требуются права root. Запустите через sudo.'
}

# Проверка разрешения имени Сервера: адрес Сервера в сертификате указан как FQDN,
# подключение по IP приведёт к ошибке проверки сертификата.
check_server_name() {
    if getent hosts "$KSC_FQDN" >/dev/null 2>&1; then
        log "Имя $KSC_FQDN разрешается в $(getent hosts "$KSC_FQDN" | awk '{print $1}' | tr '\n' ' ')" OK
    else
        log "Имя $KSC_FQDN не разрешается." WARN
        log "Для узлов вне домена добавьте в /etc/hosts:  $KSC_IP  $KSC_FQDN $KSC_HOST" WARN
        return 1
    fi
}

check_server_port() {
    if timeout 5 bash -c "</dev/tcp/${KSC_FQDN}/${KSC_PORT_SSL}" 2>/dev/null; then
        log "Порт ${KSC_PORT_SSL}/tcp на Сервере доступен." OK
    else
        die "Порт ${KSC_PORT_SSL}/tcp на ${KSC_FQDN} недоступен: Агент не сможет подключиться."
    fi
}

check_debian() {
    [ -f /etc/os-release ] || die 'Не удалось определить дистрибутив (/etc/os-release отсутствует).'
    . /etc/os-release
    log "Дистрибутив: ${PRETTY_NAME}"
    case "${ID}" in
        debian|astra|ubuntu) ;;
        *) log "Дистрибутив ${ID} не проверялся. Сверьтесь с матрицей совместимости KESL." WARN ;;
    esac
    log "Ядро: $(uname -r) (KESL поддерживает ограниченный перечень ядер — проверьте перед установкой)" WARN
}
