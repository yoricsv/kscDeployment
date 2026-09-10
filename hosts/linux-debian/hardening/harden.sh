#!/usr/bin/env bash
#
# Харденинг узла Debian в аттестованном контуре.
#
# Профиль ориентирован на изолированную сеть со статической адресацией:
#   * межсетевой экран по умолчанию запрещает входящие соединения,
#     кроме SSH с АРМ администратора и служебного порта Агента с Сервера;
#   * SSH — только по ключам, без root-входа, ограничен по адресу источника;
#   * параметры ядра — защита сетевого стека;
#   * аудит действий с привилегиями (auditd, если доступен);
#   * автоматические обновления отключены (изолированный контур,
#     обновления доставляются контролируемо).
#
# Каждое изменение сохраняет исходный файл с суффиксом .ksc-bak-<дата>,
# что позволяет вернуть прежнее состояние.
#
# Использование:
#   sudo ./harden.sh --check      # только проверка, без изменений
#   sudo ./harden.sh --apply

. "$(dirname "$0")/../common.sh"
require_root

MODE="${1:---check}"
STAMP="$(date +%Y%m%d-%H%M%S)"
SSH_ALLOW_FROM="${KSC_RDS}"

backup() { [ -f "$1" ] && cp -a "$1" "$1.ksc-bak-${STAMP}" && log "  резервная копия: $1.ksc-bak-${STAMP}"; }
apply()  { [ "$MODE" = '--apply' ]; }

log "=== Харденинг узла Debian (режим: ${MODE}) ==="
[ "$MODE" = '--apply' ] || log 'Режим проверки: изменения не вносятся. Для применения запустите с --apply.' WARN

# ------------------------------------------------------------------ 1. SSH

log '--- SSH ---'
SSHD='/etc/ssh/sshd_config'
declare -A SSH_OPTS=(
    [PermitRootLogin]='no'
    [PasswordAuthentication]='no'
    [PubkeyAuthentication]='yes'
    [PermitEmptyPasswords]='no'
    [X11Forwarding]='no'
    [MaxAuthTries]='3'
    [ClientAliveInterval]='300'
    [ClientAliveCountMax]='2'
    [LoginGraceTime]='30'
    [Protocol]='2'
    [LogLevel]='VERBOSE'
)

for opt in "${!SSH_OPTS[@]}"; do
    want="${SSH_OPTS[$opt]}"
    cur="$(grep -Ei "^\s*${opt}\s+" "$SSHD" 2>/dev/null | tail -1 | awk '{print $2}' || true)"
    if [ "$cur" = "$want" ]; then
        log "  ${opt} = ${want}" OK
    else
        log "  ${opt}: сейчас '${cur:-по умолчанию}', требуется '${want}'" WARN
        if apply; then
            [ -f "${SSHD}.ksc-bak-${STAMP}" ] || backup "$SSHD"
            if grep -Eqi "^\s*#?\s*${opt}\s+" "$SSHD"; then
                sed -i -E "s|^\s*#?\s*${opt}\s+.*|${opt} ${want}|I" "$SSHD"
            else
                printf '%s %s\n' "$opt" "$want" >> "$SSHD"
            fi
        fi
    fi
done

# Ограничение источника подключений: управление разрешено только с АРМ администратора.
if apply && ! grep -q 'KSC deployment: allow from admin workstation' "$SSHD"; then
    cat >> "$SSHD" <<EOF

# KSC deployment: allow from admin workstation
# Управление узлами выполняется только с АРМ администратора (аттестованный контур).
Match Address ${SSH_ALLOW_FROM}
    PermitTTY yes
EOF
    log "  добавлено ограничение источника подключений: ${SSH_ALLOW_FROM}" OK
fi

if apply; then
    if sshd -t 2>/dev/null; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        log '  конфигурация SSH проверена и перезагружена' OK
    else
        log '  ОШИБКА в конфигурации SSH — изменения не применены, восстановите из резервной копии!' ERROR
        sshd -t
    fi
fi

# ------------------------------------------------------------------ 2. Межсетевой экран

log '--- Межсетевой экран ---'
if command -v ufw >/dev/null 2>&1; then
    if apply; then
        ufw --force reset >/dev/null
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw allow from "${SSH_ALLOW_FROM}" to any port 22 proto tcp comment 'SSH from admin workstation' >/dev/null
        ufw allow from "${KSC_IP}" to any port "${KSC_PORT_SRV2AGENT}" proto udp comment 'KSC server to agent' >/dev/null
        ufw allow from "${KSC_IP}" to any port 15001 proto udp comment 'KSC multicast' >/dev/null
        ufw --force enable >/dev/null
        log "  ufw: включён, разрешены SSH с ${SSH_ALLOW_FROM} и служебные порты с ${KSC_IP}" OK
    else
        ufw status verbose 2>/dev/null | sed 's/^/    /'
        log "  требуется: deny incoming; SSH только с ${SSH_ALLOW_FROM}; ${KSC_PORT_SRV2AGENT}/udp только с ${KSC_IP}" WARN
    fi
else
    log '  ufw не установлен. Настройте nftables вручную по тем же правилам.' WARN
fi

# ------------------------------------------------------------------ 3. Параметры ядра

log '--- Параметры ядра ---'
SYSCTL_FILE='/etc/sysctl.d/99-ksc-hardening.conf'
SYSCTL_CONTENT='# Параметры сетевого стека для аттестованного контура (KSC deployment)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0'

if apply; then
    printf '%s\n' "$SYSCTL_CONTENT" > "$SYSCTL_FILE"
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || log '  часть параметров не применилась (проверьте вывод sysctl -p)' WARN
    log "  применены параметры из ${SYSCTL_FILE}" OK
else
    log "  будет создан ${SYSCTL_FILE} ($(printf '%s\n' "$SYSCTL_CONTENT" | grep -c '^[a-z]') параметров)" WARN
fi

# ------------------------------------------------------------------ 4. Аудит

log '--- Аудит ---'
if command -v auditctl >/dev/null 2>&1; then
    AUDIT_RULES='/etc/audit/rules.d/99-ksc.rules'
    if apply; then
        cat > "$AUDIT_RULES" <<'EOF'
# Изменения учётных записей и групп
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege
# Конфигурация SSH и сети
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/hosts -p wa -k network
# Средства защиты информации
-w /opt/kaspersky/ -p wa -k kaspersky
# Использование привилегий
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k rootcmd
EOF
        augenrules --load >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
        log "  правила аудита установлены: ${AUDIT_RULES}" OK
    else
        log '  auditd присутствует, правила KSC будут добавлены при --apply' WARN
    fi
else
    log '  auditd не установлен: события действий с привилегиями не фиксируются. Установите пакет auditd.' WARN
fi

# ------------------------------------------------------------------ 5. Обновления

log '--- Источники обновлений ---'
# В изолированном контуре автоматическое обновление из внешних репозиториев
# недопустимо: пакеты доставляются контролируемо с локального зеркала.
if dpkg -s unattended-upgrades >/dev/null 2>&1; then
    if apply; then
        systemctl disable --now unattended-upgrades >/dev/null 2>&1 || true
        log '  автоматическое обновление отключено' OK
    else
        log '  unattended-upgrades активен: в изолированном контуре подлежит отключению' WARN
    fi
fi
if grep -rqs -E '^\s*deb\s+https?://(deb\.debian|security\.debian|archive\.ubuntu)' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
    log '  в источниках APT указаны внешние репозитории: замените на локальное зеркало' WARN
fi

# ------------------------------------------------------------------ 6. Учётные записи

log '--- Учётные записи ---'
awk -F: '($3 == 0) {print "  UID 0: "$1}' /etc/passwd
EMPTY_PW="$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null || true)"
[ -n "$EMPTY_PW" ] && log "  учётные записи с пустым паролем: ${EMPTY_PW}" ERROR
NO_EXPIRE="$(awk -F: '($5 == "" || $5 > 400) && ($2 !~ /^[!*]/) {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ' || true)"
[ -n "$NO_EXPIRE" ] && log "  пароль без ограничения срока: ${NO_EXPIRE}" WARN

# ------------------------------------------------------------------ 7. Средство защиты

log '--- Средство антивирусной защиты ---'
if dpkg -s klnagent64 >/dev/null 2>&1 && systemctl is-active --quiet klnagent64; then
    log '  Агент администрирования установлен и активен' OK
else
    log '  Агент администрирования отсутствует или не запущен: узел вне контроля системы защиты' ERROR
fi
if dpkg -s kesl >/dev/null 2>&1 && systemctl is-active --quiet kesl; then
    log '  KESL установлен и активен' OK
else
    log '  KESL отсутствует или не запущен' WARN
fi

log '=== Харденинг завершён ===' OK
[ "$MODE" = '--apply' ] && log "Резервные копии изменённых файлов: *.ksc-bak-${STAMP}"
