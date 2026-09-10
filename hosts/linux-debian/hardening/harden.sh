#!/usr/bin/env bash
#
# Харденинг узла Debian в аттестованном контуре.
#
# Профили:
#   strict   — расширенный профиль для систем ограниченного доступа
#              (по умолчанию): дополнительно к базовому — набор алгоритмов SSH,
#              срок действия и сложность паролей, umask, запрет неиспользуемых
#              модулей ядра и файловых систем, ограничение cron/at,
#              запрет дампов памяти, постоянный системный журнал,
#              расширенные правила аудита, проверка параметров монтирования;
#   baseline — прежний базовый профиль.
#
# Общая часть профиля:
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
#   sudo ./harden.sh --check                    # только проверка, без изменений
#   sudo ./harden.sh --apply                    # расширенный профиль
#   sudo ./harden.sh --apply --level baseline   # базовый профиль

. "$(dirname "$0")/../common.sh"
require_root

MODE='--check'
LEVEL='strict'
while [ $# -gt 0 ]; do
    case "$1" in
        --check|--apply) MODE="$1"; shift ;;
        --level) LEVEL="$2"; shift 2 ;;
        *) log "Неизвестный параметр: $1" ERROR; exit 2 ;;
    esac
done
case "$LEVEL" in
    strict|baseline) ;;
    *) log "Недопустимый профиль: ${LEVEL} (strict|baseline)" ERROR; exit 2 ;;
esac

STAMP="$(date +%Y%m%d-%H%M%S)"
SSH_ALLOW_FROM="${KSC_RDS}"

backup() { [ -f "$1" ] && cp -a "$1" "$1.ksc-bak-${STAMP}" && log "  резервная копия: $1.ksc-bak-${STAMP}"; }
apply()  { [ "$MODE" = '--apply' ]; }
strict() { [ "$LEVEL" = 'strict' ]; }

log "=== Харденинг узла Debian (режим: ${MODE}, профиль: ${LEVEL}) ==="
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

if strict; then
    SSH_OPTS[MaxSessions]='4'
    SSH_OPTS[MaxStartups]='3:50:10'
    SSH_OPTS[AllowAgentForwarding]='no'
    SSH_OPTS[AllowTcpForwarding]='no'
    SSH_OPTS[PermitTunnel]='no'
    SSH_OPTS[PermitUserEnvironment]='no'
    SSH_OPTS[GatewayPorts]='no'
    SSH_OPTS[TCPKeepAlive]='no'
    SSH_OPTS[Compression]='no'
    SSH_OPTS[IgnoreRhosts]='yes'
    SSH_OPTS[HostbasedAuthentication]='no'
    SSH_OPTS[KerberosAuthentication]='no'
    SSH_OPTS[GSSAPIAuthentication]='no'
    SSH_OPTS[UsePAM]='yes'
    SSH_OPTS[Banner]='/etc/issue.net'
    # Наборы алгоритмов без устаревших примитивов. При подключении с АРМ
    # проверьте, что клиент их поддерживает: иначе доступ к узлу пропадёт.
    SSH_OPTS[KexAlgorithms]='curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'
    SSH_OPTS[Ciphers]='chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr'
    SSH_OPTS[MACs]='hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com'
fi

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

# Ограничение источника подключений обеспечивается межсетевым экраном (раздел ниже):
# блок Match задаёт условия сеанса с АРМ, но сам по себе не запрещает другие адреса.
if apply && ! grep -q 'KSC deployment: allow from admin workstation' "$SSHD"; then
    cat >> "$SSHD" <<EOF

# KSC deployment: allow from admin workstation
# Управление узлами выполняется только с АРМ администратора (аттестованный контур).
Match Address ${SSH_ALLOW_FROM}
    PermitTTY yes
EOF
    log "  добавлены условия сеанса для ${SSH_ALLOW_FROM}" OK
    log '  Запрет подключений с прочих адресов обеспечивает ufw; при обходе межсетевого' WARN
    log '  экрана (иной интерфейс, туннель) вход с ключом останется возможен. При наличии' WARN
    log '  учтённого перечня администраторов добавьте AllowUsers или AllowGroups вручную.' WARN
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

if strict; then
    SYSCTL_CONTENT="${SYSCTL_CONTENT}
# Расширенный профиль
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
fs.protected_fifos = 2
fs.protected_regular = 2
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.perf_event_paranoid = 3
kernel.kexec_load_disabled = 1"
fi

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
        if [ "$LEVEL" = 'strict' ]; then
            cat >> "$AUDIT_RULES" <<'EOF'
# Расширенный профиль
-w /etc/pam.d/ -p wa -k pam
-w /etc/login.defs -p wa -k login
-w /etc/security/ -p wa -k login
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /etc/systemd/ -p wa -k systemd
-w /etc/apt/ -p wa -k software
-w /var/log/auth.log -p wa -k authlog
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,setxattr,lsetxattr,fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
# Правила блокируются от изменения до перезагрузки узла
-e 2
EOF
            log '  расширенный профиль: правила аудита заблокированы от изменения (-e 2) до перезагрузки' WARN
        fi
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

# ------------------------------------------------------------------ 7. Расширенный профиль

if strict; then

log '--- Пароли и вход в систему ---'
LOGIN_DEFS='/etc/login.defs'
declare -A LOGIN_OPTS=(
    [PASS_MAX_DAYS]='90'
    [PASS_MIN_DAYS]='1'
    [PASS_WARN_AGE]='7'
    [LOGIN_RETRIES]='3'
    [LOGIN_TIMEOUT]='60'
    [UMASK]='027'
    [ENCRYPT_METHOD]='SHA512'
)
for opt in "${!LOGIN_OPTS[@]}"; do
    want="${LOGIN_OPTS[$opt]}"
    cur="$(grep -E "^\s*${opt}\s+" "$LOGIN_DEFS" 2>/dev/null | tail -1 | awk '{print $2}' || true)"
    if [ "$cur" = "$want" ]; then
        log "  ${opt} = ${want}" OK
    else
        log "  ${opt}: сейчас '${cur:-по умолчанию}', требуется '${want}'" WARN
        if apply; then
            [ -f "${LOGIN_DEFS}.ksc-bak-${STAMP}" ] || backup "$LOGIN_DEFS"
            if grep -Eq "^\s*#?\s*${opt}\s+" "$LOGIN_DEFS"; then
                sed -i -E "s|^\s*#?\s*${opt}\s+.*|${opt}\t${want}|" "$LOGIN_DEFS"
            else
                printf '%s\t%s\n' "$opt" "$want" >> "$LOGIN_DEFS"
            fi
        fi
    fi
done

# Сложность пароля обеспечивается модулем pam_pwquality; при его отсутствии
# требование выполняется организационно (регламент обеспечения кибербезопасности).
if [ -f /etc/security/pwquality.conf ]; then
    if apply; then
        backup /etc/security/pwquality.conf
        cat > /etc/security/pwquality.conf <<'EOF'
# KSC deployment: расширенный профиль
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 5
maxrepeat = 3
gecoscheck = 1
enforcing = 1
EOF
        log '  требования к сложности пароля установлены (pam_pwquality)' OK
    else
        log '  будут установлены требования к сложности пароля: не менее 14 символов, 4 класса символов' WARN
    fi
else
    log '  pam_pwquality не установлен: apt-get install libpam-pwquality' WARN
fi

# Маска создания файлов для интерактивных сеансов
if apply; then
    printf '%s\n' '# KSC deployment: расширенный профиль' 'umask 027' > /etc/profile.d/99-ksc-umask.sh
    chmod 644 /etc/profile.d/99-ksc-umask.sh
    log '  umask 027 для интерактивных сеансов' OK
fi

log '--- Предупреждение при входе ---'
if apply; then
    for f in /etc/issue /etc/issue.net /etc/motd; do
        backup "$f"
        cat > "$f" <<'EOF'
Информационная система ограниченного доступа.
Доступ предоставляется только уполномоченным лицам, действия регистрируются.
EOF
    done
    log '  предупреждение при входе установлено' OK
fi

log '--- Модули ядра и файловые системы ---'
# Перечисленные модули не используются в контуре, но пригодны для обхода
# средств контроля (носители, туннели, устаревшие файловые системы).
MODULES_FILE='/etc/modprobe.d/99-ksc-hardening.conf'
MODULES='cramfs freevxfs jffs2 hfs hfsplus udf squashfs usb-storage firewire-core bluetooth dccp sctp rds tipc can atm appletalk'
if apply; then
    : > "$MODULES_FILE"
    for m in $MODULES; do
        printf 'install %s /bin/true\nblacklist %s\n' "$m" "$m" >> "$MODULES_FILE"
    done
    log "  запрещена загрузка модулей: ${MODULES}" OK
    log '  usb-storage запрещён: доставка обновлений и дистрибутивов носителем' WARN
    log '  потребует временного снятия запрета (учтённый носитель, запись в журнале работ).' WARN
else
    log "  будет создан ${MODULES_FILE}: запрет загрузки неиспользуемых модулей" WARN
fi

# Параметры монтирования проверяются, но не изменяются автоматически:
# noexec на /tmp или /var несовместим с частью установщиков, в том числе
# с установщиком KESL, а ошибка в /etc/fstab делает узел незагружаемым.
log '--- Параметры монтирования (проверка) ---'
for mp in /tmp /var/tmp /home /dev/shm; do
    if mountpoint -q "$mp" 2>/dev/null; then
        opts="$(findmnt -no OPTIONS "$mp" 2>/dev/null || true)"
        missing=''
        for o in nodev nosuid noexec; do
            case ",${opts}," in *",${o},"*) ;; *) missing="${missing} ${o}" ;; esac
        done
        if [ -n "$missing" ]; then
            log "  ${mp}: отсутствуют параметры${missing} (текущие: ${opts})" WARN
        else
            log "  ${mp}: nodev,nosuid,noexec" OK
        fi
    else
        log "  ${mp}: отдельный раздел не выделен — параметры монтирования неприменимы" WARN
    fi
done
log '  Изменения /etc/fstab выполняются вручную: проверьте работу KESL и установщиков' WARN
log '  после добавления noexec, иначе обновление баз и установка пакетов прекратятся.' WARN

log '--- Дампы памяти ---'
if apply; then
    printf '%s\n' '* hard core 0' > /etc/security/limits.d/99-ksc-core.conf
    mkdir -p /etc/systemd/coredump.conf.d
    printf '%s\n' '[Coredump]' 'Storage=none' 'ProcessSizeMax=0' > /etc/systemd/coredump.conf.d/99-ksc.conf
    systemctl daemon-reload >/dev/null 2>&1 || true
    log '  сохранение дампов памяти запрещено (утечка сведений из памяти процессов)' OK
fi

log '--- Планировщик заданий ---'
if apply; then
    for f in /etc/cron.deny /etc/at.deny; do backup "$f"; rm -f "$f"; done
    for f in /etc/cron.allow /etc/at.allow; do
        backup "$f"
        printf 'root\n' > "$f"; chmod 600 "$f"; chown root:root "$f"
    done
    log '  прежние списки cron/at сохранены рядом с суффиксом .ksc-bak-'"${STAMP}" WARN
    log '  Если задания выполняются от служебных учётных записей, верните их в /etc/cron.allow.' WARN
    chmod 600 /etc/crontab 2>/dev/null || true
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
    log '  задания cron/at разрешены только суперпользователю' OK
fi

log '--- Системный журнал ---'
# Срок хранения сведений в системе — 1 год; на узле хранится оперативный объём,
# долговременное хранение обеспечивается Сервером администрирования.
if apply; then
    mkdir -p /etc/systemd/journald.conf.d
    printf '%s\n' '[Journal]' 'Storage=persistent' 'Compress=yes' 'SystemMaxUse=1G' 'MaxRetentionSec=90day' \
        > /etc/systemd/journald.conf.d/99-ksc.conf
    systemctl restart systemd-journald >/dev/null 2>&1 || true
    log '  системный журнал: постоянное хранение, до 1 ГБ, 90 суток' OK
fi

log '--- Права на системные файлы ---'
if apply; then
    chmod 644 /etc/passwd /etc/group
    chmod 640 /etc/shadow /etc/gshadow 2>/dev/null || true
    chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null || true
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    log '  права на файлы учётных записей и загрузчика приведены к требуемым' OK
fi

# Файлы с установленными битами SUID/SGID — типовой способ повышения привилегий
SUID_COUNT="$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)"
log "  файлов с признаками SUID/SGID: ${SUID_COUNT} — сверьте перечень с эталонным:" WARN
log '    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls' WARN

fi   # strict

# ------------------------------------------------------------------ 8. Средство защиты

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

log "=== Харденинг завершён (профиль: ${LEVEL}) ===" OK
if [ "$MODE" = '--apply' ]; then
    log "Резервные копии изменённых файлов: *.ksc-bak-${STAMP}"
    strict && log 'Проверьте до перезагрузки: подключение по SSH с АРМ, работу klnagent и kesl,' WARN
    strict && log 'обновление баз KESL и вход пользователей — расширенный профиль меняет вход и запуск.' WARN
fi
