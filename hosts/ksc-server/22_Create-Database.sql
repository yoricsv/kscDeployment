-- ============================================================================
--  Создание базы данных и учётной записи Kaspersky Security Center в MariaDB
--
--  Запуск (от root СУБД):
--      mysql -u root -p < 22_Create-Database.sql
--  либо через скрипт 20_Install-MariaDB.ps1, который подставит пароль
--  интерактивно и не сохранит его на диск.
--
--  Плейсхолдеры:
--      {{DB_NAME}}   — имя базы данных            (по умолчанию ksc)
--      {{DB_USER}}   — учётная запись СУБД        (по умолчанию kscadmin)
--      {{DB_PASS}}   — пароль учётной записи
-- ============================================================================

-- 1. База данных -------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS `{{DB_NAME}}`
    DEFAULT CHARACTER SET utf8
    COLLATE utf8_general_ci;

-- 2. Учётная запись ----------------------------------------------------------
--    Сервер администрирования работает на том же хосте, поэтому учётная запись
--    ограничена подключениями с localhost. Учётные записи вида '%' не создаются.
CREATE USER IF NOT EXISTS '{{DB_USER}}'@'localhost' IDENTIFIED BY '{{DB_PASS}}';
CREATE USER IF NOT EXISTS '{{DB_USER}}'@'127.0.0.1' IDENTIFIED BY '{{DB_PASS}}';

-- 3. Привилегии --------------------------------------------------------------
--    Полные права на собственную БД + SELECT в служебной схеме mysql:
--    инсталлятор KSC проверяет параметры сервера через mysql.*.
GRANT ALL PRIVILEGES ON `{{DB_NAME}}`.* TO '{{DB_USER}}'@'localhost';
GRANT ALL PRIVILEGES ON `{{DB_NAME}}`.* TO '{{DB_USER}}'@'127.0.0.1';
GRANT SELECT ON mysql.* TO '{{DB_USER}}'@'localhost';
GRANT SELECT ON mysql.* TO '{{DB_USER}}'@'127.0.0.1';

-- Право на создание хранимых процедур и функций требуется установщику
-- при развёртывании схемы и при обновлении Сервера администрирования.
GRANT CREATE ROUTINE, ALTER ROUTINE, EXECUTE ON `{{DB_NAME}}`.* TO '{{DB_USER}}'@'localhost';
GRANT CREATE ROUTINE, ALTER ROUTINE, EXECUTE ON `{{DB_NAME}}`.* TO '{{DB_USER}}'@'127.0.0.1';

FLUSH PRIVILEGES;

-- 4. Гигиена установки по умолчанию -----------------------------------------
--    Аналог mysql_secure_installation: удаляем анонимных пользователей,
--    тестовую БД и удалённый доступ root.
DELETE FROM mysql.global_priv WHERE User = '';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db = 'test' OR Db = 'test\\_%';
DELETE FROM mysql.global_priv WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
FLUSH PRIVILEGES;

-- 5. Контроль ----------------------------------------------------------------
SELECT User, Host FROM mysql.user ORDER BY User, Host;
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW VARIABLES LIKE 'max_allowed_packet';
SHOW VARIABLES LIKE 'innodb_flush_log_at_trx_commit';
SHOW VARIABLES LIKE 'optimizer_switch';
