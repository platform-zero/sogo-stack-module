#!/bin/bash
set -euo pipefail

if [ -f /ca/caddy-ca.crt ]; then
  install -m 0644 -D /ca/caddy-ca.crt /usr/local/share/ca-certificates/caddy-ca.crt
  if command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates >/dev/null
  fi
fi

: "${DOMAIN:?DOMAIN is required}"
: "${MARIADB_ADMIN_PASSWORD:?MARIADB_ADMIN_PASSWORD is required}"
: "${SOGO_DB_PASSWORD:?SOGO_DB_PASSWORD is required}"
: "${SOGO_OAUTH_SECRET:?SOGO_OAUTH_SECRET is required}"

export SOGO_DB_HOST="${SOGO_DB_HOST:-mariadb}"
export SOGO_DB_PORT="${SOGO_DB_PORT:-3306}"
export SOGO_DB_NAME="${SOGO_DB_NAME:-sogo}"
export SOGO_DB_USER="${SOGO_DB_USER:-sogo}"
case "$SOGO_DB_NAME" in (*[!A-Za-z0-9_]*|"") echo "invalid SOGO_DB_NAME" >&2; exit 1 ;; esac
case "$SOGO_DB_USER" in (*[!A-Za-z0-9_]*|"") echo "invalid SOGO_DB_USER" >&2; exit 1 ;; esac
sql_literal() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\'/\'\'}"
  printf "'%s'" "$value"
}
sogo_password_literal="$(sql_literal "$SOGO_DB_PASSWORD")"
export SOGO_TIMEZONE="${SOGO_TIMEZONE:-UTC}"
export SOGO_LANGUAGE="${SOGO_LANGUAGE:-English}"
export SOGO_MEMCACHED_HOST="${SOGO_MEMCACHED_HOST:-memcached}"
export SOGO_MAIL_DOMAIN="${SOGO_MAIL_DOMAIN:-${MAIL_DOMAIN:-$DOMAIN}}"
export SOGO_MAIL_HOST="${SOGO_MAIL_HOST:-mail.${DOMAIN}}"
export SOGO_IMAP_SERVER="${SOGO_IMAP_SERVER:-imaps://${SOGO_MAIL_HOST}:993}"
export SOGO_SMTP_SERVER="${SOGO_SMTP_SERVER:-smtp://${SOGO_MAIL_HOST}:587/?tls=yes}"
export SOGO_SIEVE_SERVER="${SOGO_SIEVE_SERVER:-sieve://${SOGO_MAIL_HOST}:4190/?tls=yes}"
export SOGO_IMAP_AUTH_MECHANISM="${SOGO_IMAP_AUTH_MECHANISM:-xoauth2}"
export SOGO_SMTP_AUTHENTICATION_TYPE="${SOGO_SMTP_AUTHENTICATION_TYPE:-xoauth2}"
export SOGO_XSRF_VALIDATION_ENABLED="${SOGO_XSRF_VALIDATION_ENABLED:-NO}"
export SOGO_OPENID_CONFIG_URL="${SOGO_OPENID_CONFIG_URL:-https://keycloak.${DOMAIN}/realms/webservices/.well-known/openid-configuration}"
export SOGO_OPENID_CLIENT="${SOGO_OPENID_CLIENT:-sogo}"
export SOGO_OPENID_SCOPE="${SOGO_OPENID_SCOPE:-openid profile email}"
export SOGO_OPENID_EMAIL_PARAM="${SOGO_OPENID_EMAIL_PARAM:-email}"
export SOGO_OPENID_TOKEN_CHECK_INTERVAL="${SOGO_OPENID_TOKEN_CHECK_INTERVAL:-300}"

until mariadb -h "$SOGO_DB_HOST" -P "$SOGO_DB_PORT" -u root -p"$MARIADB_ADMIN_PASSWORD" --protocol=TCP --ssl=0 -e "SELECT 1" >/dev/null 2>&1; do
  sleep 2
done

mariadb -h "$SOGO_DB_HOST" -P "$SOGO_DB_PORT" -u root -p"$MARIADB_ADMIN_PASSWORD" --protocol=TCP --ssl=0 <<EOSQL
  CREATE DATABASE IF NOT EXISTS \`$SOGO_DB_NAME\`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;
  CREATE USER IF NOT EXISTS '$SOGO_DB_USER'@'%' IDENTIFIED BY $sogo_password_literal;
  ALTER USER '$SOGO_DB_USER'@'%' IDENTIFIED BY $sogo_password_literal;
  GRANT ALL PRIVILEGES ON \`$SOGO_DB_NAME\`.* TO '$SOGO_DB_USER'@'%';
  FLUSH PRIVILEGES;
EOSQL

mariadb -h "$SOGO_DB_HOST" -P "$SOGO_DB_PORT" -u root -p"$MARIADB_ADMIN_PASSWORD" --protocol=TCP --ssl=0 "$SOGO_DB_NAME" <<-'EOSQL'
  CREATE TABLE IF NOT EXISTS sogo_openid (
    c_user_session text NOT NULL,
    c_old_session text DEFAULT '',
    c_session_started int NOT NULL,
    c_refresh_token text DEFAULT '',
    c_access_token_expires_in int DEFAULT 0,
    c_refresh_token_expires_in int DEFAULT NULL
  );

  UPDATE sogo_openid
     SET c_old_session = COALESCE(c_old_session, ''),
         c_refresh_token = COALESCE(c_refresh_token, ''),
         c_access_token_expires_in = COALESCE(c_access_token_expires_in, 0);

  SET @sogo_users_type = (
    SELECT TABLE_TYPE
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sogo_users'
    LIMIT 1
  );
  SET @drop_sogo_users_sql = CASE
    WHEN @sogo_users_type = 'VIEW' THEN 'DROP VIEW sogo_users'
    WHEN @sogo_users_type = 'BASE TABLE' THEN 'DROP TABLE sogo_users'
    ELSE 'SELECT 1'
  END;
  PREPARE drop_sogo_users_stmt FROM @drop_sogo_users_sql;
  EXECUTE drop_sogo_users_stmt;
  DEALLOCATE PREPARE drop_sogo_users_stmt;

  CREATE TABLE IF NOT EXISTS sogo_users (
    c_uid varchar(255) NOT NULL,
    c_name varchar(255) NOT NULL,
    c_password varchar(255) NOT NULL DEFAULT '',
    c_cn varchar(255) NOT NULL,
    mail varchar(255) NOT NULL,
    PRIMARY KEY (c_uid),
    KEY idx_sogo_users_mail (mail)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

  INSERT INTO sogo_users (c_uid, c_name, c_password, c_cn, mail)
  SELECT DISTINCT
    email,
    email,
    '',
    COALESCE(NULLIF(display_name, ''), preferred_username, email),
    email
  FROM (
    SELECT
      JSON_UNQUOTE(JSON_EXTRACT(claims, '$.email')) AS email,
      JSON_UNQUOTE(JSON_EXTRACT(claims, '$.name')) AS display_name,
      JSON_UNQUOTE(JSON_EXTRACT(claims, '$.preferred_username')) AS preferred_username
    FROM (
      SELECT CAST(
        FROM_BASE64(
          CONCAT(
            REPLACE(REPLACE(SUBSTRING_INDEX(SUBSTRING_INDEX(c_user_session, '.', 2), '.', -1), '-', '+'), '_', '/'),
            REPEAT('=', (4 - LENGTH(SUBSTRING_INDEX(SUBSTRING_INDEX(c_user_session, '.', 2), '.', -1)) % 4) % 4)
          )
        ) AS CHAR CHARACTER SET utf8mb4
      ) AS claims
      FROM sogo_openid
      WHERE c_user_session LIKE '%.%.%'
    ) decoded
  ) users
  WHERE email IS NOT NULL
  ON DUPLICATE KEY UPDATE
    c_name = VALUES(c_name),
    c_cn = VALUES(c_cn),
    mail = VALUES(mail);

  DROP TRIGGER IF EXISTS sogo_openid_sync_user;
  DELIMITER //
  CREATE TRIGGER sogo_openid_sync_user
  AFTER INSERT ON sogo_openid
  FOR EACH ROW
  BEGIN
    DECLARE claims_text text;
    DECLARE user_email varchar(255);
    DECLARE user_name varchar(255);
    DECLARE preferred_username varchar(255);

    IF NEW.c_user_session LIKE '%.%.%' THEN
      SET claims_text = CAST(
        FROM_BASE64(
          CONCAT(
            REPLACE(REPLACE(SUBSTRING_INDEX(SUBSTRING_INDEX(NEW.c_user_session, '.', 2), '.', -1), '-', '+'), '_', '/'),
            REPEAT('=', (4 - LENGTH(SUBSTRING_INDEX(SUBSTRING_INDEX(NEW.c_user_session, '.', 2), '.', -1)) % 4) % 4)
          )
        ) AS CHAR CHARACTER SET utf8mb4
      );
      SET user_email = JSON_UNQUOTE(JSON_EXTRACT(claims_text, '$.email'));
      SET user_name = JSON_UNQUOTE(JSON_EXTRACT(claims_text, '$.name'));
      SET preferred_username = JSON_UNQUOTE(JSON_EXTRACT(claims_text, '$.preferred_username'));

      IF user_email IS NOT NULL THEN
        INSERT INTO sogo_users (c_uid, c_name, c_password, c_cn, mail)
        VALUES (
          user_email,
          user_email,
          '',
          COALESCE(NULLIF(user_name, ''), preferred_username, user_email),
          user_email
        )
        ON DUPLICATE KEY UPDATE
          c_name = VALUES(c_name),
          c_cn = VALUES(c_cn),
          mail = VALUES(mail);
      END IF;
    END IF;
  END//
  DELIMITER ;
EOSQL

install -d -m 0750 -o sogo -g sogo /var/spool/sogo

envsubst < /config-templates/sogo.conf.template > /etc/sogo/sogo.conf

if grep -q -- "-WOWorkersCount" /opt/sogod.sh; then
  :
else
  sed -i \
    "s|/usr/local/sbin/sogod -WONoDetach YES|/usr/local/sbin/sogod -WOWorkersCount 5 -WONoDetach YES|" \
    /opt/sogod.sh
fi

exec /opt/entrypoint.sh
