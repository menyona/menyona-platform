<?php
// Local compatibility laboratory only. Credentials are never baked into images.
$tenant = getenv('LAB_TENANT');
if (!in_array($tenant, ['a', 'b'], true)) { exit(1); }
define('DB_NAME', 'tenant_' . $tenant);
define('DB_USER', 'tenant_' . $tenant);
define('DB_HOST', getenv('LAB_DB_HOST'));
define('DB_PASSWORD', trim(file_get_contents('/run/secrets/db_password')));
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
$table_prefix = 'wp_';
$salts = json_decode(file_get_contents('/run/secrets/wp_salts'), true, 16, JSON_THROW_ON_ERROR);
foreach ($salts as $key => $value) { define($key, $value); }
unset($salts, $key, $value);
define('WP_HOME', 'http://127.0.0.1:' . getenv('LAB_PORT'));
define('WP_SITEURL', WP_HOME);
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '256M');
define('WP_DEBUG', false);
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
define('AUTOMATIC_UPDATER_DISABLED', true);
define('DISABLE_WP_CRON', true);
define('WP_ENVIRONMENT_TYPE', 'local');
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('WP_CACHE', false);
define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
