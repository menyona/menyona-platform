<?php
if (PHP_SAPI !== 'cli') { exit(1); }
$input = json_decode(stream_get_contents(STDIN), true, 16, JSON_THROW_ON_ERROR);
define('WP_INSTALLING', true);
require '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
if (is_blog_installed()) { throw new RuntimeException('Laboratory install must be fresh.'); }
wp_install('مطعم تجريبي ' . getenv('LAB_TENANT'), 'lab_setup', 'setup@example.invalid', false, '', $input['admin_password']);
update_option('blog_public', 0);
update_option('WPLANG', 'ar');
update_option('woocommerce_custom_orders_table_enabled', 'yes');
update_option('woocommerce_custom_orders_table_data_sync_enabled', 'no');
$activation = activate_plugin('woocommerce/woocommerce.php');
if (is_wp_error($activation)) { throw new RuntimeException('WooCommerce activation failed.'); }
switch_theme('storefront');
echo json_encode(['installed' => true]) . "\n";
