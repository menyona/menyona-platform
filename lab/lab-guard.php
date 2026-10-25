<?php
/**
 * Plugin Name: Menyona local laboratory guard
 * Description: Laboratory-only mail/HTTP suppression and setup-account protection.
 */
defined('ABSPATH') || exit;
add_filter('pre_wp_mail', '__return_true');
add_filter('pre_http_request', static function () {
    return new WP_Error('lab_external_disabled', 'External requests are disabled in the local laboratory.');
});
add_filter('authenticate', static function ($user) {
    if ($user instanceof WP_User && in_array('administrator', $user->roles, true)) {
        return new WP_Error('lab_setup_cli_only', 'The setup account is restricted to local CLI.');
    }
    return $user;
}, 100);
