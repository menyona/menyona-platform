<?php
if (PHP_SAPI !== 'cli') { exit(1); }
require '/var/www/html/wp-load.php';
$raw = stream_get_contents(STDIN);
$input = $raw ? json_decode($raw, true, 16, JSON_THROW_ON_ERROR) : [];
$fixture = get_option('menyona_lab_fixture');
$checks = [];
function check_lab($name, $condition) {
    global $checks;
    $checks[$name] = (bool) $condition;
    if (!$condition) { throw new RuntimeException('Laboratory assertion failed: ' . $name); }
}
check_lab('hpos_active', Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled());
check_lab('storefront_active', get_template() === 'storefront');
check_lab('lab_child_theme_active', get_stylesheet() === 'menyona-lab');
check_lab('synthetic_store_visible', get_option('woocommerce_coming_soon') === 'no');
check_lab('external_http_blocked', is_wp_error(wp_remote_get('https://example.invalid')));
$product = wc_get_product($fixture['product']);
check_lab('server_product_price', wc_format_decimal($product->get_price(), 2) === '25.00');
$variants = wc_get_product($fixture['variable'])->get_variation_prices();
$prices = array_map(static fn($value) => wc_format_decimal($value, 2), array_values($variants['price']));
sort($prices);
check_lab('variable_prices', $prices === ['10.00', '15.00']);
foreach (['install_plugins', 'update_plugins', 'update_core', 'edit_plugins', 'edit_themes'] as $cap) {
    check_lab('manager_denied_' . $cap, !user_can($fixture['manager'], $cap));
    check_lab('customer_denied_' . $cap, !user_can($fixture['customer'], $cap));
}
check_lab('customer_cannot_manage_orders', !user_can($fixture['customer'], 'manage_woocommerce'));
if (isset($input['web_order'])) {
    $web_order = wc_get_order((int) $input['web_order']);
    check_lab('http_checkout_server_total', $web_order && wc_format_decimal($web_order->get_total(), 2) === '25.00');
    check_lab('http_checkout_cod_method', $web_order->get_payment_method() === 'cod');
}
$before = $product->get_stock_quantity();
$order = wc_create_order(['customer_id' => $fixture['customer']]);
$order->add_product($product, 2);
$order->set_payment_method('cod');
$order->set_billing_email('customer_' . $fixture['tenant'] . '@example.invalid');
$order->set_currency('SAR');
$order->calculate_totals();
$order->update_meta_data('_menyona_lab_only', 'local-payment-state-simulation');
$order->save();
check_lab('crud_total', wc_format_decimal($order->get_total(), 2) === '50.00');
check_lab('initially_unpaid', !$order->is_paid());
$order->payment_complete('lab-simulation-' . $order->get_id());
$order = wc_get_order($order->get_id());
check_lab('simulated_payment_state', $order->is_paid());
check_lab('stock_reduced_once', wc_get_product($fixture['product'])->get_stock_quantity() === $before - 2);
$count = count(wc_get_orders(['limit' => -1, 'return' => 'ids']));
$order->payment_complete('lab-simulation-' . $order->get_id());
check_lab('repeated_simulation_no_extra_stock', wc_get_product($fixture['product'])->get_stock_quantity() === $before - 2);
check_lab('repeated_simulation_no_extra_order', count(wc_get_orders(['limit' => -1, 'return' => 'ids'])) === $count);
update_option('menyona_lab_order', $order->get_id());
echo json_encode(['checks' => $checks, 'order' => $order->get_id(), 'total' => $order->get_total(), 'status' => $order->get_status(), 'stock' => wc_get_product($fixture['product'])->get_stock_quantity(), 'wordpress' => get_bloginfo('version'), 'woocommerce' => WC_VERSION, 'php' => PHP_VERSION, 'database' => $wpdb->db_version()]) . "\n";
