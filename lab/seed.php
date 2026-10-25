<?php
if (PHP_SAPI !== 'cli') { exit(1); }
$input = json_decode(stream_get_contents(STDIN), true, 16, JSON_THROW_ON_ERROR);
require '/var/www/html/wp-load.php';
WC_Install::install();
WC_Install::create_pages();
$tenant = getenv('LAB_TENANT');
update_option('woocommerce_store_address', 'عنوان وهمي للاختبار');
update_option('woocommerce_store_city', 'مدينة تجريبية');
update_option('woocommerce_default_country', 'SA');
update_option('woocommerce_currency', 'SAR');
update_option('woocommerce_calc_taxes', 'no');
update_option('woocommerce_enable_guest_checkout', 'yes');
update_option('woocommerce_allow_tracking', 'no');
update_option('woocommerce_task_list_hidden', 'yes');
// Explicitly expose only the loopback synthetic shop, not a real store launch.
update_option('woocommerce_coming_soon', 'no');
update_option('woocommerce_cod_settings', ['enabled' => 'yes', 'title' => 'الدفع عند الاستلام — تجربة محلية', 'enable_for_virtual' => 'yes']);
update_option('woocommerce_enable_checkout_login_reminder', 'no');
update_option('permalink_structure', '');
foreach (['cart' => '[woocommerce_cart]', 'checkout' => '[woocommerce_checkout]', 'myaccount' => '[woocommerce_my_account]'] as $page => $shortcode) {
    $id = wc_get_page_id($page);
    wp_update_post(['ID' => $id, 'post_content' => $shortcode, 'post_title' => ['cart' => 'السلة', 'checkout' => 'إتمام الطلب', 'myaccount' => 'حسابي'][$page]]);
}
update_option('show_on_front', 'page');
update_option('page_on_front', wc_get_page_id('shop'));
wp_update_post(['ID' => wc_get_page_id('shop'), 'post_title' => 'المنيو التجريبي']);
$zone = new WC_Shipping_Zone(0);
$shipping_instance = $zone->add_shipping_method('free_shipping');
$customer = wp_insert_user(['user_login' => 'customer_' . $tenant, 'user_pass' => $input['customer_password'], 'user_email' => 'customer_' . $tenant . '@example.invalid', 'role' => 'customer']);
$manager = wp_insert_user(['user_login' => 'manager_' . $tenant, 'user_pass' => $input['manager_password'], 'user_email' => 'manager_' . $tenant . '@example.invalid', 'role' => 'shop_manager']);
if (is_wp_error($customer) || is_wp_error($manager)) { throw new RuntimeException('Could not create laboratory users.'); }
$product = new WC_Product_Simple();
$product->set_name('وجبة تجريبية ' . $tenant);
$product->set_status('publish');
$product->set_regular_price('25.00');
$product->set_manage_stock(true);
$product->set_stock_quantity(10);
$product->set_description('بيانات وهمية لإثبات توافق المكونات فقط.');
$product->set_sku('LAB-' . $tenant);
$product->save();
$variable = new WC_Product_Variable();
$variable->set_name('مشروب تجريبي ' . $tenant);
$variable->set_status('publish');
$attr = new WC_Product_Attribute();
$attr->set_name('الحجم');
$attr->set_options(['صغير', 'كبير']);
$attr->set_visible(true);
$attr->set_variation(true);
$variable->set_attributes([$attr]);
$variable->save();
foreach (['صغير' => '10.00', 'كبير' => '15.00'] as $size => $price) {
    $variation = new WC_Product_Variation();
    $variation->set_parent_id($variable->get_id());
    $variation->set_attributes([sanitize_title('الحجم') => $size]);
    $variation->set_regular_price($price);
    $variation->set_status('publish');
    $variation->save();
}
WC_Product_Variable::sync($variable->get_id());
file_put_contents(WP_CONTENT_DIR . '/uploads/tenant-marker.txt', $tenant);
// A harmless file proves the web server refuses PHP-shaped uploads.
file_put_contents(WP_CONTENT_DIR . '/uploads/lab-probe.php', '<?php echo "LAB_UPLOAD_EXECUTED";');
$result = ['tenant' => $tenant, 'product' => $product->get_id(), 'variable' => $variable->get_id(), 'customer' => $customer, 'manager' => $manager, 'cart' => wc_get_page_id('cart'), 'checkout' => wc_get_page_id('checkout'), 'account' => wc_get_page_id('myaccount')];
$private_order = wc_create_order(['customer_id' => $customer]);
$private_order->add_product($product, 1);
$private_order->set_billing_email('customer_' . $tenant . '@example.invalid');
$private_order->calculate_totals();
$private_order->save();
$result['private_order'] = $private_order->get_id();
$result['shipping_method'] = 'free_shipping:' . $shipping_instance;
$result['product_url'] = get_permalink($product->get_id());
$result['own_order_url'] = wc_get_endpoint_url('view-order', $private_order->get_id(), wc_get_page_permalink('myaccount'));
update_option('menyona_lab_fixture', $result);
echo json_encode($result) . "\n";
