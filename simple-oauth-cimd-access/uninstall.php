<?php
if (!defined('WP_UNINSTALL_PLUGIN') || !defined('SOCA_ERASE_DATA') || !SOCA_ERASE_DATA) { exit; }

$socaSites = is_multisite() ? get_sites(['fields'=>'ids','number'=>0]) : [get_current_blog_id()];
foreach ($socaSites as $socaSite) {
    if (is_multisite()) { switch_to_blog($socaSite); }
    wp_clear_scheduled_hook('soca_maintenance');
    foreach (['soca_settings','soca_keys','soca_checked','soca_verified','soca_epoch','soca_disabled_latched','soca_maintenance_status','soca_audit'] as $socaOption) {
        delete_option($socaOption);
    }
    global $wpdb;
    // Explicit erasure includes the encrypted, site-local identity associations.
    $socaLinks = $wpdb->get_col($wpdb->prepare("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like('soca_link_') . '%'));
    foreach ($socaLinks as $socaLink) { delete_option($socaLink); }
    // WordPress expires short-lived SOCA transients without plugin-specific cleanup.
    if (is_multisite()) { restore_current_blog(); }
}
