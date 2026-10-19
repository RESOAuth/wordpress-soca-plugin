<?php
// Preserve encrypted keys and unused legacy binding rows unless the operator opts in.
if (!defined('WP_UNINSTALL_PLUGIN') ||
    !((defined('SOCA_ERASE_DATA') && SOCA_ERASE_DATA) || (defined('OAUTH_CIMD_AUTH_ERASE_DATA') && OAUTH_CIMD_AUTH_ERASE_DATA))) { exit; }
$ocimdSites = is_multisite() ? get_sites(['fields'=>'ids','number'=>0]) : [get_current_blog_id()];
foreach ($ocimdSites as $ocimdSite) {
    if (is_multisite()) { switch_to_blog($ocimdSite); }
    global $wpdb;
    wp_clear_scheduled_hook('soca_maintenance');
    wp_clear_scheduled_hook('ocimd_maintenance');
    $wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', $wpdb->prefix . 'ocimd_identities'));
    $wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', $wpdb->prefix . 'ocimd_transactions'));
    $ocimdNames = $wpdb->get_col($wpdb->prepare('SELECT option_name FROM %i WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s', $wpdb->options, $wpdb->esc_like('ocimd_').'%', $wpdb->esc_like('_transient_ocimd_').'%', $wpdb->esc_like('_transient_timeout_ocimd_').'%'));
    foreach ($ocimdNames as $ocimdName) {
        if (str_starts_with($ocimdName, '_transient_ocimd_')) { delete_transient(substr($ocimdName,11)); }
        delete_option($ocimdName);
    }
    if (is_multisite()) { restore_current_blog(); }
}
