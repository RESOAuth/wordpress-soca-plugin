<?php
if (!defined('WP_UNINSTALL_PLUGIN') || !defined('SOCA_ERASE_DATA') || !SOCA_ERASE_DATA) { exit; }

$socaSites = is_multisite() ? get_sites(['fields'=>'ids','number'=>0]) : [get_current_blog_id()];
foreach ($socaSites as $socaSite) {
    if (is_multisite()) { switch_to_blog($socaSite); }
    wp_clear_scheduled_hook('soca_maintenance');
    foreach (['soca_settings','soca_keys','soca_checked','soca_maintenance_status','soca_audit'] as $socaOption) {
        delete_option($socaOption);
    }
    // WordPress expires short-lived SOCA transients without plugin-specific cleanup.
    if (is_multisite()) { restore_current_blog(); }
}
