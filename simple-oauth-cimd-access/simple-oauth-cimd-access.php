<?php
/**
 * Plugin Name: SOCA - Simple OAuth CIMD Access
 * Description: Open-source WordPress SSO with OIDC, OAuth PKCE and CIMD, built and supported by RESOAuth®; configurable for compatible providers.
 * Version: 0.0.3
 * Requires at least: 6.8
 * Requires PHP: 8.1
 * License: AGPL-3.0-only
 * Text Domain: simple-oauth-cimd-access
 */
if (!defined('ABSPATH')) { exit; }
// The previous plugin can be active during migration. It owns these internal
// classes and data, so let it run until it is deactivated.
if (class_exists('OCIMD\\Plugin', false)) {
    add_action('admin_notices', static function () {
        echo '<div class="notice notice-warning"><p>Deactivate OAuth CIMD Auth to let SOCA use its existing settings and identities.</p></div>';
    });
    return;
}
define('SOCA_FILE', __FILE__);
define('OCIMD_FILE', SOCA_FILE); // Preserve existing integrations.
require_once __DIR__ . '/vendor/autoload.php';
foreach (['Support', 'Policy', 'Settings', 'Http', 'Store', 'Keys', 'Metadata', 'Provider', 'Identity', 'Plugin', 'Admin'] as $file) {
    require_once __DIR__ . '/includes/' . $file . '.php';
}
register_activation_hook(__FILE__, ['OCIMD\\Plugin', 'activate']);
register_deactivation_hook(__FILE__, ['OCIMD\\Plugin', 'deactivate']);
OCIMD\Plugin::boot();
/** Return escaped, theme-friendly markup. Does not redirect or authenticate. */
function soca_button(string $destination = ''): string {
    return OCIMD\Plugin::button($destination);
}
