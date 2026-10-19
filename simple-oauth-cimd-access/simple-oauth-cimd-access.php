<?php
/**
 * Plugin Name: Simple OAuth CIMD Access
 * Plugin URI: https://github.com/RESOAuth/wordpress-soca-plugin
 * Description: Single sign-on for WordPress with OpenID Connect, PKCE and CIMD.
 * Version: 0.2.0
 * Requires at least: 6.8
 * Requires PHP: 8.1
 * Author: RESOAuth
 * Author URI: https://github.com/RESOAuth
 * License: AGPL-3.0-only
 * License URI: https://www.gnu.org/licenses/agpl-3.0.html
 * Text Domain: simple-oauth-cimd-access
 */
if (!defined('ABSPATH')) { exit; }
define('SOCA_FILE', __FILE__);
require_once __DIR__ . '/vendor/autoload.php';
foreach (['Support', 'Policy', 'Settings', 'Http', 'Store', 'Keys', 'Metadata', 'Provider', 'Identity', 'Plugin', 'Admin'] as $soca_file) {
    require_once __DIR__ . '/includes/' . $soca_file . '.php';
}
register_activation_hook(__FILE__, ['SOCA\\Plugin', 'activate']);
register_deactivation_hook(__FILE__, ['SOCA\\Plugin', 'deactivate']);
SOCA\Plugin::boot();
/** Return escaped, theme-friendly markup. Does not redirect or authenticate. */
function soca_button(string $destination = ''): string {
    return SOCA\Plugin::button($destination);
}
