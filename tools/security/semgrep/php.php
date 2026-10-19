<?php
// Static scanner fixtures only. Never execute or deploy this file.

// ruleid: php-no-eval
eval($code);
// ruleid: php-no-shell-execution
shell_exec($command);
// ruleid: php-no-unserialize
unserialize($serialized);
// ruleid: php-tls-verification-required
wp_remote_get($url, ['sslverify' => false]);
// ruleid: php-tls-verification-required
curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);
// ruleid: php-tls-verification-required
curl_setopt_array($handle, [CURLOPT_SSL_VERIFYHOST => 0]);
// ruleid: php-no-weak-hash
md5($password);

function unsafe_sql($wpdb): void {
    $id = wp_unslash($_GET['id']);
    // ruleid: php-request-to-sql
    $wpdb->query('DELETE FROM users WHERE id = ' . $id);
}

function unsafe_output(): void {
    $name = sanitize_text_field(wp_unslash($_GET['name']));
    // ruleid: php-request-to-output
    echo $name;
    // ruleid: php-request-to-output
    echo esc_url($_GET['url'], null, 'db');
}

function unsafe_sql_template($wpdb): void {
    $query = $_GET['query'];
    // ruleid: php-request-to-sql-template
    $wpdb->prepare($query, 'bound value');
}

function unsafe_redirect(): void {
    $target = $_GET['next'];
    // ruleid: php-request-to-redirect
    wp_redirect($target);
}

function unsafe_include(): void {
    $path = $_GET['path'];
    // ruleid: php-request-to-include
    require $path;
}

function safe_examples($wpdb, string $url, string $value): void {
    // ok: php-request-to-output
    echo esc_html(wp_unslash($_GET['name']));
    // ok: php-request-to-sql
    $wpdb->query($wpdb->prepare('DELETE FROM users WHERE id = %d', $_GET['id']));
    // ok: php-request-to-redirect
    wp_safe_redirect($_GET['next']);
    // ok: php-tls-verification-required
    wp_remote_get($url, ['sslverify' => true]);
    // ok: php-no-weak-hash
    hash('sha256', $value);
    // ok: php-no-unserialize
    json_decode($value, true);
    // ok: php-request-to-include
    require __DIR__ . '/fixed.php';
}
