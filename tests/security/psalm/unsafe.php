<?php
// Static scanner fixtures only. Never execute or deploy this file.
require_once __DIR__ . '/relay.php';

function security_fixture_unsafe(wpdb $wpdb): void {
    $value = security_fixture_request('value');
    echo $value;
    echo sanitize_text_field($value);
    echo esc_url($value, null, 'db');
    $wpdb->query('SELECT * FROM users WHERE name = ' . $value);
    $wpdb->prepare($value, 'bound value');
    shell_exec($value);
    echo wp_remote_retrieve_body([]);
}
