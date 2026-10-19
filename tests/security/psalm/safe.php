<?php
// Static scanner fixtures only. Never execute or deploy this file.
require_once __DIR__ . '/relay.php';

function security_fixture_safe(wpdb $wpdb): void {
    $value = security_fixture_request('value');
    echo esc_html($value);
    echo esc_attr($value);
    echo esc_textarea($value);
    echo esc_url($value);
    $wpdb->query($wpdb->prepare('SELECT * FROM users WHERE name = %s', $value));
    echo esc_html(wp_remote_retrieve_body([]));
}
