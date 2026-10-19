<?php
// Static scanner fixtures only. Never execute or deploy this file.
function security_fixture_phpcs_safe($wpdb): void {
    check_admin_referer('security_fixture');
    $name = isset($_POST['name']) ? sanitize_text_field(wp_unslash($_POST['name'])) : '';
    $id = isset($_POST['id']) ? absint($_POST['id']) : 0;
    echo esc_html($name);
    $wpdb->query($wpdb->prepare('DELETE FROM users WHERE id = %d', $id));
}
