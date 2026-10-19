<?php
// Static scanner fixtures only. Never execute or deploy this file.
function security_fixture_phpcs_unsafe($wpdb): void {
    echo $_POST['name'];
    $wpdb->query('DELETE FROM users WHERE id = ' . $_POST['id']);
}
