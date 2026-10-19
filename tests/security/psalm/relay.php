<?php
// Deliberately preserves taint across files, matching the plugin's request wrapper.
function security_fixture_request(string $key): string {
    return SOCA\Support::scalar(wp_unslash($_GET), $key);
}
