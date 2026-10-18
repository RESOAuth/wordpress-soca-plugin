<?php
namespace OCIMD;
final class Store {
    public static function install(): void {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $collate = $wpdb->get_charset_collate();
        dbDelta("CREATE TABLE {$wpdb->prefix}ocimd_identities (
            identity_hash char(64) NOT NULL,
            issuer text NOT NULL,
            subject text NOT NULL,
            user_id bigint(20) unsigned NOT NULL,
            user_provider char(64) NOT NULL,
            created_at bigint(20) NOT NULL,
            PRIMARY KEY  (identity_hash),
            UNIQUE KEY user_provider (user_provider),
            KEY user_id (user_id)
        ) $collate;");
        dbDelta("CREATE TABLE {$wpdb->prefix}ocimd_transactions (
            id char(64) NOT NULL,
            expires bigint(20) NOT NULL,
            payload longtext NOT NULL,
            PRIMARY KEY  (id),
            KEY expires (expires)
        ) $collate;");
        foreach (['ocimd_identities','ocimd_transactions'] as $suffix) {
            $table = $wpdb->prefix . $suffix;
            Support::need($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table))) === $table, 'schema', 'Plugin database tables could not be created.');
        }
        update_option('ocimd_schema', 1, false);
    }
    public static function locked(string $name, callable $fn) {
        global $wpdb;
        $lock = 'ocimd_' . substr(hash('sha256', DB_NAME . $wpdb->base_prefix . $name), 0, 50);
        Support::need((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 5)', $lock)) === 1, 'busy', 'Authentication storage is busy; retry.');
        try { return $fn(); } finally { $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock)); }
    }
    private static function secret(): string {
        if (defined('OAUTH_CIMD_AUTH_KEY')) {
            Support::need(is_string(OAUTH_CIMD_AUTH_KEY) && strlen(OAUTH_CIMD_AUTH_KEY) >= 32, 'encryption_key', 'OAUTH_CIMD_AUTH_KEY must contain at least 32 random bytes of secret material.');
            $source = OAUTH_CIMD_AUTH_KEY;
        } else {
            foreach (['AUTH_KEY','SECURE_AUTH_KEY','AUTH_SALT','SECURE_AUTH_SALT'] as $constant) {
                Support::need(defined($constant) && is_string(constant($constant)) && strlen(constant($constant)) >= 32 && constant($constant) !== 'put your unique phrase here', 'encryption_key', 'Configure unique WordPress authentication keys and salts in wp-config.php before generating client keys.');
            }
            $source = wp_salt('auth') . wp_salt('secure_auth');
        }
        // Stable across the SOCA rebrand so previously encrypted site keys remain readable.
        return hash_hkdf('sha256', $source, 32, 'oauth-cimd-auth/site/' . get_current_blog_id());
    }
    public static function seal(array $data): string {
        $iv = random_bytes(12); $tag = '';
        $cipher = openssl_encrypt(Support::json($data), 'aes-256-gcm', self::secret(), OPENSSL_RAW_DATA, $iv, $tag, 'ocimd-v1');
        Support::need(is_string($cipher), 'encryption', 'Unable to encrypt local secret.');
        return base64_encode($iv . $tag . $cipher);
    }
    public static function open(string $data): array {
        $raw = base64_decode($data, true);
        Support::need(is_string($raw) && strlen($raw) >= 29, 'encryption', 'Invalid encrypted storage.');
        $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', self::secret(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16), 'ocimd-v1');
        Support::need(is_string($plain), 'encryption', 'Unable to unlock signing keys/transaction. Restore the original WordPress salts or configured encryption key.');
        return Support::object($plain);
    }
    public static function createTransaction(string $state, array $data): void {
        global $wpdb;
        Support::need($wpdb->insert($wpdb->prefix . 'ocimd_transactions', ['id'=>hash('sha256', $state),'expires'=>time()+600,'payload'=>self::seal($data)]) === 1, 'storage', 'Cannot store login transaction.');
    }
    public static function consumeTransaction(string $state, string $browser): array {
        global $wpdb;
        Support::need((bool) preg_match('/^[A-Za-z0-9_-]{43}$/D', $state), 'state', 'Invalid or expired login state.');
        $id = hash('sha256', $state); $table = $wpdb->prefix . 'ocimd_transactions';
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id=%s", $id), ARRAY_A);
        Support::need(is_array($row) && (int)$row['expires'] >= time(), 'state', 'Invalid or expired login state.');
        $tx = self::open($row['payload']);
        Support::need(hash_equals($tx['browser'], hash('sha256', $browser)), 'browser', 'Login must finish in the browser that started it.');
        // One concurrent callback wins even with a persistent WordPress object cache.
        $deleted = $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE id=%s AND expires >= %d", $id, time()));
        Support::need($deleted === 1, 'replay', 'Login transaction has already been used.');
        return $tx;
    }
    public static function clean(): void {
        global $wpdb; $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}ocimd_transactions WHERE expires < %d", time()));
    }
}
