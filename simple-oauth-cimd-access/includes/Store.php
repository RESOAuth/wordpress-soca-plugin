<?php
namespace SOCA;
final class Store {
    public static function locked(string $name, callable $fn) {
        global $wpdb;
        $lock = 'soca_' . substr(hash('sha256', DB_NAME . $wpdb->base_prefix . $name), 0, 50);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- A database advisory lock cannot be served from an object cache.
        Support::need((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 5)', $lock)) === 1, 'busy', 'Authentication storage is busy; retry.');
        try { return $fn(); }
        finally {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Release the advisory lock on the same database connection.
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }
    private static function secret(): string {
        if (defined('SOCA_ENCRYPTION_KEY')) {
            Support::need(is_string(SOCA_ENCRYPTION_KEY) && strlen(SOCA_ENCRYPTION_KEY) >= 32, 'encryption_key', 'SOCA_ENCRYPTION_KEY must contain at least 32 random bytes of secret material.');
            $source = SOCA_ENCRYPTION_KEY;
        } else {
            foreach (['AUTH_KEY','SECURE_AUTH_KEY','AUTH_SALT','SECURE_AUTH_SALT'] as $constant) {
                Support::need(defined($constant) && is_string(constant($constant)) && strlen(constant($constant)) >= 32 && constant($constant) !== 'put your unique phrase here', 'encryption_key', 'Configure unique WordPress authentication keys and salts in wp-config.php before generating client keys.');
            }
            $source = wp_salt('auth') . wp_salt('secure_auth');
        }
        return hash_hkdf('sha256', $source, 32, 'soca/site/' . get_current_blog_id());
    }
    public static function seal(array $data): string {
        $iv = random_bytes(12); $tag = '';
        $cipher = openssl_encrypt(Support::json($data), 'aes-256-gcm', self::secret(), OPENSSL_RAW_DATA, $iv, $tag, 'soca-v1');
        Support::need(is_string($cipher), 'encryption', 'Unable to encrypt local secret.');
        return base64_encode($iv . $tag . $cipher);
    }
    public static function open(string $data): array {
        $raw = base64_decode($data, true);
        Support::need(is_string($raw) && strlen($raw) >= 29, 'encryption', 'Invalid encrypted storage.');
        $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', self::secret(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16), 'soca-v1');
        Support::need(is_string($plain), 'encryption', 'Unable to unlock signing keys/transaction. Restore the original WordPress salts or configured encryption key.');
        return Support::object($plain);
    }
    public static function createTransaction(string $state, array $data): void {
        $key = 'soca_tx_' . hash('sha256', $state);
        Support::need(set_transient($key, self::seal($data), 600), 'storage', 'Cannot store login transaction.');
    }
    public static function consumeTransaction(string $state, string $userAgentHash): array {
        Support::need((bool) preg_match('/^[A-Za-z0-9_-]{43}$/D', $state), 'state', 'Invalid or expired login state.');
        $key = 'soca_tx_' . hash('sha256', $state);
        return self::locked($key, static function () use ($key, $userAgentHash) {
            $sealed = get_transient($key);
            Support::need(is_string($sealed), 'state', 'Invalid or expired login state.');
            $tx = self::open($sealed);
            if (!is_string($tx['user_agent'] ?? null) || !hash_equals($tx['user_agent'], $userAgentHash)) {
                throw new Failure('user_agent_mismatch', 'The browser User-Agent changed during login.', ['ref'=>$tx['audit_ref'] ?? '', 'flow'=>$tx['purpose'] ?? '']); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Diagnostic values are validated/redacted before display.
            }
            Support::need(delete_transient($key), 'replay', 'Login transaction has already been used.');
            return $tx;
        });
    }
}
