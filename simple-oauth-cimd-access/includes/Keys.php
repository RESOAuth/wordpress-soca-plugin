<?php
namespace OCIMD;
use OCIMD\Vendor\JWT\JWT;
final class Keys {
    public static function generate(int $now): array {
        $key = openssl_pkey_new(['private_key_type'=>OPENSSL_KEYTYPE_EC, 'curve_name'=>'prime256v1']);
        Support::need($key !== false && openssl_pkey_export($key, $pem), 'key_generation', 'OpenSSL P-256 key generation failed.');
        $details = openssl_pkey_get_details($key)['ec'];
        // OpenSSL may omit a leading zero byte; JWK P-256 coordinates are always 32 bytes.
        $public = ['crv'=>'P-256','kty'=>'EC','x'=>Support::b64(str_pad($details['x'],32,"\0",STR_PAD_LEFT)),'y'=>Support::b64(str_pad($details['y'],32,"\0",STR_PAD_LEFT))];
        $kid = Support::b64(hash('sha256', Support::json($public), true)); // RFC 7638 canonical member order.
        return ['kid'=>$kid, 'public'=>$public+['kid'=>$kid,'use'=>'sig','alg'=>'ES256'], 'private'=>$pem, 'created'=>$now, 'published'=>0, 'context'=>'', 'retired'=>0, 'retire_after'=>0];
    }
    public static function get(): array {
        $sealed = get_option('ocimd_keys');
        if (!$sealed) {
            return Store::locked('keys/' . get_current_blog_id(), static function () {
                $existing = get_option('ocimd_keys'); if ($existing) { return Store::open($existing); }
                $now = time(); $a = self::generate($now); $b = self::generate($now);
                $keys = ['active'=>$a['kid'], 'since'=>$now, 'items'=>[$a,$b]];
                self::save($keys); return $keys;
            });
        }
        return Store::open($sealed);
    }
    private static function save(array $keys): void { update_option('ocimd_keys', Store::seal($keys), false); }
    public static function jwks(?array $keys = null): array {
        $items = array_column(($keys ?? self::get())['items'], 'public');
        usort($items, static fn($a,$b)=>strcmp($a['kid'],$b['kid']));
        return ['keys'=>$items];
    }
    public static function published(string $context, array $kids, ?int $at = null): void {
        Store::locked('keys/' . get_current_blog_id(), static function () use ($context,$kids,$at) {
            $keys = self::get();
            foreach ($keys['items'] as &$key) {
                if (in_array($key['kid'], $kids, true)) {
                    if ($key['context'] !== $context || !$key['published']) { $key['published'] = $at ?? time(); }
                    $key['context'] = $context;
                }
            } unset($key);
            self::save($keys);
        });
    }
    /** Pure rotation transition; a delayed tick delays rotation, never compresses overlap. */
    public static function advance(array $keys, int $now, int $window, string $context): array {
        foreach ($keys['items'] as $i=>$key) {
            if ($key['retired'] && $now >= max($key['retire_after'] ?? 0, $key['retired'] + $window + 720)) { $keys['items'][$i] = self::generate($now); return $keys; }
        }
        if ($now < $keys['since'] + 604800) { return $keys; }
        foreach ($keys['items'] as $i=>$key) {
            if ($key['kid'] !== $keys['active'] && !$key['retired'] && $key['published'] && $key['context'] === $context && $now >= $key['published'] + $window) {
                foreach ($keys['items'] as &$old) { if ($old['kid'] === $keys['active']) { $old['retired'] = $now; $old['retire_after'] = $now + $window + 720; } } unset($old);
                $keys['active'] = $key['kid']; $keys['since'] = $now;
                return $keys;
            }
        }
        return $keys;
    }
    public static function rotate(array $s, string $context): void {
        Store::locked('keys/' . get_current_blog_id(), static function () use ($s,$context) {
            $old = self::get(); $keys = self::advance($old, time(), $s['cache_hours']*3600, $context);
            if ($old !== $keys) { self::save($keys); Support::audit('keys_rotated_or_staged'); }
        });
    }
    public static function ready(string $context): bool {
        $keys = self::get();
        foreach ($keys['items'] as $key) {
            if ($key['kid'] === $keys['active']) { return $key['published'] > 0 && $key['context'] === $context; }
        }
        return false;
    }
    public static function assertion(string $kid, string $client, string $audience): string {
        foreach (self::get()['items'] as $key) {
            if ($key['kid'] === $kid) {
                return JWT::encode(['iss'=>$client,'sub'=>$client,'aud'=>$audience,'iat'=>time(),'exp'=>time()+60,'jti'=>Support::random()], $key['private'], 'ES256', $kid);
            }
        }
        throw new Failure('key_missing', 'The transaction signing key is no longer available; start again.');
    }
}
