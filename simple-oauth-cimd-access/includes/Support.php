<?php
namespace OCIMD;

final class Failure extends \RuntimeException {
    public function __construct(public string $reason, string $message) { parent::__construct($message); }
}
final class Support {
    public static function need(bool $ok, string $code, string $message): void {
        if (!$ok) { throw new Failure($code, $message); }
    }
    public static function b64(string $s): string { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
    public static function unb64(string $s): string {
        self::need((bool) preg_match('/^[A-Za-z0-9_-]+$/D', $s), 'encoding', 'Invalid base64url.');
        $r = base64_decode(strtr($s, '-_', '+/'), true);
        self::need(is_string($r) && self::b64($r) === $s, 'encoding', 'Noncanonical base64url.');
        return $r;
    }
    public static function json(array $v): string {
        return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
    public static function object(string $s): array {
        self::need(strlen($s) <= 262144, 'json_size', 'JSON document is too large.');
        try { $v = json_decode($s, false, 32, JSON_THROW_ON_ERROR); }
        catch (\Throwable $e) { throw new Failure('json', 'Invalid JSON document.'); }
        self::need($v instanceof \stdClass, 'json', 'Expected a JSON object.');
        return json_decode($s, true, 32, JSON_THROW_ON_ERROR);
    }
    public static function random(): string { return self::b64(random_bytes(32)); }
    public static function scalar(array $a, string $key, int $limit = 4096): string {
        $v = $a[$key] ?? '';
        self::need(is_string($v) && strlen($v) <= $limit, 'input', 'Malformed request parameter.');
        return $v;
    }
    public static function localHost(string $host): bool {
        $h = strtolower(trim($host, '[]'));
        return filter_var($h, FILTER_VALIDATE_IP) !== false || !str_contains($h, '.') ||
            (bool) preg_match('/(?:^|\.)(localhost|local|test|invalid|example|internal|lan|home|localdomain)$/D', $h) || str_ends_with($h, '.home.arpa');
    }
    public static function query(string $url, array $params): string {
        return $url . (str_contains($url, '?') ? '&' : '?') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }
    public static function destination(string $url): string {
        $fallback = home_url('/');
        if (!$url) { return $fallback; }
        $p = wp_parse_url($url); $h = wp_parse_url($fallback);
        if (!$p || isset($p['user']) || isset($p['pass']) || preg_match('/[\\\\\x00-\x20]/', $url)) { return $fallback; }
        if (!isset($p['host'])) {
            if (!str_starts_with($url, '/') || str_starts_with($url, '//')) { return $fallback; }
            $url = $h['scheme'] . '://' . $h['host'] . (isset($h['port']) ? ':' . $h['port'] : '') . $url;
            $p = wp_parse_url($url);
        }
        foreach (['scheme','host','port'] as $k) { if (($p[$k] ?? null) !== ($h[$k] ?? null)) { return $fallback; } }
        if (preg_match('~/(?:wp-login\.php|wp-admin/admin-post\.php)$~', $p['path'] ?? '')) { return $fallback; }
        return $url;
    }
    public static function audit(string $event, int $user = 0): void {
        // Fixed codes only. Never claims, subject, email, URLs, tokens, errors from upstream, or IPs.
        if (!preg_match('/^[a-z_]{1,48}$/D', $event)) { $event = 'internal_error'; }
        $log = get_option('ocimd_audit', []);
        $log[] = ['time'=>gmdate('c'), 'event'=>$event, 'user'=>$user];
        update_option('ocimd_audit', array_slice($log, -100), false);
    }
}
