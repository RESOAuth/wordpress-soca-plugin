<?php
namespace SOCA;
final class Metadata {
    public static function callback(): string { return add_query_arg('action', 'soca_callback', admin_url('admin-post.php')); }
    public static function url(): string { return add_query_arg('soca_doc', 'client', home_url('/')); }
    public static function jwksUrl(): string { return add_query_arg('soca_doc', 'jwks', home_url('/')); }
    public static function proxyTemplate(string $template): void {
        Support::need(substr_count($template, '%s') === 1, 'proxy_template', 'The proxy template must contain exactly one literal %s in its path.');
        $p = wp_parse_url($template);
        Support::need(is_array($p) && str_contains($p['path'] ?? '', '%s') && !str_contains($p['host'] ?? '', '%s') && !str_contains($p['query'] ?? '', '%s'), 'proxy_template', 'The %s placeholder must be in the URL path, never the origin or query.');
        Http::url(str_replace('%s', 'e30', $template));
    }
    public static function template(array $s): array {
        $doc = ['client_name'=>get_bloginfo('name'), 'client_uri'=>home_url('/'),
            'redirect_uris'=>[self::callback()], 'grant_types'=>['authorization_code'], 'response_types'=>['code'],
            'scope'=>$s['scopes'], 'application_type'=>'web', 'token_endpoint_auth_method'=>'private_key_jwt',
            'token_endpoint_auth_signing_alg'=>'ES256', 'id_token_signed_response_alg'=>$s['id_alg']];
        if ($s['key_mode'] === 'inline') { $doc['jwks'] = Keys::jwks(); }
        else { $doc['jwks_uri'] = $s['jwks_url'] ?: self::jwksUrl(); }
        return $doc;
    }
    public static function clientId(array $s): string {
        if ($s['mode'] === 'self') { return self::url(); }
        self::proxyTemplate($s['proxy']);
        $url = str_replace('%s', Support::b64(Support::json(self::template($s))), $s['proxy']);
        Http::url($url); return $url;
    }
    public static function document(array $s, bool $self = false): array {
        return ['client_id'=>$self ? self::url() : self::clientId($s)] + self::template($s);
    }
    public static function context(array $s): string { return hash('sha256', Support::json(self::document($s))); }
    public static function validateDocument(array $expected, array $actual): void {
        foreach ($expected as $key=>$value) {
            Support::need(array_key_exists($key, $actual) && self::canonical($actual[$key]) === self::canonical($value), 'client_document', 'Published client metadata differs from the generated document: ' . $key . '.');
        }
        foreach (['client_secret','client_secret_expires_at'] as $key) { Support::need(!array_key_exists($key, $actual), 'client_document', 'Client metadata contains a forbidden shared secret field.'); }
        Support::need(!(isset($actual['jwks']) && isset($actual['jwks_uri'])), 'client_document', 'Publish jwks or jwks_uri, never both.');
        self::noPrivateKeys($actual);
    }
    private static function canonical($v): string {
        if (is_array($v)) { if (!array_is_list($v)) { ksort($v); } foreach ($v as &$x) { $x = self::canonical($x); } unset($x); }
        return json_encode($v, JSON_THROW_ON_ERROR);
    }
    public static function noPrivateKeys(array $doc): void {
        foreach ($doc as $k=>$v) {
            Support::need(!in_array((string)$k, ['d','p','q','dp','dq','qi','oth','k','private_key','client_secret'], true), 'private_material', 'A public document contains private key material.');
            if (is_array($v)) { self::noPrivateKeys($v); }
        }
    }
    public static function validate(array $s, Http $http): string {
        $url = self::clientId($s); Http::url($url);
        Support::need(wp_parse_url(self::callback(), PHP_URL_SCHEME) === 'https', 'callback_https', 'This web client requires an HTTPS WordPress site, including on localhost. Use a locally trusted certificate or an HTTPS tunnel.');
        $expected = self::document($s); $snapshotKeys = Keys::jwks(); $response = $http->request($url);
        self::validateDocument($expected, $response['json']);
        if ($s['key_mode'] === 'uri') {
            $published = $http->request($expected['jwks_uri'])['json'];
            self::noPrivateKeys($published);
            Support::need(isset($published['keys']) && is_array($published['keys']), 'client_jwks', 'Public JWKS must contain keys.');
            foreach ($snapshotKeys['keys'] as $key) {
                $matches = array_values(array_filter($published['keys'], static fn($x)=>is_array($x) && ($x['kid'] ?? null) === $key['kid']));
                Support::need(count($matches) === 1 && self::canonical($matches[0]) === self::canonical($key), 'client_jwks', 'The reachable JWKS must publish both generated public keys exactly.');
            }
        }
        $context = hash('sha256', Support::json($expected));
        Support::need($context === self::context($s) && $snapshotKeys === Keys::jwks(), 'publication_changed', 'Signing keys changed during publication validation; retry.');
        Keys::published($context, array_column($snapshotKeys['keys'], 'kid'));
        return $context;
    }
}
