<?php
namespace SOCA;
use SOCA\Vendor\JWT\{JWT,JWK};
final class Provider {
    public function __construct(private Http $http) {}
    public function discover(array $s, bool $force = false): array {
        $cache = 'soca_d_' . hash('sha256', $s['issuer']); $doc = $force ? false : get_transient($cache);
        if (!is_array($doc)) {
            $r = $this->http->request(rtrim($s['issuer'], '/') . '/.well-known/openid-configuration');
            $doc = $r['json']; self::validateDiscovery($s, $doc);
            $ttl = Http::ttl($r['headers'], 3600); if ($ttl) { set_transient($cache, $doc, $ttl); }
        }
        self::validateDiscovery($s, $doc); return $doc;
    }
    public static function validateDiscovery(array $s, array $d): void {
        Support::need(($d['issuer'] ?? null) === $s['issuer'], 'issuer', 'Discovery issuer does not exactly match the configured issuer.');
        foreach (['authorization_endpoint','token_endpoint','jwks_uri'] as $key) {
            Support::need(isset($d[$key]) && is_string($d[$key]), 'discovery', 'Missing OIDC discovery endpoint: ' . $key . '.'); Http::url($d[$key]);
        }
        $query = wp_parse_url($d['authorization_endpoint'], PHP_URL_QUERY);
        if ($query) {
            parse_str($query, $queryArgs);
            Support::need(!array_intersect(array_keys($queryArgs), ['response_type','response_mode','client_id','redirect_uri','scope','state','nonce','code_challenge','code_challenge_method','prompt','max_age']), 'authorization_query', 'Authorization endpoint must not contain reserved OAuth request parameters.');
        }
        Support::need(!isset($d['authorization_response_iss_parameter_supported']) || is_bool($d['authorization_response_iss_parameter_supported']), 'discovery', 'Issuer response support must be a JSON boolean.');
        if (isset($d['userinfo_endpoint'])) { Support::need(is_string($d['userinfo_endpoint']), 'discovery', 'Invalid UserInfo endpoint.'); Http::url($d['userinfo_endpoint']); }
        foreach (['response_types_supported'=>'code', 'code_challenge_methods_supported'=>'S256', 'token_endpoint_auth_methods_supported'=>'private_key_jwt', 'token_endpoint_auth_signing_alg_values_supported'=>'ES256', 'id_token_signing_alg_values_supported'=>$s['id_alg']] as $key=>$value) {
            Support::need(is_array($d[$key] ?? null) && in_array($value, $d[$key], true), 'capability', 'Provider must advertise ' . $value . ' in ' . $key . '.');
        }
        Support::need(is_array($d['subject_types_supported'] ?? null) && count(array_intersect(['public','pairwise'], $d['subject_types_supported'])) > 0, 'oidc', 'Provider does not advertise OIDC subject types. OAuth alone cannot authenticate users.');
        Support::need(!array_key_exists('client_id_metadata_document_supported', $d) || $d['client_id_metadata_document_supported'] === true, 'cimd_support', 'Provider discovery does not advertise supported CIMD with a valid boolean value.');
        if (isset($d['response_modes_supported'])) { Support::need(is_array($d['response_modes_supported']) && in_array('query', $d['response_modes_supported'], true), 'response_mode', 'Provider must support query response mode.'); }
        if (isset($d['grant_types_supported'])) { Support::need(is_array($d['grant_types_supported']) && in_array('authorization_code', $d['grant_types_supported'], true), 'grant', 'Provider must support authorization_code.'); }
        if (isset($d['scopes_supported'])) {
            Support::need(is_array($d['scopes_supported']) && !array_diff(explode(' ', $s['scopes']), $d['scopes_supported']), 'scopes', 'One or more requested scopes are not advertised by the provider.');
        }
    }
    private function jwks(array $d, bool $refresh = false): array {
        $id = hash('sha256', $d['issuer'] . '|' . $d['jwks_uri']); $cache = 'soca_j_' . $id;
        if (!$refresh) { $hit = get_transient($cache); if (is_array($hit)) { return $hit; } }
        if ($refresh) {
            $allowed = Store::locked('refresh/' . $id, static function () use ($id) {
                if (get_transient('soca_r_' . $id)) { return false; }
                set_transient('soca_r_' . $id, 1, 60); return true;
            });
            Support::need($allowed, 'jwks_refresh', 'Provider key refresh is temporarily rate limited; retry in a minute.');
        }
        $r = $this->http->request($d['jwks_uri']); $doc = $r['json'];
        Metadata::noPrivateKeys($doc);
        Support::need(isset($doc['keys']) && is_array($doc['keys']) && count($doc['keys']) > 0 && count($doc['keys']) <= 50, 'provider_jwks', 'Provider JWKS must contain 1–50 public keys.');
        $ttl = Http::ttl($r['headers'], 3600); if ($ttl) { set_transient($cache, $doc, $ttl); } else { delete_transient($cache); }
        return $doc;
    }
    private static function verificationKey(array $jwks, array $header, string $alg) {
        $matches = [];
        foreach ($jwks['keys'] as $key) {
            if (!is_array($key) || ($key['kid'] ?? null) !== $header['kid']) { continue; }
            Support::need(!isset($key['alg']) || $key['alg'] === $alg, 'key_algorithm', 'Provider key algorithm mismatch.');
            Support::need(!isset($key['use']) || $key['use'] === 'sig', 'key_use', 'Provider key is not a signing key.');
            Support::need(!isset($key['key_ops']) || (is_array($key['key_ops']) && in_array('verify', $key['key_ops'], true)), 'key_use', 'Provider key cannot verify signatures.');
            Support::need(($key['kty'] ?? '') === ($alg === 'ES256' ? 'EC' : 'RSA'), 'key_type', 'Provider key type mismatch.');
            if ($alg === 'ES256') { Support::need(($key['crv'] ?? '') === 'P-256', 'curve', 'Provider key must use P-256.'); }
            $matches[] = JWK::parseKey($key, $alg);
        }
        Support::need(count($matches) === 1, 'key_missing', 'ID token must identify exactly one provider signing key.');
        return $matches[0];
    }
    public function verify(string $jwt, array $tx, string $access = '', string $code = ''): array {
        Support::need(strlen($jwt) <= 32768 && count(explode('.', $jwt)) === 3, 'jwt', 'Malformed ID token.');
        [$h,$p] = explode('.', $jwt); $header = Support::object(Support::unb64($h)); $claims = Support::object(Support::unb64($p));
        $alg = $tx['settings']['id_alg'];
        Support::need(($header['alg'] ?? '') === $alg && is_string($header['kid'] ?? null) && strlen($header['kid']) >= 1 && strlen($header['kid']) <= 200, 'jwt_algorithm', 'Unexpected signing algorithm or missing key identifier.');
        foreach (['crit','jku','jwk','x5u','b64'] as $field) { Support::need(!array_key_exists($field, $header), 'jwt_header', 'Unsupported or untrusted JOSE header.'); }
        Support::need(!isset($header['typ']) || strcasecmp($header['typ'], 'JWT') === 0, 'jwt_type', 'Unexpected token type.');
        // Validate numeric types before a library compares them (no coercion of numeric strings).
        foreach (['exp','iat'] as $field) { Support::need(isset($claims[$field]) && is_int($claims[$field]), 'jwt_time', 'ID token requires integer exp and iat.'); }
        foreach (['nbf','auth_time'] as $field) { Support::need(!isset($claims[$field]) || is_int($claims[$field]), 'jwt_time', 'Invalid time claim type.'); }
        $jwks = $this->jwks($tx['discovery']); $verified = false;
        for ($attempt = 0; $attempt < 2; $attempt++) {
            try {
                $key = self::verificationKey($jwks, $header, $alg);
                $oldLeeway = JWT::$leeway; $oldTimestamp = JWT::$timestamp;
                try { JWT::$leeway = 60; JWT::$timestamp = null; JWT::decode($jwt, $key); }
                finally { JWT::$leeway = $oldLeeway; JWT::$timestamp = $oldTimestamp; }
                $verified = true; break;
            } catch (\SOCA\Vendor\JWT\SignatureInvalidException $e) {
                if ($attempt) { throw new Failure('signature', 'Invalid ID token signature.'); }
            } catch (Failure $e) { if ($e->reason !== 'key_missing' || $attempt) { throw $e; } }
            catch (\Throwable $e) { throw new Failure('jwt', 'ID token cryptographic or time validation failed.'); }
            $jwks = $this->jwks($tx['discovery'], true);
        }
        Support::need($verified, 'signature', 'ID token signature could not be verified.');
        self::claims($claims, $tx, $access, $code);
        return $claims;
    }
    public static function claims(array $c, array $tx, string $access = '', string $code = ''): void {
        $now = time(); $client = $tx['client'];
        Support::need(($c['iss'] ?? null) === $tx['settings']['issuer'], 'issuer', 'ID token issuer mismatch.');
        Support::need(is_string($c['sub'] ?? null) && strlen($c['sub']) >= 1 && strlen($c['sub']) <= 255 && !preg_match('/[^\x20-\x7e]/', $c['sub']), 'subject', 'Invalid OIDC subject.');
        $aud = $c['aud'] ?? null; $aud = is_string($aud) ? [$aud] : $aud;
        Support::need(is_array($aud) && array_is_list($aud) && count($aud) > 0 && count(array_filter($aud, 'is_string')) === count($aud) && in_array($client, $aud, true), 'audience', 'ID token audience mismatch.');
        Support::need((count($aud) === 1 || isset($c['azp'])) && (!isset($c['azp']) || $c['azp'] === $client), 'azp', 'ID token authorized party mismatch or missing.');
        Support::need(is_string($c['nonce'] ?? null) && hash_equals($tx['nonce'], $c['nonce']), 'nonce', 'ID token nonce mismatch.');
        Support::need(is_int($c['exp'] ?? null) && is_int($c['iat'] ?? null) && $c['exp'] > $now - 60 && $c['iat'] <= $now + 60 && $c['iat'] >= $tx['started'] - 60 && $c['exp'] > $c['iat'] && $c['exp'] - $c['iat'] <= 86400, 'jwt_time', 'ID token is expired, too old, future dated, or has an excessive lifetime.');
        if (isset($c['nbf'])) { Support::need(is_int($c['nbf']) && $c['nbf'] <= $now + 60 && $c['nbf'] < $c['exp'], 'jwt_time', 'ID token is not yet valid.'); }
        if (isset($c['auth_time'])) { Support::need(is_int($c['auth_time']) && $c['auth_time'] > 0 && $c['auth_time'] <= min($now, $c['iat']) + 60, 'auth_time', 'Invalid authentication time.'); }
        if ($tx['reauth']) { Support::need(isset($c['auth_time']) && $c['auth_time'] >= $tx['started'] - 60, 'reauth', 'Provider did not confirm fresh authentication (max_age=0).'); }
        if (isset($c['acr'])) { Support::need(is_string($c['acr']), 'acr', 'Invalid authentication context.'); }
        if (isset($c['amr'])) { Support::need(is_array($c['amr']) && array_is_list($c['amr']) && count(array_filter($c['amr'], 'is_string')) === count($c['amr']), 'amr', 'Invalid authentication methods.'); }
        foreach (['at_hash'=>$access,'c_hash'=>$code] as $field=>$value) {
            if (isset($c[$field])) { Support::need($value !== '' && is_string($c[$field]) && hash_equals(Support::b64(substr(hash('sha256', $value, true), 0, 16)), $c[$field]), 'token_hash', 'Token/code hash mismatch.'); }
        }
    }
    public function exchange(array $tx, string $code): array {
        $d = $tx['discovery'];
        try {
            $r = $this->http->request($d['token_endpoint'], ['grant_type'=>'authorization_code','code'=>$code,'redirect_uri'=>$tx['callback'],
                'client_id'=>$tx['client'],'code_verifier'=>$tx['verifier'],'client_assertion_type'=>'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion'=>Keys::assertion($tx['kid'], $tx['client'], $tx['settings']['assertion_audience'] === 'issuer' ? $tx['settings']['issuer'] : $d['token_endpoint'])]);
        } catch (Failure $e) {
            if ($e->reason === 'http_status') { throw new Failure('token_http_status', $e->getMessage(), $e->diagnostics); } // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Preserve a redacted exception; output is escaped at render time.
            throw $e;
        }
        Support::need(!isset($r['json']['error']) && is_string($r['json']['id_token'] ?? null), 'oidc', 'Token endpoint did not return an OIDC ID token.');
        $access = is_string($r['json']['access_token'] ?? null) ? $r['json']['access_token'] : '';
        $claims = $this->verify($r['json']['id_token'], $tx, $access, $code);
        if (!isset($claims['email']) || !isset($claims['email_verified'])) {
            Support::need(isset($d['userinfo_endpoint']) && $access !== '' && is_string($r['json']['token_type'] ?? null) && strcasecmp($r['json']['token_type'], 'Bearer') === 0, 'email_claims', 'Verified email claims must be available in the ID token or a Bearer-authenticated UserInfo response.');
            $info = $this->http->request($d['userinfo_endpoint'], null, $access)['json'];
            Support::need(($info['sub'] ?? null) === $claims['sub'], 'userinfo_subject', 'UserInfo subject does not match the verified ID token.');
            foreach (['email','email_verified'] as $field) {
                Support::need(array_key_exists($field, $info) && (!isset($claims[$field]) || $claims[$field] === $info[$field]), 'email_claims', 'ID token and UserInfo email claims conflict or are absent.');
                $claims[$field] = $info[$field];
            }
        }
        return $claims;
    }
}
