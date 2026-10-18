<?php
namespace OCIMD;
/** HTTPS only, no redirects, validated DNS pinned into WordPress' cURL transport. */
class Http {
    public static function url(string $url): array {
        Support::need(strlen($url) <= 16384 && !preg_match('/[\x00-\x20\x7f\\\\]/', $url), 'url', 'Invalid URL characters or length.');
        $p = wp_parse_url($url);
        Support::need(is_array($p) && ($p['scheme'] ?? '') === 'https' && !isset($p['user']) && !isset($p['pass']) && !isset($p['fragment']), 'https', 'A fixed HTTPS URL without userinfo or fragment is required.');
        $host = $p['host'] ?? '';
        Support::need(!isset($p['port']) || $p['port'] >= 1, 'port', 'Invalid HTTPS port.');
        Support::need((bool) preg_match('/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/D', $host) && !Support::localHost($host), 'host', 'Use a public DNS hostname; private/local names and IP URLs are not accepted.');
        Support::need(!preg_match('/%(?![a-fA-F0-9]{2})/', $url), 'url_encoding', 'Malformed URL percent encoding.');
        foreach (explode('/', rawurldecode($p['path'] ?? '/')) as $part) { Support::need($part !== '.' && $part !== '..', 'url_path', 'Dot path components are not allowed.'); }
        return $p;
    }
    public static function publicIp(string $ip): bool {
        if (str_contains($ip, ':')) {
            // Global unicast only; excludes mapped, loopback, ULA, link local and multicast.
            $bin = @inet_pton($ip);
            return $bin !== false && strlen($bin) === 16 && (ord($bin[0]) & 0xe0) === 0x20 &&
                !(ord($bin[0]) === 0x20 && ord($bin[1]) === 0x01 && ord($bin[2]) === 0x0d && ord($bin[3]) === 0xb8) && !str_starts_with(strtolower($ip), '2002:') &&
                !(ord($bin[0]) === 0x20 && ord($bin[1]) === 0x01 && ord($bin[2]) < 2) &&
                !(ord($bin[0]) === 0x3f && ord($bin[1]) === 0xff && (ord($bin[2]) & 0xf0) === 0);
        }
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) &&
            !preg_match('/^(?:100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|192\.0\.[02]\.|198\.(?:18|19)\.|192\.88\.99\.|198\.51\.100\.|203\.0\.113\.|(?:22[4-9]|23[0-9]|24[0-9]|25[0-5])\.)/', $ip);
    }
    public function request(string $url, ?array $form = null, ?string $bearer = null): array {
        $p = self::url($url); $host = strtolower($p['host']); $port = $p['port'] ?? 443;
        Support::need(extension_loaded('curl'), 'curl', 'PHP cURL is required.');
        $ips = gethostbynamel($host) ?: [];
        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) { if (isset($record['ipv6'])) { $ips[] = $record['ipv6']; } }
        $ips = array_values(array_unique($ips));
        Support::need(count($ips) > 0, 'dns', 'Public hostname did not resolve.');
        foreach ($ips as $ip) { Support::need(self::publicIp($ip), 'ssrf', 'HTTP target resolved to a nonpublic address.'); }
        $ip = $ips[0]; if (str_contains($ip, ':')) { $ip = '[' . $ip . ']'; }
        $headers = ['Accept'=>'application/json', 'Accept-Encoding'=>'identity'];
        if ($bearer !== null) {
            Support::need(strlen($bearer) <= 16384 && (bool)preg_match('/^[A-Za-z0-9._~+\/-]+=*$/D', $bearer), 'access_token', 'Invalid bearer token encoding.');
            $headers['Authorization'] = 'Bearer ' . $bearer;
        }
        $args = ['method'=>$form === null ? 'GET' : 'POST', 'headers'=>$headers,
            'timeout'=>12, 'redirection'=>0, 'sslverify'=>true, 'blocking'=>true,
            'decompress'=>false, 'limit_response_size'=>262145, 'user-agent'=>'SOCA/0.1.0'];
        if ($form !== null) {
            $args['headers']['Content-Type'] = 'application/x-www-form-urlencoded';
            $args['body'] = http_build_query($form, '', '&', PHP_QUERY_RFC3986);
        }
        // WordPress handles the request. Pin its cURL connection to the checked address
        // while cURL verifies the original HTTPS hostname and certificate.
        $pinned = false;
        $pin = static function ($handle, $requestArgs, $requestUrl) use ($url, $host, $port, $ip, &$pinned): void {
            if ($requestUrl !== $url) { return; }
            Support::need(curl_setopt_array($handle, [CURLOPT_RESOLVE=>["$host:$port:$ip"], CURLOPT_PROXY=>'', // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt_array -- WordPress documents this hook for cURL options.
                CURLOPT_CONNECTTIMEOUT=>5, CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS, CURLOPT_FOLLOWLOCATION=>false]),
                'http_transport', 'Could not pin the HTTPS connection to its checked address.');
            $pinned = true;
        };
        add_action('http_api_curl', $pin, PHP_INT_MAX, 3);
        try { $response = wp_remote_request($url, $args); }
        finally { remove_action('http_api_curl', $pin, PHP_INT_MAX); }
        Support::need($pinned, 'http_transport', 'WordPress did not use its cURL transport; the public address could not be pinned.');
        if (is_wp_error($response)) { throw new Failure('http_transport', 'HTTPS request failed (TLS, DNS, timeout or response limit).'); }
        $status = wp_remote_retrieve_response_code($response);
        if ($status !== 200) { throw new Failure('http_status', 'HTTPS endpoint must return 200 without redirection (received ' . (int)$status . ').', ['http_status'=>(int)$status]); }
        $body = wp_remote_retrieve_body($response);
        Support::need(is_string($body) && strlen($body) <= 262144, 'json_size', 'JSON document is too large.');
        $responseHeaders = []; $headerBytes = 0;
        foreach (wp_remote_retrieve_headers($response) as $key=>$value) {
            $value = is_array($value) ? implode(', ', $value) : (string)$value;
            $headerBytes += strlen((string)$key) + strlen($value) + 4;
            $responseHeaders[strtolower((string)$key)] = $value;
        }
        Support::need($headerBytes <= 32768, 'http_headers', 'HTTPS response headers are too large.');
        Support::need((bool) preg_match('~^application/(?:json|[a-z0-9.+-]+\+json)(?:\s*;|$)~i', $responseHeaders['content-type'] ?? ''), 'content_type', 'Endpoint must return an application/json document.');
        return ['json'=>Support::object($body), 'headers'=>$responseHeaders];
    }
    public static function ttl(array $headers, int $cap): int {
        $cc = strtolower($headers['cache-control'] ?? '');
        if (str_contains($cc, 'no-store') || str_contains($cc, 'no-cache')) { return 0; }
        $ttl = preg_match('/(?:^|,)\s*max-age=(\d+)/', $cc, $m) ? min($cap, (int)$m[1]) : $cap;
        return max(0, $ttl - (int)($headers['age'] ?? 0));
    }
}
