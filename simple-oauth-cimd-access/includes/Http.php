<?php
namespace OCIMD;
/** HTTPS only, no redirects, validated DNS pinned into cURL, strict size/time limits. */
class Http {
    public static function url(string $url): array {
        Support::need(strlen($url) <= 16384 && !preg_match('/[\x00-\x20\x7f\\\\]/', $url), 'url', 'Invalid URL characters or length.');
        $p = parse_url($url);
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
        $body = ''; $headers = []; $headerBytes = 0;
        $requestHeaders = ['Accept: application/json', 'Accept-Encoding: identity'];
        if ($bearer !== null) {
            Support::need(strlen($bearer) <= 16384 && (bool)preg_match('/^[A-Za-z0-9._~+\\/-]+=*$/D', $bearer), 'access_token', 'Invalid bearer token encoding.');
            $requestHeaders[] = 'Authorization: Bearer ' . $bearer;
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_FOLLOWLOCATION=>false, CURLOPT_MAXREDIRS=>0, CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_SSL_VERIFYHOST=>2, CURLOPT_CONNECTTIMEOUT=>5, CURLOPT_TIMEOUT=>12,
            CURLOPT_PROXY=>'', CURLOPT_RESOLVE=>["$host:$port:$ip"], CURLOPT_USERAGENT=>'OAuth-CIMD-Auth/1.0',
            CURLOPT_HTTPHEADER=>$requestHeaders,
            CURLOPT_WRITEFUNCTION=>static function ($ch, $data) use (&$body) {
                if (strlen($body) + strlen($data) > 262144) { return 0; } $body .= $data; return strlen($data);
            }, CURLOPT_HEADERFUNCTION=>static function ($ch, $line) use (&$headers, &$headerBytes) {
                $headerBytes += strlen($line); if ($headerBytes > 32768) { return 0; }
                if (str_contains($line, ':')) { [$k,$v] = explode(':', $line, 2); $headers[strtolower(trim($k))] = trim($v); }
                return strlen($line);
            }]);
        if ($form !== null) { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($form, '', '&', PHP_QUERY_RFC3986)); }
        $ok = curl_exec($ch); $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE); curl_close($ch);
        Support::need($ok !== false, 'http_transport', 'HTTPS request failed (TLS, DNS, timeout or response limit).');
        Support::need($status === 200, 'http_status', 'HTTPS endpoint must return 200 without redirection (received ' . (int)$status . ').');
        Support::need((bool) preg_match('~^application/(?:json|[a-z0-9.+-]+\+json)(?:\s*;|$)~i', $headers['content-type'] ?? ''), 'content_type', 'Endpoint must return an application/json document.');
        return ['json'=>Support::object($body), 'headers'=>$headers];
    }
    public static function ttl(array $headers, int $cap): int {
        $cc = strtolower($headers['cache-control'] ?? '');
        if (str_contains($cc, 'no-store') || str_contains($cc, 'no-cache')) { return 0; }
        $ttl = preg_match('/(?:^|,)\s*max-age=(\d+)/', $cc, $m) ? min($cap, (int)$m[1]) : $cap;
        return max(0, $ttl - (int)($headers['age'] ?? 0));
    }
}
