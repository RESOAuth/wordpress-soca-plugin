<?php
namespace OCIMD;
final class Settings {
    public static function defaults(): array {
        $host = (string) wp_parse_url(home_url('/'), PHP_URL_HOST); $domain = preg_replace('/^www\./i', '', $host);
        try { $suggested = [Policy::domain($domain)]; } catch (Failure $e) { $suggested = []; }
        $ready = !Support::localHost($host) && wp_parse_url(home_url('/'), PHP_URL_SCHEME) === 'https' && (bool)$suggested;
        return ['enabled'=>$ready, 'automatic'=>false, 'provider'=>'RESOAuth', 'issuer'=>'https://auth.resoauth.cloud',
            'button'=>'Continue with SSO', 'scopes'=>'openid email profile', 'mode'=>Support::localHost($host)?'proxy':'self', 'key_mode'=>Support::localHost($host)?'inline':'uri', 'jwks_url'=>'',
            'proxy'=>'https://dynamic-cimd.resoauth.cloud/cimd/%s', 'id_alg'=>'ES256', 'assertion_audience'=>'issuer',
            'cache_hours'=>24, 'create_users'=>false,
            'unrestricted'=>false, 'allow_domains'=>$suggested, 'allow_emails'=>[], 'deny_domains'=>[], 'deny_emails'=>[], 'revision'=>Support::random()];
    }
    public static function get(): array {
        $s = get_option('ocimd_settings');
        if (!is_array($s)) { $s = self::defaults(); add_option('ocimd_settings', $s, '', false); }
        if (array_key_exists('trust_email', $s) || array_key_exists('cimd_confirmed', $s) || array_key_exists('inline_ack', $s)) {
            // Previously unrestricted applied only when both allowlists were empty. Preserve that effective policy on upgrade.
            if ($s['allow_domains'] || $s['allow_emails']) { $s['unrestricted'] = false; }
            unset($s['trust_email'], $s['cimd_confirmed'], $s['inline_ack']);
            $s['revision'] = Support::random();
            update_option('ocimd_settings', $s, false);
            delete_option('ocimd_checked');
        }
        if (!isset($s['assertion_audience'])) {
            // Existing providers keep their previous assertion audience until an administrator changes it.
            $s['assertion_audience'] = 'token_endpoint';
            $s['revision'] = Support::random();
            update_option('ocimd_settings', $s, false);
            delete_option('ocimd_checked');
        }
        return $s;
    }
    public static function disabled(): bool {
        return (defined('SOCA_DISABLED') && SOCA_DISABLED) || (defined('OAUTH_CIMD_AUTH_DISABLED') && OAUTH_CIMD_AUTH_DISABLED);
    }
    public static function save(array $input): array {
        $s = self::get();
        foreach (['enabled','automatic','create_users','unrestricted'] as $key) { $s[$key] = !empty($input[$key]); }
        foreach (['provider','issuer','button','scopes','mode','key_mode','jwks_url','proxy','id_alg','assertion_audience'] as $key) { $s[$key] = trim(Support::scalar($input, $key)); }
        foreach (['provider','button'] as $key) { Support::need(strlen($s[$key]) > 0 && strlen($s[$key]) <= 120 && wp_strip_all_tags($s[$key]) === $s[$key], 'settings', 'Provider name and button label must be plain text, 1–120 bytes.'); }
        Http::url($s['issuer']);
        $p = wp_parse_url($s['issuer']); Support::need(!isset($p['query']), 'issuer', 'Issuer must not have a query. Preserve the provider’s exact issuer, including any trailing slash.');
        Support::need(in_array($s['mode'], ['self','proxy'], true) && in_array($s['key_mode'], ['uri','inline'], true), 'settings', 'Invalid metadata/key mode.');
        Support::need(in_array($s['id_alg'], ['ES256','RS256'], true), 'algorithm', 'Select ES256 or RS256 for ID tokens.');
        Support::need(in_array($s['assertion_audience'], ['issuer','token_endpoint'], true), 'assertion_audience', 'Select the provider issuer or token endpoint as the client assertion audience.');
        Support::need((bool) preg_match('/^[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*$/D', $s['scopes']) && strlen($s['scopes']) <= 500, 'scopes', 'Enter space-separated OAuth scopes.');
        Support::need(in_array('openid', explode(' ', $s['scopes']), true) && in_array('email', explode(' ', $s['scopes']), true), 'scopes', 'openid and email scopes are required.');
        Metadata::proxyTemplate($s['proxy']);
        if ($s['jwks_url']) { Http::url($s['jwks_url']); }
        $hours = filter_var($input['cache_hours'] ?? null, FILTER_VALIDATE_INT);
        Support::need($hours !== false && $hours >= 1 && $hours <= 168, 'cache_window', 'Provider cache window must be 1–168 hours. Longer windows may delay weekly rotation.');
        $s['cache_hours'] = $hours;
        foreach (['allow_domains','deny_domains','allow_emails','deny_emails'] as $key) {
            if ($s['unrestricted'] && str_starts_with($key, 'allow_') && !array_key_exists($key, $input)) { continue; }
            $s[$key] = Policy::entries(Support::scalar($input, $key, 32000), str_ends_with($key, 'emails'));
        }
        unset($s['trust_email'], $s['cimd_confirmed'], $s['inline_ack']);
        $s['revision'] = Support::random();
        update_option('ocimd_settings', $s, false);
        delete_option('ocimd_checked'); // A configuration change invalidates pending transactions and previous tests.
        Support::audit('settings_changed', get_current_user_id());
        return $s;
    }
}
