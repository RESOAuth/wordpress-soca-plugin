<?php
namespace SOCA;
final class Settings {
    public static function defaults(): array {
        $host = (string) wp_parse_url(home_url('/'), PHP_URL_HOST); $domain = preg_replace('/^www\./i', '', $host);
        try { $suggested = [Policy::domain($domain)]; } catch (Failure $e) { $suggested = []; }
        return ['enabled'=>false, 'automatic'=>false, 'provider'=>'RESOAuth', 'issuer'=>'https://auth.resoauth.cloud',
            'button'=>'Continue with SSO', 'scopes'=>'openid email profile', 'mode'=>Support::localHost($host)?'proxy':'self', 'key_mode'=>Support::localHost($host)?'inline':'uri', 'jwks_url'=>'',
            'proxy'=>'https://dynamic-cimd.resoauth.cloud/cimd/%s', 'id_alg'=>'ES256', 'assertion_audience'=>'issuer',
            'client_name'=>'', 'client_uri'=>'', 'logo_uri'=>'', 'policy_uri'=>'', 'tos_uri'=>'',
            'cache_hours'=>24, 'create_users'=>false,
            'unrestricted'=>false, 'allow_domains'=>$suggested, 'allow_emails'=>[], 'deny_domains'=>[], 'deny_emails'=>[]];
    }
    public static function deployment(): array {
        $config = defined('SOCA_CONFIG') ? SOCA_CONFIG : [];
        Support::need(is_array($config) && !array_diff(array_keys($config), array_keys(self::defaults())), 'configuration', 'SOCA_CONFIG must be an array containing only documented setting names.');
        return $config;
    }
    public static function get(bool $fresh = false): array {
        if ($fresh) {
            foreach (['soca_settings','soca_epoch','soca_verified','soca_disabled_latched','notoptions'] as $key) { wp_cache_delete($key,'options'); }
        }
        $stored = get_option('soca_settings');
        if (!is_array($stored)) { $stored = self::defaults(); $stored['revision'] = Support::random(); add_option('soca_settings', $stored, '', false); }
        // Latch emergency disable so transactions cannot resume after it is removed.
        if (self::disabled() && !get_option('soca_disabled_latched')) { self::invalidate(); update_option('soca_disabled_latched', true, false); }
        if (!self::disabled()) { delete_option('soca_disabled_latched'); }
        $s = self::validate(array_replace(self::defaults(), $stored, self::deployment()));
        $s['revision'] = hash('sha256', Support::json($s) . ($stored['revision'] ?? '') . get_option('soca_epoch', '') . home_url('/') . admin_url('admin-post.php'));
        return $s;
    }
    public static function disabled(): bool { return defined('SOCA_DISABLED') && SOCA_DISABLED; }
    public static function invalidate(): void {
        update_option('soca_epoch', Support::random(), false);
        delete_option('soca_checked'); delete_option('soca_verified');
    }
    /** Candidate revision excludes only the switches used to activate a tested profile. */
    public static function profile(array $s): string {
        unset($s['enabled'], $s['automatic'], $s['revision']);
        return hash('sha256', Support::json($s) . Metadata::context($s) . Metadata::callback() . get_option('soca_epoch', ''));
    }
    public static function validate(array $input): array {
        $s = array_intersect_key($input, self::defaults());
        foreach (['enabled','automatic','create_users','unrestricted'] as $key) {
            Support::need(in_array($s[$key], [true,false,0,1,'0','1',''], true), 'settings', 'Boolean settings accept only true, false, 0 or 1.');
            $s[$key] = (bool)$s[$key];
        }
        foreach (['provider','issuer','button','scopes','mode','key_mode','jwks_url','proxy','id_alg','assertion_audience','client_name','client_uri','logo_uri','policy_uri','tos_uri'] as $key) { $s[$key] = trim(Support::scalar($s, $key)); }
        foreach (['provider','button','client_name'] as $key) { Support::need(($key === 'client_name' || strlen($s[$key]) > 0) && strlen($s[$key]) <= 120 && wp_strip_all_tags($s[$key]) === $s[$key], 'settings', 'Names and labels must be plain text, at most 120 bytes.'); }
        Http::url($s['issuer']);
        Support::need(wp_parse_url($s['issuer'], PHP_URL_QUERY) === null, 'issuer', 'Issuer must not have a query. Preserve the exact issuer, including any trailing slash.');
        Support::need(in_array($s['mode'], ['self','proxy'], true) && in_array($s['key_mode'], ['uri','inline'], true), 'settings', 'Invalid metadata/key mode.');
        Support::need(in_array($s['id_alg'], ['ES256','RS256'], true), 'algorithm', 'Select ES256 or RS256 for ID tokens.');
        Support::need(in_array($s['assertion_audience'], ['issuer','token_endpoint'], true), 'assertion_audience', 'Select the provider issuer or token endpoint as the client assertion audience.');
        Support::need((bool) preg_match('/^[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*$/D', $s['scopes']) && strlen($s['scopes']) <= 500, 'scopes', 'Enter space-separated OAuth scopes.');
        Support::need(in_array('openid', explode(' ', $s['scopes']), true) && in_array('email', explode(' ', $s['scopes']), true), 'scopes', 'openid and email scopes are required.');
        Metadata::proxyTemplate($s['proxy']);
        foreach (['jwks_url','client_uri','logo_uri','policy_uri','tos_uri'] as $key) { if ($s[$key] !== '') { Http::url($s[$key]); } }
        $hours = filter_var($s['cache_hours'], FILTER_VALIDATE_INT);
        Support::need($hours !== false && $hours >= 1 && $hours <= 168, 'cache_window', 'Provider cache window must be 1–168 hours.');
        $s['cache_hours'] = $hours;
        foreach (['allow_domains','deny_domains','allow_emails','deny_emails'] as $key) {
            if (is_array($s[$key])) {
                Support::need(array_is_list($s[$key]) && count(array_filter($s[$key], 'is_string')) === count($s[$key]), 'policy', 'Policy lists must contain strings.');
                $s[$key] = implode("\n", $s[$key]);
            }
            $s[$key] = Policy::entries(Support::scalar($s, $key, 32000), str_ends_with($key, 'emails'));
        }
        return $s;
    }
    /** Partial writes are shared by WP-CLI and the form. Locked values are never persisted. */
    public static function save(array $input): array {
        return Store::locked('settings/' . get_current_blog_id(), static function () use ($input) {
            $current = self::get(true);
            if (isset($input['revision'])) { Support::need($input['revision'] === $current['revision'], 'stale_settings', 'Settings changed. Reload before saving.'); }
            $s = array_replace(self::defaults(), (array)get_option('soca_settings'), array_intersect_key($input, self::defaults()));
            foreach (self::deployment() as $key=>$value) { $s[$key] = $current[$key]; }
            $s = self::validate($s);
            $stored = (array)get_option('soca_settings');
            foreach (self::deployment() as $key=>$value) {
                if (array_key_exists($key,$stored)) { $s[$key] = $stored[$key]; } else { unset($s[$key]); }
            }
            $previous = array_replace(self::defaults(),$stored); unset($previous['revision']);
            if ($s === $previous) { return $current; }
            $s['revision'] = Support::random();
            update_option('soca_settings', $s, false);
            delete_option('soca_checked');
            Support::audit('settings_changed', get_current_user_id());
            return self::get();
        });
    }
}
