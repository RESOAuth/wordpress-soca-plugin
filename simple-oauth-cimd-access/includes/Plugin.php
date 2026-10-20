<?php
namespace SOCA;
final class Plugin {
    public static function boot(): void {
        add_action('init', [self::class,'initialize'], 0);
        add_action('init', [self::class,'documents'], 1);
        foreach (['soca_start'=>'start','soca_callback'=>'callback'] as $action=>$method) {
            add_action('admin_post_' . $action, [self::class,$method]);
            add_action('admin_post_nopriv_' . $action, [self::class,$method]);
        }
        // The button helper escapes its URL and label before returning HTML.
        // nosemgrep: php-request-to-output -- button() escapes its URL and label; scanned independently by Psalm and WordPressCS.
        add_action('login_form', static function () { echo self::button(Support::scalar(wp_unslash($_GET), 'redirect_to')); }); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped,WordPress.Security.NonceVerification.Recommended -- Public login button; no state change. button() escapes its markup.
        add_action('login_init', [self::class,'automatic']);
        add_filter('login_message', static function ($message) {
            if (isset($_GET['soca_error'])) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only login error display; the reference is validated and escaped.
                $errorRef = sanitize_text_field(wp_unslash($_GET['soca_error'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only login error display; the reference is validated and escaped.
                $ref = preg_match('/^[a-f0-9]{12}$/D', $errorRef) ? $errorRef : '';
                $message .= '<p class="message">SOCA login did not complete. You can retry or use your local account. An administrator can review the redacted audit events.' . ($ref ? ' Reference: <code>' . esc_html($ref) . '</code>.' : '') . '</p>';
            }
            return $message;
        });
        add_filter('logout_redirect', static fn($url)=>self::recoveryUrl(), 99);
        add_action('soca_maintenance', [self::class,'maintenance']);
        Admin::boot();
        if (defined('WP_CLI') && WP_CLI) {
            $cli = static function ($args) {
                $command = $args[0] ?? 'status';
                try {
                    if ($command === 'disable') { Settings::save(['enabled'=>false,'automatic'=>false]); Settings::invalidate(); \WP_CLI::success('Pending transactions invalidated. SOCA_DISABLED=true overrides deployment-locked enablement.'); }
                    elseif ($command === 'configure') {
                        Support::need(isset($args[1]) && is_file($args[1]), 'configuration', 'Usage: wp soca configure /path/to/settings.json');
                        $json = file_get_contents($args[1]);
                        Support::need(is_string($json), 'configuration', 'Cannot read settings JSON.');
                        $input = Support::object($json);
                        Support::need(!array_diff(array_keys($input), array_keys(Settings::defaults())), 'configuration', 'Unknown configuration setting.');
                        Settings::save($input); \WP_CLI::success('Settings validated and saved. Deployment locks still apply.');
                    }
                    elseif ($command === 'config') { \WP_CLI::log(Support::json(['effective'=>Settings::get(),'locked'=>array_keys(Settings::deployment()),'emergency_disabled'=>Settings::disabled()])); }
                    elseif ($command === 'test-url') {
                        Support::need(current_user_can('manage_options'), 'authorization', 'Use --user=<administrator> to authorise a test login.');
                        $ticket = Support::random(); $s = Settings::get();
                        set_transient('soca_test_ticket_' . hash('sha256',$ticket), ['operator'=>get_current_user_id(),'revision'=>$s['revision']],600);
                        \WP_CLI::log(Support::query(admin_url('admin-post.php'), ['action'=>'soca_start','purpose'=>'test','ticket'=>$ticket]));
                    }
                    elseif ($command === 'link' || $command === 'unlink') {
                        Support::need(current_user_can('manage_options'), 'authorization', 'Use --user=<administrator> to approve identity association changes.');
                        Support::need(count($args) === 4 && ctype_digit($args[1]) && (int)$args[1] > 0, 'identity', 'Usage: wp soca <link|unlink> <user-id> <exact-issuer> <exact-subject>');
                        if ($command === 'link') { Identity::link((int)$args[1], $args[2], $args[3]); }
                        else { Identity::unlink((int)$args[1], $args[2], $args[3]); }
                        \WP_CLI::success('Identity association updated.');
                    }
                    elseif ($command === 'check') { \WP_CLI::log(Support::json(self::check())); }
                    elseif ($command === 'maintain') { self::maintenance(); \WP_CLI::log(Support::json(get_option('soca_maintenance_status',[]))); }
                    elseif ($command === 'status') { \WP_CLI::log(Support::json(self::status())); }
                    elseif ($command === 'jwks') { \WP_CLI::log(Support::json(Keys::jwks())); }
                    elseif ($command === 'audit') { \WP_CLI::log(Support::json(get_option('soca_audit',[]))); }
                    else { \WP_CLI::error('Usage: wp soca <status|config|configure|check|test-url|maintain|disable|link|unlink|jwks|audit>. Select a multisite site using --url.'); }
                } catch (\Throwable $e) { \WP_CLI::error($e instanceof Failure ? $e->getMessage() : 'Internal failure; inspect the runtime configuration.'); }
            };
            \WP_CLI::add_command('soca', $cli);
        }
    }
    /** Dependency injection for trusted WordPress integrations and deterministic protocol fixtures. */
    public static function http(): Http {
        return apply_filters('soca_http', new Http());
    }
    public static function initialize(): void {
        if (!wp_next_scheduled('soca_maintenance')) { wp_schedule_event(time()+60, 'hourly', 'soca_maintenance'); }
    }
    public static function activate(bool $network = false): void {
        if (!extension_loaded('openssl') || !extension_loaded('curl')) { wp_die('SOCA requires PHP OpenSSL and cURL.'); }
        // Lazy per-site initialization also covers future sites and avoids network-wide key sharing.
        self::initialize(); Settings::get(); Keys::get();
    }
    public static function deactivate(bool $network = false): void {
        if ($network && is_multisite()) {
            foreach (get_sites(['fields'=>'ids','number'=>0]) as $id) { switch_to_blog($id); wp_clear_scheduled_hook('soca_maintenance'); Settings::invalidate(); restore_current_blog(); }
        } else { wp_clear_scheduled_hook('soca_maintenance'); Settings::invalidate(); }
    }
    public static function documents(): void {
        if (!isset($_GET['soca_doc'])) { return; } // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only public client metadata and JWKS endpoint.
        $method = Support::serverString('REQUEST_METHOD');
        if (!in_array($method, ['GET','HEAD'], true)) { status_header(405); exit; }
        try {
            $kind = Support::scalar(wp_unslash($_GET),'soca_doc'); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only public client metadata and JWKS endpoint; kind is allowlisted.
            Support::need(in_array($kind,['client','jwks'],true), 'document', 'Unknown public document.');
            $doc = $kind === 'jwks' ? Keys::jwks() : Metadata::document(Settings::get(), true);
            header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: public, max-age=300, must-revalidate');
            header('X-Content-Type-Options: nosniff'); header('Access-Control-Allow-Origin: *');
            // The response is application/json with nosniff, never embedded in HTML.
            if ($method !== 'HEAD') {
                /**
                 * @psalm-taint-escape html
                 * @psalm-taint-escape has_quotes
                 */
                $json = Support::json($doc);
                echo $json; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON response, not HTML.
            }
            exit;
        } catch (\Throwable $e) { status_header(503); header('Cache-Control: no-store'); header('Content-Type: application/json'); echo '{"error":"metadata_unavailable"}'; exit; }
    }
    public static function button(string $destination = ''): string {
        try { $s = Settings::get(); if (!self::loginReady($s)) { return ''; } }
        catch (\Throwable $e) { return ''; } // Invalid deployment settings must leave local recovery usable.
        $url = Support::query(admin_url('admin-post.php'), ['action'=>'soca_start','redirect_to'=>Support::destination($destination)]);
        return '<p class="soca-login"><a class="button button-secondary" href="' . esc_url($url) . '">' . esc_html($s['button']) . '</a></p>';
    }
    public static function recoveryUrl(bool $error = false, string $ref = ''): string {
        $args = ['soca_local'=>'1'];
        if ($error) { $args['soca_error'] = preg_match('/^[a-f0-9]{12}$/D', $ref) ? $ref : '1'; }
        return add_query_arg($args, wp_login_url());
    }
    public static function automatic(): void {
        try { $s = Settings::get(); if (!self::loginReady($s)) { return; } }
        catch (\Throwable $e) { return; }
        if (!$s['automatic'] || is_user_logged_in() || Support::serverString('REQUEST_METHOD') !== 'GET') { return; }
        // A narrow allowlist preserves recovery, reset, logout, interim, reauth and plugin-specific flows.
        if (array_diff(array_keys($_GET), ['redirect_to','action']) || (isset($_GET['action']) && $_GET['action'] !== 'login')) { return; } // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public login initiation; the callback requires one-time OAuth state and PKCE.
        wp_safe_redirect(Support::query(admin_url('admin-post.php'), ['action'=>'soca_start','redirect_to'=>Support::destination(Support::scalar(wp_unslash($_GET),'redirect_to'))])); exit; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public login initiation; the callback requires one-time OAuth state and PKCE.
    }
    private static function rate(string $purpose, int $limit): void {
        $address = Support::serverString('REMOTE_ADDR');
        $ip = filter_var($address, FILTER_VALIDATE_IP);
        $key = 'soca_rate_' . hash_hmac('sha256', $purpose . ($ip !== false ? $ip : 'unknown'), wp_salt('nonce'));
        Store::locked($key, static function () use ($key,$limit) {
            $record = get_transient($key) ?: ['count'=>0,'until'=>time()+600];
            Support::need($record['count'] < $limit, 'rate_limit', 'Too many attempts; wait ten minutes.');
            $record['count']++; set_transient($key,$record,max(1,$record['until']-time()));
        });
    }
    public static function check(): array {
        $s=Settings::get(); $http=self::http(); $p=new Provider($http); $d=$p->discover($s,true);
        $context=Metadata::validate($s,$http);
        $result=['time'=>time(),'revision'=>$s['revision'],'context'=>$context,'issuer'=>$d['issuer'],'authorization_endpoint'=>$d['authorization_endpoint'],
            'token_endpoint'=>$d['token_endpoint'],'jwks_uri'=>$d['jwks_uri'],'cimd_advertised'=>($d['client_id_metadata_document_supported']??false)===true,
            'client_id'=>Metadata::clientId($s),'result'=>'Discovery and public documents validated. Complete a test login to verify interoperability.'];
        update_option('soca_checked',$result,false); return $result;
    }
    public static function maintenance(): void {
        try {
            $s=Settings::get();
            if (!$s['enabled'] || Settings::disabled()) {
                update_option('soca_maintenance_status',['time'=>time(),'ok'=>true,'code'=>'login_disabled'],false);
                return;
            }
            $context=Metadata::validate($s,self::http()); Keys::rotate($s,$context);
            update_option('soca_maintenance_status',['time'=>time(),'ok'=>true,'code'=>'publication_checked'],false);
        } catch (\Throwable $e) { update_option('soca_maintenance_status',['time'=>time(),'ok'=>false,'code'=>$e instanceof Failure?$e->reason:'internal_error'],false); Support::audit('maintenance_failed'); }
    }
    public static function status(): array {
        $s=Settings::get(); $k=Keys::get();
        return ['enabled'=>self::loginReady($s),'requested_enabled'=>$s['enabled'],'test_login_current'=>self::verified($s),'locked'=>array_keys(Settings::deployment()),'mode'=>$s['mode'],'key_mode'=>$s['key_mode'],'active_kid'=>$k['active'],
            'active_since'=>$k['since'],'public_keys'=>array_map(static fn($x)=>array_intersect_key($x,array_flip(['kid','published','retired'])), $k['items']),
            'maintenance'=>get_option('soca_maintenance_status',[]),'next_cron'=>wp_next_scheduled('soca_maintenance'),
            'inline_client_id_changes'=>$s['mode']==='proxy' && $s['key_mode']==='inline'];
    }
    public static function verified(array $s): bool {
        return (get_option('soca_verified', [])['profile'] ?? '') === Settings::profile($s);
    }
    public static function loginReady(array $s): bool { return $s['enabled'] && !Settings::disabled() && self::verified($s); }
    public static function cookieName(string $state): string { return '__Host-soca_tx_' . substr(hash('sha256', $state), 0, 32); }
    private static function browserCookie(string $state, string $value, int $expires): void {
        Support::need(setcookie(self::cookieName($state), $value, ['expires'=>$expires,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Lax']), 'browser_cookie', 'Cannot set the secure login transaction cookie.');
    }
    private static function userAgentHash(): string { return hash('sha256', Support::serverString('HTTP_USER_AGENT')); }
    public static function start(): void {
        $ref = bin2hex(random_bytes(6)); $flow = 'login'; $step = 'request';
        try {
            Support::need(Support::serverString('REQUEST_METHOD')==='GET','method','Login must start with GET.');
            $purpose=Support::scalar(wp_unslash($_GET),'purpose',20) ?: 'login';
            Support::need(in_array($purpose,['login','test'],true),'purpose','Invalid login purpose.');
            $flow = $purpose;
            if ($purpose==='test') {
                Support::need(current_user_can('manage_options'),'authorization','Administrator access required.');
                $ticket = Support::scalar(wp_unslash($_GET),'ticket',100); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- A one-use CLI test ticket is checked against the authenticated operator and revision.
                if ($ticket !== '') {
                    Support::need((bool)preg_match('/^[A-Za-z0-9_-]{43}$/D',$ticket), 'nonce', 'Invalid test ticket.');
                    Store::locked('test-ticket/' . hash('sha256',$ticket), static function () use ($ticket) {
                        $key='soca_test_ticket_' . hash('sha256',$ticket); $record=get_transient($key);
                        Support::need(is_array($record) && $record['operator']===get_current_user_id() && $record['revision']===Settings::get()['revision'] && delete_transient($key), 'nonce', 'Test ticket expired, used, or belongs to another operator or revision.');
                    });
                } else { Support::need((bool) wp_verify_nonce(Support::scalar(wp_unslash($_GET),'_wpnonce',100), 'soca_test'), 'nonce', 'Invalid test-login nonce.'); }
            }
            self::begin($purpose,$ref,$step);
        } catch (\Throwable $e) { self::fail($e,$flow,$step,$ref); }
    }
    private static function begin(string $purpose, string $ref, string &$step): void {
        $step = 'configuration';
        $s=Settings::get(); Support::need(!Settings::disabled(),'disabled','Upstream login is disabled by configuration.');
        Support::need($purpose!=='login' || self::loginReady($s),'disabled','Ordinary SSO requires enablement and a successful test login for the current candidate.'); self::rate('start',30);
        Support::need(is_ssl() && wp_parse_url(Metadata::callback(),PHP_URL_SCHEME)==='https','https','HTTPS is required for browser transactions.');
        $step = 'discovery';
        $http=self::http(); $d=(new Provider($http))->discover($s); $context=Metadata::context($s); $checked=get_option('soca_checked',[]);
        $step = 'publication';
        if (!Keys::ready($context) || ($checked['context']??'')!==$context || ($checked['time']??0)<time()-300 || ($checked['revision']??'')!==$s['revision']) {
            Metadata::validate($s,$http); update_option('soca_checked',['time'=>time(),'context'=>$context,'revision'=>$s['revision']],false);
        }
        $step = 'transaction';
        $keys=Keys::get(); $state=Support::random(); $nonce=Support::random(); $verifier=Support::random();
        $tx=['settings'=>$s,'discovery'=>$d,'client'=>Metadata::clientId($s),'callback'=>Metadata::callback(),'kid'=>$keys['active'],
            'nonce'=>$nonce,'verifier'=>$verifier,'user_agent'=>self::userAgentHash(),'started'=>time(),'purpose'=>$purpose,'reauth'=>$purpose!=='login',
            'user'=>$purpose==='login'?0:get_current_user_id(),'session'=>$purpose==='login'?'':hash('sha256',wp_get_session_token()),
            'destination'=>Support::destination(Support::scalar(wp_unslash($_GET),'redirect_to')),'audit_ref'=>$ref]; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public login destination is restricted to this site before storage and redirect.
        $browser = Support::random();
        Store::createTransaction($state,$tx,$browser);
        self::browserCookie($state,$browser,time()+600);
        Support::audit('login_started', $purpose==='test' ? get_current_user_id() : 0, ['flow'=>$purpose,'step'=>'redirect','ref'=>$ref]);
        $step = 'redirect';
        $params=['response_type'=>'code','response_mode'=>'query','client_id'=>$tx['client'],'redirect_uri'=>$tx['callback'],'scope'=>$s['scopes'],
            'state'=>$state,'nonce'=>$nonce,'code_challenge'=>Support::b64(hash('sha256',$verifier,true)),'code_challenge_method'=>'S256'];
        if ($tx['reauth']) { $params['prompt']='login'; $params['max_age']='0'; }
        nocache_headers(); header('Referrer-Policy: no-referrer');
        // Permit only this validated authorization host for this redirect.
        $authorizationHost = (string) wp_parse_url($d['authorization_endpoint'], PHP_URL_HOST);
        $allowAuthorizationHost = static function (array $hosts, string $redirectHost) use ($authorizationHost): array {
            if ($redirectHost === $authorizationHost) { $hosts[] = $authorizationHost; }
            return $hosts;
        };
        add_filter('allowed_redirect_hosts', $allowAuthorizationHost, 10, 2);
        try { $redirected = wp_safe_redirect(Support::query($d['authorization_endpoint'],$params), 302, 'SOCA'); }
        finally { remove_filter('allowed_redirect_hosts', $allowAuthorizationHost, 10); }
        Support::need($redirected, 'redirect', 'Unable to start the provider login.');
        exit;
    }
    public static function callback(): void {
        nocache_headers(); header('Referrer-Policy: no-referrer'); header('X-Content-Type-Options: nosniff');
        $ref = bin2hex(random_bytes(6)); $flow = 'login'; $step = 'request';
        try {
            Support::need(Support::serverString('REQUEST_METHOD')==='GET','method','Only query response mode is supported.');
            // PHP collapses duplicate query keys; reject them before reading the parsed request.
            $queryString = Support::serverString('QUERY_STRING');
            Support::need(strlen($queryString) <= 16384, 'callback_query', 'Callback query is too long.');
            $names=[]; foreach (explode('&',$queryString) as $pair) { $name=urldecode(explode('=',$pair,2)[0]); Support::need(!in_array($name,$names,true),'duplicate_parameter','Duplicate callback parameter.'); $names[]=$name; }
            $step = 'transaction';
            $state=Support::scalar(wp_unslash($_GET),'state',100); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- OAuth callback consumes one-time state bound to the browser transaction.
            $browser = Support::scalar(wp_unslash($_COOKIE),self::cookieName($state),100);
            $tx=Store::consumeTransaction($state,self::userAgentHash(),$browser);
            self::browserCookie($state,'',time()-3600);
            $ref = is_string($tx['audit_ref'] ?? null) && preg_match('/^[a-f0-9]{12}$/D', $tx['audit_ref']) ? $tx['audit_ref'] : $ref;
            $flow = ($tx['purpose'] ?? '') === 'test' ? 'test' : 'login';
            Support::audit('callback_received', 0, ['flow'=>$flow,'step'=>'configuration','ref'=>$ref]);
            $step = 'configuration';
            $s=Settings::get();
            Support::need(!Settings::disabled() && $s['revision']===$tx['settings']['revision'] && Metadata::callback()===$tx['callback'] && ($tx['purpose']!=='login' || self::loginReady($s)),'configuration_changed','Configuration changed during login. Start again.');
            $step = 'authorization_response';
            $iss=Support::scalar(wp_unslash($_GET),'iss'); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- OAuth callback validates the response issuer against the stored provider.
            Support::need(($iss==='' && empty($tx['discovery']['authorization_response_iss_parameter_supported'])) || $iss===$tx['settings']['issuer'],'response_issuer','Authorization response issuer mismatch or missing.');
            Support::need(!isset($_GET['error']),'provider_denied','Provider cancelled or denied the request.'); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- OAuth callback rejects provider errors after consuming one-time state.
            $code=Support::authorizationCode(Support::scalar(wp_unslash($_GET),'code')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- OAuth callback exchanges the code using PKCE and validates the signed ID token.
            if ($tx['purpose']!=='login') {
                Support::need(get_current_user_id()===$tx['user'] && hash_equals($tx['session'],hash('sha256',wp_get_session_token())),'session','The original authenticated local session is required.');
            }
            $step = 'token_exchange';
            $claims=(new Provider(self::http()))->exchange($tx,$code);
            // Refresh request-local option caches: another worker may have revoked this flow.
            $s=Settings::get(true);
            Support::need(!Settings::disabled() && $s['revision']===$tx['settings']['revision'] && Metadata::callback()===$tx['callback'], 'configuration_changed', 'Configuration changed during token exchange. Start again.');
            Support::audit('claims_verified', 0, ['flow'=>$flow,'step'=>'access_policy','ref'=>$ref]);
            if ($tx['purpose']==='test') {
                $step = 'access_policy';
                Support::need(current_user_can('manage_options'),'authorization','Administrator access required.');
                [$allowed,$reason]=Policy::test($s,is_string($claims['email']??null)?$claims['email']:'',($claims['email_verified']??false)===true);
                set_transient('soca_test_' . get_current_user_id(),['time'=>time(),'policy'=>$allowed,'message'=>$reason,'revision'=>$s['revision']],600);
                if ($allowed) { update_option('soca_verified',['time'=>time(),'profile'=>Settings::profile($s),'operator'=>get_current_user_id()],false); }
                Support::audit('test_login_verified',get_current_user_id(),['flow'=>$flow,'ref'=>$ref]);
                wp_safe_redirect(admin_url('options-general.php?page=simple-oauth-cimd-access&tested=1')); exit;
            }
            $step = 'account_resolution';
            $user=Identity::resolve($claims,$s);
            Support::audit('account_selected',$user->ID,['flow'=>$flow,'ref'=>$ref]);
            $step = 'session';
            wp_set_current_user($user->ID); wp_set_auth_cookie($user->ID,false,is_ssl()); do_action('wp_login',$user->user_login,$user);
            Support::audit('login_success',$user->ID,['flow'=>$flow,'ref'=>$ref]); wp_safe_redirect(Support::destination($tx['destination'])); exit;
        } catch (\Throwable $e) { self::fail($e,$flow,$step,$ref); }
    }
    private static function fail(\Throwable $e, string $flow, string $step, string $ref): void {
        if ($e instanceof Failure) {
            if (is_string($e->diagnostics['ref'] ?? null) && preg_match('/^[a-f0-9]{12}$/D', $e->diagnostics['ref'])) { $ref = $e->diagnostics['ref']; }
            if (in_array($e->diagnostics['flow'] ?? null, ['login','test'], true)) { $flow = $e->diagnostics['flow']; }
        }
        $context = ['flow'=>$flow,'step'=>$step,'reason'=>$e instanceof Failure ? $e->reason : 'internal_error','ref'=>$ref];
        if ($e instanceof Failure) { $context += $e->diagnostics; }
        if (!$e instanceof Failure) { $context['exception'] = get_class($e); }
        Support::audit('login_failed',0,$context);
        wp_safe_redirect(self::recoveryUrl(true,$ref)); exit;
    }
}
