<?php
namespace OCIMD;
final class Plugin {
    public static function boot(): void {
        add_action('init', [self::class,'initialize'], 0);
        add_action('init', [self::class,'documents'], 1);
        foreach (['soca_start'=>'start','soca_callback'=>'callback'] as $action=>$method) {
            add_action('admin_post_' . $action, [self::class,$method]);
            add_action('admin_post_nopriv_' . $action, [self::class,$method]);
        }
        add_action('login_form', static function () { echo self::button(Support::scalar($_GET, 'redirect_to')); });
        add_action('login_init', [self::class,'automatic']);
        add_filter('login_message', static function ($message) {
            if (isset($_GET['soca_error']) || isset($_GET['oauth_cimd_error'])) {
                $ref = is_string($_GET['soca_error'] ?? null) && preg_match('/^[a-f0-9]{12}$/D', $_GET['soca_error']) ? $_GET['soca_error'] : '';
                $message .= '<p class="message">SOCA login did not complete. You can retry or use your local account. An administrator can review the redacted audit events.' . ($ref ? ' Reference: <code>' . esc_html($ref) . '</code>.' : '') . '</p>';
            }
            return $message;
        });
        add_filter('logout_redirect', static fn($url)=>self::recoveryUrl(), 99);
        add_action('soca_maintenance', [self::class,'maintenance']);
        add_action('ocimd_maintenance', [self::class,'maintenance']); // Existing scheduled events.
        Admin::boot();
        if (defined('WP_CLI') && WP_CLI) {
            $cli = static function ($args) {
                $command = $args[0] ?? 'status';
                try {
                    if ($command === 'disable') { $s=Settings::get(); $s['enabled']=false; $s['automatic']=false; $s['revision']=Support::random(); update_option('ocimd_settings',$s,false); \WP_CLI::success('SOCA login disabled.'); }
                    elseif ($command === 'check') { \WP_CLI::log(Support::json(self::check())); }
                    elseif ($command === 'maintain') { self::maintenance(); \WP_CLI::log(Support::json(get_option('ocimd_maintenance_status',[]))); }
                    elseif ($command === 'status') { \WP_CLI::log(Support::json(self::status())); }
                    elseif ($command === 'jwks') { \WP_CLI::log(Support::json(Keys::jwks())); }
                    elseif ($command === 'audit') { \WP_CLI::log(Support::json(get_option('ocimd_audit',[]))); }
                    else { \WP_CLI::error('Usage: wp soca <status|check|maintain|disable|jwks|audit>. Select a multisite site using --url.'); }
                } catch (\Throwable $e) { \WP_CLI::error($e instanceof Failure ? $e->getMessage() : 'Internal failure; inspect the runtime configuration.'); }
            };
            \WP_CLI::add_command('soca', $cli);
            \WP_CLI::add_command('oauth-cimd', $cli); // Preserve existing maintenance jobs.
        }
    }
    /** Dependency injection for trusted WordPress integrations and deterministic protocol fixtures. */
    public static function http(): Http {
        $http = apply_filters('oauth_cimd_auth_http', new Http());
        return apply_filters('soca_http', $http);
    }
    public static function initialize(): void {
        if (!get_option('ocimd_schema')) { Store::install(); }
        if (wp_next_scheduled('ocimd_maintenance')) { wp_clear_scheduled_hook('ocimd_maintenance'); }
        if (!wp_next_scheduled('soca_maintenance')) { wp_schedule_event(time()+60, 'hourly', 'soca_maintenance'); }
    }
    public static function activate(bool $network = false): void {
        if (!extension_loaded('openssl') || !extension_loaded('curl')) { wp_die('SOCA requires PHP OpenSSL and cURL.'); }
        // Lazy per-site initialization also covers future sites and avoids network-wide key sharing.
        self::initialize(); Settings::get(); Keys::get();
    }
    public static function deactivate(bool $network = false): void {
        if ($network && is_multisite()) {
            foreach (get_sites(['fields'=>'ids','number'=>0]) as $id) { switch_to_blog($id); wp_clear_scheduled_hook('soca_maintenance'); wp_clear_scheduled_hook('ocimd_maintenance'); restore_current_blog(); }
        } else { wp_clear_scheduled_hook('soca_maintenance'); wp_clear_scheduled_hook('ocimd_maintenance'); }
    }
    public static function documents(): void {
        if (!isset($_GET['soca_doc'])) { return; }
        if (!in_array($_SERVER['REQUEST_METHOD'], ['GET','HEAD'], true)) { status_header(405); exit; }
        try {
            $kind = Support::scalar($_GET,'soca_doc');
            Support::need(in_array($kind,['client','jwks'],true), 'document', 'Unknown public document.');
            $doc = $kind === 'jwks' ? Keys::jwks() : Metadata::document(Settings::get(), true);
            header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: public, max-age=300, must-revalidate');
            header('X-Content-Type-Options: nosniff'); header('Access-Control-Allow-Origin: *');
            if ($_SERVER['REQUEST_METHOD'] !== 'HEAD') { echo Support::json($doc); } exit;
        } catch (\Throwable $e) { status_header(503); header('Cache-Control: no-store'); header('Content-Type: application/json'); echo '{"error":"metadata_unavailable"}'; exit; }
    }
    public static function button(string $destination = ''): string {
        $s = Settings::get(); if (!$s['enabled'] || Settings::disabled()) { return ''; }
        $url = Support::query(admin_url('admin-post.php'), ['action'=>'soca_start','redirect_to'=>Support::destination($destination)]);
        return '<p class="soca-login"><a class="button button-secondary" href="' . esc_url($url) . '">' . esc_html($s['button']) . '</a></p>';
    }
    public static function recoveryUrl(bool $error = false, string $ref = ''): string {
        $args = ['soca_local'=>'1'];
        if ($error) { $args['soca_error'] = preg_match('/^[a-f0-9]{12}$/D', $ref) ? $ref : '1'; }
        return add_query_arg($args, wp_login_url());
    }
    public static function automatic(): void {
        $s = Settings::get();
        if (!$s['enabled'] || !$s['automatic'] || Settings::disabled() || is_user_logged_in() || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') { return; }
        // A narrow allowlist preserves recovery, reset, logout, interim, reauth and plugin-specific flows.
        if (array_diff(array_keys($_GET), ['redirect_to','action']) || (isset($_GET['action']) && $_GET['action'] !== 'login')) { return; }
        wp_safe_redirect(Support::query(admin_url('admin-post.php'), ['action'=>'soca_start','redirect_to'=>Support::destination(Support::scalar($_GET,'redirect_to'))])); exit;
    }
    private static function rate(string $purpose, int $limit): void {
        $key = 'ocimd_rate_' . hash_hmac('sha256', $purpose . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), wp_salt('nonce'));
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
        update_option('ocimd_checked',$result,false); return $result;
    }
    public static function maintenance(): void {
        try {
            Store::clean(); $s=Settings::get(); $context=Metadata::validate($s,self::http()); Keys::rotate($s,$context);
            update_option('ocimd_maintenance_status',['time'=>time(),'ok'=>true,'code'=>'publication_checked'],false);
        } catch (\Throwable $e) { update_option('ocimd_maintenance_status',['time'=>time(),'ok'=>false,'code'=>$e instanceof Failure?$e->reason:'internal_error'],false); Support::audit('maintenance_failed'); }
    }
    public static function status(): array {
        $s=Settings::get(); $k=Keys::get();
        return ['enabled'=>$s['enabled'] && !Settings::disabled(),'mode'=>$s['mode'],'key_mode'=>$s['key_mode'],'active_kid'=>$k['active'],
            'active_since'=>$k['since'],'public_keys'=>array_map(static fn($x)=>array_intersect_key($x,array_flip(['kid','published','retired'])), $k['items']),
            'maintenance'=>get_option('ocimd_maintenance_status',[]),'next_cron'=>wp_next_scheduled('soca_maintenance'),
            'inline_client_id_changes'=>$s['mode']==='proxy' && $s['key_mode']==='inline'];
    }
    private static function cookieName(string $state): string { return '__Host-ocimd_' . get_current_blog_id() . '_' . substr(hash('sha256',$state),0,16); }
    private static function cookie(string $state, string $value): void {
        setcookie(self::cookieName($state),$value,['expires'=>$value?time()+600:time()-3600,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Lax']);
    }
    public static function start(): void {
        $ref = bin2hex(random_bytes(6)); $flow = 'login'; $step = 'request';
        try {
            Support::need(($_SERVER['REQUEST_METHOD']??'')==='GET','method','Login must start with GET.');
            $purpose=Support::scalar($_GET,'purpose',20) ?: 'login';
            Support::need(in_array($purpose,['login','test'],true),'purpose','Invalid login purpose.');
            $flow = $purpose;
            if ($purpose==='test') {
                Support::need(current_user_can('manage_options'),'authorization','Administrator access required.');
                Support::need((bool) wp_verify_nonce(Support::scalar($_GET,'_wpnonce',100), 'ocimd_test'), 'nonce', 'Invalid test-login nonce.');
            }
            self::begin($purpose,$ref,$step);
        } catch (\Throwable $e) { self::fail($e,$flow,$step,$ref); }
    }
    private static function begin(string $purpose, string $ref, string &$step): void {
        $step = 'configuration';
        $s=Settings::get(); Support::need(!Settings::disabled(),'disabled','Upstream login is disabled by configuration.');
        Support::need($s['enabled'] || $purpose!=='login','disabled','Upstream login is not enabled.'); self::rate('start',30);
        Support::need(is_ssl() && parse_url(Metadata::callback(),PHP_URL_SCHEME)==='https','https','HTTPS is required for browser transactions.');
        $step = 'discovery';
        $http=self::http(); $d=(new Provider($http))->discover($s); $context=Metadata::context($s); $checked=get_option('ocimd_checked',[]);
        $step = 'publication';
        if (!Keys::ready($context) || ($checked['context']??'')!==$context || ($checked['time']??0)<time()-300 || ($checked['revision']??'')!==$s['revision']) {
            Metadata::validate($s,$http); update_option('ocimd_checked',['time'=>time(),'context'=>$context,'revision'=>$s['revision']],false);
        }
        $step = 'transaction';
        $keys=Keys::get(); $state=Support::random(); $browser=Support::random(); $nonce=Support::random(); $verifier=Support::random();
        $tx=['settings'=>$s,'discovery'=>$d,'client'=>Metadata::clientId($s),'callback'=>Metadata::callback(),'kid'=>$keys['active'],
            'nonce'=>$nonce,'verifier'=>$verifier,'browser'=>hash('sha256',$browser),'started'=>time(),'purpose'=>$purpose,'reauth'=>$purpose!=='login',
            'user'=>$purpose==='login'?0:get_current_user_id(),'session'=>$purpose==='login'?'':hash('sha256',wp_get_session_token()),
            'destination'=>Support::destination(Support::scalar($_GET,'redirect_to')),'audit_ref'=>$ref];
        Store::createTransaction($state,$tx); self::cookie($state,$browser);
        Support::audit('login_started', $purpose==='test' ? get_current_user_id() : 0, ['flow'=>$purpose,'step'=>'redirect','ref'=>$ref]);
        $step = 'redirect';
        $params=['response_type'=>'code','response_mode'=>'query','client_id'=>$tx['client'],'redirect_uri'=>$tx['callback'],'scope'=>$s['scopes'],
            'state'=>$state,'nonce'=>$nonce,'code_challenge'=>Support::b64(hash('sha256',$verifier,true)),'code_challenge_method'=>'S256'];
        if ($tx['reauth']) { $params['prompt']='login'; $params['max_age']='0'; }
        nocache_headers(); header('Referrer-Policy: no-referrer');
        // Discovery has pinned and validated this HTTPS destination. wp_safe_redirect is for local destinations only.
        wp_redirect(Support::query($d['authorization_endpoint'],$params),302,'SOCA'); exit;
    }
    public static function callback(): void {
        nocache_headers(); header('Referrer-Policy: no-referrer'); header('X-Content-Type-Options: nosniff');
        $ref = bin2hex(random_bytes(6)); $flow = 'login'; $step = 'request';
        try {
            Support::need(($_SERVER['REQUEST_METHOD']??'')==='GET','method','Only query response mode is supported.');
            // PHP collapses duplicate query keys; reject them before reading the parsed request.
            $names=[]; foreach (explode('&',$_SERVER['QUERY_STRING']??'') as $pair) { $name=urldecode(explode('=',$pair,2)[0]); Support::need(!in_array($name,$names,true),'duplicate_parameter','Duplicate callback parameter.'); $names[]=$name; }
            $step = 'transaction';
            $state=Support::scalar($_GET,'state',100); $browser=Support::scalar($_COOKIE,self::cookieName($state),100);
            $tx=Store::consumeTransaction($state,$browser); self::cookie($state,'');
            $ref = is_string($tx['audit_ref'] ?? null) && preg_match('/^[a-f0-9]{12}$/D', $tx['audit_ref']) ? $tx['audit_ref'] : $ref;
            $flow = ($tx['purpose'] ?? '') === 'test' ? 'test' : 'login';
            Support::audit('callback_received', 0, ['flow'=>$flow,'step'=>'configuration','ref'=>$ref]);
            $step = 'configuration';
            $s=Settings::get();
            Support::need(!Settings::disabled() && $s['revision']===$tx['settings']['revision'] && ($s['enabled'] || $tx['purpose']!=='login'),'configuration_changed','Configuration changed during login. Start again.');
            $step = 'authorization_response';
            $iss=Support::scalar($_GET,'iss');
            Support::need(($iss==='' && empty($tx['discovery']['authorization_response_iss_parameter_supported'])) || $iss===$tx['settings']['issuer'],'response_issuer','Authorization response issuer mismatch or missing.');
            Support::need(!isset($_GET['error']),'provider_denied','Provider cancelled or denied the request.');
            $code=Support::scalar($_GET,'code'); Support::need($code!=='','code','Authorization code is missing.');
            if ($tx['purpose']!=='login') {
                Support::need(get_current_user_id()===$tx['user'] && hash_equals($tx['session'],hash('sha256',wp_get_session_token())),'session','The original authenticated local session is required.');
            }
            $step = 'token_exchange';
            $claims=(new Provider(self::http()))->exchange($tx,$code);
            Support::audit('claims_verified', 0, ['flow'=>$flow,'step'=>'access_policy','ref'=>$ref]);
            if ($tx['purpose']==='test') {
                $step = 'access_policy';
                Support::need(current_user_can('manage_options'),'authorization','Administrator access required.');
                [$allowed,$reason]=Policy::test($s,is_string($claims['email']??null)?$claims['email']:'',($claims['email_verified']??false)===true);
                set_transient('ocimd_test_' . get_current_user_id(),['time'=>time(),'policy'=>$allowed,'message'=>$reason],600);
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
        $context = ['flow'=>$flow,'step'=>$step,'reason'=>$e instanceof Failure ? $e->reason : 'internal_error','ref'=>$ref];
        if ($e instanceof Failure) { $context += $e->diagnostics; }
        if (!$e instanceof Failure) { $context['exception'] = get_class($e); }
        Support::audit('login_failed',0,$context);
        wp_safe_redirect(self::recoveryUrl(true,$ref)); exit;
    }
}
