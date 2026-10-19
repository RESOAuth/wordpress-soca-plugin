<?php
if (!defined('ABSPATH')) {
    define('DB_NAME','unit');
    foreach (['AUTH_KEY','SECURE_AUTH_KEY','AUTH_SALT','SECURE_AUTH_SALT'] as $c) define($c,str_repeat('unit-test-secret-',4));
    $GLOBALS['test_options']=[]; $GLOBALS['test_transients']=[];
    function get_option($k,$d=false) { return $GLOBALS['test_options'][$k]??$d; }
    function update_option($k,$v,$autoload=null) { $GLOBALS['test_options'][$k]=$v; return true; }
    function add_option($k,$v,$deprecated='',$autoload=null) { if (isset($GLOBALS['test_options'][$k])) return false; return update_option($k,$v); }
    function delete_option($k) { unset($GLOBALS['test_options'][$k]); }
    function get_transient($k) { $r=$GLOBALS['test_transients'][$k]??null; return $r && $r[1]>time()?$r[0]:false; }
    function set_transient($k,$v,$t) { $GLOBALS['test_transients'][$k]=[$v,time()+$t]; return true; }
    function delete_transient($k) { if (!isset($GLOBALS['test_transients'][$k])) return false; unset($GLOBALS['test_transients'][$k]); return true; }
    function get_current_blog_id() { return 1; }
    function get_current_user_id() { return 1; }
    function wp_salt($scheme) { return 'unit-test-only-key-' . $scheme; }
    function home_url($p='/') { return 'https://www.client.company.com' . $p; }
    function admin_url($p='') { return 'https://www.client.company.com/wp-admin/' . $p; }
    function wp_parse_url($v,$component=-1) { return parse_url($v,$component); }
    function wp_strip_all_tags($v) { return trim(strip_tags($v)); }
    function wp_unslash($v) { return is_array($v) ? array_map('wp_unslash', $v) : stripslashes($v); }
    function get_bloginfo($k) { return 'Test WordPress'; }
    function add_query_arg($a,$b,$c=null) {
        if (is_array($a)) { $args=$a; $url=$b; } else { $args=[$a=>$b]; $url=$c; }
        return $url . (str_contains($url,'?')?'&':'?') . http_build_query($args,'','&',PHP_QUERY_RFC3986);
    }
    $GLOBALS['wpdb']=new class {
        public $base_prefix='wp_';
        public function prepare($sql,...$args) { return $sql; }
        public function get_var($sql) { return 1; }
    };
}
$plugin = defined('ABSPATH') ? WP_PLUGIN_DIR . '/simple-oauth-cimd-access' : __DIR__ . '/../simple-oauth-cimd-access';
require_once $plugin . '/vendor/autoload.php';
foreach (['Support','Policy','Settings','Http','Store','Keys','Metadata','Provider','Identity'] as $name) require_once $plugin . '/includes/' . $name . '.php';
use SOCA\{Failure,Http,Settings,Support};
function expect(bool $ok,string $message='assertion failed'): void { if (!$ok) throw new RuntimeException($message); }
function rejects(callable $fn,?string $reason=null): void {
    try { $fn(); } catch (Failure $e) { if ($reason!==null) expect($e->reason===$reason,'Expected ' . $reason . ', got ' . $e->reason . ': ' . $e->getMessage()); return; }
    throw new RuntimeException('Expected rejection: ' . ($reason??'any'));
}
function test(string $name,callable $fn): void {
    try { $fn(); echo "PASS $name\n"; $GLOBALS['passed']=($GLOBALS['passed']??0)+1; }
    catch (Throwable $e) { echo "FAIL $name: {$e->getMessage()}\n{$e->getTraceAsString()}\n"; $GLOBALS['failed']=($GLOBALS['failed']??0)+1; }
}
class FixtureHttp extends Http {
    public array $calls=[]; public $handler;
    public function __construct(callable $handler) { $this->handler=$handler; }
    public function request(string $url,?array $form=null,?string $bearer=null): array { $this->calls[]=[$url,$form,$bearer]; return ($this->handler)($url,$form,$bearer); }
}
function discovery(): array {
    return ['issuer'=>'https://provider.company.com','authorization_endpoint'=>'https://provider.company.com/authorize','token_endpoint'=>'https://provider.company.com/token','jwks_uri'=>'https://provider.company.com/jwks',
        'userinfo_endpoint'=>'https://provider.company.com/userinfo','response_types_supported'=>['code'],'response_modes_supported'=>['query'],'subject_types_supported'=>['public','pairwise'],
        'code_challenge_methods_supported'=>['S256'],'token_endpoint_auth_methods_supported'=>['private_key_jwt'],'token_endpoint_auth_signing_alg_values_supported'=>['ES256'],
        'id_token_signing_alg_values_supported'=>['ES256','RS256'],'scopes_supported'=>['openid','email','profile'],'client_id_metadata_document_supported'=>true,'authorization_response_iss_parameter_supported'=>true];
}
function settings(): array { $s=Settings::defaults(); $s['issuer']='https://provider.company.com'; return $s; }
function transaction(): array { return ['settings'=>settings(),'discovery'=>discovery(),'client'=>'https://client.company.com/client.json','nonce'=>'test-nonce','started'=>time(),'reauth'=>false,'callback'=>'https://client.company.com/callback','verifier'=>Support::random(),'kid'=>SOCA\Keys::get()['active']]; }
function claims(array $tx): array { return ['iss'=>$tx['settings']['issuer'],'sub'=>'subject-1','aud'=>$tx['client'],'nonce'=>$tx['nonce'],'iat'=>time(),'exp'=>time()+300,'email'=>'user@company.com','email_verified'=>true]; }
