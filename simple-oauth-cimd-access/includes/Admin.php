<?php
namespace SOCA;
final class Admin {
    public static function boot(): void {
        add_action('admin_menu', static function () { add_options_page('Simple OAuth CIMD Access','SOCA','manage_options','simple-oauth-cimd-access',[self::class,'page']); });
        add_action('admin_enqueue_scripts', static function ($hook) {
            if ($hook==='settings_page_simple-oauth-cimd-access') {
                wp_enqueue_script('soca-admin',plugins_url('assets/admin.js',SOCA_FILE),[], '0.3.0',true);
                wp_enqueue_style('soca-admin',plugins_url('assets/admin.css',SOCA_FILE),[], '0.3.0');
            }
        });
        add_filter('site_status_tests',static function ($tests) { $tests['direct']['soca']=['label'=>'SOCA','test'=>[self::class,'health']]; return $tests; });
        add_filter('debug_information',static function ($info) {
            $s=Settings::get(); $info['soca']=['label'=>'Simple OAuth CIMD Access','fields'=>[
                'version'=>['label'=>'Version','value'=>'0.3.0'], 'mode'=>['label'=>'Metadata mode','value'=>$s['mode']],
                'enabled'=>['label'=>'Enabled','value'=>$s['enabled'] && !Settings::disabled()?'yes':'no'],
                'cron'=>['label'=>'Maintenance','value'=>wp_next_scheduled('soca_maintenance')?'scheduled':'missing']]]; return $info;
        });
    }
    public static function health(): array {
        $m=get_option('soca_maintenance_status',[]); $s=Settings::get();
        $ok=$s['enabled'] && !Settings::disabled() && !empty($m['ok']) && ($m['time']??0)>time()-7200;
        try { $k=Keys::get(); $ok=$ok && $k['since']>time()-691200; } catch (\Throwable $e) { $ok=false; }
        return ['label'=>$ok?'SOCA publication and maintenance are current':'SOCA needs setup or maintenance review',
            'status'=>$ok?'good':'recommended','badge'=>['label'=>'Security','color'=>'blue'],
            'description'=>'<p>Review provider compatibility, public key publication, weekly rollover and the latest test login. Cron delays or provider caching can safely delay rollover. Inline proxy keys change the client identifier.</p>',
            'actions'=>'<a href="' . esc_url(admin_url('options-general.php?page=simple-oauth-cimd-access')) . '">Review SOCA</a>','test'=>'soca'];
    }
    private static function locked(string $key): string { return array_key_exists($key, Settings::deployment()) ? ' disabled' : ''; }
    private static function input(string $key, string $label, array $s, string $help='', string $type='text'): void {
        echo '<tr><th scope="row"><label for="soca-' . esc_attr($key) . '">' . esc_html($label) . '</label></th><td><input class="regular-text" id="soca-' . esc_attr($key) . '" name="' . esc_attr($key) . '" type="' . esc_attr($type) . '" value="' . esc_attr((string)$s[$key]) . '"' . esc_attr(self::locked($key)) . ' aria-describedby="help-' . esc_attr($key) . '"><p class="description" id="help-' . esc_attr($key) . '">' . esc_html($help) . '</p></td></tr>';
    }
    private static function checkbox(string $key, string $label, array $s): void {
        echo '<p><label><input type="checkbox" name="' . esc_attr($key) . '" value="1" ' . checked($s[$key],true,false) . esc_attr(self::locked($key)) . '> ' . esc_html($label) . '</label></p>';
    }
    private static function select(string $key, string $label, array $choices, array $s): void {
        echo '<tr><th scope="row"><label for="soca-' . esc_attr($key) . '">' . esc_html($label) . '</label></th><td><select id="soca-' . esc_attr($key) . '" name="' . esc_attr($key) . '"' . esc_attr(self::locked($key)) . '>';
        foreach ($choices as $v=>$text) { echo '<option value="' . esc_attr($v) . '" ' . selected($s[$key],$v,false) . '>' . esc_html($text) . '</option>'; }
        echo '</select></td></tr>';
    }
    public static function page(): void {
        if (!current_user_can('manage_options')) { return; }
        $notice=''; $error=false; $result=null; $policyResult=null; $policyEmail=''; $policyVerified=true; $action='';
        if (Support::serverString('REQUEST_METHOD') === 'POST') {
            check_admin_referer('soca_settings');
            try {
                $action=Support::scalar($_POST,'operation',20);
                if ($action==='save') {
                    $input = wp_unslash($_POST);
                    foreach (['enabled','automatic','create_users','unrestricted'] as $key) { $input[$key] = isset($input[$key]) ? '1' : '0'; }
                    Settings::save($input); $notice='Settings saved. Run connection validation, then test login.'; }
                elseif ($action==='link' || $action==='unlink') {
                    $id = filter_var(Support::scalar(wp_unslash($_POST),'link_user'), FILTER_VALIDATE_INT);
                    Support::need($id !== false && $id > 0, 'identity', 'Enter an existing local user ID.');
                    $issuer = Support::scalar(wp_unslash($_POST),'link_issuer'); $subject = Support::scalar(wp_unslash($_POST),'link_subject',255);
                    if ($action==='link') { Identity::link($id,$issuer,$subject); } else { Identity::unlink($id,$issuer,$subject); }
                    $notice='Identity association updated.';
                }
                elseif ($action==='check') { $result=Plugin::check(); $notice='Discovery and published client document passed validation. A test login is still required.'; }
                elseif ($action==='policy') {
                    $policyEmail=Support::scalar(wp_unslash($_POST),'test_email',254); $policyVerified=isset($_POST['verified']);
                    [$allowed,$why]=Policy::test(Settings::get(),$policyEmail,$policyVerified);
                    $policyResult=['allowed'=>$allowed,'message'=>$why];
                }
            } catch (\Throwable $e) {
                $message=$e instanceof Failure?$e->getMessage():'An internal check failed. Confirm OpenSSL, cURL, database access and WordPress salts.';
                if ($action==='policy') { $policyResult=['allowed'=>false,'message'=>$message]; }
                else { $error=true; $notice=$message; }
            }
        }
        $s=Settings::get();
        echo '<div class="wrap soca"><h1>Simple OAuth CIMD Access</h1>';
        echo '<p>SOCA is an open-source WordPress single sign-on (SSO) plugin built and supported by RESOAuth®. You can configure another compatible provider. OAuth handles the secure authorization-code redirect, OpenID Connect (OIDC) verifies who signed in, and a Client ID Metadata Document (CIMD) publishes this site’s client details and public keys to compatible providers. <a href="https://openid.net/specs/openid-connect-core-1_0.html">About OIDC</a> · <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document">About CIMD</a>.</p>';
        echo '<p>The provider and site defaults are ready to review. Save any changes, validate the connection and try a test login. Local WordPress login remains available. The default issuer is the <a href="https://sag.resoauth.dev/hosted">RESOAuth hosted gateway</a>; review its <a href="https://sag.resoauth.dev/hosted/privacy-notice">privacy notice</a> and <a href="https://sag.resoauth.dev/hosted/terms-of-service">terms of service</a>.</p>';
        if ($notice) { echo '<div role="status" class="notice ' . ($error?'notice-error':'notice-success') . '"><p>' . esc_html($notice) . '</p></div>'; }
        $test=get_transient('soca_test_' . get_current_user_id());
        if ($test && ($test['revision'] ?? '') === $s['revision']) { echo '<div class="notice notice-success"><p>Test login: cryptographic OIDC validation succeeded. Admission policy: ' . esc_html($test['message']) . ' No account or session was changed.</p></div>'; }
        if (Settings::disabled()) { echo '<div class="notice notice-warning"><p>SOCA is disabled by configuration. Upstream login is disabled.</p></div>'; }
        if (!Plugin::verified($s)) { echo '<div class="notice notice-warning"><p>Ordinary SSO is unavailable until an admitted test login succeeds for this candidate configuration. Save the candidate, validate documents and complete Test login first.</p></div>'; }
        if (Settings::deployment()) { echo '<p>Deployment-managed fields are disabled. Effective values use defaults, saved settings, then <code>SOCA_CONFIG</code>. Locked fields: <code>' . esc_html(implode(', ',array_keys(Settings::deployment()))) . '</code>. Use <code>wp soca config</code> to inspect values and locks.</p>'; }
        $host=(string)wp_parse_url(home_url('/'),PHP_URL_HOST);
        if (Support::localHost($host)) { echo '<div class="notice notice-info"><p>Local development detected. Use HTTPS with a certificate your browser trusts. Proxy + inline public keys are selected because a cloud provider cannot fetch localhost metadata or JWKS. Add an allowed email/domain or select Allow any verified email, then enable login. Rotating inline keys changes the client identifier and may require fresh provider consent.</p></div>'; }
        $recoveryUrl=Plugin::recoveryUrl();
        echo '<p><strong>Recovery URL:</strong> <a href="' . esc_url($recoveryUrl) . '">' . esc_html($recoveryUrl) . '</a></p>';
        echo '<form method="post">'; wp_nonce_field('soca_settings'); echo '<input type="hidden" name="revision" value="' . esc_attr($s['revision']) . '"><input type="hidden" name="operation" value="save"><h2>Provider and public metadata</h2><table class="form-table">';
        self::input('provider','Provider display name',$s);
        self::input('button','Login button label',$s,'Edit this label when changing provider.');
        self::input('issuer','Exact issuer',$s,'HTTPS issuer from the provider. Never inferred from email or incoming requests.','url');
        echo '</table><details class="soca-advanced"' . (Support::localHost($host)?' open':'') . '><summary>Client metadata and advanced provider settings</summary><table class="form-table">';
        foreach (['client_name'=>'Application name','client_uri'=>'Application home URL','logo_uri'=>'Application logo URL','policy_uri'=>'Privacy policy URL','tos_uri'=>'Terms of service URL'] as $key=>$label) { self::input($key,$label,$s,'Leave blank to use an available WordPress default. Optional unavailable fields are omitted. Public HTTPS URLs only.'); }
        self::input('scopes','Scopes',$s,'Space separated. openid and email are required. Verified email claims must be in the ID token or subject-matched UserInfo.');
        self::select('id_alg','ID token signature',['ES256'=>'ES256 / P-256','RS256'=>'RS256 / RSA ≥ 2048 bits'],$s);
        self::select('assertion_audience','Client assertion audience',['issuer'=>'Provider issuer','token_endpoint'=>'Token endpoint URL'],$s);
        self::select('mode','Metadata mode',['self'=>'Self-hosted CIMD (recommended for production)','proxy'=>'Configured CIMD proxy'],$s);
        self::input('proxy','CIMD proxy template',$s,'One literal %s in the path. Other valid URL encoding is preserved. The fetched response must insert the exact client_id. The default uses RESOAuth Dynamic CIMD; public metadata is encoded in the URL.');
        self::select('key_mode','Public keys in metadata',['uri'=>'Stable public JWKS URL','inline'=>'Inline public JWKS'],$s);
        self::input('jwks_url','Public JWKS URL override',$s,'Leave blank for the derived endpoint. An external mirror must publish both generated public keys; maintenance verifies it.','url');
        self::input('cache_hours','Provider cache safety window (hours)',$s,'Default 24 hours. Confirm the provider’s maximum metadata/JWKS cache duration; use at least that long. 1–168 hours. Longer overlap can delay weekly rollover.','number');
        echo '</table>';
        echo '<p>Proxy + inline keys changes the client identifier when published keys rotate. A stable public JWKS URL keeps that identifier stable. Connection validation checks the actual published document.</p>';
        echo '</details><h2 id="soca-access-rules">Access rules</h2><p>Only verified emails are admitted. Deny rules always win. Exact domains match only themselves. *.example.com matches one or more subdomain labels, including a.b.example.com, and excludes example.com. Emails are matched case-insensitively. Use ASCII or punycode domains.</p>';
        self::checkbox('unrestricted','Allow any verified email/domain (deny rules still apply)',$s);
        foreach (['allow_domains'=>'Allowed domains','deny_domains'=>'Denied domains','allow_emails'=>'Allowed emails','deny_emails'=>'Denied emails'] as $key=>$label) {
            echo '<div class="soca-policy" data-policy="' . (str_starts_with($key,'allow_')?'allow':'deny') . '" data-locked="' . (self::locked($key) ? '1' : '0') . '" data-kind="' . (str_ends_with($key,'emails')?'email':'domain') . '"><label for="' . esc_attr($key) . '"><strong>' . esc_html($label) . '</strong></label><textarea id="' . esc_attr($key) . '" name="' . esc_attr($key) . '"' . esc_attr(self::locked($key)) . ' rows="3" aria-describedby="' . esc_attr($key) . '-help">' . esc_textarea(implode("\n",$s[$key])) . '</textarea><p id="' . esc_attr($key) . '-help" class="description">One per line, or paste entries separated by commas, spaces or semicolons. Maximum 200 entries.</p></div>';
        }
        echo '<h2>Accounts and login</h2><p>Returning users are selected by an administrator-approved issuer/subject link. Verified email is used for admission only. An existing email match never grants access by itself. Changed subjects require explicit linking; roles and local profile fields are preserved.</p>';
        self::checkbox('create_users','Create missing accounts and identity links as Subscribers after verified-email policy admission. Existing roles are never changed.',$s);
        self::checkbox('enabled','Enable the upstream button on the standard WordPress login screen.',$s);
        self::checkbox('automatic','Automatically redirect ordinary GET visits to wp-login.php upstream. The recovery URL, logout, reset, interim and reauthentication flows remain local.',$s);
        submit_button('Save settings'); echo '</form>';
        echo '<h2>Derived documents and checks</h2><dl>';
        foreach (['Callback'=>Metadata::callback(),'Self-hosted metadata'=>Metadata::url(),'Public JWKS'=>Metadata::jwksUrl()] as $label=>$url) { echo '<dt><strong>' . esc_html($label) . '</strong></dt><dd><code>' . esc_html($url) . '</code></dd>'; }
        try { $client=Metadata::clientId($s); echo '<dt><strong>Current client identifier</strong></dt><dd><code>' . esc_html($client) . '</code></dd></dl><details><summary>Public metadata preview</summary><pre>' . esc_html(json_encode(Metadata::document($s),JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)) . '</pre></details>'; }
        catch (\Throwable $e) { echo '</dl><p>Preview is unavailable; review the configuration and encryption keys.</p>'; }
        echo '<form method="post">'; wp_nonce_field('soca_settings'); echo '<input type="hidden" name="operation" value="check">'; submit_button('Validate connection and documents','secondary'); echo '</form>';
        $testUrl=wp_nonce_url(add_query_arg(['action'=>'soca_start','purpose'=>'test'],admin_url('admin-post.php')),'soca_test');
        echo '<p><a class="button button-secondary" href="' . esc_url($testUrl) . '">Test login (keeps this admin session)</a></p><p>The provider must accept this client’s redirect origin, inline JWKS if selected, and key refresh policy. A document check alone does not establish these capabilities.</p>';
        if ($result) { echo '<pre>' . esc_html(json_encode($result,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)) . '</pre>'; }
        echo '<h2 id="soca-access-test">Test access rules</h2><p id="soca-access-test-help">Check an email against the saved <a href="#soca-access-rules">Access rules</a> above. Unsaved edits are not included; deny rules always win.</p>';
        echo '<form id="soca-access-test-form" method="post" action="#soca-access-test">'; wp_nonce_field('soca_settings');
        echo '<input type="hidden" name="operation" value="policy"><div class="soca-access-test-row"><label for="test_email">Email to test</label><input id="test_email" name="test_email" type="email" value="' . esc_attr($policyEmail) . '" aria-describedby="soca-access-test-help" required>';
        echo '<label><input type="checkbox" name="verified" value="1" ' . checked($policyVerified,true,false) . '> Verified by provider</label><button type="submit" class="button button-secondary">Explain access decision</button>';
        if ($policyResult) {
            echo '<span id="soca-policy-result" role="status" class="soca-access-result ' . ($policyResult['allowed']?'is-allowed':'is-denied') . '">' . esc_html(($policyResult['allowed']?'Allowed':'Denied') . ' for ' . $policyEmail . ': ' . $policyResult['message']) . '</span>';
        }
        echo '</div></form>';
        echo '<h2>Approve or remove an identity link</h2><p>Verify ownership independently before approving. Obtain the exact subject from your trusted provider. Unlinking ends all sessions for this local account and invalidates pending SOCA transactions and activation evidence. Local account credentials are preserved.</p><form method="post">'; wp_nonce_field('soca_settings');
        echo '<p><label>Local user ID <input name="link_user" type="number" min="1" required></label></p><p><label>Exact issuer <input name="link_issuer" type="url" value="' . esc_attr($s['issuer']) . '" required></label></p><p><label>Exact subject <input name="link_subject" maxlength="255" required></label></p><button class="button" name="operation" value="link">Approve identity link</button> <button class="button" name="operation" value="unlink">Remove identity link</button></form>';
        echo '<h2>Operations</h2><p>Signing keys rotate weekly after the replacement has been published for the cache safety window. Old keys remain for the window plus 12 minutes. A missed cron or unreachable mirror delays rotation. Keep WordPress salts stable, protect database backups, and run <code>wp soca maintain</code> hourly using real cron on low-traffic sites.</p>';
        echo '<p>To recover, use the recovery URL above, <code>wp soca disable</code>, or set <code>define(\'SOCA_DISABLED\', true);</code> in wp-config.php. A failed login shows a reference that matches a redacted audit event below. Logout ends the WordPress session only.</p>';
        try { echo '<details><summary>Key publication and maintenance details</summary><pre>' . esc_html(json_encode(Plugin::status(),JSON_PRETTY_PRINT)) . '</pre></details>'; } catch (\Throwable $e) { echo '<p>Cannot read keys. Restore encryption configuration from backup.</p>'; }
        echo '<details><summary>Recent redacted audit events (last 100)</summary><p>Match the reference from the login page to a <code>login_failed</code> event. Its flow, step and reason identify where the attempt stopped. HTTP status appears when an endpoint responds with an error. A <code>transaction</code> failure occurs before token exchange; <code>token_exchange</code> and later steps show how far the callback progressed. Events contain no email, subject, token or provider response body.</p><pre>' . esc_html(json_encode(get_option('soca_audit',[]),JSON_PRETTY_PRINT)) . '</pre></details></div>';
    }
}
