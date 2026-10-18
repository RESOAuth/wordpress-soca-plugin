<?php
// Run only against a disposable installation: wp eval-file tests/wordpress.php
require __DIR__ . '/bootstrap.php';
use OCIMD\{Settings,Support,Store,Keys,Identity,Policy,Metadata,Plugin};
Support::need(wp_get_environment_type()==='local','test_environment','Tests require WP_ENVIRONMENT_TYPE=local.');
$before=Settings::get();$created=[];
$make=function($name,$email,$role='subscriber')use(&$created){$id=wp_insert_user(['user_login'=>$name,'user_pass'=>'Test-only-password!','user_email'=>$email,'role'=>$role]);expect(!is_wp_error($id),is_wp_error($id)?$id->get_error_message():'');$created[]=$id;return (int)$id;};
$s=$before;$s['allow_domains']=['company.com'];$s['allow_emails']=[];$s['deny_domains']=[];$s['deny_emails']=[];$s['unrestricted']=false;$s['create_users']=false;
$c=['iss'=>'https://fixture.company.com','sub'=>'wp-test-1','email'=>'ordinary@company.com','email_verified'=>true];
try {
    test('localhost defaults keep login off and infer no domain',function(){
        $home=get_option('home'); update_option('home','https://localhost:8443');
        try { $local=Settings::defaults(); expect(!$local['enabled'] && $local['mode']==='proxy' && $local['key_mode']==='inline' && $local['allow_domains']===[] && !$local['unrestricted']); }
        finally { update_option('home',$home); }
    });
    test('allow-any save preserves hidden allowlists while deny rules still win',function()use($before){
        $input=$before;
        foreach (['allow_domains','allow_emails','deny_domains','deny_emails'] as $key) { $input[$key]=implode("\n",$before[$key]); }
        unset($input['allow_domains'],$input['allow_emails']);
        $input['unrestricted']='1'; $input['deny_domains']='blocked.company.com';
        try {
            $saved=Settings::save($input);
            expect($saved['allow_domains']===$before['allow_domains'] && $saved['unrestricted']);
            expect(Policy::test($saved,'person@other.com',true)[0]);
            expect(!Policy::test($saved,'person@blocked.company.com',true)[0]);
        } finally { update_option('ocimd_settings',$before,false); }
    });
    test('WordPress tables installed and keys encrypted without autoload',function(){global $wpdb;expect((int)get_option('ocimd_schema')===1);expect(count(Keys::get()['items'])===2);$row=$wpdb->get_row("SELECT option_value,autoload FROM {$wpdb->options} WHERE option_name='ocimd_keys'",ARRAY_A);expect(!str_contains($row['option_value'],'PRIVATE KEY'));expect(in_array($row['autoload'],['off','no','auto-off'],true));});
    test('new callback hook is registered and profile identity controls are absent',function(){
        expect(plugin_basename(SOCA_FILE)==='simple-oauth-cimd-access/simple-oauth-cimd-access.php');
        expect(OCIMD_FILE===SOCA_FILE);
        expect(function_exists('soca_button'));
        expect(wp_next_scheduled('soca_maintenance')!==false);
        expect(has_action('admin_post_nopriv_soca_start',[Plugin::class,'start'])!==false);
        expect(has_action('admin_post_nopriv_soca_callback',[Plugin::class,'callback'])!==false);
        expect(has_action('admin_post_nopriv_oauthcimd_callback')===false);
        expect(has_action('show_user_profile',[\OCIMD\Admin::class,'profile'])===false);
    });
    test('SOCA recovery URLs and legacy error links remain usable',function(){
        $url=Plugin::recoveryUrl(true);
        expect(str_contains($url,'soca_local=1') && str_contains($url,'soca_error=1') && !str_contains($url,'oauth_cimd_'));
        $original=$_GET;
        try {
            $ref='abcdef123456';
            expect(str_contains(Plugin::recoveryUrl(true,$ref),'soca_error='.$ref));
            $_GET=['soca_error'=>$ref];
            expect(str_contains(apply_filters('login_message',''),'Reference: <code>'.$ref.'</code>'));
            $_GET=['soca_error'=>'<script>'];
            expect(!str_contains(apply_filters('login_message',''),'<script>'));
            $_GET=['soca_error'=>'1'];
            expect(str_contains(apply_filters('login_message',''),'SOCA login did not complete.'));
            $_GET=['oauth_cimd_error'=>'1'];
            expect(str_contains(apply_filters('login_message',''),'SOCA login did not complete.'));
        } finally { $_GET=$original; }
    });
    test('SOCA HTTP filter runs after the legacy integration filter',function(){
        $calls=[];
        $legacy=static function($http) use (&$calls) { $calls[]='legacy'; return $http; };
        $current=static function($http) use (&$calls) { $calls[]='soca'; return $http; };
        add_filter('oauth_cimd_auth_http',$legacy);
        add_filter('soca_http',$current);
        try { expect(Plugin::http() instanceof \OCIMD\Http && $calls===['legacy','soca']); }
        finally { remove_filter('soca_http',$current); remove_filter('oauth_cimd_auth_http',$legacy); }
    });
    test('single-use and encrypted transactions',function(){
        global $wpdb;$state=Support::random();$ref='abcdef123456';$ua=hash('sha256','fixture-agent');Store::createTransaction($state,['verifier'=>'confidential-verifier','audit_ref'=>$ref,'purpose'=>'login','user_agent'=>$ua]);
        $raw=$wpdb->get_var($wpdb->prepare("SELECT payload FROM {$wpdb->prefix}ocimd_transactions WHERE id=%s",hash('sha256',$state)));expect(!str_contains($raw,'confidential-verifier'));
        rejects(fn()=>Store::consumeTransaction($state,hash('sha256','different-agent')),'user_agent_mismatch');
        expect(Store::consumeTransaction($state,$ua)['verifier']==='confidential-verifier');rejects(fn()=>Store::consumeTransaction($state,$ua),'state');
        $state=Support::random();Store::createTransaction($state,['user_agent'=>$ua]);$wpdb->update($wpdb->prefix.'ocimd_transactions',['expires'=>time()-1],['id'=>hash('sha256',$state)]);rejects(fn()=>Store::consumeTransaction($state,$ua),'state');Store::clean();expect(!$wpdb->get_var($wpdb->prepare("SELECT id FROM {$wpdb->prefix}ocimd_transactions WHERE id=%s",hash('sha256',$state))));
    });
    $ordinary=$make('soca-test-ordinary','ordinary@company.com');$admin=$make('soca-test-admin','privileged@company.com','administrator');
    $ordinary2=$make('soca-test-ordinary2','ordinary2@company.com');
    test('access-rule test keeps its explanation beside the form',function()use($admin){
        $settings=Settings::get(); $originalUser=get_current_user_id(); $originalPost=$_POST; $originalRequest=$_REQUEST; $originalMethod=$_SERVER['REQUEST_METHOD']??null; $bufferLevel=ob_get_level();
        try {
            $configured=$settings; $configured['allow_domains']=['company.com']; $configured['allow_emails']=[]; $configured['deny_domains']=[]; $configured['deny_emails']=[]; $configured['unrestricted']=false;
            update_option('ocimd_settings',$configured,false); wp_set_current_user($admin);
            $_SERVER['REQUEST_METHOD']='POST';
            $_POST=['operation'=>'policy','test_email'=>'ordinary@company.com','verified'=>'1','_wpnonce'=>wp_create_nonce('ocimd_settings')];
            $_REQUEST=$_POST;
            ob_start(); \OCIMD\Admin::page(); $html=ob_get_clean();
            expect(str_contains($html,'SOCA - Simple OAuth CIMD Access'));
            expect(str_contains($html,'soca_local=1') && !str_contains($html,'oauth_cimd_local'));
            expect(str_contains($html,'id="soca-access-rules"') && str_contains($html,'href="#soca-access-rules"'));
            expect(str_contains($html,'action="#soca-access-test"') && str_contains($html,'value="ordinary@company.com"'));
            $result=strpos($html,'id="soca-policy-result"'); $input=strpos($html,'id="test_email"'); $operations=strpos($html,'<h2>Operations</h2>');
            expect($result!==false && $input!==false && $operations!==false && $input<$result && $result<$operations);
            expect(str_contains($html,'Allowed for ordinary@company.com: Exact domain allow rule matches'));
            $configured['deny_emails']=['ordinary@company.com']; update_option('ocimd_settings',$configured,false);
            ob_start(); \OCIMD\Admin::page(); $denied=ob_get_clean();
            expect(str_contains($denied,'Denied for ordinary@company.com: Email deny rule wins'));
            expect(strpos($denied,'id="soca-policy-result"')>strpos($denied,'id="test_email"'));
        } finally {
            while (ob_get_level()>$bufferLevel) { ob_end_clean(); }
            update_option('ocimd_settings',$settings,false); wp_set_current_user($originalUser); $_POST=$originalPost; $_REQUEST=$originalRequest;
            if ($originalMethod===null) { unset($_SERVER['REQUEST_METHOD']); } else { $_SERVER['REQUEST_METHOD']=$originalMethod; }
        }
    });
    test('verified email selects an existing account on every login',function()use($c,$s,$ordinary){expect(Identity::resolve($c,$s)->ID===$ordinary);expect(Identity::resolve($c,$s)->ID===$ordinary);});
    test('a changed subject still selects the same verified email account',function()use($c,$s,$ordinary){$changed=$c;$changed['sub']='wp-test-changed';expect(Identity::resolve($changed,$s)->ID===$ordinary);});
    test('a changed verified email selects its current local account',function()use($c,$s,$ordinary,$ordinary2){$changed=$c;$changed['email']='ordinary2@company.com';expect(Identity::resolve($changed,$s)->ID===$ordinary2);expect(get_userdata($ordinary)->user_email==='ordinary@company.com');});
    test('verified email also selects an administrator by default',function()use($c,$s,$admin){$c['email']='privileged@company.com';$c['sub']='wp-admin-sub';expect(Identity::resolve($c,$s)->ID===$admin);expect(in_array('administrator',get_userdata($admin)->roles,true));});
    test('verified email matches another ordinary account',function()use($c,$s,$ordinary2){$c['sub']='wp-ordinary2';$c['email']='ordinary2@company.com';expect(Identity::resolve($c,$s)->ID===$ordinary2);});
    test('registration off; explicit controlled creation is subscriber only',function()use($c,$s,&$created){$c['sub']='wp-new';$c['email']='new@company.com';rejects(fn()=>Identity::resolve($c,$s),'registration_disabled');$s['create_users']=true;$c['role']='administrator';$c['roles']=['administrator'];$u=Identity::resolve($c,$s);$created[]=$u->ID;expect($u->roles===['subscriber']);});
    test('email_verified must be boolean true and denial applies on every login',function()use($c,$s){$c['email_verified']='true';rejects(fn()=>Identity::resolve($c,$s),'access_denied');$c['email_verified']=true;$s['deny_domains']=['company.com'];rejects(fn()=>Identity::resolve($c,$s),'access_denied');});
    $dup=$make('soca-test-duplicate','temporary@company.com');
    test('ambiguous local emails rejected',function()use($c,$s,$dup){global $wpdb;$wpdb->update($wpdb->users,['user_email'=>'ordinary2@company.com'],['ID'=>$dup]);try {$c['email']='ordinary2@company.com';$c['sub']='ambiguous-sub';rejects(fn()=>Identity::resolve($c,$s),'ambiguous_email');} finally {$wpdb->update($wpdb->users,['user_email'=>'temporary@company.com'],['ID'=>$dup]);clean_user_cache($dup);}});
    test('existing custom capabilities remain unchanged',function()use($ordinary2,$c,$s){$u=get_userdata($ordinary2);$u->add_cap('edit_posts');$c['sub']='wp-ordinary2';$c['email']='ordinary2@company.com';expect(Identity::resolve($c,$s)->ID===$ordinary2);expect(get_userdata($ordinary2)->has_cap('edit_posts'));$u->remove_cap('edit_posts');});
    test('redacted audit keeps failure step, reason and reference',function(){Support::audit('login_started',0,['flow'=>'login','ref'=>'abcdef123456']);Support::audit('login_failed',0,['flow'=>'login','step'=>'token_exchange','reason'=>'token_http_status','ref'=>'abcdef123456','http_status'=>401,'email'=>'secret@company.com','token'=>'access_token']);$log=get_option('ocimd_audit');$last=end($log);expect($last['event']==='login_failed' && $last['step']==='token_exchange' && $last['reason']==='token_http_status' && $last['ref']==='abcdef123456' && $last['http_status']===401);$json=Support::json($log);expect(!str_contains($json,'@company.com') && !str_contains($json,'wp-test-1') && !str_contains($json,'access_token'));});
    test('public metadata exposes public keys only and no access policy',function(){ $d=Metadata::document(Settings::get(),true);Metadata::noPrivateKeys($d);$j=Support::json($d);expect(!str_contains($j,'allow_domains') && !str_contains($j,'PRIVATE KEY')); });
} finally {
    require_once ABSPATH.'wp-admin/includes/user.php';
    foreach($created as $id) wp_delete_user($id);
    update_option('ocimd_settings',$before,false);
}
echo ($GLOBALS['passed']??0).' passed, '.($GLOBALS['failed']??0)." failed\n";
if(!empty($GLOBALS['failed'])) \WP_CLI::halt(1);
