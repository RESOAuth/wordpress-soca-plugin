<?php
// Run only against a disposable installation: wp eval-file tests/wordpress.php
require __DIR__ . '/bootstrap.php';
use SOCA\{Settings,Support,Store,Keys,Identity,Policy,Metadata,Plugin};
Support::need(wp_get_environment_type()==='local','test_environment','Tests require WP_ENVIRONMENT_TYPE=local.');
$before=Settings::get();$created=[];
$make=function($name,$email,$role='subscriber')use(&$created){$id=wp_insert_user(['user_login'=>$name,'user_pass'=>'Test-only-password!','user_email'=>$email,'role'=>$role]);expect(!is_wp_error($id),is_wp_error($id)?$id->get_error_message():'');$created[]=$id;return (int)$id;};
$s=$before;$s['allow_domains']=['company.com'];$s['allow_emails']=[];$s['deny_domains']=[];$s['deny_emails']=[];$s['unrestricted']=false;$s['create_users']=false;
$s['issuer']='https://fixture.company.com';
$c=['iss'=>'https://fixture.company.com','sub'=>'wp-test-1','email'=>'ordinary@company.com','email_verified'=>true];
try {
    test('localhost defaults keep login off and infer no domain',function(){
        $home=get_option('home'); update_option('home','https://localhost:8443');
        try { $local=Settings::defaults(); expect(!$local['enabled'] && $local['mode']==='proxy' && $local['key_mode']==='inline' && $local['allow_domains']===[] && !$local['unrestricted'] && $local['proxy']==='https://dynamic-cimd.resoauth.cloud/cimd/%s'); }
        finally { update_option('home',$home); }
    });
    test('disabled maintenance does not contact a provider',function()use($before){
        $previousStatus=get_option('soca_maintenance_status',false);
        $called=false;
        $observeHttp=static function($http)use(&$called){$called=true;return $http;};
        add_filter('soca_http',$observeHttp);
        try {
            $disabled=$before; $disabled['enabled']=false;
            update_option('soca_settings',$disabled,false);
            Plugin::maintenance();
            $status=get_option('soca_maintenance_status');
            expect(!$called && $status['ok']===true && $status['code']==='login_disabled');
        } finally {
            remove_filter('soca_http',$observeHttp);
            update_option('soca_settings',$before,false);
            if($previousStatus===false){delete_option('soca_maintenance_status');}
            else{update_option('soca_maintenance_status',$previousStatus,false);}
        }
    });
    test('allow-any save preserves hidden allowlists while deny rules still win',function()use($before){
        $input=$before;$input['revision']=Settings::get()['revision'];
        foreach (['allow_domains','allow_emails','deny_domains','deny_emails'] as $key) { $input[$key]=implode("\n",$before[$key]); }
        unset($input['allow_domains'],$input['allow_emails']);
        $input['unrestricted']='1'; $input['deny_domains']='blocked.company.com';
        try {
            $saved=Settings::save($input);
            expect($saved['allow_domains']===$before['allow_domains'] && $saved['unrestricted']);
            expect(Policy::test($saved,'person@other.com',true)[0]);
            expect(!Policy::test($saved,'person@blocked.company.com',true)[0]);
        } finally { update_option('soca_settings',$before,false); }
    });
    test('stale settings edits are rejected and candidate evidence gates login',function()use($before){
        try {
            $current=Settings::get();$saved=Settings::save(['button'=>'A fresh label','revision'=>$current['revision']]);
            rejects(fn()=>Settings::save(['button'=>'A stale label','revision'=>$current['revision']]),'stale_settings');
            expect(Settings::get()['button']==='A fresh label');
            expect(Settings::save(['button'=>'A fresh label'])['revision'] === $saved['revision']);
            $saved=Settings::save(['enabled'=>true]);expect(!Plugin::loginReady($saved));
            update_option('soca_verified',['profile'=>Settings::profile($saved)],false);expect(Plugin::loginReady($saved));
            $saved=Settings::save(['automatic'=>true]);expect(Plugin::loginReady($saved));
            $saved=Settings::save(['allow_domains'=>['*.company.com']]);expect(!Plugin::loginReady($saved));
        } finally { update_option('soca_settings',$before,false);delete_option('soca_verified'); }
    });
    test('keys are encrypted and not autoloaded',function(){global $wpdb;expect(count(Keys::get()['items'])===2);$row=$wpdb->get_row("SELECT option_value,autoload FROM {$wpdb->options} WHERE option_name='soca_keys'",ARRAY_A);expect(!str_contains($row['option_value'],'PRIVATE KEY'));expect(in_array($row['autoload'],['off','no','auto-off'],true));});
    test('new callback hook is registered and profile identity controls are absent',function(){
        expect(plugin_basename(SOCA_FILE)==='simple-oauth-cimd-access/simple-oauth-cimd-access.php');
        expect(function_exists('soca_button'));
        expect(wp_next_scheduled('soca_maintenance')!==false);
        expect(has_action('admin_post_nopriv_soca_start',[Plugin::class,'start'])!==false);
        expect(has_action('admin_post_nopriv_soca_callback',[Plugin::class,'callback'])!==false);
        expect(has_action('show_user_profile',[\SOCA\Admin::class,'profile'])===false);
    });
    test('SOCA recovery URLs show validated error references',function(){
        $url=Plugin::recoveryUrl(true);
        expect(str_contains($url,'soca_local=1') && str_contains($url,'soca_error=1'));
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
        } finally { $_GET=$original; }
    });
    test('SOCA HTTP filter accepts trusted integration',function(){
        $calls=[];
        $current=static function($http) use (&$calls) { $calls[]='soca'; return $http; };
        add_filter('soca_http',$current);
        try { expect(Plugin::http() instanceof \SOCA\Http && $calls===['soca']); }
        finally { remove_filter('soca_http',$current); }
    });
    test('single-use and encrypted transactions',function(){
        $browser=Support::random();$state=Support::random();$ref='abcdef123456';$ua=hash('sha256','fixture-agent');Store::createTransaction($state,['verifier'=>'confidential-verifier','audit_ref'=>$ref,'purpose'=>'login','user_agent'=>$ua],$browser);
        $key='soca_tx_'.hash('sha256',$state);$raw=get_transient($key);expect(is_string($raw) && !str_contains($raw,'confidential-verifier'));
        rejects(fn()=>Store::consumeTransaction($state,hash('sha256','different-agent'),$browser),'user_agent_mismatch');
        rejects(fn()=>Store::consumeTransaction($state,$ua,Support::random()),'browser_binding');
        rejects(fn()=>Store::consumeTransaction($state,$ua,''),'browser_binding');
        expect(Store::consumeTransaction($state,$ua,$browser)['verifier']==='confidential-verifier');rejects(fn()=>Store::consumeTransaction($state,$ua,$browser),'state');
        $state=Support::random();Store::createTransaction($state,['user_agent'=>$ua],$browser);delete_transient('soca_tx_'.hash('sha256',$state));rejects(fn()=>Store::consumeTransaction($state,$ua,$browser),'state');
    });
    $ordinary=$make('soca-test-ordinary','ordinary@company.com');$admin=$make('soca-test-admin','privileged@company.com','administrator');
    $ordinary2=$make('soca-test-ordinary2','ordinary2@company.com');
    test('access-rule test keeps its explanation beside the form',function()use($admin){
        $settings=Settings::get(); $originalUser=get_current_user_id(); $originalPost=$_POST; $originalRequest=$_REQUEST; $originalMethod=$_SERVER['REQUEST_METHOD']??null; $bufferLevel=ob_get_level();
        try {
            $configured=$settings; $configured['allow_domains']=['company.com']; $configured['allow_emails']=[]; $configured['deny_domains']=[]; $configured['deny_emails']=[]; $configured['unrestricted']=false;
            update_option('soca_settings',$configured,false); wp_set_current_user($admin);
            $_SERVER['REQUEST_METHOD']='POST';
            $_POST=['operation'=>'policy','test_email'=>'ordinary@company.com','verified'=>'1','_wpnonce'=>wp_create_nonce('soca_settings')];
            $_REQUEST=$_POST;
            ob_start(); \SOCA\Admin::page(); $html=ob_get_clean();
            expect(str_contains($html,'Simple OAuth CIMD Access'));
            expect(str_contains($html,'soca_local=1'));
            expect(str_contains($html,'id="soca-access-rules"') && str_contains($html,'href="#soca-access-rules"'));
            expect(str_contains($html,'action="#soca-access-test"') && str_contains($html,'value="ordinary@company.com"'));
            $result=strpos($html,'id="soca-policy-result"'); $input=strpos($html,'id="test_email"'); $operations=strpos($html,'<h2>Operations</h2>');
            expect($result!==false && $input!==false && $operations!==false && $input<$result && $result<$operations);
            expect(str_contains($html,'Allowed for ordinary@company.com: Domain allow rule matches'));
            $configured['deny_emails']=['ordinary@company.com']; update_option('soca_settings',$configured,false);
            ob_start(); \SOCA\Admin::page(); $denied=ob_get_clean();
            expect(str_contains($denied,'Denied for ordinary@company.com: Email deny rule wins'));
            expect(strpos($denied,'id="soca-policy-result"')>strpos($denied,'id="test_email"'));
        } finally {
            while (ob_get_level()>$bufferLevel) { ob_end_clean(); }
            update_option('soca_settings',$settings,false); wp_set_current_user($originalUser); $_POST=$originalPost; $_REQUEST=$originalRequest;
            if ($originalMethod===null) { unset($_SERVER['REQUEST_METHOD']); } else { $_SERVER['REQUEST_METHOD']=$originalMethod; }
        }
    });
    test('email alone cannot select an existing ordinary or administrator account',function()use($c,$s){
        rejects(fn()=>Identity::resolve($c,$s),'identity_unlinked');
        $c['email']='privileged@company.com'; rejects(fn()=>Identity::resolve($c,$s),'identity_unlinked');
    });
    test('administrator-approved issuer and subject select the linked account',function()use($c,$s,$ordinary,$ordinary2){
        Identity::link($ordinary,$c['iss'],$c['sub']);
        expect(Identity::resolve($c,$s)->ID===$ordinary);
        Identity::link($ordinary,$c['iss'],$c['sub']);
        rejects(fn()=>Identity::link($ordinary2,$c['iss'],$c['sub']),'identity_conflict');
    });
    test('a changed subject cannot silently relink by email',function()use($c,$s){$c['sub']='changed-subject';rejects(fn()=>Identity::resolve($c,$s),'identity_unlinked');});
    test('a changed email never selects a different local account',function()use($c,$s,$ordinary){$c['email']='ordinary2@company.com';expect(Identity::resolve($c,$s)->ID===$ordinary);});
    test('privileged accounts require explicit approval and retain their role',function()use($c,$s,$admin){$c['sub']='wp-admin-sub';$c['email']='privileged@company.com';Identity::link($admin,$c['iss'],$c['sub']);expect(Identity::resolve($c,$s)->ID===$admin);expect(in_array('administrator',get_userdata($admin)->roles,true));});
    Identity::link($ordinary2,$c['iss'],'wp-ordinary2');
    test('registration off; explicit controlled creation is subscriber only',function()use($c,$s,&$created){$c['sub']='wp-new';$c['email']='new@company.com';rejects(fn()=>Identity::resolve($c,$s),'registration_disabled');$s['create_users']=true;$c['role']='administrator';$c['roles']=['administrator'];$u=Identity::resolve($c,$s);$created[]=$u->ID;expect($u->roles===['subscriber']);});
    test('email_verified must be boolean true and denial applies on every login',function()use($c,$s){$c['email_verified']='true';rejects(fn()=>Identity::resolve($c,$s),'access_denied');$c['email_verified']=true;$s['deny_domains']=['company.com'];rejects(fn()=>Identity::resolve($c,$s),'access_denied');});
    $dup=$make('soca-test-duplicate','temporary@company.com');
    test('ambiguous local emails rejected',function()use($c,$s,$dup){global $wpdb;$wpdb->update($wpdb->users,['user_email'=>'ordinary2@company.com'],['ID'=>$dup]);try {$c['email']='ordinary2@company.com';$c['sub']='ambiguous-sub';rejects(fn()=>Identity::resolve($c,$s),'ambiguous_email');} finally {$wpdb->update($wpdb->users,['user_email'=>'temporary@company.com'],['ID'=>$dup]);clean_user_cache($dup);}});
    test('existing custom capabilities remain unchanged',function()use($ordinary2,$c,$s){$u=get_userdata($ordinary2);$u->add_cap('edit_posts');$c['sub']='wp-ordinary2';$c['email']='ordinary2@company.com';expect(Identity::resolve($c,$s)->ID===$ordinary2);expect(get_userdata($ordinary2)->has_cap('edit_posts'));$u->remove_cap('edit_posts');});
    test('unlink revokes identity reuse and all local sessions until explicit approval',function()use($c,$s,$ordinary){
        $token=WP_Session_Tokens::get_instance($ordinary)->create(time()+3600);
        Identity::unlink($ordinary,$c['iss'],$c['sub']);
        expect(!WP_Session_Tokens::get_instance($ordinary)->verify($token));
        $changed=$c;$changed['email']='changed-new@company.com';$allow=$s;$allow['create_users']=true;
        rejects(fn()=>Identity::resolve($changed,$allow),'identity_revoked');
        Identity::link($ordinary,$c['iss'],$c['sub']);expect(Identity::resolve($c,$s)->ID===$ordinary);
    });
    test('failed identity-link storage rolls back a newly created account',function()use($c,$s,$ordinary){
        $c['sub']='rollback-sub';$c['email']='rollback@company.com';$s['create_users']=true;
        $key='soca_link_'.hash('sha256',Support::json([$c['iss'],$c['sub']]));
        $interfere=static function($id)use($key,$ordinary,$c){add_option($key,Store::seal(['issuer'=>$c['iss'],'subject'=>$c['sub'],'user'=>$ordinary]),'',false);};
        add_action('user_register',$interfere);
        try{rejects(fn()=>Identity::resolve($c,$s),'identity_conflict');expect(!email_exists('rollback@company.com'));}
        finally{remove_action('user_register',$interfere);delete_option($key);}
    });
    test('redacted audit keeps failure step, reason and reference',function(){Support::audit('login_started',0,['flow'=>'login','ref'=>'abcdef123456']);Support::audit('login_failed',0,['flow'=>'login','step'=>'token_exchange','reason'=>'token_http_status','ref'=>'abcdef123456','http_status'=>401,'email'=>'secret@company.com','token'=>'access_token']);$log=get_option('soca_audit');$last=end($log);expect($last['event']==='login_failed' && $last['step']==='token_exchange' && $last['reason']==='token_http_status' && $last['ref']==='abcdef123456' && $last['http_status']===401);$json=Support::json($log);expect(!str_contains($json,'@company.com') && !str_contains($json,'wp-test-1') && !str_contains($json,'access_token'));});
    test('public metadata exposes public keys only and no access policy',function(){ $d=Metadata::document(Settings::get(),true);Metadata::noPrivateKeys($d);$j=Support::json($d);expect(!str_contains($j,'allow_domains') && !str_contains($j,'PRIVATE KEY')); });
} finally {
    require_once ABSPATH.'wp-admin/includes/user.php';
    foreach($created as $id) wp_delete_user($id);
    global $wpdb;
    foreach ($wpdb->get_col($wpdb->prepare("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",$wpdb->esc_like('soca_link_').'%')) as $key) { $link=Store::open(get_option($key)); if (in_array($link['user'],$created,true)) delete_option($key); }
    update_option('soca_settings',$before,false);
}
echo ($GLOBALS['passed']??0).' passed, '.($GLOBALS['failed']??0)." failed\n";
if(!empty($GLOBALS['failed'])) \WP_CLI::halt(1);
