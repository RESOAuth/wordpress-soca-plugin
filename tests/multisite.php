<?php
require __DIR__.'/bootstrap.php';
use SOCA\{Store,Settings,Keys,Identity,Support,Plugin};
expect(is_multisite(),'Multisite installation required');
$site=(int)wp_insert_site(['domain'=>'network.company.com','path'=>'/second/','network_id'=>get_current_network_id()]);
expect($site>1,'Failed to create test site');
$root=get_current_blog_id();$rootSettings=Settings::get();$rootKeys=Keys::get();$rootCipher=get_option('soca_keys');
$browser=Support::random();$state=Support::random();$userAgent=hash('sha256','fixture-agent');Store::createTransaction($state,['verifier'=>'fixture','user_agent'=>$userAgent],$browser);
$user=wp_insert_user(['user_login'=>'multisite_fixture','user_pass'=>wp_generate_password(),'user_email'=>'multisite@company.com','role'=>'subscriber']);expect(!is_wp_error($user));
$s=$rootSettings;$s['issuer']='https://network-provider.company.com';$s['allow_domains']=['company.com'];$s['deny_domains']=[];$s['deny_emails']=[];
$claims=['iss'=>'https://network-provider.company.com','sub'=>'network-subject','email'=>'multisite@company.com','email_verified'=>true];
Identity::link((int)$user,$claims['iss'],$claims['sub']);Identity::resolve($claims,$s);
switch_to_blog($site);Plugin::initialize();
test('multisite has separate settings, key pairs and encryption context',function()use($rootSettings,$rootKeys,$rootCipher){
    $other=Settings::get();expect($other['revision']!==$rootSettings['revision']);expect(Keys::get()['active']!==$rootKeys['active']);
    $other['provider']='Second site';update_option('soca_settings',$other,false);expect(parse_url(home_url('/'),PHP_URL_PATH)==='/second/');rejects(fn()=>Store::open($rootCipher),'encryption');
});
test('site cannot consume another site transaction',function()use($state,$userAgent,$browser){rejects(fn()=>Store::consumeTransaction($state,$userAgent,$browser),'state');});
test('site cannot authenticate a matching network user who is not a member',function()use($claims,$s){rejects(fn()=>Identity::resolve($claims,$s),'identity_unlinked');});
add_user_to_blog($site,(int)$user,'subscriber');
Identity::link((int)$user,$claims['iss'],$claims['sub']);
test('site independently resolves the approved identity',function()use($claims,$s,$user){expect(Identity::resolve($claims,$s)->ID===$user);$changed=$claims;$changed['sub']='new-pairwise-subject';rejects(fn()=>Identity::resolve($changed,$s),'identity_unlinked');});
test('removal from one site prevents login on that site',function()use($user,$claims,$s){require_once ABSPATH.'wp-admin/includes/user.php';wp_delete_user((int)$user);rejects(fn()=>Identity::resolve($claims,$s),'account_missing');});
restore_current_blog();
test('original site settings, key and account access remain intact',function()use($rootSettings,$rootKeys,$user,$state,$userAgent,$browser,$claims,$s){expect(Settings::get()===$rootSettings);expect(Keys::get()['active']===$rootKeys['active']);expect(Identity::resolve($claims,$s)->ID===$user);Store::consumeTransaction($state,$userAgent,$browser);});
test('a network spam flag prevents authentication of the matching account',function()use($claims,$s,$user){
    global $wpdb;$wpdb->update($wpdb->users,['spam'=>1],['ID'=>$user]);clean_user_cache($user);rejects(fn()=>Identity::resolve($claims,$s),'account_blocked');
    $wpdb->update($wpdb->users,['spam'=>0],['ID'=>$user]);clean_user_cache($user);
});
require_once ABSPATH.'wp-admin/includes/ms.php';wpmu_delete_user((int)$user);rejects(fn()=>Identity::resolve($claims,$s),'account_missing');delete_option('soca_link_'.hash('sha256',Support::json([$claims['iss'],$claims['sub']])));switch_to_blog($site);delete_option('soca_link_'.hash('sha256',Support::json([$claims['iss'],$claims['sub']])));restore_current_blog();wp_delete_site($site);
echo ($GLOBALS['passed']??0).' passed, '.($GLOBALS['failed']??0)." failed\n";if(!empty($GLOBALS['failed']))WP_CLI::halt(1);
