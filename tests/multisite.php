<?php
require __DIR__.'/bootstrap.php';
use OCIMD\{Store,Settings,Keys,Identity,Support,Plugin};
expect(is_multisite(),'Multisite installation required');
$site=(int)wp_insert_site(['domain'=>'network.company.com','path'=>'/second/','network_id'=>get_current_network_id()]);
expect($site>1,'Failed to create test site');
$root=get_current_blog_id();$rootSettings=Settings::get();$rootKeys=Keys::get();$rootCipher=get_option('ocimd_keys');
$state=Support::random();$browser=Support::random();Store::createTransaction($state,['browser'=>hash('sha256',$browser)]);
$user=wp_insert_user(['user_login'=>'multisite_fixture','user_pass'=>wp_generate_password(),'user_email'=>'multisite@company.com','role'=>'subscriber']);expect(!is_wp_error($user));
$s=$rootSettings;$s['allow_domains']=['company.com'];$s['deny_domains']=[];$s['deny_emails']=[];
$claims=['iss'=>'https://network-provider.company.com','sub'=>'network-subject','email'=>'multisite@company.com','email_verified'=>true];
Identity::resolve($claims,$s);
switch_to_blog($site);Plugin::initialize();
test('multisite has separate settings, key pairs and encryption context',function()use($rootSettings,$rootKeys,$rootCipher){
    $other=Settings::get();expect($other['revision']!==$rootSettings['revision']);expect(Keys::get()['active']!==$rootKeys['active']);
    $other['provider']='Second site';update_option('ocimd_settings',$other,false);expect(parse_url(home_url('/'),PHP_URL_PATH)==='/second/');rejects(fn()=>Store::open($rootCipher),'encryption');
});
test('site cannot consume another site transaction',function()use($state,$browser){rejects(fn()=>Store::consumeTransaction($state,$browser),'state');});
test('site cannot see another site identity and cannot match a nonmember',function()use($claims,$s,$user){expect(Identity::forUser((int)$user)===[]);rejects(fn()=>Identity::resolve($claims,$s),'account_missing');});
add_user_to_blog($site,(int)$user,'subscriber');
test('site independently binds same exact issuer and subject',function()use($claims,$s,$user){expect(Identity::resolve($claims,$s)->ID===$user);expect(count(Identity::forUser((int)$user))===1);});
test('removal from one site removes only that site binding',function()use($user,$site){require_once ABSPATH.'wp-admin/includes/user.php';wp_delete_user((int)$user);expect(Identity::forUser((int)$user)===[]);});
restore_current_blog();
test('original site settings, key and identity remain intact',function()use($rootSettings,$rootKeys,$user,$state,$browser){expect(Settings::get()===$rootSettings);expect(Keys::get()['active']===$rootKeys['active']);expect(count(Identity::forUser((int)$user))===1);Store::consumeTransaction($state,$browser);});
test('a network spam flag prevents authentication of an existing binding',function()use($claims,$s,$user){
    global $wpdb;$wpdb->update($wpdb->users,['spam'=>1],['ID'=>$user]);clean_user_cache($user);rejects(fn()=>Identity::resolve($claims,$s),'account_blocked');
    $wpdb->update($wpdb->users,['spam'=>0],['ID'=>$user]);clean_user_cache($user);
});
require_once ABSPATH.'wp-admin/includes/ms.php';wpmu_delete_user((int)$user);expect(Identity::forUser((int)$user)===[],'Network deletion must remove identity');wp_delete_site($site);
echo ($GLOBALS['passed']??0).' passed, '.($GLOBALS['failed']??0)." failed\n";if(!empty($GLOBALS['failed']))WP_CLI::halt(1);
