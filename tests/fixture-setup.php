<?php
if (wp_get_environment_type()!=='local' || !defined('SOCA_TEST_FIXTURES') || !SOCA_TEST_FIXTURES) WP_CLI::error('Disposable local install required.');
$s=SOCA\Settings::get();delete_option('soca_verified');
$s['enabled']=true;$s['automatic']=false;$s['issuer']='https://provider.company.com';$s['mode']='proxy';$s['proxy']='https://proxy.company.com/%s/add_client_id/client.json';$s['key_mode']='inline';$s['assertion_audience']='issuer';$s['allow_domains']=['company.com'];$s['allow_emails']=[];$s['deny_domains']=[];$s['deny_emails']=[];$s['unrestricted']=false;$s['create_users']=true;$s['revision']=SOCA\Support::random();update_option('soca_settings',$s,false);
update_option('soca_fixture_scenario','valid',false);update_option('soca_fixture_email','browser@company.com',false);update_option('soca_fixture_sub','browser-sub',false);
WP_CLI::success('Synthetic provider enabled for disposable tests only.');
