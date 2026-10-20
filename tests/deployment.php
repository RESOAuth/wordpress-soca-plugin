<?php
// Separate process: PHP deployment constants cannot be removed within a request.
require __DIR__ . '/bootstrap.php';
use SOCA\{Settings,Support,Plugin};
Support::need(wp_get_environment_type()==='local','test_environment','Disposable local installation required.');
$stored=get_option('soca_settings');$before=Settings::get();
define('SOCA_CONFIG',['issuer'=>'https://locked.company.com','enabled'=>false,'allow_domains'=>['*.company.com'],'client_name'=>'Deployment branding']);
try {
    test('deployment configuration overrides previously saved settings and locks writes',function()use($stored){
        $s=Settings::get();expect($s['issuer']===SOCA_CONFIG['issuer'] && $s['allow_domains']===['*.company.com'] && !$s['enabled']);
        Settings::save(['issuer'=>'http://invalid','enabled'=>true,'allow_domains'=>'*company.com','button'=>'Deployment test']);
        $s=Settings::get();expect($s['issuer']===SOCA_CONFIG['issuer'] && !$s['enabled'] && $s['button']==='Deployment test');
        expect(get_option('soca_settings')['issuer']===$stored['issuer']);
        $revision=$s['revision'];expect(Settings::get()['revision']===$revision);
    });
    test('deployment fields render disabled in the WordPress settings screen',function(){
        $user=get_current_user_id();wp_set_current_user(1);
        try{ob_start();\SOCA\Admin::page();$html=ob_get_clean();
            expect((bool)preg_match('/name="issuer"[^>]* disabled/',$html));
            expect((bool)preg_match('/name="enabled"[^>]* disabled/',$html));
            expect((bool)preg_match('/name="allow_domains"[^>]* disabled/',$html));
        }finally{wp_set_current_user($user);}
    });
} finally {update_option('soca_settings',$stored,false);}
echo ($GLOBALS['passed']??0).' passed, '.($GLOBALS['failed']??0)." failed\n";
if(!empty($GLOBALS['failed']))\WP_CLI::halt(1);
