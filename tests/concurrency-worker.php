<?php
if(wp_get_environment_type()!=='local')WP_CLI::halt(1);
$job=$args[0]??'';
try {
    if($job==='transaction') {
        $r=get_option('ocimd_concurrency');OCIMD\Store::consumeTransaction($r['state'],$r['browser']);echo 'consumed';
    } else {
        $s=OCIMD\Settings::get();$s['allow_domains']=['company.com'];$s['create_users']=true;
        $user=OCIMD\Identity::resolve(['iss'=>'https://concurrency.company.com','sub'=>'race-sub','email'=>'race@company.com','email_verified'=>true],$s);
        echo 'user:'.$user->ID;
    }
} catch(OCIMD\Failure $e) { echo 'rejected:'.$e->reason; }
