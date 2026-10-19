<?php
if(wp_get_environment_type()!=='local')WP_CLI::halt(1);
$job=$args[0]??'';
try {
    if($job==='transaction') {
        $r=get_option('soca_concurrency');SOCA\Store::consumeTransaction($r['state'],$r['user_agent']);echo 'consumed';
    } else {
        $s=SOCA\Settings::get();$s['allow_domains']=['company.com'];$s['create_users']=true;
        $user=SOCA\Identity::resolve(['iss'=>'https://concurrency.company.com','sub'=>'race-sub','email'=>'race@company.com','email_verified'=>true],$s);
        echo 'user:'.$user->ID;
    }
} catch(SOCA\Failure $e) { echo 'rejected:'.$e->reason; }
