<?php
if(wp_get_environment_type()!=='local')WP_CLI::halt(1);
$job=$args[0]??'';
try {
    if($job==='transaction') {
        $r=get_option('soca_concurrency');SOCA\Store::consumeTransaction($r['state'],$r['user_agent'],$r['browser']);echo 'consumed';
    } elseif($job==='link') {
        SOCA\Identity::link((int)$args[1],'https://concurrency.company.com','link-race-sub');echo 'linked:'.$args[1];
    } else {
        $s=SOCA\Settings::get();$s['issuer']='https://concurrency.company.com';$s['allow_domains']=['company.com'];$s['create_users']=true;
        $user=SOCA\Identity::resolve(['iss'=>'https://concurrency.company.com','sub'=>'race-sub','email'=>'race@company.com','email_verified'=>true],$s);
        echo 'user:'.$user->ID;
    }
} catch(SOCA\Failure $e) { echo 'rejected:'.$e->reason; }
