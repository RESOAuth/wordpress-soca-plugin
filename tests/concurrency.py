#!/usr/bin/env python3
import concurrent.futures, os, subprocess
engine=os.environ.get('CONTAINER_ENGINE','podman')
container=os.environ.get('SOCA_CONTAINER','soca-local_wordpress_1')
def cli(*args):
    return subprocess.check_output([engine,'exec','-u','www-data',container,'php','/tmp/wp-cli.phar',*args],text=True).strip()
cli('eval',"$state=SOCA\\Support::random();$ua=hash('sha256','fixture-agent');$browser=SOCA\\Support::random();SOCA\\Store::createTransaction($state,['verifier'=>'fixture','user_agent'=>$ua],$browser);update_option('soca_concurrency',['state'=>$state,'user_agent'=>$ua,'browser'=>$browser],false);")
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    results=list(pool.map(lambda _:cli('eval-file','/tmp/tests/concurrency-worker.php','transaction'),range(2)))
assert results.count('consumed')==1 and sum(r.startswith('rejected:') for r in results)==1,results
print('PASS concurrent callback consumption has exactly one winner')
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    results=list(pool.map(lambda _:cli('eval-file','/tmp/tests/concurrency-worker.php','identity'),range(2)))
assert results[0].startswith('user:') and results[0]==results[1],results
assert cli('eval',"global $wpdb;echo $wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->users} WHERE user_email='race@company.com'\");")=='1'
cli('eval',"require_once ABSPATH.'wp-admin/includes/user.php';wp_delete_user("+results[0].split(':')[1]+");delete_option('soca_link_'.hash('sha256',SOCA\\Support::json(['https://concurrency.company.com','race-sub'])));delete_option('soca_concurrency');")
print('PASS concurrent linked-account creation produces exactly one account')

users=[cli('user','create','soca-link-race-'+str(i),'link-race-'+str(i)+'@company.com','--role=subscriber','--porcelain') for i in range(2)]
try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda user:cli('eval-file','/tmp/tests/concurrency-worker.php','link',user),users))
    assert sum(r.startswith('linked:') for r in results)==1 and results.count('rejected:identity_conflict')==1,results
    print('PASS concurrent conflicting identity links have exactly one owner')
finally:
    cli('eval',"delete_option('soca_link_'.hash('sha256',SOCA\\Support::json(['https://concurrency.company.com','link-race-sub'])));")
    for user in users: cli('user','delete',user,'--yes')
