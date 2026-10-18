#!/usr/bin/env python3
import concurrent.futures, os, subprocess
engine=os.environ.get('CONTAINER_ENGINE','podman')
container=os.environ.get('SOCA_CONTAINER','soca-local_wordpress_1')
def cli(*args):
    return subprocess.check_output([engine,'exec','-u','www-data',container,'php','/tmp/wp-cli.phar',*args],text=True).strip()
cli('eval',"$state=OCIMD\\Support::random();$browser=OCIMD\\Support::random();OCIMD\\Store::createTransaction($state,['browser'=>hash('sha256',$browser)]);update_option('ocimd_concurrency',['state'=>$state,'browser'=>$browser],false);")
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    results=list(pool.map(lambda _:cli('eval-file','/tmp/tests/concurrency-worker.php','transaction'),range(2)))
assert results.count('consumed')==1 and sum(r.startswith('rejected:') for r in results)==1,results
print('PASS concurrent callback consumption has exactly one winner')
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    results=list(pool.map(lambda _:cli('eval-file','/tmp/tests/concurrency-worker.php','identity'),range(2)))
assert results[0].startswith('user:') and results[0]==results[1],results
assert cli('eval',"global $wpdb;echo $wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->users} WHERE user_email='race@company.com'\");")=='1'
cli('eval',"require_once ABSPATH.'wp-admin/includes/user.php';wp_delete_user("+results[0].split(':')[1]+");delete_option('ocimd_concurrency');")
print('PASS concurrent email-based creation produces exactly one account')
