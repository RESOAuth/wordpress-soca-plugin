<?php
require __DIR__ . '/bootstrap.php';
use SOCA\{Settings,Support,Plugin};
Support::need(wp_get_environment_type()==='local','test_environment','Disposable local installation required.');
$epoch=get_option('soca_epoch','');$s=Settings::get();
update_option('soca_verified',['profile'=>Settings::profile($s)],false);
define('SOCA_DISABLED',true);
test('emergency disable invalidates activation and pending-transaction revisions once',function()use($epoch,$s){
    $disabled=Settings::get();$first=get_option('soca_epoch');
    expect(Settings::disabled() && $first!==$epoch && $disabled['revision']!==$s['revision']);
    expect(!get_option('soca_verified') && !Plugin::loginReady($disabled));
    Settings::get();expect(get_option('soca_epoch')===$first);
});
echo ($GLOBALS['passed']??0).' passed, '.($GLOBALS['failed']??0)." failed\n";
if(!empty($GLOBALS['failed']))\WP_CLI::halt(1);
