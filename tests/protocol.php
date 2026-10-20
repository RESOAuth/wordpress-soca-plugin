<?php
require __DIR__ . '/bootstrap.php';
use SOCA\{Support,Policy,Http,Settings,Metadata,Provider,Keys,Store};
use SOCA\Vendor\JWT\{JWT,JWK};

test('PKCE RFC 7636 vector',function(){ expect(Support::b64(hash('sha256','dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',true))==='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'); });
test('strict base64url and JSON limits',function(){ foreach (['a=','a+','a/','a','%%%'] as $bad) rejects(fn()=>Support::unb64($bad)); rejects(fn()=>Support::object('[]')); rejects(fn()=>Support::object(str_repeat(' ',262145))); expect(Support::unb64('e30')==='{}'); });
test('authorization codes preserve protocol characters and reject controls',function(){
    expect(Support::authorizationCode('abc+/=._~-')==='abc+/=._~-');
    foreach (['', "a\r\nb", "a\tb", 'abc' . chr(127)] as $bad) rejects(fn()=>Support::authorizationCode($bad),'code');
});
test('public callback, metadata and JWKS routes use the new names',function(){
    $s=settings();
    expect(Metadata::callback()==='https://www.client.company.com/wp-admin/admin-post.php?action=soca_callback');
    expect(Metadata::url()==='https://www.client.company.com/?soca_doc=client');
    expect(Metadata::jwksUrl()==='https://www.client.company.com/?soca_doc=jwks');
    expect(Metadata::template($s)['redirect_uris']===[Metadata::callback()]);
    expect(Metadata::template($s)['jwks_uri']===Metadata::jwksUrl());
    expect(Metadata::document($s,true)['client_id']===Metadata::url());
});
test('proxy placeholder and percent encoding',function(){
    $s=settings(); $s['mode']='proxy'; $s['proxy']='https://proxy.company.com/%s/a%20b?x=%2F';
    $u=Metadata::clientId($s); expect(str_ends_with($u,'/a%20b?x=%2F')); $p=explode('/',parse_url($u,PHP_URL_PATH))[1];
    $d=Support::object(Support::unb64($p)); expect(!isset($d['client_id']) && isset($d['redirect_uris']));
    foreach (['https://%s.company.com/a','https://proxy.company.com/a?x=%s','https://proxy.company.com/%s/%s','https://user@proxy.company.com/%s','https://proxy.company.com/%s#x','http://proxy.company.com/%s','https://proxy.company.com/%s/%q','https://proxy.company.com/%s/%2e%2e'] as $bad) rejects(fn()=>Metadata::proxyTemplate($bad));
});
test('URL/SSRF literals and private addresses',function(){
    foreach (['http://provider.company.com/a','https://localhost/a','https://127.0.0.1/a','https://[::1]/a','https://x.local/a','https://user:pass@provider.company.com/a',"https://provider.company.com/\r\nx"] as $bad) rejects(fn()=>Http::url($bad));
    foreach (['127.0.0.1','10.0.0.1','172.16.0.1','192.168.1.1','169.254.169.254','100.64.1.2','192.0.2.1','198.51.100.1','203.0.113.1','224.0.0.1','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::1','2001:0db8::1','192.88.99.1','2001::1','2002:7f00:1::'] as $ip) expect(!Http::publicIp($ip),'accepted ' . $ip);
    expect(Http::publicIp('8.8.8.8') && Http::publicIp('2606:4700:4700::1111'));
});
test('bounded HTTP cache handling',function(){ expect(Http::ttl(['cache-control'=>'public, max-age=9000','age'=>'20'],3600)===3580); expect(Http::ttl(['cache-control'=>'no-store'],3600)===0); expect(Http::ttl(['cache-control'=>'max-age=0'],3600)===0); });
test('policy deny overrides allow; OR lists; exact domains',function(){
    $s=settings();$s['allow_domains']=['company.com'];$s['allow_emails']=['friend@other.com'];$s['deny_emails']=['blocked@company.com'];
    expect(!Policy::test($s,'blocked@company.com',true)[0]); expect(Policy::test($s,'friend@other.com',true)[0]); expect(Policy::test($s,'USER@COMPANY.COM',true)[0]);
    foreach (['user@sub.company.com','user@evilcompany.com','user@company.com.evil.org'] as $e) expect(!Policy::test($s,$e,true)[0]);
    expect(!Policy::test($s,'user@company.com',false)[0]);$s['deny_domains']=['company.com'];expect(!Policy::test($s,'user@company.com',true)[0]);
});
test('allow any verified email overrides allowlists but never deny rules',function(){
    $s=settings();$s['allow_domains']=[];expect(!Policy::test($s,'user@company.com',true)[0]);$s['unrestricted']=true;expect(Policy::test($s,'user@company.com',true)[0]);
    $s['allow_domains']=['company.com'];expect(Policy::test($s,'user@other.com',true)[0]);$s['deny_domains']=['other.com'];expect(!Policy::test($s,'user@other.com',true)[0]);
    expect(Policy::entries("Company.com, company.com;other.com\n",false)===['company.com','other.com']);
    foreach (['*.company.com','company.com.','company.com/','@company.com','localhost','127.0.0.1','аpple.com'] as $v) rejects(fn()=>Policy::domain($v));
});
test('wildcard domain rules respect DNS label boundaries and deny precedence',function(){
    $s=settings();$s['allow_domains']=['*.example.com'];$s['deny_domains']=['*.blocked.example.com'];
    expect(Policy::test($s,'a@x.example.com',true)[0]);expect(Policy::test($s,'a@a.b.example.com',true)[0]);
    expect(!Policy::test($s,'a@example.com',true)[0]);expect(!Policy::test($s,'a@badexample.com',true)[0]);
    expect(!Policy::test($s,'a@x.blocked.example.com',true)[0]);
    expect(Policy::entries('*.EXAMPLE.COM example.com',false)===['*.example.com','example.com']);
    foreach(['*example.com','*.*.example.com','a.*.example.com','*.com','https://example.com','a@example.com','a..example.com']as$rule) rejects(fn()=>Policy::entries($rule,false),'domain');
    $s['deny_domains']=['*example.com'];rejects(fn()=>Policy::test($s,'a@x.example.com',true),'domain');
    $s['deny_domains']=[];$s['allow_domains']=['example.com'];expect(!Policy::test($s,'a@x.example.com',true)[0]);
});
test('metadata inherits available branding and legal URLs in both modes',function(){
    update_option('test_icon','https://www.client.company.com/icon.png');update_option('test_privacy','https://www.client.company.com/privacy/');
    try {
        foreach(['self','proxy']as$mode){
            $s=settings();$s['mode']=$mode;$doc=Metadata::document($s);
            expect($doc['logo_uri']==='https://www.client.company.com/icon.png' && $doc['policy_uri']==='https://www.client.company.com/privacy/' && !isset($doc['tos_uri']));
            $s['client_name']='Custom site';$s['logo_uri']='https://www.client.company.com/brand.png';$s['tos_uri']='https://www.client.company.com/terms/';
            $doc=Metadata::document($s);expect($doc['client_name']==='Custom site' && $doc['logo_uri']===$s['logo_uri'] && $doc['tos_uri']===$s['tos_uri']);
        }
        update_option('test_icon','http://www.client.company.com/icon.png');expect(!isset(Metadata::template(settings())['logo_uri']));
    }finally{delete_option('test_icon');delete_option('test_privacy');}
});
test('proxy encoding is deterministic, excludes client_id and rejects oversized metadata',function(){
    $s=settings();$s['mode']='proxy';$s['key_mode']='inline';$id=Metadata::clientId($s);expect(Metadata::clientId($s)===$id);
    $encoded=substr($id,strlen('https://dynamic-cimd.resoauth.cloud/cimd/'));$payload=Support::object(Support::unb64($encoded));
    expect(!isset($payload['client_id']) && count($payload['jwks']['keys'])===2);
    $s['logo_uri']='https://www.client.company.com/'.str_repeat('a',3000);$s['policy_uri']=$s['logo_uri'];$s['tos_uri']=$s['logo_uri'];$s=Settings::validate($s);rejects(fn()=>Metadata::clientId($s),'proxy_size');
});
test('public HTTPS defaults require activation before self-hosted login for the exact hostname',function(){ $s=Settings::defaults();expect($s['allow_domains']===['client.company.com'] && $s['mode']==='self' && $s['key_mode']==='uri' && !$s['enabled'] && !$s['unrestricted'] && $s['assertion_audience']==='issuer' && $s['button']==='Continue with SSO' && $s['proxy']==='https://dynamic-cimd.resoauth.cloud/cimd/%s'); });
test('settings initialize with current names and defaults',function(){
    $s=Settings::get();
    expect($s['assertion_audience']==='issuer' && is_array(get_option('soca_settings')));
    delete_option('soca_settings');
});
test('local destinations cannot escape origin or point into login loop',function(){ foreach (['//evil.com','https://evil.com/','https://www.client.company.com.evil.org/', 'https://www.client.company.com:444/a','https://www.client.company.com/wp-login.php'] as $v) expect(Support::destination($v)===home_url('/'));expect(Support::destination('/welcome')==='https://www.client.company.com/welcome'); });
test('discovery OIDC and capability failures never downgrade',function(){
    $s=settings();$d=discovery();Provider::validateDiscovery($s,$d);
    foreach (['issuer','response_types_supported','code_challenge_methods_supported','token_endpoint_auth_methods_supported','token_endpoint_auth_signing_alg_values_supported','id_token_signing_alg_values_supported','subject_types_supported'] as $field) { $bad=$d;unset($bad[$field]);rejects(fn()=>Provider::validateDiscovery($s,$bad)); }
    unset($d['client_id_metadata_document_supported']);Provider::validateDiscovery($s,$d);
    foreach ([false,null,'true'] as $invalid) { $d['client_id_metadata_document_supported']=$invalid;rejects(fn()=>Provider::validateDiscovery($s,$d),'cimd_support'); }
});
test('client document exact identity and private material',function(){
    $d=Metadata::document(settings());Metadata::validateDocument($d,$d);$bad=$d;$bad['client_id'].='/';rejects(fn()=>Metadata::validateDocument($d,$bad),'client_document');
    $bad=$d;$bad['jwks']=['keys'=>[['d'=>'secret']]];rejects(fn()=>Metadata::validateDocument($d,$bad));
    $bad=$d;$bad['redirect_uris']=['https://evil.com/cb'];rejects(fn()=>Metadata::validateDocument($d,$bad));
});
test('client key storage encryption, tampering, thumbprints and JWT assertion',function(){
    $keys=Keys::get();expect(count($keys['items'])===2);expect(!str_contains(get_option('soca_keys'),'PRIVATE KEY'));Metadata::noPrivateKeys(Keys::jwks());
    $pub=$keys['items'][0]['public'];$ordered=array_intersect_key($pub,array_flip(['crv','kty','x','y']));expect($pub['kid']===Support::b64(hash('sha256',Support::json($ordered),true)));
    $sealed=Store::seal(['private'=>'secret']);expect(Store::open($sealed)['private']==='secret');$sealed[20]=$sealed[20]==='A'?'B':'A';rejects(fn()=>Store::open($sealed),'encryption');
    $jwt=Keys::assertion($keys['active'],'https://client.company.com/meta','https://provider.company.com/token');$parsed=JWT::decode($jwt,JWK::parseKeySet(Keys::jwks(),'ES256'));expect($parsed->iss===$parsed->sub && $parsed->exp-$parsed->iat===60 && strlen($parsed->jti)===43);
});
test('generated P-256 JWKs retain leading-zero coordinate bytes',function(){
    $sawShort = false;
    for ($i=0; $i<1000; $i++) {
        $key = Keys::generate(time());
        $details = openssl_pkey_get_details(openssl_pkey_get_private($key['private']))['ec'];
        if (strlen($details['x'])===32 && strlen($details['y'])===32) { continue; }
        $sawShort = true;
        expect(strlen(Support::unb64($key['public']['x']))===32 && strlen(Support::unb64($key['public']['y']))===32);
        $jwt = JWT::encode(['sub'=>'padding-test'], $key['private'], 'ES256', $key['kid']);
        expect(JWT::decode($jwt, JWK::parseKey($key['public'], 'ES256'))->sub==='padding-test');
        break;
    }
    expect($sawShort, 'could not generate a leading-zero P-256 coordinate');
});
test('weekly rollover publishes first, retains old and stages only after overlap',function(){
    $k=Keys::get();$t=1000000;$k['since']=$t;foreach($k['items'] as &$i){$i['published']=$t;$i['context']='c';$i['retired']=0;}unset($i);$original=$k['active'];
    expect(Keys::advance($k,$t+604799,86400,'c')['active']===$original);
    $next=Keys::advance($k,$t+604800,86400,'c');expect($next['active']!==$original && count($next['items'])===2);
    expect(Keys::advance($next,$t+604800+86400+719,86400,'c')['items']===$next['items']);
    $stage=Keys::advance($next,$t+604800+86400+720,86400,'c');expect(count($stage['items'])===2 && !in_array($original,array_column($stage['items'],'kid'),true));
    $late=$k;$late['items'][1]['published']=$t+604800;expect(Keys::advance($late,$t+604800,86400,'c')['active']===$original);expect(Keys::advance($late,$t+604800+86400,86400,'c')['active']!==$original);
    expect(Keys::advance($k,$t+1000000,86400,'different-context')['active']===$original);
});
test('signed ES256 token and strict claim failures',function(){
    $key=Keys::generate(time());$tx=transaction();$c=claims($tx);$http=new FixtureHttp(fn()=>['json'=>['keys'=>[$key['public']]],'headers'=>['cache-control'=>'no-store']]);$p=new Provider($http);
    $sign=fn($c,$headers=[])=>JWT::encode($c,$key['private'],'ES256',$key['kid'],$headers);
    expect($p->verify($sign($c),$tx)['sub']==='subject-1');
    foreach (['iss'=>'https://evil.com','aud'=>'wrong','azp'=>'wrong','nonce'=>'wrong','sub'=>'','exp'=>time()-120,'iat'=>time()+120,'nbf'=>time()+120,'auth_time'=>time()+120,'email_verified'=>'true'] as $field=>$value) {
        $bad=$c;$bad[$field]=$value;
        if ($field==='email_verified') { expect(Policy::test(settings(),$bad['email'],$bad['email_verified']===true)[0]===false); } else rejects(fn()=>$p->verify($sign($bad),$tx));
    }
    foreach(['exp','iat'] as $f){$bad=$c;$bad[$f]=(string)$bad[$f];rejects(fn()=>$p->verify($sign($bad),$tx),'jwt_time');}
    $bad=$c;$bad['aud']=[$tx['client'],'other'];rejects(fn()=>$p->verify($sign($bad),$tx),'azp');$bad['azp']=$tx['client'];$p->verify($sign($bad),$tx);
    foreach(['jku'=>'https://evil.com/jwks','jwk'=>$key['public'],'crit'=>['x'],'typ'=>'at+jwt'] as $f=>$v) rejects(fn()=>$p->verify($sign($c,[$f=>$v]),$tx));
    $tx['reauth']=true;rejects(fn()=>$p->verify($sign($c),$tx),'reauth');$c['auth_time']=time();$p->verify($sign($c),$tx);
});
test('RS256 profile uses independent provider key',function(){
    $rsa=openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);openssl_pkey_export($rsa,$pem);$d=openssl_pkey_get_details($rsa)['rsa'];$jwk=['kty'=>'RSA','kid'=>'rsa-key','n'=>Support::b64($d['n']),'e'=>Support::b64($d['e']),'alg'=>'RS256'];
    $tx=transaction();$tx['settings']['id_alg']='RS256';$p=new Provider(new FixtureHttp(fn()=>['json'=>['keys'=>[$jwk]],'headers'=>['cache-control'=>'no-store']]));expect($p->verify(JWT::encode(claims($tx),$pem,'RS256','rsa-key'),$tx)['sub']==='subject-1');
});
test('algorithm confusion and client/provider key separation',function(){
    $provider=Keys::generate(time());$client=Keys::get()['items'][0];$tx=transaction();$tx['discovery']['jwks_uri']='https://provider.company.com/separate';
    $p=new Provider(new FixtureHttp(fn()=>['json'=>['keys'=>[$provider['public']]],'headers'=>['cache-control'=>'no-store']]));
    rejects(fn()=>$p->verify(JWT::encode(claims($tx),str_repeat('x',32),'HS256','x'),$tx),'jwt_algorithm');
    rejects(fn()=>$p->verify(JWT::encode(claims($tx),$client['private'],'ES256',$client['kid']),$tx),'key_missing');
});
test('unknown kid gets one controlled refresh; repeated refresh throttled',function(){
    $old=Keys::generate(time());$new=Keys::generate(time());$tx=transaction();$tx['discovery']['jwks_uri']='https://provider.company.com/rotation';$n=0;
    $http=new FixtureHttp(function()use(&$n,$old,$new){return ['json'=>['keys'=>[(++$n===1?$old:$new)['public']]],'headers'=>['cache-control'=>'max-age=3600']];});$p=new Provider($http);
    expect($p->verify(JWT::encode(claims($tx),$new['private'],'ES256',$new['kid']),$tx)['sub']==='subject-1');expect(count($http->calls)===2);
    rejects(fn()=>$p->verify(JWT::encode(claims($tx),$old['private'],'ES256',$old['kid']),$tx),'jwks_refresh');expect(count($http->calls)===2);
});
test('token endpoint assertion, PKCE, hashes and UserInfo subject binding',function(){
    $k=Keys::generate(time());$tx=transaction();$tx['settings']['assertion_audience']='token_endpoint';$c=claims($tx);unset($c['email'],$c['email_verified']);$c['at_hash']=Support::b64(substr(hash('sha256','access-token',true),0,16));$c['c_hash']=Support::b64(substr(hash('sha256','auth-code',true),0,16));
    $wrong=false;$http=new FixtureHttp(function($url,$form,$bearer)use($k,$tx,&$c,&$wrong){
        if(str_ends_with($url,'/token')) {expect($form['code_verifier']===$tx['verifier']);expect($form['redirect_uri']===$tx['callback']);$a=JWT::decode($form['client_assertion'],JWK::parseKeySet(Keys::jwks(),'ES256'));expect($a->aud===$tx['discovery']['token_endpoint'] && $a->sub===$tx['client']);return ['json'=>['id_token'=>JWT::encode($c,$k['private'],'ES256',$k['kid']),'access_token'=>'access-token','token_type'=>'Bearer'],'headers'=>[]];}
        if(str_ends_with($url,'/userinfo')){expect($bearer==='access-token');return ['json'=>['sub'=>$wrong?'attacker':'subject-1','email'=>'user@company.com','email_verified'=>true],'headers'=>[]];}
        return ['json'=>['keys'=>[$k['public']]],'headers'=>['cache-control'=>'no-store']];
    });$p=new Provider($http);expect($p->exchange($tx,'auth-code')['email_verified']===true);$c['email']='signed-other@company.com';rejects(fn()=>$p->exchange($tx,'auth-code'),'email_claims');unset($c['email']);$wrong=true;rejects(fn()=>$p->exchange($tx,'auth-code'),'userinfo_subject');rejects(fn()=>$p->exchange($tx,'wrong-code'),'token_hash');
});
test('issuer audience is used when configured for client authentication',function(){
    $tx=transaction();$providerKey=Keys::generate(time());
    $http=new FixtureHttp(function($url,$form)use($tx,$providerKey){
        if($url===$tx['discovery']['token_endpoint']) {
            $a=JWT::decode($form['client_assertion'],JWK::parseKeySet(Keys::jwks(),'ES256'));
            expect($a->aud===$tx['settings']['issuer'] && $a->iss===$tx['client'] && $a->sub===$tx['client']);
            return ['json'=>['id_token'=>JWT::encode(claims($tx),$providerKey['private'],'ES256',$providerKey['kid'])],'headers'=>[]];
        }
        return ['json'=>['keys'=>[$providerKey['public']]],'headers'=>['cache-control'=>'no-store']];
    });
    expect((new Provider($http))->exchange($tx,'test-code')['sub']==='subject-1');
});
test('token HTTP refusal has a distinct redacted audit reason',function(){
    $tx=transaction();$http=new FixtureHttp(fn()=>throw new \SOCA\Failure('http_status','HTTPS endpoint must return 200 (received 401).',['http_status'=>401]));
    try {(new Provider($http))->exchange($tx,'test-code');throw new \RuntimeException('Expected token refusal.');}
    catch (\SOCA\Failure $e) {expect($e->reason==='token_http_status' && $e->diagnostics['http_status']===401);}
});
test('query values are encoded without parameter injection',function(){
    $url=Support::query('https://provider.company.com/auth?tenant=one',['client_id'=>'https://proxy.company.com/meta?a=1&b=2','redirect_uri'=>'https://client.company.com/cb?action=oauth&x=y']);
    parse_str(parse_url($url,PHP_URL_QUERY),$q);expect(count($q)===3 && $q['client_id']==='https://proxy.company.com/meta?a=1&b=2');
    $d=discovery();$d['authorization_endpoint'].='?client_id=injected';rejects(fn()=>Provider::validateDiscovery(settings(),$d),'authorization_query');
});
test('reducing cache setting cannot shorten an already promised key retention',function(){
    $k=Keys::get();$t=1000000;$k['since']=$t;foreach($k['items']as &$v){$v['published']=$t;$v['context']='retention';$v['retired']=0;}unset($v);
    $k=Keys::advance($k,$t+604800,86400,'retention');$old=array_values(array_filter($k['items'],fn($x)=>$x['retired']>0))[0];
    $same=Keys::advance($k,$t+604800+3600+720,3600,'retention');expect(in_array($old['kid'],array_column($same['items'],'kid'),true));
});
test('new active keys must be observed at their current publication context',function(){
    expect(!Keys::ready('new-publication'));Keys::published('new-publication',array_column(Keys::jwks()['keys'],'kid'));expect(Keys::ready('new-publication'));expect(!Keys::ready('changed-publication'));
});
test('same-kid provider rotation refreshes a stale signature key once',function(){
    $a=Keys::generate(time());$b=Keys::generate(time());$b['kid']=$a['kid'];$b['public']['kid']=$a['kid'];$tx=transaction();$tx['discovery']['jwks_uri']='https://provider.company.com/same-kid';$count=0;
    $http=new FixtureHttp(function()use(&$count,$a,$b){return ['json'=>['keys'=>[(++$count===1?$a:$b)['public']]],'headers'=>['cache-control'=>'max-age=3600']];});
    $p=new Provider($http);expect($p->verify(JWT::encode(claims($tx),$b['private'],'ES256',$b['kid']),$tx)['sub']==='subject-1');expect($count===2);
});
echo ($GLOBALS['passed']??0) . ' passed, ' . ($GLOBALS['failed']??0) . " failed\n";
exit(empty($GLOBALS['failed'])?0:1);
