<?php
/** Disposable-test MU plugin. NEVER include in a deployment ZIP. */
if (!defined('SOCA_TEST_FIXTURES') || !SOCA_TEST_FIXTURES || wp_get_environment_type() !== 'local') { return; }
add_action('plugins_loaded', static function () {
    class SOCA_Mock_HTTP extends \SOCA\Http {
        public function request(string $url, ?array $form=null, ?string $bearer=null): array {
            $s=\SOCA\Settings::get();$issuer='https://provider.company.com';$headers=['cache-control'=>'no-store'];
            $key=get_option('soca_fixture_key');if(!$key){$key=\SOCA\Keys::generate(time());update_option('soca_fixture_key',$key,false);}
            if (str_starts_with($url,'https://proxy.company.com/')) {
                $parts=explode('/',parse_url($url,PHP_URL_PATH));$doc=\SOCA\Support::object(\SOCA\Support::unb64($parts[1]));$doc['client_id']=$url;
                return ['json'=>$doc,'headers'=>$headers];
            }
            if ($url===$issuer.'/.well-known/openid-configuration') {
                $port=wp_parse_url(home_url('/'),PHP_URL_PORT) ?: 443;
                return ['json'=>['issuer'=>$issuer,'authorization_endpoint'=>$issuer.':'.$port.'/?soca_fixture_authorize=1','token_endpoint'=>$issuer.'/token','jwks_uri'=>$issuer.'/jwks',
                    'response_types_supported'=>['code'],'response_modes_supported'=>['query'],'subject_types_supported'=>['public','pairwise'],
                    'code_challenge_methods_supported'=>['S256'],'token_endpoint_auth_methods_supported'=>['private_key_jwt'],'token_endpoint_auth_signing_alg_values_supported'=>['ES256'],
                    'id_token_signing_alg_values_supported'=>['ES256'],'scopes_supported'=>['openid','email','profile'],'client_id_metadata_document_supported'=>true,'authorization_response_iss_parameter_supported'=>true], 'headers'=>$headers];
            }
            if ($url===$issuer.'/jwks') { return ['json'=>['keys'=>[$key['public']]],'headers'=>$headers]; }
            if ($url===$issuer.'/token') {
                $record=get_option('soca_fixture_code_'.hash('sha256',$form['code']??''));
                \SOCA\Support::need(is_array($record),'fixture_code','Invalid fixture authorization code.');delete_option('soca_fixture_code_'.hash('sha256',$form['code']));
                \SOCA\Support::need($form['client_id']===$record['client_id'] && $form['redirect_uri']===$record['redirect_uri'] && $form['grant_type']==='authorization_code','fixture_binding','Code binding mismatch.');
                \SOCA\Support::need(\SOCA\Support::b64(hash('sha256',$form['code_verifier'],true))===$record['code_challenge'],'fixture_pkce','PKCE failed.');
                $metadata=$this->request($form['client_id'])['json'];
                $assertion=\SOCA\Vendor\JWT\JWT::decode($form['client_assertion'],\SOCA\Vendor\JWT\JWK::parseKeySet($metadata['jwks'],'ES256'));
                \SOCA\Support::need($assertion->iss===$form['client_id'] && $assertion->sub===$form['client_id'] && $assertion->aud===$issuer && $assertion->exp-$assertion->iat===60,'fixture_assertion','Invalid client assertion.');
                $scenario=get_option('soca_fixture_scenario','valid');$email=get_option('soca_fixture_email','browser@company.com');
                $claims=['iss'=>$issuer,'sub'=>get_option('soca_fixture_sub','browser-sub'),'aud'=>$form['client_id'],'iat'=>time(),'exp'=>time()+300,'nonce'=>$record['nonce'],'auth_time'=>time(),'email'=>$email,'email_verified'=>true];
                if($scenario==='nonce')$claims['nonce']='attacker';
                if($scenario==='unverified')$claims['email_verified']=false;
                if($scenario==='expired')$claims['exp']=time()-120;
                return ['json'=>['id_token'=>\SOCA\Vendor\JWT\JWT::encode($claims,$key['private'],'ES256',$key['kid']),'access_token'=>'unused-fixture-token','token_type'=>'Bearer'],'headers'=>$headers];
            }
            throw new \SOCA\Failure('fixture_url','Unknown fixture endpoint.');
        }
    }
    add_filter('soca_http',static fn()=>new SOCA_Mock_HTTP());
    add_action('init',static function(){
        if(!isset($_GET['soca_fixture_authorize']))return;
        $record=[];foreach(['client_id','redirect_uri','code_challenge','nonce','state']as$key)$record[$key]=\SOCA\Support::scalar($_GET,$key,16384);
        if(($_GET['code_challenge_method']??'')!=='S256'||($_GET['response_type']??'')!=='code'||($_GET['response_mode']??'')!=='query')wp_die('Invalid fixture request');
        $scenario=get_option('soca_fixture_scenario','valid');
        $response=['state'=>$record['state'],'iss'=>$scenario==='issuer'?'https://wrong.company.com':'https://provider.company.com'];
        if($scenario==='cancel')$response['error']='access_denied';else{$code=\SOCA\Support::random();update_option('soca_fixture_code_'.hash('sha256',$code),$record,false);$response['code']=$code;}
        wp_safe_redirect(add_query_arg($response,$record['redirect_uri']));exit;
    },2);
});
