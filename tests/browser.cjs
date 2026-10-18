/* Run with PLAYWRIGHT_PATH and SOCA_CONTAINER against the disposable fixture install. */
const {chromium} = require(process.env.PLAYWRIGHT_PATH || 'playwright');
const {execFileSync} = require('node:child_process');
const assert = require('node:assert/strict');
const base = process.env.SOCA_BASE || 'https://localhost:8443';
const cli = (...args) => execFileSync(process.env.CONTAINER_ENGINE || 'podman',['exec','-u','www-data',process.env.SOCA_CONTAINER || 'soca-local_wordpress_1','php','/tmp/wp-cli.phar',...args],{encoding:'utf8'}).trim();
const scenario = (name) => cli('option','update','ocimd_fixture_scenario',name);
let passed = 0;
const test = async (name, fn) => { await fn(); passed++; console.log('PASS ' + name); };
(async()=>{
 cli('eval-file','/tmp/tests/fixture-setup.php'); cli('transient','delete','--all');
 const browser=await chromium.launch({executablePath:process.env.CHROME_PATH || '/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--host-resolver-rules=MAP provider.company.com 127.0.0.1']});
 // Ignore the disposable local CA in this test browser only. Plugin outbound TLS is still enforced.
 const context=await browser.newContext({ignoreHTTPSErrors:true});
 const page=await context.newPage(); let lastCallback='';
 page.on('request',r=>{if(r.url().includes('action=soca_callback'))lastCallback=r.url();});
 async function upstream(destination='/') { await page.goto(base+'/wp-admin/admin-post.php?action=soca_start&redirect_to='+encodeURIComponent(base+destination)); await page.waitForLoadState(); }
 async function startRequest() { const userAgent=await page.evaluate(()=>navigator.userAgent); return context.request.get(base+'/wp-admin/admin-post.php?action=soca_start',{maxRedirects:0,headers:{'User-Agent':userAgent}}); }
 await test('WP-CLI uses soca and keeps the previous command as an alias',async()=>{
   const current=JSON.parse(cli('soca','status'));
   const legacy=JSON.parse(cli('oauth-cimd','status'));
   assert.equal(current.active_kid,legacy.active_kid);
   assert.equal(current.mode,legacy.mode);
 });
 await test('authorization, assertion, PKCE, ID token and WordPress session end to end',async()=>{
   await upstream('/?signed-in=1'); assert.equal(new URL(page.url()).searchParams.get('signed-in'),'1');
   const cookies=await context.cookies();assert(cookies.some(c=>c.name.startsWith('wordpress_logged_in_')));assert(!cookies.some(c=>c.name.startsWith('__Host-ocimd_')));
 });
 await test('callback replay fails and presents a matching audit reference',async()=>{await page.goto(lastCallback);const ref=new URL(page.url()).searchParams.get('soca_error');assert.match(ref,/^[a-f0-9]{12}$/);assert(await page.locator('#user_login').isVisible());assert((await page.locator('.message').innerText()).includes(ref));const events=JSON.parse(cli('soca','audit'));assert(events.some(e=>e.event==='login_failed'&&e.ref===ref&&e.step==='transaction'&&e.reason==='state'));});
 await context.clearCookies();
 for(const mode of ['nonce','issuer','unverified','expired','cancel']) await test('rejects '+mode+' response without redirect loop',async()=>{
   scenario(mode);await upstream();assert(page.url().includes('soca_local=1'));assert.match(new URL(page.url()).searchParams.get('soca_error'),/^[a-f0-9]{12}$/);assert(!(await context.cookies()).some(c=>c.name.startsWith('wordpress_logged_in_')));
 });
 scenario('valid');
 await test('a direct callback can finish in another browser and remains single-use',async()=>{
   const start=await startRequest();assert.equal(start.status(),302);
   const auth=start.headers().location;const other=await browser.newContext({ignoreHTTPSErrors:true});const stolen=await other.newPage();
   await stolen.goto(auth);assert(!(new URL(stolen.url()).searchParams.has('soca_error')));assert((await other.cookies()).some(c=>c.name.startsWith('wordpress_logged_in_')));await other.close();
   await page.goto(auth);const ref=new URL(page.url()).searchParams.get('soca_error');assert.match(ref,/^[a-f0-9]{12}$/);const events=JSON.parse(cli('soca','audit'));assert(events.some(e=>e.event==='login_failed'&&e.ref===ref&&e.reason==='state'));await context.clearCookies();
 });
 await test('a changed User-Agent is rejected before consuming the transaction',async()=>{
   const start=await startRequest();assert.equal(start.status(),302);
   const auth=start.headers().location;const other=await browser.newContext({ignoreHTTPSErrors:true,userAgent:'SOCA-different-browser'});const stolen=await other.newPage();
   await stolen.goto(auth);const ref=new URL(stolen.url()).searchParams.get('soca_error');assert.match(ref,/^[a-f0-9]{12}$/);
   const events=JSON.parse(cli('soca','audit'));assert(events.some(e=>e.event==='login_failed'&&e.ref===ref&&e.reason==='user_agent_mismatch'));
   assert(!(await other.cookies()).some(c=>c.name.startsWith('wordpress_logged_in_')));await other.close();
   await page.goto(auth);assert(!new URL(page.url()).searchParams.has('soca_error'));await context.clearCookies();
 });
 await test('a settings change invalidates an in-flight transaction',async()=>{
   const start=await startRequest();assert.equal(start.status(),302);
   cli('eval',"$s=OCIMD\\Settings::get();$s['revision']=OCIMD\\Support::random();update_option('ocimd_settings',$s,false);");
   await page.goto(start.headers().location);assert(new URL(page.url()).searchParams.has('soca_error'));assert(!(await context.cookies()).some(c=>c.name.startsWith('wordpress_logged_in_')));
 });
 await test('automatic mode and recovery/password flows',async()=>{
   cli('eval',"$s=OCIMD\\Settings::get();$s['automatic']=true;update_option('ocimd_settings',$s,false);");
   await page.goto(base+'/wp-login.php?soca_local=1');assert(await page.locator('#user_login').isVisible());
   await page.goto(base+'/wp-login.php?oauth_cimd_local=1');assert(await page.locator('#user_login').isVisible());
   await page.goto(base+'/wp-login.php?action=lostpassword');assert(await page.locator('#wp-submit').isVisible());assert(page.url().includes('lostpassword'));
   await page.goto(base+'/wp-login.php');await page.waitForLoadState();assert(!page.url().includes('wp-login.php'));
 });
 await context.clearCookies();
 await test('external redirect_to cannot escape site',async()=>{await page.goto(base+'/wp-admin/admin-post.php?action=soca_start&redirect_to=https%3A%2F%2Fevil.com');assert.equal(new URL(page.url()).origin,base);});
 await context.clearCookies();
 await test('local administrator login, setup UI and accessible bulk input',async()=>{
   await page.goto(base+'/wp-login.php?soca_local=1');await page.locator('#user_login').fill('localadmin');await page.locator('#user_pass').fill('Local-fixture-password-749!');await page.locator('#wp-submit').click();await page.waitForURL('**/wp-admin/**');
   await page.goto(base+'/wp-admin/options-general.php?page=simple-oauth-cimd-access');assert(await page.getByRole('heading',{name:'SOCA - Simple OAuth CIMD Access',exact:true}).isVisible());
   assert(await page.getByText('SOCA is an open-source WordPress single sign-on',{exact:false}).isVisible());
   assert.equal(await page.locator('input[name="trust_email"], input[name="cimd_confirmed"], input[name="inline_ack"]').count(),0);
   const allowAny=page.locator('input[name="unrestricted"]');await allowAny.check();
   assert(!(await page.locator('.soca-policy[data-policy="allow"]').first().isVisible()));
   assert(await page.locator('.soca-policy[data-policy="allow"] textarea').first().isDisabled());
   assert(await page.locator('.soca-policy[data-policy="deny"]').first().isVisible());
   await allowAny.uncheck();assert(await page.locator('.soca-policy[data-policy="allow"]').first().isVisible());
   const input=page.locator('#allow_domains-entry');await input.fill('other.com other.com @invalid');await input.press('Enter');
   assert.match(await page.locator('#allow_domains-feedback').innerText(),/1 added; 1 duplicates skipped; 1 invalid/);
   assert.equal(await input.getAttribute('aria-invalid'),'true');await input.fill('');
   await page.getByRole('button',{name:'Remove other.com',exact:true}).click();
   await page.screenshot({path:'work/setup-screen.png',fullPage:true});
 });
 await test('connection check validates actual generated document',async()=>{await page.getByRole('button',{name:'Validate connection and documents',exact:true}).click();await page.waitForLoadState();assert(await page.getByText('Discovery and published client document passed validation.',{exact:false}).isVisible());});
 await test('test login preserves original administrator session',async()=>{
   const before=(await context.cookies()).find(c=>c.name.startsWith('wordpress_logged_in_')).value;
   await page.getByRole('link',{name:'Test login (keeps this admin session)',exact:true}).click();await page.waitForLoadState();
   assert(page.url().includes('tested=1'));assert.equal((await context.cookies()).find(c=>c.name.startsWith('wordpress_logged_in_')).value,before);
 });
 await test('user profile has no separate plugin identity controls',async()=>{
   await page.goto(base+'/wp-admin/profile.php');
   assert.equal(await page.getByRole('heading',{name:'SOCA identity'}).count(),0);
   assert.equal(await page.locator('#soca-profile').count(),0);
   assert.equal(await page.locator('#ocimd-profile').count(),0);
 });
 await test('logout lands on local form even with automatic mode enabled',async()=>{
   const logout=await page.locator('#wp-admin-bar-logout a').getAttribute('href');await page.goto(logout);assert(page.url().includes('soca_local=1'));assert(await page.locator('#user_login').isVisible());
 });
 await browser.close();console.log(`${passed} browser scenarios passed`);
})().catch(e=>{console.error(e);process.exit(1)});
