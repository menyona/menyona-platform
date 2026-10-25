// Trusted local pages only; this is a partial keyboard/AX check, not NVDA acceptance.
const fs = require('node:fs');
const path = require('node:path');
const state = path.resolve(process.argv[2]);
const {chromium} = require(path.join(state, 'tools/node_modules/playwright'));
const axePath = path.join(state, 'tools/node_modules/axe-core/axe.min.js');
const fixtures = JSON.parse(fs.readFileSync(path.join(state, 'fixtures.json')));
const credentials = JSON.parse(fs.readFileSync(path.join(state, 'credentials.json')));
const base = 'http://127.0.0.1:18981';
const other = 'http://127.0.0.1:18982';
const checks = {};
function check(name, result) { checks[name] = !!result; if (!result) throw Error(name); }
(async () => {
  const browser = await chromium.launch({executablePath: process.env.LAB_CHROMIUM, headless: true, chromiumSandbox: true, args: ['--disable-dev-shm-usage']});
  try {
    const context = await browser.newContext({serviceWorkers:'block'});
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      return url.protocol === 'http:' && url.hostname === '127.0.0.1' && ['18981','18982'].includes(url.port) ? route.continue() : route.abort();
    });
    const page = await context.newPage();
    await page.goto(`${base}/?p=${fixtures.a.product}`, {waitUntil: 'networkidle'});
    check('arabic_document', await page.locator('html').getAttribute('lang') === 'ar');
    check('rtl_document', await page.locator('html').getAttribute('dir') === 'rtl');
    check('main_landmark', await page.locator('main').count() === 1);
    await page.keyboard.press('Tab');
    check('keyboard_skip_link', await page.evaluate(() => document.activeElement.matches('a[href^="#"]') && !!document.activeElement.textContent.trim()));
    let reached = false;
    for (let i=0;i<45;i++) {
      if (await page.evaluate(() => document.activeElement.matches('.single_add_to_cart_button'))) { reached=true; break; }
      await page.keyboard.press('Tab');
    }
    check('keyboard_reaches_add_to_cart', reached);
    await page.keyboard.press('Enter');
    await page.waitForLoadState('networkidle');
    await page.goto(`${base}/?page_id=${fixtures.a.cart}`, {waitUntil: 'networkidle'});
    check('cart_has_product', await page.locator('.cart_item').count() === 1);
    await page.goto(`${base}/?page_id=${fixtures.a.checkout}`, {waitUntil: 'networkidle'});
    const fields = {billing_first_name:'عميل', billing_last_name:'تجريبي', billing_address_1:'عنوان وهمي', billing_city:'مدينة تجريبية', billing_state:'منطقة تجريبية', billing_postcode:'12345', billing_phone:'0500000000', billing_email:'guest@example.invalid'};
    for (const [id,value] of Object.entries(fields)) {
      const input = page.locator('#'+id);
      check('label_'+id, await input.evaluate(el => [...el.labels].some(label=>label.textContent.trim())));
      await input.focus();
      await page.keyboard.insertText(value);
      await page.keyboard.press('Tab');
    }
    await page.addScriptTag({path:axePath});
    const axe = await page.evaluate(async()=> {
      const r=await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}});
      return {status:r.violations.length?'FAIL':'PASS',violations:r.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.length})), passes:r.passes.length};
    });
    const ax = await context.newCDPSession(page);
    const tree = await ax.send('Accessibility.getFullAXTree');
    check('accessibility_tree_has_named_controls', tree.nodes.some(n=>n.role?.value==='textbox' && n.name?.value));
    await page.locator('#payment_method_cod').check();
    const terms=page.locator('#terms');
    if (await terms.count()) await terms.check();
    await page.waitForTimeout(1200);
    await page.locator('#place_order').focus();
    await page.keyboard.press('Enter');
    await page.waitForURL(/order-received/,{timeout:30000});
    check('classic_checkout_order_received', await page.locator('.woocommerce-order').count() === 1);
    // Unauthenticated cross-tenant access must not reveal the private order API.
    const unauth=await context.request.get(`${other}/?rest_route=/wc/v3/orders/${fixtures.b.private_order}`);
    check('anonymous_order_api_denied', [401,403].includes(unauth.status()));
    await context.request.get(base+'/wp-login.php');
    const login = await context.request.post(base+'/wp-login.php',{form:{log:'customer_a',pwd:credentials.a.customer_password,redirect_to:`${base}/?page_id=${fixtures.a.account}`,testcookie:'1'}});
    check('customer_login_completed', login.status() === 200);
    const aCookies = await context.cookies(base);
    check('customer_has_login_cookie', aCookies.some(c=>c.name.startsWith('wordpress_logged_in_')));
    await page.goto(`${base}/?page_id=${fixtures.a.account}`,{waitUntil:'networkidle'});
    check('customer_own_account_access', await page.locator('.woocommerce-MyAccount-content').count()===1 && (await page.locator('body').innerText()).includes('customer_a'));
    await page.goto(fixtures.a.own_order_url,{waitUntil:'networkidle'});
    check('customer_own_order_access', await page.locator('.woocommerce-order-details').count()===1 && (await page.locator('body').innerText()).includes('وجبة تجريبية a'));
    const adminAttempt=await context.request.post(base+'/wp-login.php',{form:{log:'lab_setup',pwd:credentials.a.admin_password,testcookie:'1'}});
    check('setup_administrator_web_login_denied', (await adminAttempt.text()).includes('restricted to local CLI'));
    // localhost ports share a cookie domain; independently salted site cookies must not authenticate B.
    const accountB=await page.goto(`${other}/?page_id=${fixtures.b.account}`,{waitUntil:'networkidle'});
    check('copied_a_cookie_cannot_login_b', accountB.ok() && await page.locator('form.woocommerce-form-login').count() === 1);
    await page.goto(fixtures.b.own_order_url,{waitUntil:'networkidle'});
    check('copied_a_cookie_cannot_view_b_order', await page.locator('.woocommerce-order-details').count()===0 && await page.locator('form.woocommerce-form-login').count()===1);
    const forbidden = await context.request.get(`${other}/?rest_route=/wc/v3/orders/${fixtures.b.private_order}`);
    check('customer_a_cross_order_api_denied', [401,403].includes(forbidden.status()));
    const upload=await context.request.get(base+'/wp-content/uploads/lab-probe.php');
    check('php_upload_http_denied', upload.status() === 403 && !(await upload.text()).includes('LAB_UPLOAD_EXECUTED'));
    const result={checks,axe,chromium:browser.version(),human_screen_reader:'NOT_RUN'};
    fs.writeFileSync(path.join(state,'browser-results.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
    console.log(JSON.stringify(result));
  } finally { await browser.close(); }
})().catch(error=> { console.error('Browser laboratory check failed: '+error.message.replace(/https?:\/\/[^\s]+/g,'[local page]')); process.exit(1); });
