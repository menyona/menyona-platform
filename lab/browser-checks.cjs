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
let phase="launch";
let failureCode="browser_operation_failed";
function check(name, result) { checks[name] = !!result; if (!result) { failureCode=name; throw Error(name); } }
(async () => {
  const browser = await chromium.launch({executablePath: process.env.LAB_CHROMIUM, headless: true, chromiumSandbox: true, args: ['--disable-dev-shm-usage']});
  try {
    const context = await browser.newContext({serviceWorkers:'block'});
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      return url.protocol === 'http:' && url.hostname === '127.0.0.1' && ['18981','18982'].includes(url.port) ? route.continue() : route.abort();
    });
    phase='product';
    const page = await context.newPage();
    check('product_page_loaded', new URL(fixtures.a.product_url).origin === base);
    const productPage=await page.goto(fixtures.a.product_url, {waitUntil: 'load'});
    check('product_page_loaded', productPage.ok() && await page.locator('form.cart .single_add_to_cart_button').count() === 1);
    check('arabic_document', await page.locator('html').getAttribute('lang') === 'ar');
    check('rtl_document', await page.locator('html').getAttribute('dir') === 'rtl');
    check('main_landmark', await page.locator('main').count() === 1);
    phase='keyboard';
    await page.keyboard.press('Tab');
    check('keyboard_skip_link', await page.evaluate(() => document.activeElement.matches('a[href^="#"]') && !!document.activeElement.textContent.trim()));
    let reached = false;
    for (let i=0;i<45;i++) {
      if (await page.evaluate(() => document.activeElement.matches('.single_add_to_cart_button'))) { reached=true; break; }
      await page.keyboard.press('Tab');
    }
    check('keyboard_reaches_add_to_cart', reached);
    phase='add_to_cart';
    await page.keyboard.press('Enter');
    await page.locator('.woocommerce-message').waitFor({state:'visible'});
    phase='cart';
    await page.goto(`${base}/?page_id=${fixtures.a.cart}`, {waitUntil: 'load'});
    check('cart_has_product', await page.locator('.cart_item').count() === 1);
    phase='checkout_fields';
    await page.goto(`${base}/?page_id=${fixtures.a.checkout}`, {waitUntil: 'load'});
    const fields = {billing_first_name:'عميل', billing_last_name:'تجريبي', billing_address_1:'عنوان وهمي', billing_city:'مدينة تجريبية', billing_state:'منطقة تجريبية', billing_postcode:'12345', billing_phone:'0500000000', billing_email:'guest@example.invalid'};
    for (const [id,value] of Object.entries(fields)) {
      const input = page.locator('#'+id);
      check('label_'+id, await input.evaluate(el => [...el.labels].some(label=>label.textContent.trim())));
      await input.focus();
      await page.keyboard.insertText(value);
      await page.keyboard.press('Tab');
    }
    phase='axe';
    await page.addScriptTag({path:axePath});
    const axe = await page.evaluate(async()=> {
      const r=await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}});
      const tags=new Set(['a','p','span','label','abbr','button','input','div','select','textarea']);
      const ids=new Set(['place_order','terms','billing_first_name','billing_last_name','billing_country','billing_address_1','billing_address_2','billing_company','billing_city','billing_state','billing_phone','billing_email','billing_postcode','coupon_code','order_comments','payment_method_cod','select2-billing_country-container']);
      const classes=new Set(['required','optional','button','alt','woocommerce-info','woocommerce-privacy-policy-text','woocommerce-terms-and-conditions-checkbox-text','woocommerce-input-wrapper','woocommerce-form__input-checkbox','woocommerce-form__label-for-checkbox','showcoupon','screen-reader-text','woocommerce-password-strength','input-text','woocommerce-form-coupon-toggle']);
      return {status:r.violations.length?'FAIL':'PASS',violations:r.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.length,details:v.nodes.map(n=>{
        let el=null;
        try {if(typeof n.target[0]==='string') el=document.querySelector(n.target[0]);}catch{}
        const data=n.any.find(check=>check.id==='color-contrast')?.data||{};
        const color=value=>typeof value==='string'&&/^#[0-9a-f]{6}$/i.test(value)?value:null;
        return {tag:tags.has(el?.tagName.toLowerCase())?el.tagName.toLowerCase():null,
          id:ids.has(el?.id)?el.id:null,classes:el?[...el.classList].filter(c=>classes.has(c)):[],
          foreground:color(data.fgColor),background:color(data.bgColor),
          ratio:Number.isFinite(data.contrastRatio)?data.contrastRatio:null};
      })})), passes:r.passes.length};
    });
    const ax = await context.newCDPSession(page);
    const tree = await ax.send('Accessibility.getFullAXTree');
    check('accessibility_tree_has_named_controls', tree.nodes.some(n=>n.role?.value==='textbox' && n.name?.value));
    phase='checkout_submit';
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
    phase='account_security';
    const login = await context.request.post(base+'/wp-login.php',{form:{log:'customer_a',pwd:credentials.a.customer_password,redirect_to:`${base}/?page_id=${fixtures.a.account}`,testcookie:'1'}});
    check('customer_login_completed', login.status() === 200);
    const aCookies = await context.cookies(base);
    check('customer_has_login_cookie', aCookies.some(c=>c.name.startsWith('wordpress_logged_in_')));
    await page.goto(`${base}/?page_id=${fixtures.a.account}`,{waitUntil:'load'});
    check('customer_own_account_access', await page.locator('.woocommerce-MyAccount-content').count()===1 && (await page.locator('body').innerText()).includes('customer_a'));
    await page.goto(fixtures.a.own_order_url,{waitUntil:'load'});
    check('customer_own_order_access', await page.locator('.woocommerce-order-details').count()===1 && (await page.locator('body').innerText()).includes('وجبة تجريبية a'));
    const adminAttempt=await context.request.post(base+'/wp-login.php',{form:{log:'lab_setup',pwd:credentials.a.admin_password,testcookie:'1'}});
    check('setup_administrator_web_login_denied', (await adminAttempt.text()).includes('restricted to local CLI'));
    // localhost ports share a cookie domain; independently salted site cookies must not authenticate B.
    const accountB=await page.goto(`${other}/?page_id=${fixtures.b.account}`,{waitUntil:'load'});
    check('copied_a_cookie_cannot_login_b', accountB.ok() && await page.locator('form.woocommerce-form-login').count() === 1);
    await page.goto(fixtures.b.own_order_url,{waitUntil:'load'});
    check('copied_a_cookie_cannot_view_b_order', await page.locator('.woocommerce-order-details').count()===0 && await page.locator('form.woocommerce-form-login').count()===1);
    const forbidden = await context.request.get(`${other}/?rest_route=/wc/v3/orders/${fixtures.b.private_order}`);
    check('customer_a_cross_order_api_denied', [401,403].includes(forbidden.status()));
    const upload=await context.request.get(base+'/wp-content/uploads/lab-probe.php');
    check('php_upload_http_denied', upload.status() === 403 && !(await upload.text()).includes('LAB_UPLOAD_EXECUTED'));
    const result={checks,axe,chromium:browser.version(),human_screen_reader:'NOT_RUN'};
    fs.writeFileSync(path.join(state,'browser-results.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
    console.log(JSON.stringify(result));
  } finally { await browser.close(); }
})().catch(error=> {
  if (phase==='launch' && error.message.includes('No usable sandbox')) failureCode='chromium_sandbox_unavailable';
  else if (failureCode==='browser_operation_failed' && error.name==='TimeoutError') failureCode='browser_timeout';
  fs.writeFileSync(path.join(state,'browser-failure.json'),JSON.stringify({phase,code:failureCode}),{mode:0o600});
  fs.writeFileSync(path.join(state,'browser-raw-error.txt'),error.stack || error.message,{mode:0o600});
  console.error('Browser laboratory failed at '+phase+' ('+failureCode+')');
  process.exit(1);
});
