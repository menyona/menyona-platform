#!/usr/bin/env python3
"""Prepare/run a private, loopback-only compatibility experiment; no provider payment.

Read lab/README.md and obtain independent review of the exact configuration before
run. State and synthetic credentials stay outside the public repository.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / 'lab/components.lock.json').read_text())
SOURCE_FILES = sorted((ROOT / 'lab').glob('*')) + [Path(__file__).resolve()]
CHROMIUM = Path(os.environ.get('LAB_CHROMIUM_EXECUTABLE','/home/chatbot/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome'))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Artifact redirects are forbidden')


class LocalRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        local_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def local_url(value):
    url=urllib.parse.urlsplit(value)
    if (url.scheme!='http' or url.hostname!='127.0.0.1' or url.port not in (18981,18982)
            or url.username is not None or url.password is not None):
        raise ValueError('Non-local laboratory URL rejected')
    return value


def local_client():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),LocalRedirect(),
                                      urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def browser_failure(state):
    path=state/'browser-failure.json'
    failure=json.loads(path.read_text()) if path.exists() else {'phase':'setup','code':'browser_setup_failed'}
    phases={'setup','launch','product','keyboard','checkout_fields','axe','checkout_submit','account_security'}
    codes={'browser_setup_failed','browser_operation_failed','chromium_sandbox_unavailable',
           'product_page_loaded','arabic_document','rtl_document','main_landmark','keyboard_skip_link',
           'keyboard_reaches_add_to_cart','cart_has_product','accessibility_tree_has_named_controls',
           'classic_checkout_order_received','anonymous_order_api_denied','customer_login_completed',
           'customer_has_login_cookie','customer_own_account_access','customer_own_order_access',
           'setup_administrator_web_login_denied','copied_a_cookie_cannot_login_b',
           'copied_a_cookie_cannot_view_b_order','customer_a_cross_order_api_denied','php_upload_http_denied'}
    codes.update('label_'+name for name in ('billing_first_name','billing_last_name','billing_address_1',
                 'billing_city','billing_state','billing_postcode','billing_phone','billing_email'))
    if (not isinstance(failure,dict) or set(failure)!={'phase','code'} or
            not isinstance(failure.get('phase'),str) or not isinstance(failure.get('code'),str) or
            failure['phase'] not in phases or failure['code'] not in codes):
        raise RuntimeError('Invalid browser failure record')
    blocked=failure['phase']=='launch' and failure['code']=='chromium_sandbox_unavailable'
    return {'status':'BLOCKED' if blocked else 'FAIL','phase':failure['phase'],
            'code':failure['code'],'human_screen_reader':'NOT_RUN'}


def http_checkout(fixtures, credentials):
    client=local_client()
    a='http://127.0.0.1:18981'; b='http://127.0.0.1:18982'
    def request(url, fields=None):
        data=urllib.parse.urlencode(fields).encode() if fields else None
        with client.open(local_url(url),data=data,timeout=30) as response: return response.read().decode()
    request(a+'/?add-to-cart='+str(fixtures['a']['product']))
    checkout=request(a+'/?page_id='+str(fixtures['a']['checkout']))
    nonce=re.search(r'name="woocommerce-process-checkout-nonce"[^>]*value="([^"]+)"',checkout)
    if not nonce: raise RuntimeError('Classic checkout nonce missing')
    fields={'billing_first_name':'عميل','billing_last_name':'اختبار','billing_country':'SA',
            'billing_address_1':'عنوان وهمي','billing_city':'مدينة تجريبية','billing_state':'منطقة تجريبية','billing_postcode':'12345',
            'billing_phone':'0500000000','billing_email':'guest@example.invalid',
            'payment_method':'cod','shipping_method[0]':fixtures['a']['shipping_method'],
            'woocommerce-process-checkout-nonce':nonce[1],'terms':'1','order_total':'0.01'}
    result=json.loads(request(a+'/?wc-ajax=checkout',fields))
    if result.get('result')!='success': raise RuntimeError('HTTP checkout did not succeed')
    destination=urllib.parse.urlsplit(result['redirect'])
    if destination.scheme!='http' or destination.hostname!='127.0.0.1' or destination.port!=18981:
        raise ValueError('Unexpected order destination')
    order=urllib.parse.parse_qs(destination.query).get('order-received',[''])[0]
    if not order.isdigit(): raise ValueError('Expected a local order reference')
    received=request(result['redirect'])
    if 'woocommerce-order' not in received: raise RuntimeError('Order confirmation page missing')
    request(a+'/wp-login.php')
    request(a+'/wp-login.php',{'log':'customer_a','pwd':credentials['a']['customer_password'],'testcookie':'1'})
    own=request(fixtures['a']['own_order_url'])
    if 'woocommerce-order-details' not in own: raise RuntimeError('Positive own-order access failed')
    foreign=request(fixtures['b']['own_order_url'])
    if 'woocommerce-order-details' in foreign or 'woocommerce-form-login' not in foreign:
        raise RuntimeError('Cross-store cookie isolation failed')
    admin=request(a+'/wp-login.php',{'log':'lab_setup','pwd':credentials['a']['admin_password'],'testcookie':'1'})
    if 'restricted to local CLI' not in admin: raise RuntimeError('Setup administrator accepted on web')
    return {'status':'PASS','order':int(order),'classic_checkout':True,
            'own_order_access':True,'cross_store_cookie_denied':True,'setup_admin_denied':True,
            'client_price_tamper':'verified against backend total separately'}


def command(args, *, env=None, data=None, timeout=300):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, timeout=timeout)
    if result.returncode:
        if env and env.get('LAB_DIAGNOSTICS'):
            diagnostic=Path(env['LAB_DIAGNOSTICS'])
            diagnostic.write_bytes(result.stdout+b'\n'+result.stderr)
            diagnostic.chmod(0o600)
        raise RuntimeError('Command failed; private diagnostic review required: ' + args[0])
    return result.stdout.decode()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    path.chmod(0o600)


def regular_private_directory(path):
    path = path.absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink state paths are forbidden')
    path = path.resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError('State must be a private directory owned by the operator')
    return path


def sources():
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in SOURCE_FILES if p.is_file() and not p.is_symlink()}


def material(state):
    for directory in (state/'build',state/'tools'):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('Execution material roots must be real directories')
    files=[state/'compose.yaml', *sorted((state/'build').rglob('*')),
           *sorted((state/'tools').rglob('*'))]
    result={}
    for path in files:
        if path.is_symlink():
            if not path.is_relative_to(state/'tools') or not path.resolve().is_relative_to(state/'tools'):
                raise ValueError('Unsafe symlink execution material')
            result[str(path.relative_to(state))]='link:'+os.readlink(path)
            continue
        if path.is_file():
            result[str(path.relative_to(state))]=hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def chromium_hash():
    with CHROMIUM.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def stop_state(state, info):
    marker=hashlib.sha256(str(state).encode()).hexdigest()
    ids=command(['docker','ps','-aq','--filter','label=com.docker.compose.project='+info['project'],
                 '--filter','label=org.menyona.compatibility='+marker]).split()
    if ids:
        if not all(re.fullmatch('[0-9a-f]{12,64}',item) for item in ids):
            raise ValueError('Unexpected container identity')
        command(['docker','stop','--time','15',*ids],timeout=90)


def unpack(archive, target):
    with zipfile.ZipFile(archive) as package:
        if sum(i.file_size for i in package.infolist()) > 700 * 1024 * 1024:
            raise ValueError('Archive exceeds laboratory size limit')
        for item in package.infolist():
            parts = Path(item.filename).parts
            if (Path(item.filename).is_absolute() or '..' in parts or '\\' in item.filename
                    or stat.S_ISLNK(item.external_attr >> 16)):
                raise ValueError('Unsafe archive entry')
        package.extractall(target)


def state_parent(path):
    if not path.is_absolute() or path.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError('State parent must be absolute and outside the public repository')
    return path


def prepare(cache):
    if shutil.disk_usage(ROOT).free < 5 * 1024**3:
        raise RuntimeError('Laboratory requires at least 5 GiB free; no pruning is performed')
    parent = state_parent(Path(os.environ.get('LAB_STATE_PARENT',str(Path.home()/'.local/state/menyona-compatibility'))))
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    regular_private_directory(parent)
    state = Path(tempfile.mkdtemp(prefix='run-', dir=parent))
    state.chmod(0o700)
    build = state / 'build'
    build.mkdir()
    wordpress = build / 'wordpress'
    (wordpress / 'wp-content/plugins').mkdir(parents=True)
    (wordpress / 'wp-content/themes').mkdir()
    (wordpress / 'wp-content/mu-plugins').mkdir()
    (wordpress / 'wp-content/languages/plugins').mkdir(parents=True)
    (wordpress / 'wp-content/languages/themes').mkdir()
    for artifact in LOCK['artifacts']:
        archive = state / (artifact['name'] + '.zip')
        cached = cache / archive.name if cache else None
        if cached and cached.is_file() and not cached.is_symlink():
            shutil.copyfile(cached, archive)
        else:
            url = artifact['url']
            if urllib.parse.urlsplit(url).hostname != 'downloads.wordpress.org':
                raise ValueError('Unapproved artifact host')
            with urllib.request.build_opener(NoRedirect()).open(url, timeout=60) as response:
                if urllib.parse.urlsplit(response.url).hostname != 'downloads.wordpress.org':
                    raise ValueError('Unexpected artifact redirect')
                archive.write_bytes(response.read(100*1024*1024+1))
        if archive.stat().st_size != artifact['bytes'] or hashlib.sha256(archive.read_bytes()).hexdigest() != artifact['sha256']:
            raise ValueError('Artifact does not match reviewed lock')
        target = {'woocommerce':'plugins','storefront':'themes','ar-core':'languages',
                  'ar-plugins':'languages/plugins','ar-themes':'languages/themes'}[artifact['name']]
        if artifact['name'] in {'woocommerce','storefront'}:
            target = wordpress / 'wp-content' / target
        else:
            target = wordpress / 'wp-content' / target
        unpack(archive, target)
    shutil.copyfile(ROOT/'lab/wp-config.php', wordpress/'wp-config.php')
    shutil.copyfile(ROOT/'lab/lab-guard.php', wordpress/'wp-content/mu-plugins/lab-guard.php')
    helpers = build/'helpers'
    helpers.mkdir()
    for name in ('install.php','seed.php','verify.php'):
        shutil.copyfile(ROOT/'lab'/name, helpers/name)
    for name in ('Dockerfile','Dockerfile.proxy','apache-lab.conf','Caddyfile'):
        shutil.copyfile(ROOT/'lab'/name, build/name)
    shutil.copyfile(ROOT/'lab/compose.yaml', state/'compose.yaml')
    credentials = {}
    for tenant in ('a','b'):
        for kind in ('db','root'):
            # Parent 0700 prevents host access; container secret mounts are read-only.
            secret_file = state/(tenant+'_'+kind)
            secret_file.write_text(secrets.token_urlsafe(48))
            secret_file.chmod(0o444)
        salt_keys = ['AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY',
                     'AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT']
        salt_file=state/(tenant+'_salts')
        write_json(salt_file,{k:secrets.token_urlsafe(48) for k in salt_keys})
        salt_file.chmod(0o444)
        credentials[tenant]={key:secrets.token_urlsafe(32) for key in
                             ('admin_password','customer_password','manager_password')}
    write_json(state/'credentials.json', credentials)
    project='menyona-compat-'+secrets.token_hex(6)
    command(['npm','install','--ignore-scripts','--no-audit','--no-fund','--prefix',str(state/'tools'),
             '--registry=https://registry.npmjs.org',
             'playwright@1.64.1','axe-core@4.14.0'],timeout=180)
    write_json(state/'state.json', {'project':project,'source_hashes':sources(),'lock':LOCK,
                                   'material_hashes':material(state),
                                   'chromium_sha256':chromium_hash(),
                                   'npm_lock_sha256':hashlib.sha256((state/'tools/package-lock.json').read_bytes()).hexdigest()})
    print('Prepared private laboratory state: '+str(state),flush=True)


def load_state(path, verify_sources=True):
    state=regular_private_directory(path)
    info=json.loads((state/'state.json').read_text())
    if not re.fullmatch(r'menyona-compat-[0-9a-f]{12}',info['project']):
        raise ValueError('Unexpected laboratory project identity')
    if verify_sources and (info['source_hashes'] != sources() or info['lock'] != LOCK):
        raise ValueError('Source changed; prepare a new state after review')
    if verify_sources and (info['material_hashes'] != material(state) or
            info['npm_lock_sha256'] != hashlib.sha256((state/'tools/package-lock.json').read_bytes()).hexdigest()):
        raise ValueError('Prepared execution material changed')
    if verify_sources and info['chromium_sha256'] != chromium_hash():
        raise ValueError('Chromium binary changed')
    env=os.environ.copy()
    env.update(LAB_STATE_DIR=str(state),LAB_BUILD_DIR=str(state/'build'),
               LAB_IMAGE=info['project']+':locked',LAB_PROXY_IMAGE=info['project']+':proxy-locked',LAB_WP_IMAGE=LOCK['wordpress_image'],
               LAB_DB_IMAGE=LOCK['mariadb_image'],LAB_DIAGNOSTICS=str(state/'command-failure.txt'),
               LAB_CADDY_IMAGE=LOCK['caddy_image'],
               LAB_INSTANCE=hashlib.sha256(str(state).encode()).hexdigest())
    return state,info,env


def run(state, info, env):
    if shutil.disk_usage(ROOT).free < 4 * 1024**3:
        raise RuntimeError('Insufficient disk headroom; no pruning is performed')
    for port in (18981,18982):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',port))
    compose=['docker','compose','-p',info['project'],'-f',str(state/'compose.yaml')]
    print('Building pinned laboratory image without build network access.',flush=True)
    command(compose+['build','--pull=false','web_a','proxy_a'],env=env,timeout=300)
    load_state(state)  # Recheck copied Compose and build bytes before creating services.
    command(compose+['up','-d','--no-build','--wait','--wait-timeout','150'],env=env,timeout=180)
    credentials=json.loads((state/'credentials.json').read_text())
    fixtures={}
    def php(tenant,name,data=None):
        output=command(compose+['exec','-T','web_'+tenant,'php','/opt/menyona-lab/'+name+'.php'],
                       env=env,data=json.dumps(data).encode() if data else None,timeout=180)
        return json.loads(output.strip().splitlines()[-1])
    for tenant in ('a','b'):
        php(tenant,'install',credentials[tenant])
        fixtures[tenant]=php(tenant,'seed',credentials[tenant])
    write_json(state/'fixtures.json',fixtures)
    http_result=http_checkout(fixtures,credentials)
    print('Two isolated Arabic stores seeded; testing browser checkout and controls.',flush=True)
    browser_env=env.copy()
    browser=CHROMIUM
    if not browser.is_file(): raise RuntimeError('Reviewed Chromium binary unavailable')
    browser_env['LAB_CHROMIUM']=str(browser)
    try:
        browser_output=command(['node',str(ROOT/'lab/browser-checks.cjs'),str(state)],env=browser_env,timeout=180)
        browser_result=json.loads(browser_output.strip().splitlines()[-1])
        browser_result['status']='FAIL' if browser_result['axe']['status']=='FAIL' else 'PASS'
    except RuntimeError:
        browser_result=browser_failure(state)
    results={tenant:php(tenant,'verify',{'web_order':http_result['order']} if tenant=='a' else None) for tenant in ('a','b')}
    ids={service:command(compose+['ps','-q',service],env=env).strip()
         for service in ('web_a','web_b','db_a','db_b','proxy_a','proxy_b')}
    inspection=json.loads(command(['docker','inspect',*ids.values()]))
    check={}
    by_id={item['Id']:item for item in inspection}
    for service,cid in ids.items():
        item=by_id[cid]
        check[service+'_nonroot']=item['Config']['User'] in ('33:33','mysql')
        check[service+'_readonly']=item['HostConfig']['ReadonlyRootfs']
        check[service+'_no_privilege']=not item['HostConfig']['Privileged'] and item['HostConfig']['CapDrop']==['ALL']
        check[service+'_resources']=0<item['HostConfig']['Memory']<=512*1024*1024 and item['HostConfig']['PidsLimit']==80
        check[service+'_no_socket']=not any(m['Destination']=='/var/run/docker.sock' for m in item['Mounts'])
        ports=item['HostConfig']['PortBindings'] or {}
        check[service+'_local_ports']=bool(ports) and all(p['HostIp']=='127.0.0.1' for bindings in ports.values() for p in bindings) if service.startswith('proxy') else not ports
    a=by_id[ids['web_a']]; b=by_id[ids['web_b']]
    check['separate_networks']=not set(a['NetworkSettings']['Networks']) & set(b['NetworkSettings']['Networks'])
    check['separate_volumes']=not {m['Name'] for m in a['Mounts'] if m['Type']=='volume'} & {m['Name'] for m in b['Mounts'] if m['Type']=='volume'}
    for target,port in (('web_b',8080),('db_b',3306)):
        item=by_id[ids[target]]
        ip=next(iter(item['NetworkSettings']['Networks'].values()))['IPAddress']
        probe='$s=@fsockopen($argv[1],(int)$argv[2],$e,$m,2); echo $s?"OPEN":"DENIED";'
        output=command(compose+['exec','-T','web_a','php','-r',probe,ip,str(port)],env=env)
        check['a_cannot_connect_'+target]=output=='DENIED'
    for target,port,expected in (('web_a',8080,'OPEN'),('db_a',3306,'DENIED'),('db_b',3306,'DENIED'),('web_b',8080,'DENIED')):
        item=by_id[ids[target]]
        # Use the database/back-end address even for a multi-network web service.
        network=info['project']+('_a' if target.endswith('_a') else '_b')
        ip=item['NetworkSettings']['Networks'][network]['IPAddress']
        if target=='web_a': ip=item['NetworkSettings']['Networks'][info['project']+'_front_a']['IPAddress']
        output=command(['docker','run','--rm','--network','container:'+ids['proxy_a'],
                        '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                        '--user','33:33','--memory','64m','--pids-limit','20','--cpus','0.1',
                        '--entrypoint','php',LOCK['wordpress_image'],'-r',probe,ip,str(port)])
        check['proxy_a_probe_'+target]=output==expected
    for tenant,port in (('a',18981),('b',18982)):
        with local_client().open(local_url('http://127.0.0.1:'+str(port)+'/'),timeout=10) as response:
            check[tenant+'_http_ready']=response.status==200
    before={t:(r['order'],r['total'],r['stock']) for t,r in results.items()}
    command(compose+['restart'],env=env,timeout=90)
    time.sleep(3)
    persisted={}
    code='require "/var/www/html/wp-load.php"; $o=wc_get_order(get_option("menyona_lab_order")); $f=get_option("menyona_lab_fixture"); echo json_encode([$o->get_id(),$o->get_total(),wc_get_product($f["product"])->get_stock_quantity()]);'
    for tenant in ('a','b'):
        for attempt in range(20):
            try:
                persisted[tenant]=json.loads(command(compose+['exec','-T','web_'+tenant,'php','-r',code],env=env))
                break
            except (RuntimeError,json.JSONDecodeError): time.sleep(1)
        check[tenant+'_restart_persistence']=tuple(persisted.get(tenant,[]))==before[tenant]
    if not all(check.values()): raise RuntimeError('Laboratory isolation or persistence check failed')
    evidence={'project':info['project'],'lock':LOCK,'source_hashes':info['source_hashes'],
              'chromium_sha256':info['chromium_sha256'],'npm_lock_sha256':info['npm_lock_sha256'],
              'runtime_checks':check,'woocommerce':results,'browser':browser_result,
              'http_checkout':http_result,
              'free_disk_bytes_after':shutil.disk_usage(ROOT).free,
              'limits':{'provider_gateway':'NOT_RUN','human_screen_reader':'NOT_RUN','production_tls':'NOT_RUN','full_product_acceptance':'NOT_RUN'}}
    write_json(state/'evidence.json',evidence)
    stop_state(state,info)
    print('Laboratory checks completed; containers stopped and synthetic volumes retained. Evidence: '+str(state/'evidence.json'),flush=True)
    if browser_result['status']!='PASS':
        raise RuntimeError('Browser result '+browser_result['status']+'; partial evidence saved without acceptance')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','run','stop'])
    parser.add_argument('--state',type=Path)
    parser.add_argument('--source-cache',type=Path)
    args=parser.parse_args()
    if args.action=='prepare': prepare(args.source_cache)
    else:
        if not args.state: parser.error('--state is required')
        state,info,env=load_state(args.state,verify_sources=args.action!='stop')
        if args.action=='run':
            try: run(state,info,env)
            finally: stop_state(state,info)
        else: stop_state(state,info)


if __name__=='__main__':
    try: main()
    except (RuntimeError,ValueError,OSError,subprocess.SubprocessError) as exc:
        print('Laboratory stopped: '+str(exc),file=sys.stderr)
        sys.exit(1)
