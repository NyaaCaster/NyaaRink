"""Explicit opt-in production acceptance; creates only unique disposable C accounts/sessions."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
REMOTE = r'''
import hashlib, http.cookiejar, json, os, pathlib, pwd, secrets, shutil, signal, socket, ssl, subprocess, sys, tarfile, time, urllib.error, urllib.parse, urllib.request, uuid
root = pathlib.Path(sys.argv[1]); stage = pathlib.Path(sys.argv[2]); name = sys.argv[3]; port = int(sys.argv[4])
assert stage == pathlib.Path('/tmp/nyaarink-production-' + name)
assert name.startswith('nrtest') and len(name) == 18 and name[6:].isalnum()
sys.path.insert(0, str(root))
from scripts.ops import environment, run
from backup import backup_database
root, env = environment(root); env['PATH'] += ':/snap/bin'
origin = env['PUBLIC_BASE_URL']; host = urllib.parse.urlsplit(origin).hostname
real_lookup = socket.getaddrinfo
socket.getaddrinfo = lambda address, *a, **k: real_lookup('127.0.0.1' if address == host else address, *a, **k)
tls = ssl.create_default_context()
def opener(jar=None):
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls), urllib.request.HTTPCookieProcessor(jar or http.cookiejar.CookieJar()))
manager = opener(); sessions = []; processes = []; created = False; account = None
compose = ['docker', 'compose', '--project-directory', str(root), '-f', str(root / 'docker-compose.yml')]
sudoers = pathlib.Path('/etc/sudoers.d/' + name)
def api(path, body=None, browser=None, expected=200, key=True, csrf=None):
    headers = {'Content-Type': 'application/json', 'Idempotency-Key': str(uuid.uuid4())}
    if key: headers['Authorization'] = 'Bearer ' + env['MCP_API_KEY']
    if browser:
        headers['Origin'] = origin
        if csrf: headers['X-NR-CSRF'] = csrf
    request = urllib.request.Request(origin + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        response = (browser or manager).open(request, timeout=25)
    except urllib.error.HTTPError as error:
        assert error.code == expected, 'Unexpected API rejection: ' + path + ' status=' + str(error.code)
        return json.load(error)
    with response:
        assert response.status == expected, 'Unexpected API status: ' + path
        return json.load(response)
def command(args, **kw):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kw)
def wait(predicate, label, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate(): return
        except (urllib.error.URLError, ConnectionError): pass
        time.sleep(0.5)
    raise RuntimeError('Timed out: ' + label)
def summary(s): return api('/api/v1/sessions/' + s['id'])
def probe(s):
    task = api('/api/v1/sessions/' + s['id'] + '/executions', {'command': 'id -un', 'shell': 'posix', 'timeoutSeconds': 10}, expected=202)
    path = '/api/v1/executions/' + task['executionId']
    wait(lambda: api(path)['state'] not in ['queued','running'], 'SSH exec', 20)
    result = api(path)
    assert result['state'] == 'succeeded' and result['stdout'].strip() == name, 'SSH account mismatch'
def restore(snapshot):
    backup_database(env['STATE_DIR'])
    run(compose + ['stop', '-t', '30', 'gateway', 'app'], env, root)
    run(['python3', 'restore.py', '--database', str(snapshot)], env, root)
    run(['python3', 'restart.py'], env, root)
def make_session(payload):
    backup_database(env['STATE_DIR'])
    invitation = api('/api/v1/invitations', {'helperName':'Production acceptance', 'purpose':'Disposable ordinary-account verification'}, expected=201)
    code = invitation['inviteUrl'].rsplit('/',1)[-1]
    browser = opener(); page = api('/api/v1/browser/invitation?code=' + code, browser=browser, key=False)
    assert api('/api/v1/invitations/' + invitation['inviteId'])['state'] == 'issued'
    accepted = api('/api/v1/invitations/accept', {'code':code,'consent':True}, browser=browser, csrf=page['csrf'], key=False)
    s = {'id': accepted['id'], 'code':code, 'browser':browser, 'csrf':page['csrf']}; sessions.append(s)
    api('/api/v1/browser/invitation?code=' + code, browser=opener(), key=False, expected=404)
    boot = api('/api/v1/browser/bootstrap', {}, browser=browser, csrf=s['csrf'], key=False)
    inputfile = payload / (s['id'] + '.json')
    inputfile.write_text(json.dumps({'bootstrap':boot, 'port':port, 'runtime':str(payload)})); inputfile.chmod(0o600)
    os.chown(inputfile, account.pw_uid, account.pw_gid)
    log = (payload / (s['id'] + '.log')).open('w')
    process = subprocess.Popen(['runuser','-u',name,'--',str(payload/'node'),str(payload/'client.cjs'),str(inputfile)], stdout=log, stderr=subprocess.STDOUT)
    processes.append((process, log))
    wait(lambda: summary(s)['connectivity'] == 'online', 'production WSS enrollment')
    probe(s)
    s['state'] = pathlib.Path(account.pw_dir) / '.local/share/nyaarink' / s['id'] / 'state.json'
    s['credentialHash'] = hashlib.sha256(json.loads(s['state'].read_text())['sshPublicKey'].encode()).hexdigest()
    return s
try:
    before = backup_database(env['STATE_DIR'])
    api('/api/v1/sessions', key=False, expected=401)
    result = api('/mcp', {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}}, expected=406)
    # MCP requires both JSON and SSE media types; use the real protocol headers.
    req = urllib.request.Request(origin + '/mcp', data=json.dumps({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}}).encode(), headers={'Authorization':'Bearer '+env['MCP_API_KEY'],'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
    with manager.open(req, timeout=20) as response:
        tools = {tool['name'] for tool in json.load(response)['result']['tools']}
        assert {'rink_exec', 'rink_disconnect', 'rink_get_ssh_config', 'rink_upload_file', 'rink_download_file'} <= tools
        print('Production MCP tools discovered: ' + str(len(tools)), flush=True)
    command(['useradd','--create-home','--shell','/bin/bash',name]); created = True
    command(['chpasswd'], input=name+':'+secrets.token_urlsafe(48)+'\n')
    account = pwd.getpwnam(name); home = pathlib.Path(account.pw_dir); payload = home/'acceptance'; payload.mkdir(mode=0o700)
    with tarfile.open(stage/'runtime.tar.xz','r:xz') as archive:
        member = next(m for m in archive.getmembers() if m.name.endswith('/bin/node'))
        with (payload/'node').open('wb') as out: shutil.copyfileobj(archive.extractfile(member),out)
    (payload/'node').chmod(0o700); shutil.copyfile(stage/'client.cjs',payload/'client.cjs')
    ssh = home/'.ssh'; ssh.mkdir(mode=0o700); original = '# disposable production acceptance\n'; (ssh/'authorized_keys').write_text(original); (ssh/'authorized_keys').chmod(0o600)
    for parent, dirs, files in os.walk(home):
        os.chown(parent,account.pw_uid,account.pw_gid)
        for item in dirs+files: os.chown(pathlib.Path(parent)/item,account.pw_uid,account.pw_gid)
    pid = command(['systemctl','show','ssh.service','--property=MainPID','--value']).stdout.strip(); assert pid.isdigit() and int(pid)>0
    context = ('user='+name+',host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport='+str(port)).replace('=',r'\=').replace(',',r'\,')
    sudoers.write_text(name+' ALL=(root) NOPASSWD: /usr/bin/readlink -e /proc/'+pid+'/exe, /usr/sbin/sshd -T -C '+context+'\n'); sudoers.chmod(0o440); command(['visudo','-cf',str(sudoers)])
    first = make_session(payload); second = make_session(payload)
    config = api('/api/v1/sessions/'+first['id']+'/ssh-config')
    native = run(compose+['exec','-T','app','ssh','-F',config['configPath'],config['host'],'id','-un'],env,root,quiet=True); assert native.strip()==name
    print('PASS verified TLS, API/MCP authentication, one-time acceptance, real WSS/SSH and native OpenSSH', flush=True)
    conflict = subprocess.run(compose+['run','--rm','--no-deps','app','node','dist/server/maintenance.js','verify-authority'],env=env,cwd=root,capture_output=True)
    assert conflict.returncode != 0, 'Concurrent authority writer was accepted'
    run(['python3','restart.py'],env,root)
    for s in sessions:
        wait(lambda: summary(s)['connectivity']=='online','restart reconnect'); probe(s)
        assert hashlib.sha256(json.loads(s['state'].read_text())['sshPublicKey'].encode()).hexdigest()==s['credentialHash']
    run(compose+['kill','-s','SIGKILL','app'],env,root)
    run(compose+['up','-d','--wait','--wait-timeout','120','app'],env,root)
    for s in sessions: wait(lambda: summary(s)['connectivity']=='online','crash reconnect'); probe(s)
    print('PASS restart/crash retained authorization and credentials; concurrent writer rejected',flush=True)
    restore(before)
    for s in sessions: wait(lambda: summary(s)['connectivity']=='online','database restore reconnect'); probe(s)
    backup_database(env['STATE_DIR']); api('/api/v1/sessions/'+first['id']+'/disconnect',{})
    wait(lambda: summary(first)['cCleanup']=='confirmed','S revoke cleanup')
    assert summary(first)['sCleanup']=='confirmed'
    gone = subprocess.run(compose+['exec','-T','app','test','!','-e',config['configPath']],env=env,cwd=root,capture_output=True); assert gone.returncode==0
    api('/api/v1/browser/invitation?code='+first['code'],browser=first['browser'],key=False,expected=404)
    restore(before)
    assert summary(first)['authorization']=='revoked'
    wait(lambda: summary(second)['connectivity']=='online','valid session after revoked restore'); probe(second)
    backup_database(env['STATE_DIR']); api('/api/v1/browser/disconnect',{'sessionId':second['id']},browser=second['browser'],csrf=second['csrf'],key=False)
    wait(lambda: summary(second)['cCleanup']=='confirmed','C revoke cleanup')
    api('/api/v1/browser/invitation?code='+second['code'],browser=second['browser'],key=False,expected=404)
    for s in sessions:
        state = json.loads(s['state'].read_text()); assert state['phase']=='cleaned' and 'devicePrivateKey' not in state
    assert (ssh/'authorized_keys').read_text()==original
    print('PASS old DB restore retains new valid sessions and never revives revoked access; both sides revoke and clean credentials',flush=True)
finally:
    # Preserve immutable revoke history. Never edit the authority to hide acceptance records.
    for s in sessions:
        try:
            if summary(s)['authorization']!='revoked':
                backup_database(env['STATE_DIR']); api('/api/v1/sessions/'+s['id']+'/disconnect',{})
            wait(lambda: summary(s)['cCleanup']=='confirmed','final revoke cleanup',20)
        except Exception: print('Acceptance cleanup receipt pending; inspect this test session before removal',file=sys.stderr)
    for process, log in processes:
        if process.poll() is None: process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
        log.close()
    sudoers.unlink(missing_ok=True)
    if created:
        for item in pathlib.Path('/proc').iterdir():
            if item.name.isdigit():
                try:
                    if item.stat().st_uid==account.pw_uid: os.kill(int(item.name),signal.SIGKILL)
                except (ProcessLookupError,FileNotFoundError): pass
        command(['userdel','--remove',name])
    shutil.rmtree(stage,ignore_errors=True)
print('Production acceptance complete; disposable C account/processes/files removed; immutable revocations and private recovery backups retained.',flush=True)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--remote-root', required=True)
    parser.add_argument('--ssh-port', type=int, required=True)
    parser.add_argument('--runtime-archive', type=Path, required=True)
    args = parser.parse_args()
    assert args.runtime_archive.is_file()
    name = 'nrtest' + uuid.uuid4().hex[:12]
    stage = '/tmp/nyaarink-production-' + name
    with tempfile.TemporaryDirectory(prefix='nyaarink-production-') as directory:
        bundle = Path(directory) / 'client.cjs'
        subprocess.run(['node', 'node_modules/esbuild/bin/esbuild', 'tests/production-client.ts', '--bundle', '--platform=node', '--target=node24', '--format=cjs', '--external:cpu-features', '--external:*.node', '--outfile=' + str(bundle)], cwd=ROOT, check=True)
        subprocess.run(['ssh', args.host, 'umask 077 && mkdir ' + stage], check=True)
        try:
            for source, target in [(bundle, 'client.cjs'), (args.runtime_archive, 'runtime.tar.xz')]:
                subprocess.run(['scp', '-q', str(source), args.host + ':' + stage + '/' + target], check=True)
            subprocess.run(['ssh', args.host, 'python3', '-', args.remote_root, stage, name, str(args.ssh_port)], input=REMOTE, text=True, check=True, timeout=1200)
        finally:
            subprocess.run(['ssh', args.host, 'python3 -c "import pathlib,shutil; p=pathlib.Path(\'' + stage + '\'); shutil.rmtree(p) if p.exists() else None"'], check=True)


if __name__ == '__main__':
    main()
