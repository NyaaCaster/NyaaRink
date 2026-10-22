"""Opt-in native Linux check over an existing root SSH alias; owns only a unique test account."""
import argparse
import json
import queue
from pathlib import Path
import subprocess
import tempfile
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
REMOTE = r'''
import json, os, pathlib, pwd, secrets, shutil, signal, socket, subprocess, sys, tarfile, time
stage = pathlib.Path(sys.argv[1])
name = sys.argv[2]
port = int(sys.argv[3]); assert 0 < port < 65536
assert stage.parent == pathlib.Path('/tmp') and stage.name == 'nyaarink-check-' + name
assert name.startswith('nrtest') and len(name) == 18 and name[6:].isalnum()
sudoers = pathlib.Path('/etc/sudoers.d/' + name)
created = False
daemon = None
login = None
def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)
try:
    run(['useradd', '--create-home', '--shell', '/bin/bash', name]); created = True
    # A random unknown password unlocks public-key login without enabling an empty password.
    run(['chpasswd'], input=name + ':' + secrets.token_urlsafe(48) + '\n')
    account = pwd.getpwnam(name); home = pathlib.Path(account.pw_dir)
    payload = home / 'check'; payload.mkdir(mode=0o700)
    with tarfile.open(stage / 'runtime.tar.xz', 'r:xz') as archive:
        member = next(m for m in archive.getmembers() if m.name.endswith('/bin/node'))
        with (payload / 'node').open('wb') as out: shutil.copyfileobj(archive.extractfile(member), out)
    (payload / 'node').chmod(0o700)
    shutil.copyfile(stage / 'native.cjs', payload / 'native.cjs')
    shutil.copyfile(stage / 'client.cjs', payload / 'client.cjs')
    recovery = (stage / 'input.json').exists()
    if recovery:
        for item in ['input.json', 'cert.pem', 'login.cjs']:
            shutil.copyfile(stage / item, payload / item)
    ssh = home / '.ssh'; ssh.mkdir(mode=0o700)
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(stage / 'key')])
    (ssh / 'authorized_keys').write_text((stage / 'key.pub').read_text()); (ssh / 'authorized_keys').chmod(0o600)
    for parent, dirs, files in os.walk(home):
        os.chown(parent, account.pw_uid, account.pw_gid)
        for item in dirs + files: os.chown(pathlib.Path(parent) / item, account.pw_uid, account.pw_gid)
    host = pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
    # A separate loopback login daemon provides a real PAM user session without
    # changing the host service (which may intentionally have UsePAM disabled).
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0)); login_port = probe.getsockname()[1]
    (stage / 'login.conf').write_text('Port ' + str(login_port) + '\nListenAddress 127.0.0.1\nHostKey /etc/ssh/ssh_host_ed25519_key\nAuthorizedKeysFile .ssh/authorized_keys\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\nAllowUsers ' + name + '\n')
    daemon = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(stage / 'login.conf')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for attempt in range(50):
        try:
            with socket.create_connection(('127.0.0.1', login_port), timeout=1): break
        except OSError:
            if daemon.poll() is not None: raise RuntimeError('Isolated login daemon failed')
            time.sleep(0.1)
    else: raise RuntimeError('Isolated login daemon timed out')
    (stage / 'known_hosts').write_text('[127.0.0.1]:' + str(login_port) + ' ' + ' '.join(host[:2]) + '\n')
    pid = run(['systemctl', 'show', 'ssh.service', '--property=MainPID', '--value']).stdout.strip()
    assert pid.isdigit() and int(pid) > 0
    context = 'user=' + name + ',host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=' + str(port)
    escaped = context.replace('=', r'\=').replace(',', r'\,')
    sudoers.write_text(name + ' ALL=(root) NOPASSWD: /usr/bin/readlink -e /proc/' + pid + '/exe, /usr/sbin/sshd -T -C ' + escaped + '\n')
    sudoers.chmod(0o440); run(['visudo', '-cf', str(sudoers)])
    ssh_args = ['ssh', '-p', str(login_port), '-i', str(stage / 'key'), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                  '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(stage / 'known_hosts'),
                  name + '@127.0.0.1']
    result = run(ssh_args + ['env', 'NR_TEST_RUNTIME=' + str(payload), str(payload / 'node'), str(payload / 'native.cjs'), str(port)], timeout=60)
    print(result.stdout, end='')
    print(json.dumps({'ordinaryLinuxAccountCheck': True, 'loginRegistrationOnly': True, 'systemSshConfigurationUnchanged': True}))
    if recovery:
        import ssl, urllib.request
        data = json.loads((payload / 'input.json').read_text())
        origin = data['bootstrap']['origin']; observer = data['observer']
        context_tls = ssl.create_default_context(cafile=str(payload / 'cert.pem'))
        def observe(suffix='', method='GET'):
            request = urllib.request.Request(origin + observer + suffix, method=method)
            # Ignore proxy environment variables for this explicit loopback fixture.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context_tls))
            with opener.open(request, timeout=20) as response: return json.load(response)
        def wait_for(predicate, label):
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                if predicate(): return
                time.sleep(0.2)
            raise RuntimeError('Timed out: ' + label)
        def terminate_user():
            subprocess.run(['loginctl', 'terminate-user', name], capture_output=True)
            wait_for(lambda: subprocess.run(['systemctl', 'is-active', '--quiet', 'user@' + str(account.pw_uid) + '.service']).returncode != 0, 'user manager shutdown')
        run(ssh_args + ['env', 'NR_TEST_RUNTIME=' + str(payload), 'NODE_EXTRA_CA_CERTS=' + str(payload / 'cert.pem'), str(payload / 'node'), str(payload / 'login.cjs'), str(port)], timeout=90)
        terminate_user()
        for cycle in range(2):
            login = subprocess.Popen(ssh_args + ['sleep', '120'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_for(lambda: observe()['online'], 'login auto recovery')
            result = observe('/probe', 'POST')
            assert result['state'] == 'succeeded' and result['stdout'].strip() == name, 'Recovered SSH account mismatch'
            if cycle == 0:
                terminate_user(); login.wait(timeout=15); login = None
                wait_for(lambda: not observe()['online'], 'logout transport shutdown')
                assert observe()['authorization'] == 'enrolled', 'Logout revoked authorization'
        observe('/revoke', 'POST')
        wait_for(lambda: observe()['cCleanup'] == 'confirmed', 'explicit revoke cleanup')
        state = json.loads((home / '.local/share/nyaarink' / data['bootstrap']['sessionId'] / 'state.json').read_text())
        assert state['phase'] == 'cleaned' and 'devicePrivateKey' not in state
        assert not pathlib.Path(state['loginFile']).exists()
        assert (ssh / 'authorized_keys').read_text() == (payload / 'original-keys').read_text()
        print(json.dumps({'realLoginRecoveryCycles': 2, 'sshAccountVerified': True, 'logoutPreservedAuthorization': True, 'explicitRevokeCleanupConfirmed': True}))
except subprocess.CalledProcessError as error:
    # Only these fixed check commands run here; no credentials are printed.
    print((error.stderr or '')[-4000:], file=sys.stderr)
    raise
finally:
    if login is not None:
        login.terminate(); login.wait(timeout=10)
    if daemon is not None:
        daemon.terminate(); daemon.wait(timeout=10)
    sudoers.unlink(missing_ok=True)
    if created:
        subprocess.run(['loginctl', 'terminate-user', name], capture_output=True)
        # A terminated SSH client can leave its remote sleep in a closing scope.
        # This unique account belongs exclusively to this test; kill only its UID.
        for item in pathlib.Path('/proc').iterdir():
            if item.name.isdigit():
                try:
                    if item.stat().st_uid == account.pw_uid: os.kill(int(item.name), signal.SIGKILL)
                except (ProcessLookupError, FileNotFoundError): pass
        # User manager shutdown is asynchronous; wait rather than racing userdel.
        for attempt in range(50):
            result = subprocess.run(['userdel', '--remove', name], capture_output=True, text=True)
            if result.returncode == 0: break
            time.sleep(0.2)
        else: raise RuntimeError('Temporary account cleanup failed: ' + name)
    shutil.rmtree(stage)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--runtime-archive', type=Path, required=True)
    parser.add_argument('--ssh-port', type=int, default=22)
    parser.add_argument('--login-recovery', action='store_true')
    args = parser.parse_args()
    # Call only after the existing release builder has verified the official runtime archive.
    if not args.runtime_archive.is_file() or not (ROOT / 'dist/client/client.cjs').is_file():
        raise SystemExit('Build the client and provide its verified official Linux runtime archive first')
    name = 'nrtest' + uuid.uuid4().hex[:12]
    stage = '/tmp/nyaarink-check-' + name
    with tempfile.TemporaryDirectory(prefix='nyaarink-native-bundle-') as directory:
        fixture = None
        forward = None
        bundle = Path(directory) / 'native.cjs'
        subprocess.run(['node', 'node_modules/esbuild/bin/esbuild', 'tests/native-client-check.ts', '--bundle', '--platform=node',
                        '--target=node24', '--format=cjs', '--external:cpu-features', '--external:*.node', '--outfile=' + str(bundle)], cwd=ROOT, check=True)
        try:
            sources = [(bundle, 'native.cjs'), (ROOT / 'dist/client/client.cjs', 'client.cjs'), (args.runtime_archive, 'runtime.tar.xz')]
            if args.login_recovery:
                login_bundle = Path(directory) / 'login.cjs'
                subprocess.run(['node', 'node_modules/esbuild/bin/esbuild', 'tests/linux-login-client.ts', '--bundle', '--platform=node', '--target=node24', '--format=cjs', '--external:cpu-features', '--external:*.node', '--outfile=' + str(login_bundle)], cwd=ROOT, check=True)
                fixture = subprocess.Popen(['node', '--import', 'tsx', 'tests/linux-login-server.ts', directory], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                lines = queue.Queue()
                threading.Thread(target=lambda: lines.put(fixture.stdout.readline()), daemon=True).start()
                ready = json.loads(lines.get(timeout=40)); port = ready['port']
                forward = subprocess.Popen(['ssh', '-N', '-o', 'BatchMode=yes', '-o', 'ExitOnForwardFailure=yes', '-R', f'127.0.0.1:{port}:127.0.0.1:{port}', args.host], stdout=subprocess.DEVNULL)
                sources += [(login_bundle, 'login.cjs'), (Path(directory) / 'cert.pem', 'cert.pem'), (Path(directory) / 'input.json', 'input.json')]
            subprocess.run(['ssh', '-o', 'BatchMode=yes', args.host, 'umask 077 && mkdir ' + stage], check=True)
            for source, target in sources:
                subprocess.run(['scp', '-q', str(source), args.host + ':' + stage + '/' + target], check=True)
            subprocess.run(['ssh', '-o', 'BatchMode=yes', args.host, 'python3', '-', stage, name, str(args.ssh_port)], input=REMOTE, text=True, check=True, timeout=300)
        finally:
            try:
                subprocess.run(['ssh', args.host, 'python3 -c "import pathlib,shutil; p=pathlib.Path(\'' + stage + '\'); shutil.rmtree(p) if p.exists() else None"'], check=True, timeout=30)
            finally:
                if forward is not None:
                    forward.terminate(); forward.wait(timeout=10)
                if fixture is not None:
                    fixture.stdin.close()
                    try: fixture.wait(timeout=15)
                    except subprocess.TimeoutExpired: fixture.terminate(); fixture.wait(timeout=10)
    print('Temporary account, sudo rules, keys, login registration and payload cleaned.')


if __name__ == '__main__':
    main()
