"""acme wrapper: preserve the configured existing hook and refresh this project."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from scripts.ops import environment, main, run


def execute():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sync-only', action='store_true')
    args = parser.parse_args()
    root, env = environment()
    env['PATH'] = env.get('PATH', '') + ':/snap/bin'
    failed = False
    if not args.sync_only:
        previous = json.loads(env.get('CERT_PREVIOUS_RELOAD_JSON', '[]'))
        if not isinstance(previous, list) or any(not isinstance(x, str) for x in previous):
            raise ValueError('Invalid previous hook')
        if previous:
            try:
                run(previous, env, root, quiet=True)
            except Exception:
                failed = True
    source, target = Path(env['CERT_SOURCE_DIR']), Path(env['TLS_CERT_DIR'])
    if source.resolve() == target.resolve():
        raise ValueError('Use a dedicated certificate copy')
    target.mkdir(mode=0o755, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.renew-', dir=target) as temporary:
        temp = Path(temporary)
        for name in ['fullchain.pem', 'privkey.pem']:
            shutil.copyfile(source / name, temp / name)
        cert = subprocess.run(['openssl', 'x509', '-in', str(temp / 'fullchain.pem'), '-pubkey', '-noout'], check=True, capture_output=True).stdout
        key = subprocess.run(['openssl', 'pkey', '-in', str(temp / 'privkey.pem'), '-pubout'], check=True, capture_output=True).stdout
        if cert != key:
            raise ValueError('Certificate and private key mismatch')
        subprocess.run(['openssl', 'x509', '-in', str(temp / 'fullchain.pem'), '-checkend', '86400', '-noout'], check=True, capture_output=True)
        for name in ['fullchain.pem', 'privkey.pem']:
            item = temp / name
            os.chmod(item, 0o600 if name == 'privkey.pem' else 0o644)
            os.chown(item, 101 if name == 'privkey.pem' else 0, 101 if name == 'privkey.pem' else 0)
            os.replace(item, target / name)
    if not args.sync_only:
        compose = ['docker', 'compose', '--project-directory', str(root), '-f', str(root / 'docker-compose.yml')]
        run(compose + ['exec', '-T', 'gateway', 'nginx', '-t'], env, root)
        run(compose + ['exec', '-T', 'gateway', 'nginx', '-s', 'reload'], env, root)
    if failed:
        raise RuntimeError('Previous certificate consumer hook failed')
    print('Certificate consumers refreshed.')


if __name__ == '__main__':
    main(execute)
