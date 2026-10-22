"""Fail-closed production restart. Never restores an older authorization ledger."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import time
import uuid
from backup import backup_database
from scripts.ops import environment, main, run


def execute():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--initialize', action='store_true', help='Only for a completely new empty authority')
    parser.add_argument('--tag', help='Explicit compatible release tag; leaves .env unchanged')
    args = parser.parse_args()
    root, env = environment()
    env['PATH'] = env.get('PATH', '') + ':/snap/bin'
    tag = args.tag or env.get('IMAGE_TAG', 'latest')
    if not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}', tag):
        raise ValueError('Invalid release tag')
    env['IMAGE_TAG'] = tag
    compose = ['docker', 'compose', '--project-directory', str(root), '-f', str(root / 'docker-compose.yml')]
    def call(*command):
        return run(compose + list(command), env, root)
    paths = {k: Path(env[k]).resolve(strict=True) for k in
             ['STATE_DIR', 'AUTHORITY_DIR', 'TLS_CERT_DIR', 'CLIENT_ARTIFACT_DIR', 'SESSION_MASTER_KEY_FILE']}
    for key, path in paths.items():
        if path.is_symlink() or (key != 'SESSION_MASTER_KEY_FILE' and not path.is_dir()):
            raise ValueError('Invalid private path')
    state, authority = paths['STATE_DIR'], paths['AUTHORITY_DIR']
    if state == authority or state in authority.parents or authority in state.parents:
        raise ValueError('Authority must be independent')
    if len(paths['SESSION_MASTER_KEY_FILE'].read_bytes()) != 32:
        raise ValueError('Invalid master key')
    if args.initialize and any(p.name != '.process.lock' for p in authority.iterdir()):
        raise ValueError('Initialization refuses existing authority')
    if not args.initialize and not (authority / 'identity.json').is_file():
        raise ValueError('Missing authority; never initialize as recovery')
    import fcntl
    with (root / '.restart.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        call('config', '--quiet')
        call('pull')  # Download failure leaves the running release untouched.
        if (state / 'state.db').exists():
            backup_database(state)
        changed = False
        try:
            call('stop', '-t', '30', 'gateway', 'app')
            changed = True
            # A container PID can be reused across namespaces. Only recover a stale lock
            # after every running container using this authority mount has been excluded.
            ids = run(['docker', 'ps', '-q'], env, root, quiet=True).split()
            if ids:
                running = json.loads(run(['docker', 'inspect'] + ids, env, root, quiet=True))
                if any(Path(m.get('Source', '/')).resolve() == authority or Path(m.get('Source', '/')).resolve() in authority.parents
                       for c in running for m in c.get('Mounts', [])):
                    raise RuntimeError('Authority still mounted by a running writer')
            destination = state / 'backups' / ('release-' + str(uuid.uuid4()))
            destination.mkdir(mode=0o700, parents=True)
            shutil.copytree(authority, destination / 'authority')
            shutil.copy2(paths['SESSION_MASTER_KEY_FILE'], destination / 'master.key')
            for directory, _, files in os.walk(destination):
                os.chmod(directory, 0o700)
                for name in files:
                    os.chmod(Path(directory) / name, 0o600)
            (authority / 'writer.lock').unlink(missing_ok=True)
            if args.initialize:
                call('run', '--rm', '--no-deps', 'app', 'node', 'dist/server/index.js', '--initialize-authority')
            call('run', '--rm', '--no-deps', 'app', 'node', 'dist/server/maintenance.js', 'verify-authority')
            # Configuration loads certificates and verifies both signed client artifacts.
            call('run', '--rm', '--no-deps', 'app', 'node', 'dist/server/preflight.js')
            call('up', '-d', '--wait', '--wait-timeout', '120', 'app')
            call('run', '--rm', '--no-deps', '--entrypoint', 'nginx', 'gateway', '-t')
            call('up', '-d', '--wait', '--wait-timeout', '120', 'gateway')
            # The gateway may run before TLS becomes reachable. Verify hostname, CA and ready.
            from urllib.parse import urlsplit
            origin = urlsplit(env['PUBLIC_BASE_URL'])
            for attempt in range(30):
                try:
                    result = run(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--max-time', '5',
                                  '--resolve', f'{origin.hostname}:{origin.port}:127.0.0.1',
                                  env['PUBLIC_BASE_URL'] + '/health/ready'], env, root, quiet=True)
                    if json.loads(result)['status'] == 'ready':
                        break
                    raise RuntimeError('Unexpected readiness response')
                except Exception:
                    if attempt == 29:
                        raise RuntimeError('Public TLS readiness failed') from None
                    time.sleep(2)
            print('Production release is healthy; authorization ledger and keys retained.')
        except Exception:
            if changed:
                call('stop', '-t', '30', 'gateway', 'app')
            raise
        # Deliberately retain previous tagged images for explicit compatible rollback.
        print('Both production services started; inspect with docker compose ps.')


if __name__ == '__main__':
    main(execute)
