"""Opt-in Docker build/content verification; never starts containers or publishes images."""
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def verify(archive, target):
    # Replay layer deletion markers before inspecting the final image view.
    files = {}
    with tarfile.open(archive) as image:
        manifest = json.load(image.extractfile('manifest.json'))[0]
        config = json.load(image.extractfile(manifest['Config']))['config']
        assert config['User'] == ('node' if target == 'app' else '101:101')
        for layer_name in manifest['Layers']:
            with image.extractfile(layer_name) as stream, tarfile.open(fileobj=stream, mode='r|*') as layer:
                for member in layer:
                    path = member.name.removeprefix('./').lstrip('/')
                    parent, _, name = path.rpartition('/')
                    if name == '.wh..wh..opq':
                        files = {key: value for key, value in files.items() if not key.startswith(parent + '/')}
                    elif name.startswith('.wh.'):
                        deleted = parent + '/' + name[4:]
                        files = {key: value for key, value in files.items() if key != deleted and not key.startswith(deleted + '/')}
                    elif member.isfile() and (path.startswith('app/') or path == 'etc/nginx/nginx.conf'):
                        # Keep only project-owned files, not the base OS payload.
                        files[path] = layer.extractfile(member).read()
    if target == 'gateway':
        assert b'listen 8443 ssl' in files['etc/nginx/nginx.conf']
        assert config['Entrypoint'] == ['nginx', '-g', 'daemon off;']
        return
    assert config['Cmd'] == ['node', 'dist/server/index.js']
    for name in ['dist/server/index.js', 'dist/server/maintenance.js', 'dist/server/proxy-client.js',
                 'dist/cli/index.js', 'dist/web/index.html', 'LICENSE', 'THIRD-PARTY-NOTICES.md',
                 'dist/licenses/dependencies.json', 'dist/licenses/THIRD-PARTY-NOTICES.txt']:
        assert 'app/' + name in files, 'Missing required image file: ' + name
    inventory = json.loads(files['app/dist/licenses/dependencies.json'])
    notices = files['app/dist/licenses/THIRD-PARTY-NOTICES.txt']
    assert inventory and all((item['name'] + '@' + item['version']).encode() in notices for item in inventory)
    forbidden = re.compile(r'^app/(?:\.env(?:\.|$)|\.git/|\.docs/|\.claude/|\.agents/|private/|certs/|secrets/|sessions/|backups/|data/)')
    for path, data in files.items():
        assert not forbidden.search(path), 'Private/development path in image: ' + path
        if not path.startswith('app/'):
            continue
        for variable in ['GITHUB_PAT', 'MCP_API_KEY', 'MCP_API_KEY_PREVIOUS']:
            secret = os.environ.get(variable, '')
            assert len(secret) < 24 or secret.encode() not in data, 'Environment secret in image'
        # Dependency source code contains key-format literals; inspect project bundles only.
        if path.startswith('app/dist/'):
            assert not re.search(rb'-----BEGIN (?:OPENSSH |RSA |EC |ENCRYPTED )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{32}', data), 'Private key in bundle'
    print(json.dumps({'image': target, 'licensePackages': len(inventory), 'contentCheck': True}))


def main():
    owned = []
    cache_root = Path('E:/DockerRes/NyaaRink') if os.name == 'nt' else None
    if cache_root:
        cache_root.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix='image-check-', dir=cache_root) as directory:
            for target in ['app', 'gateway']:
                tag = 'nyaarink-check-' + uuid.uuid4().hex + ':' + target
                owned.append(tag)  # Cleanup also covers a build that completed before interruption.
                subprocess.run(['docker', 'build', '--target', target, '-t', tag, '.'], cwd=ROOT, check=True)
                archive = Path(directory) / (target + '.tar')
                subprocess.run(['docker', 'image', 'save', '-o', str(archive), tag], check=True)
                verify(archive, target)
                archive.unlink()
    finally:
        for tag in owned:
            if subprocess.run(['docker', 'image', 'inspect', tag], capture_output=True).returncode == 0:
                subprocess.run(['docker', 'image', 'rm', tag], check=True, stdout=subprocess.DEVNULL)
    print('Image checks passed; temporary exports and image tags removed. No containers started.')


if __name__ == '__main__':
    main()
