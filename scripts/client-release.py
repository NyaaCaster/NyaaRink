"""Build offline-signed C distributions from verified official Node archives. Never downloads or runs containers."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NODE_VERSION = '24.22.1'
SIGNER = '5BE8A3F6C8A5C01D106C0AD820B1A390B168D356'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, required=True)
    parser.add_argument('--gpg', default='gpg')
    parser.add_argument('--gpg-home', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    version = json.loads((ROOT / 'package.json').read_text())['version']
    sums = args.runtime_dir / 'SHASUMS256.txt'
    verification = subprocess.run([args.gpg, '--homedir', str(args.gpg_home), '--status-fd', '1', '--verify', str(sums) + '.sig', str(sums)], capture_output=True, text=True)
    if verification.returncode or not re.search(r'\[GNUPG:\] VALIDSIG ' + SIGNER + r' ', verification.stdout):
        raise SystemExit('Official Node signature could not be verified with the pinned signer')
    hashes = dict((name, sha) for sha, name in (line.split() for line in sums.read_text().splitlines()))
    args.output.mkdir(parents=True, exist_ok=True)
    artifacts = []
    notices = (ROOT / 'THIRD-PARTY-NOTICES.md').read_bytes()
    for dependency in ['ssh2', 'asn1', 'safer-buffer', 'bcrypt-pbkdf', 'tweetnacl', 'ws', 'zod']:
        notices += ('\n\n----- ' + dependency + ' -----\n').encode() + (ROOT / 'node_modules' / dependency / 'LICENSE').read_bytes()
    for platform, suffix, minimum in [('win32', 'win-x64.zip', 'Windows 11 / Server 2022 x64'), ('linux', 'linux-x64.tar.xz', 'Ubuntu 22.04 / Debian 12 x64, glibc 2.35')]:
        archive_name = f'node-v{NODE_VERSION}-{suffix}'
        data = (args.runtime_dir / archive_name).read_bytes()
        if hashes.get(archive_name) != digest(data):
            raise SystemExit(f'Official Node archive SHA256 mismatch: {platform}')
        prefix = f'node-v{NODE_VERSION}-' + ('win-x64' if platform == 'win32' else 'linux-x64')
        files = {}
        if platform == 'win32':
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                files['node.exe'] = archive.read(prefix + '/node.exe')
                files['NODE-LICENSE'] = archive.read(prefix + '/LICENSE')
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as archive:
                files['node'] = archive.extractfile(prefix + '/bin/node').read()
                files['NODE-LICENSE'] = archive.extractfile(prefix + '/LICENSE').read()
        files.update({'client.cjs': (ROOT / 'dist/client/client.cjs').read_bytes(), 'verify.cjs': (ROOT / 'dist/client/verify.cjs').read_bytes(),
                      'LICENSE': (ROOT / 'LICENSE').read_bytes(), 'THIRD-PARTY-NOTICES': notices})
        manifest = {'v': 1, 'version': version, 'platform': platform, 'arch': 'x64', 'nodeVersion': NODE_VERSION, 'minimumSystem': minimum,
                    'files': {name: digest(content) for name, content in files.items()}}
        files['manifest.json'] = json.dumps(manifest, separators=(',', ':'), ensure_ascii=False).encode()
        signing = subprocess.run(['node', '--input-type=module', '-e',
                                 "import{readFileSync}from'node:fs';import{sign}from'node:crypto';process.stdout.write(sign(null,readFileSync(0),readFileSync(process.env.NR_SIGN_KEY)));"],
                                input=files['manifest.json'], capture_output=True, env={**os.environ, 'NR_SIGN_KEY': str(args.key.resolve())})
        if signing.returncode:
            raise SystemExit('Offline release signing failed')
        files['manifest.sig'] = signing.stdout
        name = f'nyaarink-client-{version}-{platform}-x64.' + ('zip' if platform == 'win32' else 'tar.gz')
        path = args.output / name
        if platform == 'win32':
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for filename, content in files.items():
                    info = zipfile.ZipInfo(filename, date_time=(2026, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, content)
        else:
            with tarfile.open(path, 'w:gz') as archive:
                for filename, content in files.items():
                    info = tarfile.TarInfo(filename)
                    info.size, info.mode, info.mtime = len(content), 0o700 if filename == 'node' else 0o600, 0
                    archive.addfile(info, io.BytesIO(content))
        artifacts.append({'platform': platform, 'arch': 'x64', 'version': version, 'filename': name, 'sha256': digest(path.read_bytes()), 'manifestSha256': digest(files['manifest.json'])})
        print(f'Built signed client: {name}')
    index = json.dumps({'v': 1, 'version': version, 'artifacts': artifacts}, separators=(',', ':')).encode()
    (args.output / 'index.json').write_bytes(index)
    signing = subprocess.run(['node', '--input-type=module', '-e',
                             "import{readFileSync}from'node:fs';import{sign}from'node:crypto';process.stdout.write(sign(null,readFileSync(0),readFileSync(process.env.NR_SIGN_KEY)));"],
                            input=index, capture_output=True, env={**os.environ, 'NR_SIGN_KEY': str(args.key.resolve())})
    if signing.returncode:
        raise SystemExit('Catalog signing failed')
    (args.output / 'index.sig').write_bytes(signing.stdout)


if __name__ == '__main__':
    main()
