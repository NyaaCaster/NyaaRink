"""Build offline-signed native clients; never installs SSH or starts containers."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
GO_VERSION = 'go1.27.3'
OPENSSH = json.loads((ROOT / 'packages/windows-openssh.json').read_text())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def windows_openssh_files(directory):
    data = (directory / OPENSSH['filename']).read_bytes()
    if digest(data) != OPENSSH['sha256']:
        raise ValueError('Official OpenSSH ZIP SHA256 mismatch')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = {name: archive.read('OpenSSH-Win64/' + name) for name in OPENSSH['files']}
        files.update({'OPENSSH-LICENSE.txt': archive.read('OpenSSH-Win64/LICENSE.txt'),
                      'OPENSSH-NOTICE.txt': archive.read('OpenSSH-Win64/NOTICE.txt')})
    with tempfile.TemporaryDirectory(prefix='nyaarink-signatures-') as temporary:
        for name in OPENSSH['files']:
            path = Path(temporary) / name
            path.write_bytes(files[name])
            script = "$ErrorActionPreference='Stop';$env:PSModulePath=Join-Path $PSHOME 'Modules';$s=Get-AuthenticodeSignature -LiteralPath $env:NR_COMPONENT;if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ine '" + OPENSSH['signers'][name] + "'){throw 'Microsoft component signature rejected'}"
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                    capture_output=True, env={**os.environ, 'NR_COMPONENT': str(path)})
            if result.returncode:
                raise ValueError('Official Microsoft signature rejected: ' + name + ': ' + result.stderr.decode(errors='replace'))
    return files


def sign(data, key):
    result = subprocess.run(['node', '--input-type=module', '-e',
        "import{readFileSync}from'node:fs';import{sign}from'node:crypto';process.stdout.write(sign(null,readFileSync(0),readFileSync(process.env.NR_SIGN_KEY)));"],
        input=data, capture_output=True, env={**os.environ, 'NR_SIGN_KEY': str(key.resolve())})
    if result.returncode or len(result.stdout) != 64:
        raise ValueError('Offline release signing failed')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--openssh-dir', required=True, type=Path)
    args = parser.parse_args()
    go = str(args.go.resolve())
    version_output = subprocess.check_output([go, 'version'], text=True)
    if version_output.split()[2] != GO_VERSION:
        raise ValueError('Pinned Go toolchain required: ' + GO_VERSION)
    module = ROOT / 'apps/client-native'
    version = json.loads((ROOT / 'package.json').read_text())['version']
    notices = (ROOT / 'THIRD-PARTY-NOTICES.md').read_bytes()
    go_root = Path(subprocess.check_output([go, 'env', 'GOROOT'], text=True).strip())
    notices += b'\n\n----- Go standard library -----\n' + (go_root / 'LICENSE').read_bytes()
    for dependency in ['github.com/gorilla/websocket', 'golang.org/x/crypto', 'golang.org/x/sys']:
        location = Path(subprocess.check_output([go, 'list', '-m', '-f', '{{.Dir}}', dependency], cwd=module, text=True).strip())
        notices += ('\n\n----- ' + dependency + ' -----\n').encode() + (location / 'LICENSE').read_bytes()
    microsoft = windows_openssh_files(args.openssh_dir)
    args.output.mkdir(parents=True, exist_ok=True)
    artifacts = []
    with tempfile.TemporaryDirectory(prefix='nyaarink-native-build-') as temporary:
        for platform, goos, minimum in [('win32', 'windows', 'Windows 11 / Server 2022 x64'),
                                      ('linux', 'linux', 'Ubuntu 22.04/24.04 or Debian 12/13 x64; system OpenSSH')]:
            binary = 'nyaarink-client' + ('.exe' if goos == 'windows' else '')
            target = Path(temporary) / binary
            env = {**os.environ, 'CGO_ENABLED': '0', 'GOOS': goos, 'GOARCH': 'amd64', 'GOTOOLCHAIN': 'local'}
            subprocess.run([go, 'build', '-trimpath', '-buildvcs=false', '-ldflags', '-s -w -X main.version=' + version,
                            '-o', str(target), '.'], cwd=module, env=env, check=True)
            files = {binary: target.read_bytes(), 'LICENSE': (ROOT / 'LICENSE').read_bytes(), 'THIRD-PARTY-NOTICES': notices}
            if platform == 'win32':
                files.update(microsoft)
            manifest = {'v': 2, 'version': version, 'platform': platform, 'arch': 'x64', 'runtime': 'go',
                        'goVersion': GO_VERSION, 'minimumSystem': minimum,
                        'files': {name: digest(content) for name, content in files.items()}}
            files['manifest.json'] = json.dumps(manifest, separators=(',', ':'), ensure_ascii=False).encode()
            files['manifest.sig'] = sign(files['manifest.json'], args.key)
            name = f'nyaarink-client-{version}-{platform}-x64.' + ('zip' if platform == 'win32' else 'tar.gz')
            path = args.output / name
            if platform == 'win32':
                with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                    for filename, content in files.items():
                        info = zipfile.ZipInfo(filename, date_time=(2026, 1, 1, 0, 0, 0))
                        info.compress_type = zipfile.ZIP_DEFLATED
                        archive.writestr(info, content, compresslevel=9)
            else:
                with tarfile.open(path, 'w:gz') as archive:
                    for filename, content in files.items():
                        info = tarfile.TarInfo(filename)
                        info.size, info.mode, info.mtime = len(content), 0o700 if filename == binary else 0o600, 0
                        archive.addfile(info, io.BytesIO(content))
            artifacts.append({'platform': platform, 'arch': 'x64', 'version': version, 'filename': name,
                              'runtime': 'go', 'executableSha256': digest(files[binary]),
                              'sha256': digest(path.read_bytes()), 'manifestSha256': digest(files['manifest.json'])})
            print(f'Built signed native client: {name} ({path.stat().st_size:,} bytes)')
    index = json.dumps({'v': 1, 'version': version, 'artifacts': artifacts}, separators=(',', ':')).encode()
    (args.output / 'index.json').write_bytes(index)
    (args.output / 'index.sig').write_bytes(sign(index, args.key))


if __name__ == '__main__':
    main()
