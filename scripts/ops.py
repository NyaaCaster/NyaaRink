"""Shared operations. Never persist or display private registry values."""
from pathlib import Path
import os
import subprocess
import sys


def environment(directory=None):
    root = Path(directory or Path(__file__).resolve().parents[1])
    result = dict(os.environ)
    for line in (root / '.env').read_text(encoding='utf-8-sig').splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            result[key.strip()] = value.strip().strip('\"\'')
    return root, result


def run(args, env=None, cwd=None, attempts=1, quiet=False):
    for _ in range(attempts):
        result = subprocess.run(args, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
        output = result.stdout
        for key in ['PRIVATE_DOCKER_REGISTRY_HOST', 'MCP_API_KEY', 'MCP_API_KEY_PREVIOUS', 'GITHUB_PAT']:
            if (env or os.environ).get(key):
                output = output.replace((env or os.environ)[key], '<PRIVATE_REGISTRY>' if key == 'PRIVATE_DOCKER_REGISTRY_HOST' else '<REDACTED>')
        if not quiet:
            print(output, end='')
        if result.returncode == 0:
            return result.stdout.strip()
    raise RuntimeError('Command failed: ' + args[0])


def main(action):
    try:
        action()
    except Exception as error:
        print('Operation refused: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)


def maintenance(root, env, arguments):
    """Use local development build or the stopped production image, with identical semantics."""
    if (root / 'dist/server/maintenance.js').is_file():
        return run(['node', str(root / 'dist/server/maintenance.js'), *arguments], env, root)
    env = dict(env)
    env['PATH'] = env.get('PATH', '') + ':/snap/bin'
    compose = ['docker', 'compose', '--project-directory', str(root), '-f', str(root / 'docker-compose.yml')]
    if run(compose + ['ps', '--status', 'running', '-q', 'app'], env, root, quiet=True):
        raise RuntimeError('Stop app before offline maintenance')
    if arguments[0] == 'restore-database':
        relative = Path(arguments[1]).resolve(strict=True).relative_to(Path(env['STATE_DIR']).resolve(strict=True))
        arguments = [arguments[0], '/private/state/' + relative.as_posix()]
    return run(compose + ['run', '--rm', '--no-deps', 'app', 'node', 'dist/server/maintenance.js', *arguments], env, root)
