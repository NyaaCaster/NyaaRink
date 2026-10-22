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


def run(args, env=None, cwd=None, attempts=1):
    for _ in range(attempts):
        result = subprocess.run(args, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
        output = result.stdout
        for key in ['PRIVATE_DOCKER_REGISTRY_HOST', 'MCP_API_KEY', 'MCP_API_KEY_PREVIOUS', 'GITHUB_PAT']:
            if (env or os.environ).get(key):
                output = output.replace((env or os.environ)[key], '<PRIVATE_REGISTRY>' if key == 'PRIVATE_DOCKER_REGISTRY_HOST' else '<REDACTED>')
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
