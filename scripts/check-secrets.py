"""Review staged publication content without displaying sensitive matches."""
import os
import re
import subprocess
import sys

paths = subprocess.check_output(['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']).decode().split('\0')
failures = []
for path in filter(None, paths):
    if re.search(r'(^|/)(private|certs|secrets|backups|sessions|node_modules[^/]*)/|\.(pem|key|pfx|p12|db|sqlite|log)$|(^|/)\.env(?!\.example$)|开发环境准备\.md', path):
        failures.append(path)
        continue
    value = subprocess.check_output(['git', 'show', ':' + path]).decode('utf-8', errors='replace')
    patterns = [r'gh[pousr]_[A-Za-z0-9]{20,}', r'github_pat_[A-Za-z0-9_]{20,}', r'-----BEGIN (?:OPENSSH |RSA |EC |ENCRYPTED )?PRIVATE KEY-----', r'(?:localhost:5000|192\.168\.31\.142:5000|h\.nyaa\.host:5000)']
    if path.endswith('check-secrets.py'):
        patterns = patterns[:3]
    if any(re.search(pattern, value) for pattern in patterns): failures.append(path)
    for name in ['GITHUB_PAT', 'MCP_API_KEY', 'MCP_API_KEY_PREVIOUS']:
        secret = os.environ.get(name, '')
        if len(secret) >= 24 and secret in value: failures.append(path)
if failures:
    print('Publication refused; sensitive paths/content:', ', '.join(sorted(set(failures))), file=sys.stderr)
    sys.exit(1)
print('Staged secret checks passed:', len(list(filter(None, paths))), 'files')
