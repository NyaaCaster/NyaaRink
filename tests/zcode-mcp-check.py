"""Opt-in real ZCode discovery check; never sends a prompt or changes user config."""
import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading
import time


def messages(stream, target):
    for line in stream:
        try:
            target.put(json.loads(line))
        except json.JSONDecodeError:
            pass


def response(target, identifier, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            item = target.get(timeout=max(0.1, deadline - time.monotonic()))
        except queue.Empty as error:
            raise TimeoutError('ZCode protocol response timed out') from error
        if item.get('id') == 'invalid-message':
            raise RuntimeError('Invalid ZCode protocol envelope')
        if item.get('id') == identifier:
            if 'error' in item:
                raise RuntimeError('ZCode protocol request failed: ' + str(item['error'].get('code')))
            return item['result']
    raise TimeoutError('ZCode protocol response timed out')


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        process.stdin.close()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
    process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', required=True, type=Path, help='Installed ZCode zcode.cjs')
    args = parser.parse_args()
    cli = args.cli.resolve(strict=True)
    bundled = (cli.parent.parent / 'config/provider/zcode-builtin.json').resolve(strict=True)
    repo = Path(__file__).resolve().parent.parent
    node = shutil.which('node')
    if not node:
        raise RuntimeError('Node is required')
    # Fresh storage only: no existing user database is opened or mutated.
    with tempfile.TemporaryDirectory(prefix='nyaarink-zcode-') as directory:
        root = Path(directory)
        fixture = root / 'fixture'
        fixture.mkdir()
        workspace = root / 'workspace'
        workspace.mkdir()
        home = root / 'home'
        config = home / '.zcode' / 'cli'
        config.mkdir(parents=True)
        (config / 'config.json').write_text(json.dumps({'plugins': {'enabled': False}, 'hooks': {'enabled': False}}))
        server = client = None
        try:
            with (root / 'server.err').open('w') as server_errors, (root / 'client.err').open('w') as client_errors:
                server = subprocess.Popen([node, '--import', 'tsx', 'tests/linux-login-server.ts', str(fixture), '--management'], cwd=repo,
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=server_errors, text=True)
                server_queue = queue.Queue()
                threading.Thread(target=messages, args=(server.stdout, server_queue), daemon=True).start()
                server_queue.get(timeout=30)
                management = json.loads((fixture / 'management.json').read_text())
                # Deliberately exclude inherited provider keys, PATs and all user ZCode settings.
                env = {k: v for k, v in os.environ.items() if k.upper() in {'PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP'}}
                env.update({'HOME': str(home), 'USERPROFILE': str(home), 'APPDATA': str(home / 'AppData/Roaming'),
                            'LOCALAPPDATA': str(home / 'AppData/Local'), 'ZCODE_DATA_BASE_DIR': str(home),
                            'ZCODE_STORAGE_DIR': str(home / '.zcode'), 'ZCODE_LOG_DIR': str(root / 'logs'),
                            'ZCODE_BUILTIN_PROVIDER_CONFIG_FILE': str(bundled),
                            'ZCODE_BUILTIN_PROVIDER_BUNDLED_CONFIG_FILE': str(bundled),
                            'ZCODE_PERSONAL_PROVIDER_CONFIG_FILE': str(home / 'provider_config.json'),
                            'ZCODE_MODEL_TELEMETRY_ENABLED': 'false', 'NODE_EXTRA_CA_CERTS': str(fixture / 'cert.pem'),
                            'ZCODE_AGENT_CA_CERT': str(fixture / 'cert.pem'), 'NO_PROXY': '127.0.0.1,localhost'})
                client = subprocess.Popen([node, str(cli), 'app-server'], cwd=workspace, env=env,
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=client_errors, text=True)
                inbox = queue.Queue()
                threading.Thread(target=messages, args=(client.stdout, inbox), daemon=True).start()
                servers = []
                for name, key in [('valid', management['apiKey']), ('wrong', 'invalid-test-key'), ('missing', None)]:
                    servers.append({'name': name, 'type': 'http', 'url': management['origin'] + '/mcp',
                                    'headers': [] if key is None else [{'name': 'Authorization', 'value': 'Bearer ' + key}],
                                    'timeoutMs': 15000})
                servers.append({'name': 'stdio', 'command': node,
                                'args': [str(repo / 'dist/cli/index.js'), 'mcp', 'stdio'],
                                'env': [{'name': name, 'value': value} for name, value in {
                                    'PUBLIC_BASE_URL': management['origin'], 'MCP_API_KEY': management['apiKey'],
                                    'NODE_EXTRA_CA_CERTS': str(fixture / 'cert.pem')}.items()],
                                'timeoutMs': 15000})
                request = {'id': 'discovery', 'method': 'mcp/list', 'params': {
                    'workspace': {'workspacePath': str(workspace), 'workspaceKey': str(workspace)},
                    'mcpServers': servers, 'mode': 'connect'}}
                client.stdin.write(json.dumps(request) + '\n')
                client.stdin.flush()
                statuses = response(inbox, 'discovery')['statuses']
                if set(statuses) != {'valid', 'wrong', 'missing', 'stdio'}:
                    raise RuntimeError('Unexpected MCP servers in isolated configuration')
                valid = statuses['valid']
                if valid['status'] != 'connected' or valid['toolCount'] < 9:
                    raise RuntimeError('ZCode could not discover NyaaRink tools: ' + str(valid.get('failureKind', valid['status'])))
                for name in ['wrong', 'missing']:
                    failure = statuses[name]
                    if failure['status'] == 'connected':
                        raise RuntimeError('ZCode unexpectedly connected without valid authentication')
                # Some clients report OAuth negotiation failure after HTTP 401.
                # Require the server's actual rejection rather than a generic client failure.
                rejected = json.loads((fixture / 'auth-rejections.json').read_text())
                if rejected['wrongKey'] < 1 or rejected['missingKey'] < 1:
                    raise RuntimeError('Missing actual HTTP 401 authentication rejection')
                if statuses['stdio']['status'] != 'connected' or statuses['stdio']['toolCount'] != valid['toolCount']:
                    raise RuntimeError('ZCode stdio bridge discovery failed: ' + str(statuses['stdio'].get('failureKind')))
                print(json.dumps({'zcodeRealHttpDiscovery': True, 'toolCount': valid['toolCount'],
                                  'zcodeRealStdioDiscovery': True,
                                  'wrongKeyRejected': True, 'missingKeyRejected': True,
                                  'modelRequests': 0, 'fullWorkflowVerified': False}))
        finally:
            try:
                stop(client)
            finally:
                stop(server)
    print('Isolated ZCode storage, fixture, certificates and processes cleaned.')


if __name__ == '__main__':
    main()
