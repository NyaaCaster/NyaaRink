"""Ordering and failure safety without running containers or touching real private data."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('restart', ROOT / 'restart.py')
restart = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restart)


class RestartSafety(unittest.TestCase):
    def exercise(self, failure=None):
        with tempfile.TemporaryDirectory(prefix='nyaarink-restart-') as directory:
            root = Path(directory)
            env = {'PATH': '', 'PUBLIC_BASE_URL': 'https://example.invalid:5116'}
            for key in ['STATE_DIR', 'AUTHORITY_DIR', 'TLS_CERT_DIR', 'CLIENT_ARTIFACT_DIR']:
                folder = root / key
                folder.mkdir()
                env[key] = str(folder)
            key = root / 'master.key'
            key.write_bytes(b'x' * 32)
            env['SESSION_MASTER_KEY_FILE'] = str(key)
            authority = Path(env['AUTHORITY_DIR'])
            (authority / 'identity.json').write_text('{}')
            (authority / 'writer.lock').write_text('7')
            commands = []
            def run(args, *unused, **kwargs):
                commands.append(args)
                if failure and failure in args:
                    raise RuntimeError('Injected failure')
                if args[:3] == ['docker', 'ps', '-q']:
                    return ''
                return ''
            flock = types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *a: None)
            with patch.object(sys, 'argv', ['restart.py']), patch.dict(sys.modules, {'fcntl': flock}), patch.object(restart, 'environment', return_value=(root, env)), patch.object(restart, 'run', side_effect=run):
                with self.assertRaises(RuntimeError):
                    restart.execute()
            return commands, (authority / 'writer.lock').exists(), list((root / 'STATE_DIR').rglob('master.key')) != []

    def test_pull_failure_preserves_running_service(self):
        commands, locked, snapshot = self.exercise('pull')
        self.assertFalse(any('stop' in c for c in commands))
        self.assertTrue(locked)
        self.assertFalse(snapshot)

    def test_preflight_failure_keeps_entry_stopped_and_snapshots_secrets(self):
        commands, locked, snapshot = self.exercise('dist/server/preflight.js')
        self.assertEqual(sum('stop' in c for c in commands), 2)
        self.assertFalse(any('up' in c for c in commands))
        self.assertFalse(locked)
        self.assertTrue(snapshot)
        verification = next(i for i,c in enumerate(commands) if 'verify-authority' in c)
        stopped = next(i for i,c in enumerate(commands) if 'stop' in c)
        self.assertLess(stopped, verification)


if __name__ == '__main__':
    unittest.main()
