"""Consistent online SQLite backup; authority backups require a stopped writer."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import sqlite3
import uuid
from scripts.ops import environment, main, run


def backup_database(state):
    directory = Path(state)
    source = sqlite3.connect((directory / 'state.db').resolve().as_uri() + '?mode=ro', uri=True)
    target_dir = directory / 'backups'
    target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = target_dir / (str(uuid.uuid4()) + '.db')
    try:
        with sqlite3.connect(path) as target:
            source.backup(target)
            instance, epoch, seq = target.execute('SELECT instanceId, epoch, seq FROM snapshot WHERE id=1').fetchone()
        os.chmod(path, 0o600)
        manifest = dict(schema=1, instanceId=instance, epoch=epoch, seq=seq,
                        sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        manifest_path = Path(str(path) + '.manifest.json')
        with manifest_path.open('x', encoding='utf-8') as output:
            json.dump(manifest, output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(manifest_path, 0o600)
        return path
    finally:
        source.close()


def action():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--database', action='store_true')
    group.add_argument('--authority', action='store_true')
    args = parser.parse_args()
    root, env = environment()
    if args.database:
        backup_database(env['STATE_DIR'])
        print('Consistent database backup completed in private state backups directory.')
    else:
        run(['node', str(root / 'dist/server/maintenance.js'), 'backup-authority'], env=env, cwd=root)


if __name__ == '__main__':
    main(action)
