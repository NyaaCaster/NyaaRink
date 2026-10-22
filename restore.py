"""Offline database projection recovery or read-only authority verification."""
import argparse
from scripts.ops import environment, main, run


def action():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--database')
    group.add_argument('--verify-authority')
    args = parser.parse_args()
    root, env = environment()
    if args.verify_authority:
        env['AUTHORITY_DIR'] = args.verify_authority
        arguments = ['verify-authority']
    else:
        arguments = ['restore-database', args.database]
    run(['node', str(root / 'dist/server/maintenance.js'), *arguments], env=env, cwd=root)


if __name__ == '__main__':
    main(action)
