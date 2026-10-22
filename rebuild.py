"""Build/publish both images. Never starts containers."""
from scripts.ops import environment, main, run
import argparse
import json
import urllib.request


def protected_cleanup(host, image, tags):
    # Resolve every retained digest before any delete. Registry only deletes digests.
    base = ('https://' if not host.startswith(('localhost:', '127.0.0.1:')) else 'http://') + host + '/v2/' + image
    headers = {'Accept': 'application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.index.v1+json'}
    def digest(tag):
        with urllib.request.urlopen(urllib.request.Request(base + '/manifests/' + tag, headers=headers, method='HEAD'), timeout=20) as response:
            return response.headers['Docker-Content-Digest']
    protected = {digest(tag) for tag in tags}
    with urllib.request.urlopen(base + '/tags/list', timeout=20) as response:
        current = json.load(response).get('tags') or []
    stale = {digest(tag) for tag in current if tag not in tags} - protected
    for value in stale:
        with urllib.request.urlopen(urllib.request.Request(base + '/manifests/' + value, method='DELETE'), timeout=20):
            print('Removed obsolete manifest from <PRIVATE_REGISTRY>/' + image)


def execute():
    parser = argparse.ArgumentParser()
    parser.add_argument('--push', action='store_true')
    parser.add_argument('--cleanup-registry', action='store_true')
    args = parser.parse_args()
    root, env = environment()
    host = env['PRIVATE_DOCKER_REGISTRY_HOST']
    if not host or '/' in host or '@' in host: raise ValueError('Invalid registry host')
    if run(['git', 'status', '--porcelain'], env, root): raise RuntimeError('Commit worktree before publishing')
    sha = run(['git', 'rev-parse', '--short=7', 'HEAD'], env, root)
    for image, target in [('nyaarink', 'app'), ('nyaarink-gateway', 'gateway')]:
        run(['docker', 'build', '--target', target, '--label', 'org.opencontainers.image.revision=' + sha,
             '-t', host + '/' + image + ':' + sha, '-t', host + '/' + image + ':latest', '.'], env, root)
        if args.push:
            for tag in [sha, 'latest']:
                run(['docker', 'push', host + '/' + image + ':' + tag], env, root, attempts=3)
            if args.cleanup_registry: protected_cleanup(host, image, {sha, 'latest'})


if __name__ == '__main__': main(execute)
