"""Exercise an already-built image without publishing ports beyond localhost."""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def docker(*arguments, check=True):
    return subprocess.run(['docker', *arguments], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def wait_ready(base_url):
    for _ in range(60):
        try:
            with urllib.request.urlopen(base_url + '/readyz', timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.HTTPError):
            pass
        time.sleep(1)
    raise RuntimeError('The container did not become ready within 60 seconds.')


def main():
    image = sys.argv[1]
    name = 'tracker-smoke-' + uuid.uuid4().hex[:12]
    volume = name + '-data'
    docker('volume', 'create', volume)
    try:
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / 'secret'
            secret.write_text(os.urandom(32).hex() + '\n')
            secret.chmod(0o444)
            options = [
                '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
                '--mount', 'type=volume,src={},dst=/var/lib/tracker'.format(volume),
                '--mount', 'type=bind,src={},dst=/run/secrets/tracker-secret,readonly'.format(secret),
                '--env=TRACKER_SECRET_KEY_FILE=/run/secrets/tracker-secret',
                '--env=TRACKER_PUBLIC_URL=https://security.archlinux.mx',
            ]
            docker('run', '--rm', *options, image, 'init')
            duplicate = docker('run', '--rm', *options, image, 'init', check=False)
            if duplicate.returncode == 0:
                raise RuntimeError('Initialization accepted an existing database.')
            docker('run', '--rm', *options, image, 'migrate')
            docker('run', '--rm', *options, image, 'refresh')

            for _ in range(2):
                docker('run', '--detach', '--name', name, '--publish=127.0.0.1::8080',
                       *options, image)
                address = docker('port', name, '8080/tcp').stdout.strip()
                base_url = 'http://' + address
                wait_ready(base_url)
                for path in ('/healthz', '/', '/login', '/api/v1/packages',
                             '/static/normalize.css', '/static/favicon.ico'):
                    with urllib.request.urlopen(base_url + path, timeout=5) as response:
                        if response.status != 200:
                            raise RuntimeError('Unexpected status for ' + path)
                        if path == '/api/v1/packages' and not json.load(response)['items']:
                            raise RuntimeError('Repository refresh left the package catalog empty.')
                docker('exec', name, 'python', '-c',
                       'import os; assert os.getuid() == 10001; '
                       'assert not os.access("/opt/tracker/config.py", os.W_OK)')
                docker('stop', '--time=15', name)
                code = docker('inspect', '--format={{.State.ExitCode}}', name).stdout.strip()
                if code != '0':
                    raise RuntimeError('Gunicorn did not shut down cleanly: ' + code)
                docker('rm', name)
            docker('run', '--rm', *options, image, 'trackerctl', 'db', 'check')
            print('Container startup, package refresh, assets, persistence and shutdown passed.')
    except Exception:
        logs = docker('logs', name, check=False)
        sys.stderr.write(logs.stdout + logs.stderr)
        raise
    finally:
        docker('rm', '--force', name, check=False)
        docker('volume', 'rm', volume, check=False)


if __name__ == '__main__':
    main()
