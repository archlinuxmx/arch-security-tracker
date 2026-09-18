#!/usr/bin/env python
import fcntl
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from threading import Event

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
stopping = Event()
child = None


def stop(signum, frame):
    stopping.set()
    if child is not None:
        try:
            child.send_signal(signum)
        except ProcessLookupError:
            pass


def run_tracker(*args):
    global child
    if stopping.is_set():
        return 0
    child = subprocess.Popen([sys.executable, str(ROOT / 'trackerctl'), *args], cwd=ROOT)
    try:
        if stopping.is_set():
            try:
                child.terminate()
            except ProcessLookupError:
                pass
        return child.wait()
    finally:
        child = None


def prepare():
    os.environ.setdefault('TRACKER_CONFIG_LOCAL', 'false')
    os.environ.setdefault('TRACKER_DATA_DIR', '/var/lib/tracker')
    if not os.environ.get('TRACKER_PUBLIC_URL'):
        raise ValueError('Set TRACKER_PUBLIC_URL to the public HTTPS origin')

    import config
    if len(config.SECRET_KEY) < 32 or len(set(config.SECRET_KEY)) < 8:
        raise ValueError('Set a stable random secret of at least 32 characters with TRACKER_SECRET_KEY_FILE')
    if config.FLASK_DEBUG or not config.WTF_CSRF_ENABLED:
        raise ValueError('Container deployment requires debug=off and csrf=on')

    data = Path(os.environ['TRACKER_DATA_DIR'])
    pacman = Path(config.PACMAN_ROOT)
    for directory in (data, pacman / 'cache', pacman / 'log', pacman / 'arch/x86_64/db'):
        directory.mkdir(parents=True, exist_ok=True)

    lines = ['[options]', 'RootDir = {}'.format(pacman),
             'DBPath = {}'.format(pacman / 'arch/x86_64/db'),
             'CacheDir = {}'.format(pacman / 'cache'),
             'LogFile = {}'.format(pacman / 'log/pacman.log'),
             'Architecture = x86_64', 'SigLevel = Required DatabaseOptional']
    for repository in ('core-testing', 'core', 'extra-testing', 'extra', 'multilib-testing', 'multilib'):
        lines.extend(['', '[{}]'.format(repository), 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch'])
    target = Path(config.PACMAN_CONFIG_PATH)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=pacman, delete=False, encoding='utf-8') as stream:
            temporary = Path(stream.name)
            stream.write('\n'.join(lines) + '\n')
        temporary.replace(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return data


def refresh(data):
    with (data / 'refresh.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('A package refresh is already running.', file=sys.stderr)
            return 1
        return run_tracker('update', 'env')


def main(args):
    os.umask(0o077)
    command = args[0] if args else 'serve'
    if command not in ('serve', 'init', 'migrate', 'refresh', 'refresh-loop', 'trackerctl'):
        raise ValueError('Unknown command: {}'.format(command))
    if len(args) > 1 and command != 'trackerctl':
        raise ValueError('{} does not accept arguments'.format(command))
    data = prepare()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    if command == 'serve':
        os.chdir(ROOT)
        os.execvp('gunicorn', ['gunicorn', '--config', str(ROOT / 'deploy/gunicorn.conf.py'),
                             'tracker:create_app()'])
    if command == 'trackerctl':
        os.execv(sys.executable, [sys.executable, str(ROOT / 'trackerctl'), *args[1:]])
    if command in ('init', 'migrate'):
        with (data / 'database.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            database = data / 'tracker.db'
            if command == 'init':
                if database.exists() and database.stat().st_size:
                    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
                        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
                            raise ValueError('Database already exists; use migrate to upgrade it')
                return run_tracker('db', 'initdb')
            if not database.exists() or not database.stat().st_size:
                raise ValueError('Database does not exist; use init for a fresh installation')
            return run_tracker('db', 'upgrade')
    if command == 'refresh':
        return refresh(data)

    interval = int(os.environ.get('TRACKER_REFRESH_INTERVAL', '21600'))
    if interval < 60:
        raise ValueError('TRACKER_REFRESH_INTERVAL must be at least 60 seconds')
    while not stopping.is_set():
        result = refresh(data)
        if result:
            print('Package refresh failed; retrying after the configured interval.', file=sys.stderr)
        stopping.wait(interval)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, sqlite3.Error) as error:
        print('tracker: {}'.format(error), file=sys.stderr)
        sys.exit(1)
