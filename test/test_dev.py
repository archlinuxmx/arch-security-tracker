from pathlib import Path
from subprocess import run

import pytest


@pytest.mark.parametrize('arguments, command, publish', [
    ([], ['./trackerctl', 'run', '--host', '0.0.0.0', '--port', '5000'], True),
    (['run', '--no-reload'], ['./trackerctl', 'run', '--no-reload'], True),
    (['db', 'check'], ['./trackerctl', 'db', 'check'], False),
    (['python', '-c', 'print("hello world")'], ['python', '-c', 'print("hello world")'], False),
])
def test_container_wrapper_reserves_port_only_for_server(tmp_path, monkeypatch, arguments, command, publish):
    podman = tmp_path / 'podman'
    podman.write_text('''#!/bin/sh
if [ "$1" = image ]; then exit 0; fi
printf '%s\\n' "$@" > "$PODMAN_TEST_LOG"
''')
    podman.chmod(0o755)
    log = tmp_path / 'arguments'
    monkeypatch.setenv('PATH', str(tmp_path), prepend=':')
    monkeypatch.setenv('PODMAN_TEST_LOG', str(log))
    wrapper = Path(__file__).resolve().parents[1] / 'dev' / 'tracker'
    result = run(['/bin/sh', str(wrapper), *arguments], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    received = log.read_text().splitlines()
    assert ('--publish' in received) is publish
    if publish:
        assert received[received.index('--publish') + 1] == '127.0.0.1:5000:5000'
    image = received.index('localhost/arch-security-tracker-dev:latest')
    assert received[image + 1:] == command
