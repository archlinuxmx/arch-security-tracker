from pathlib import Path
from runpy import run_path
from shutil import copyfile
from types import SimpleNamespace

import pytest

import config
from tracker.form.base import BaseForm


@pytest.mark.parametrize('enabled', [False, True])
def test_configuration_controls_form_csrf(app, tmp_path, monkeypatch, enabled):
    source = Path(config.__file__)
    copyfile(source, tmp_path / 'config.py')
    settings = tmp_path / 'config'
    settings.mkdir()
    copyfile(source.parent / 'config' / '00-default.conf', settings / '00-default.conf')
    (settings / '10-test.conf').write_text('[flask]\ncsrf = {}\n'.format('on' if enabled else 'off'))
    monkeypatch.delenv('FLASK_DEBUG', raising=False)
    monkeypatch.delitem(app.config, 'WTF_CSRF_ENABLED', raising=False)
    app.config.from_object(SimpleNamespace(**run_path(str(tmp_path / 'config.py'))))
    with app.test_request_context():
        assert BaseForm().meta.csrf is enabled
