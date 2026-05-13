"""Create private settings for a fresh local installation."""

import os
import secrets
from pathlib import Path

path = Path(__file__).resolve().parents[1] / 'config' / '20-user.local.conf'
try:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    raise SystemExit('Local settings already exist; leaving them unchanged.')
with os.fdopen(descriptor, 'w') as stream:
    stream.write('[flask]\nsecret_key = ' + secrets.token_hex(32) + '\ncsrf = on\ndebug = off\n')
print('Created local settings. Initialize the database and create your account next.')
