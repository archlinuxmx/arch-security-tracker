from configparser import ConfigParser
from glob import glob
from os import environ
from os.path import abspath
from os.path import dirname
from pathlib import Path
from urllib.parse import urlsplit

basedir = abspath(dirname(__file__))

config = ConfigParser()
config_files = sorted(glob('{}/config/*.conf'.format(basedir)))

# ignore local configs during test run or when explicitly deactivated
if environ.get('TRACKER_CONFIG_LOCAL', 'true').lower() not in ['1', 'yes', 'true', 'on']:
    config_files = list(filter(lambda f: not f.endswith(".local.conf"), config_files))

for config_file in config_files:
    config.read(config_file)

if environ.get('TRACKER_CONFIG_FILE'):
    with open(environ['TRACKER_CONFIG_FILE'], encoding='utf-8') as config_file:
        config.read_file(config_file)

data_dir = environ.get('TRACKER_DATA_DIR')
if data_dir and not Path(data_dir).is_absolute():
    raise ValueError('TRACKER_DATA_DIR must be an absolute path')
PACMAN_ROOT = str(Path(data_dir or basedir) / 'pacman')
PACMAN_CONFIG_PATH = (str(Path(PACMAN_ROOT) / 'pacman.conf') if data_dir else
                      str(Path(PACMAN_ROOT) / 'arch/{}/pacman.conf'))

public_url = environ.get('TRACKER_PUBLIC_URL')
if public_url:
    public = urlsplit(public_url)
    if (public.scheme not in ('http', 'https') or not public.hostname or public.username is not None
            or public.password is not None or public.path not in ('', '/') or public.query or public.fragment
            or any(char.isspace() for char in public_url)):
        raise ValueError('TRACKER_PUBLIC_URL must be an HTTP(S) origin without credentials or a path')
    if public.scheme == 'http' and public.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('TRACKER_PUBLIC_URL requires HTTPS except on localhost')
    if public.port == 0:
        raise ValueError('TRACKER_PUBLIC_URL requires a port between 1 and 65535')
    public_url = public_url.rstrip('/')
    SERVER_NAME = public.netloc
    PREFERRED_URL_SCHEME = public.scheme

TRACKER_PROXY_HOPS = int(environ.get('TRACKER_PROXY_HOPS', '0'))
if not 0 <= TRACKER_PROXY_HOPS <= 5:
    raise ValueError('TRACKER_PROXY_HOPS must be between 0 and 5')

atom_feeds = []


def get_debug_flag():
    return config_flask.getboolean('debug')


def set_debug_flag(debug):
    global FLASK_DEBUG
    FLASK_DEBUG = debug
    environ.setdefault('FLASK_DEBUG', '1' if FLASK_DEBUG else '0')
    config_flask['debug'] = 'on' if debug else 'off'


config_tracker = config['tracker']
TRACKER_ADVISORY_URL = config_tracker['advisory_url']
TRACKER_BUGTRACKER_URL = config_tracker['bugtracker_url']
TRACKER_MAILMAN_URL = config_tracker['mailman_url']
TRACKER_GROUP_URL = config_tracker['group_url']
TRACKER_ISSUE_URL = config_tracker['issue_url']
if public_url:
    TRACKER_ADVISORY_URL = public_url + '/AVG-{1}'
    TRACKER_GROUP_URL = public_url + '/AVG-{0}'
    TRACKER_ISSUE_URL = public_url + '/{0}'
TRACKER_PASSWORD_LENGTH_MIN = config_tracker.getint('password_length_min')
TRACKER_PASSWORD_LENGTH_MAX = config_tracker.getint('password_length_max')
TRACKER_SUMMARY_LENGTH_MAX = config_tracker.getint('summary_length_max')
TRACKER_LOG_ENTRIES_PER_PAGE = config_tracker.getint('log_entries_per_page')
TRACKER_FEED_ADVISORY_ENTRIES = config_tracker.getint('feed_advisory_entries')

config_sqlite = config['sqlite']
SQLITE_JOURNAL_MODE = config_sqlite['journal_mode']
SQLITE_TEMP_STORE = config_sqlite['temp_store']
SQLITE_SYNCHRONOUS = config_sqlite['synchronous']
SQLITE_MMAP_SIZE = config_sqlite.getint('mmap_size')
SQLITE_CACHE_SIZE = config_sqlite.getint('cache_size')

config_sqlalchemy = config['sqlalchemy']
SQLALCHEMY_DATABASE_URI = config_sqlalchemy['database_uri'].replace('{{BASEDIR}}', basedir)
if data_dir:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + str(Path(data_dir) / 'tracker.db')
SQLALCHEMY_MIGRATE_REPO = config_sqlalchemy['migrate_repo'].replace('{{BASEDIR}}', basedir)
SQLALCHEMY_ECHO = config_sqlalchemy.getboolean('echo')
SQLALCHEMY_TRACK_MODIFICATIONS = config_sqlalchemy.getboolean('track_modifications')

config_flask = config['flask']
WTF_CSRF_ENABLED = config_flask.getboolean('csrf')
SECRET_KEY = config_flask['secret_key']
if environ.get('TRACKER_SECRET_KEY') and environ.get('TRACKER_SECRET_KEY_FILE'):
    raise ValueError('Set only one of TRACKER_SECRET_KEY and TRACKER_SECRET_KEY_FILE')
if environ.get('TRACKER_SECRET_KEY_FILE'):
    SECRET_KEY = Path(environ['TRACKER_SECRET_KEY_FILE']).read_text(encoding='utf-8').rstrip('\r\n')
elif 'TRACKER_SECRET_KEY' in environ:
    SECRET_KEY = environ['TRACKER_SECRET_KEY']
FLASK_HOST = config_flask['host']
FLASK_PORT = config_flask.getint('port')
FLASK_SESSION_PROTECTION = None if 'none' == config_flask['session_protection'] else config_flask['session_protection']
set_debug_flag(config_flask.getboolean('debug'))
FLASK_STRICT_TRANSPORT_SECURITY = config_flask.getboolean('strict_transport_security')
SESSION_COOKIE_SAMESITE = config_flask['session_cookie_samesite']
SESSION_COOKIE_SECURE = config_flask.getboolean('session_cookie_secure')
if public_url:
    SESSION_COOKIE_SECURE = public.scheme == 'https'

config_pacman = config['pacman']
PACMAN_HANDLE_CACHE_TIME = config_pacman.getint('handle_cache_time')

config_sso = config['sso']
SSO_ENABLED = config_sso.getboolean('enabled')
SSO_CLIENT_SECRET = config_sso.get('client_secret')
SSO_CLIENT_ID = config_sso.get('client_id')
SSO_ADMINISTRATOR_GROUP = config_sso.get('administrator_group')
SSO_SECURITY_TEAM_GROUP = config_sso.get('security_team_group')
SSO_REPORTER_GROUP = config_sso.get('reporter_group')
SSO_METADATA_URL = config_sso.get('metadata_url')
