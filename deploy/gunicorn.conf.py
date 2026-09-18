import os

bind = '0.0.0.0:8080'
workers = int(os.environ.get('TRACKER_WORKERS', '1'))
if not 1 <= workers <= 32:
    raise ValueError('TRACKER_WORKERS must be between 1 and 32')
worker_class = 'sync'
threads = 1
timeout = 60
graceful_timeout = 30
accesslog = '-'
errorlog = '-'
worker_tmp_dir = '/tmp'
forwarded_allow_ips = ''
umask = 0o077
