import re
from functools import cmp_to_key as comparison_key
from functools import wraps

from flask import abort
from flask import json
from requests.models import PreparedRequest

from config import atom_feeds

word_split_re = re.compile(r'(\s+)')
punctuation_re = re.compile(
    '^(?P<lead>(?:%s)*)(?P<middle>.*?)(?P<trail>(?:%s)*)$' % (
        '|'.join(map(re.escape, ('(', '<', '&lt;'))),
        '|'.join(map(re.escape, ('.', ',', ')', '>', '\n', '&gt;')))
    )
)


def page_number(value, per_page):
    try:
        page = int(value)
    except ValueError:
        abort(400)
    if page < 1 or (page - 1) * per_page > 2**63 - 1:
        abort(400)
    return page


def multiline_to_list(data, whitespace_separator=True, unique_only=True, filter_empty=True):
    if not data:
        return []
    if whitespace_separator:
        data = data.replace(' ', '\n')
    data_list = data.replace('\r', '').split('\n')
    if unique_only:
        data_list = list_uniquify(data_list)
    if filter_empty:
        data_list = list(filter(lambda e: len(e) > 0, data_list))
    return data_list


def list_uniquify(data):
    return list(dict.fromkeys(data))


def cmp_to_key(compare, getter=None):
    if getter is None:
        return comparison_key(compare)

    def compare_items(left, right):
        return compare(getter(left), getter(right))

    return comparison_key(compare_items)


def chunks(items, size):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def json_response(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        response = func(*args, **kwargs)
        code = 200
        if isinstance(response, tuple):
            response, code = response
        dump = json.dumps(response, indent=2, sort_keys=False)
        return dump, code, {'Content-Type': 'application/json; charset=utf-8'}
    return wrapped


def atom_feed(title):
    def decorator(func):
        atom_feeds.append({'func': 'tracker.{}'.format(func.__name__), 'title': title})

        @wraps(func)
        def wrapped(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapped
    return decorator


def issue_to_numeric(issue_label):
    _, year, number = issue_label.split('-')
    return int(year), int(number)


def add_params_to_uri(url, params):
    req = PreparedRequest()
    req.prepare_url(url, params)
    return req.url
