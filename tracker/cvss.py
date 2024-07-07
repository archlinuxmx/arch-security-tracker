"""Store a source's CVSS assessment without replacing the Arch severity."""

import re
from decimal import Decimal
from decimal import InvalidOperation
from urllib.parse import urlsplit

from wtforms.validators import URL


def parse_cvss(value):
    names = ('version', 'score', 'vector', 'source')
    if value is None:
        return {'cvss_' + name: None for name in names}
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError('CVSS requires version, score, vector, and source.')
    version = value['version']
    if version not in ('3.0', '3.1', '4.0'):
        raise ValueError('CVSS version must be 3.0, 3.1, or 4.0.')
    if isinstance(value['score'], bool) or not isinstance(value['score'], (int, float)):
        raise ValueError('CVSS score must be a number.')
    try:
        score = Decimal(str(value['score']))
        if not score.is_finite() or not 0 <= score <= 10 or score != score.quantize(Decimal('0.1')):
            raise ValueError('CVSS score must be between 0 and 10 with at most one decimal place.')
    except (InvalidOperation, TypeError):
        raise ValueError('CVSS score must be a number.')
    vector = value['vector']
    if (not isinstance(vector, str) or len(vector) > 256
            or not re.fullmatch(r'CVSS:' + re.escape(version) + r'(?:/[A-Z][A-Z0-9]*:[A-Za-z0-9]+)+', vector)):
        raise ValueError('CVSS vector must have the matching version prefix and metric:value syntax.')
    source = value['source']
    try:
        parsed = urlsplit(source) if isinstance(source, str) else None
        valid_source = (parsed is not None and len(source) <= 2048
                        and not any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in source)
                        and parsed.scheme in ('http', 'https') and parsed.hostname
                        and (parsed.port is None or parsed.port <= 65535) and URL().regex.fullmatch(source))
        if valid_source:
            source.encode('utf-8')
    except ValueError:
        valid_source = False
    if not valid_source:
        raise ValueError('CVSS source must be an HTTP(S) reference URL.')
    return dict(cvss_version=version, cvss_score=score, cvss_vector=vector, cvss_source=source)


def cvss_json(cve):
    if cve.cvss_score is None:
        return None
    return dict(version=cve.cvss_version, score=float(cve.cvss_score),
                vector=cve.cvss_vector, source=cve.cvss_source)
