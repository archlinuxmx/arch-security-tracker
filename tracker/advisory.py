from datetime import datetime
from itertools import zip_longest
from os.path import join
from re import IGNORECASE
from re import escape
from re import search
from re import sub
from shlex import quote
from urllib.parse import unquote
from urllib.parse import urlparse

from flask import render_template
from markupsafe import escape as html_escape
from requests import Session
from requests.exceptions import RequestException
from sqlalchemy_continuum import version_class

from config import TRACKER_ADVISORY_URL
from config import TRACKER_BUGTRACKER_URL
from config import TRACKER_GROUP_URL
from config import TRACKER_ISSUE_URL
from config import TRACKER_MAILMAN_URL
from tracker import db
from tracker import tracker
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model.enum import Publication
from tracker.model.enum import Remote
from tracker.user import user_can_handle_advisory
from tracker.util import chunks
from tracker.util import issue_to_numeric
from tracker.util import multiline_to_list


@tracker.app_template_global()
def can_view_advisory(advisory):
    return user_can_handle_advisory() or (advisory is not None and advisory.publication == Publication.published)


@tracker.after_request
def prevent_draft_caching(response):
    response.vary.add('Cookie')
    if user_can_handle_advisory():
        response.headers['Cache-Control'] = 'private, no-store'
    return response


def generate_advisory(advisory_id, with_subject=True, raw=True):
    entries = (db.session.query(Advisory, CVEGroup, CVEGroupPackage, CVE)
               .filter(Advisory.id == advisory_id)
               .join(CVEGroupPackage, Advisory.group_package)
               .join(CVEGroup, CVEGroupPackage.group)
               .join(CVEGroupEntry, CVEGroup.issues)
               .join(CVE, CVEGroupEntry.cve)
               .order_by(CVE.id)
               ).all()
    if not entries:
        return None

    advisory = entries[0][0]
    group = entries[0][1]
    if not group.fixed:
        return None
    package = entries[0][2]
    issues = sorted([issue for (advisory, group, package, issue) in entries])
    severity_sorted_issues = sorted(issues, key=lambda issue: (issue.severity, issue.issue_type or 'unknown'))
    remote = any(issue.remote is Remote.remote for issue in issues)
    issue_listing_formatted = advisory_format_issue_listing([issue.id for issue in issues])

    link = TRACKER_ADVISORY_URL.format(advisory.id, group.id)
    upstream_released = group.affected.split('-')[0].split('+')[0] != group.fixed.split('-')[0].split('+')[0]
    upstream_version = group.fixed.split('-')[0].split('+')[0]
    if ':' in upstream_version:
        upstream_version = upstream_version[upstream_version.index(':') + 1:]
    unique_issue_types = []
    for issue in severity_sorted_issues:
        issue_type = issue.issue_type or 'unknown'
        if issue_type not in unique_issue_types:
            unique_issue_types.append(issue_type)

    references = []
    if group.bug_ticket:
        ticket = str(group.bug_ticket)
        references.append(ticket if ticket.startswith('https://') else TRACKER_BUGTRACKER_URL.format(ticket))
    for record in [group, *issues]:
        for reference in multiline_to_list(record.reference):
            if reference not in references:
                references.append(reference)

    raw_asa = render_template('advisory.txt',
                              advisory=advisory,
                              group=group,
                              package=package,
                              upgrade_requirement=quote('{}>={}'.format(package.pkgname, group.fixed)),
                              issues=issues,
                              remote=remote,
                              issue_listing_formatted=issue_listing_formatted,
                              link=link,
                              workaround=advisory.workaround,
                              impact=advisory.impact,
                              upstream_released=upstream_released,
                              upstream_version=upstream_version,
                              unique_issue_types=unique_issue_types,
                              references=references,
                              with_subject=with_subject,
                              TRACKER_ISSUE_URL=TRACKER_ISSUE_URL,
                              TRACKER_GROUP_URL=TRACKER_GROUP_URL)
    if raw:
        return raw_asa

    raw_asa = '\n'.join(raw_asa.split('\n')[2:])
    raw_asa = str(html_escape(raw_asa))
    raw_asa = advisory_extend_html(raw_asa, issues, package)
    return render_html_advisory(advisory=advisory, package=package, group=group, raw_asa=raw_asa, generated=True)


def render_html_advisory(advisory, package, group, raw_asa, generated):
    return render_template('advisory.html',
                           title='[{}] {}: {}'.format(advisory.id, package.pkgname, advisory.advisory_type),
                           advisory=advisory,
                           package=package,
                           raw_asa=raw_asa,
                           generated=generated,
                           can_handle_advisory=user_can_handle_advisory(),
                           Publication=Publication)


def advisory_fetch_from_mailman(url):
    try:
        archive = urlparse(TRACKER_MAILMAN_URL)
        target = urlparse(url)
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
            return None
        if target.username is not None or target.password is not None:
            return None
        if target.scheme not in ('http', 'https') or not target.hostname:
            return None
        archive_port = archive.port if archive.port is not None else (443 if archive.scheme == 'https' else 80)
        target_port = target.port if target.port is not None else (443 if target.scheme == 'https' else 80)
        if (target.scheme, target.hostname, target_port) != (archive.scheme, archive.hostname, archive_port):
            return None

        path = unquote(target.path)
        if (not target.path.startswith(archive.path.rstrip('/') + '/') or '%' in path or '\\' in path or
                any(part in ('.', '..') for part in path.split('/'))):
            return None

        # Only the configured archive is trusted; never follow its redirects.
        with Session() as session:
            with session.get(url, timeout=10, allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    return None
                content = bytearray()
                for chunk in response.iter_content(chunk_size=8192):
                    if len(content) + len(chunk) > 1024 * 1024:
                        return None
                    content.extend(chunk)
                try:
                    return content.decode(response.encoding or 'utf-8', errors='replace')
                except LookupError:
                    return content.decode('utf-8', errors='replace')
    except (RequestException, TypeError, ValueError):
        return None


def advisory_fetch_reference_url_from_mailman(advisory):
    year = advisory.id[4:8]
    month = advisory.id[8:10]
    mailman_monthly = '{}{}/{}/?count=100'.format(TRACKER_MAILMAN_URL, year, month)
    content = advisory_fetch_from_mailman(mailman_monthly)
    if not content:
        return None

    mailman_url = urlparse(TRACKER_MAILMAN_URL)
    thread_url_base = join(mailman_url.path, 'thread')
    message_url = None
    for line in content.splitlines():
        if thread_url_base in line:
            match = search(r'href="{}/([/a-zA-Z0-9]+)"'.format(escape(thread_url_base)), line)
            if not match:
                continue
            thread = match.group(1)
            message_url = join(TRACKER_MAILMAN_URL, 'message', thread)
        if '[{}]'.format(advisory.id) in line:
            return message_url
    return None


def advisory_get_section_from_text(advisory, start, end):
    if start not in advisory or end not in advisory:
        return None
    start_index = advisory.index(start)
    end_index = advisory.index(end)
    section = advisory[start_index + len(start):end_index]
    return section


def advisory_get_impact_from_text(advisory):
    start = '\nImpact\n======\n\n'
    end = '\n\nReferences\n==========\n\n'
    impact = advisory_get_section_from_text(advisory, start, end)
    if not impact:
        return None
    return sub('([^.\n])\\n', '\\1 ', impact)


def advisory_get_workaround_from_text(advisory):
    start = '\nWorkaround\n==========\n\n'
    end = '\n\nDescription\n===========\n\n'
    workaround = advisory_get_section_from_text(advisory, start, end)
    if 'None.' == workaround:
        return None
    return workaround


def advisory_escape_html(advisory):
    return str(html_escape(advisory))


def advisory_extend_html(advisory, issues, package):
    advisory = sub('({}) '.format(escape(package.pkgname)), '<a href="/package/{0}" rel="noopener">\\g<1></a> '.format(package.pkgname), advisory, flags=IGNORECASE)
    advisory = sub(' ({})'.format(escape(package.pkgname)), ' <a href="/package/{0}" rel="noopener">\\g<1></a>'.format(package.pkgname), advisory, flags=IGNORECASE)
    advisory = sub(';({})'.format(escape(package.pkgname)), ';<a href="/package/{0}" rel="noopener">\\g<1></a>'.format(package.pkgname), advisory, flags=IGNORECASE)
    advisory = sub('"({})'.format(escape(package.pkgname)), '"<a href="/package/{0}" rel="noopener">\\g<1></a>'.format(package.pkgname), advisory, flags=IGNORECASE)
    return advisory


def advisory_get_date_label(utctimetuple=None):
    now = utctimetuple if utctimetuple else datetime.utcnow().utctimetuple()
    return '{}{:02}'.format(now.tm_year, now.tm_mon)


def advisory_get_label(date_label=None, number=1):
    date_label = date_label if date_label else advisory_get_date_label()
    return 'ASA-{}-{}'.format(date_label, number)


def advisory_get_last_number(date_label):
    """Include retired identifiers while the caller holds the write lock."""
    history = version_class(Advisory)
    prefix = 'ASA-{}-'.format(date_label)
    identifiers = (db.session.query(Advisory.id).filter(Advisory.id.startswith(prefix))
                   .union(db.session.query(history.id).filter(history.id.startswith(prefix))))
    return max((int(identifier.rsplit('-', 1)[1]) for identifier, in identifiers), default=0)


def advisory_format_issue_listing(issues, columns=4, rjust_left=len('CVE-ID  : ')):
    rows = list(chunks(sorted(issues, key=issue_to_numeric), columns))
    widths = [max(len(issue) for issue in column) for column in zip_longest(*rows, fillvalue='')]
    lines = []
    for row in rows:
        cells = [issue.ljust(widths[index]) if index < len(widths) - 1 else issue
                 for index, issue in enumerate(row)]
        lines.append(' '.join(cells))
    return ('\n' + ' ' * rjust_left).join(lines)
