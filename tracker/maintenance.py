from collections import defaultdict
from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError

from tracker import db
from tracker.model import CVE
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import Package
from tracker.model.enum import Status
from tracker.model.enum import group_status
from tracker.model.enum import highest_severity
from tracker.model.enum import status_to_affected
from tracker.pacman import search


def update_group_status():
    groups = CVEGroup.query.filter(CVEGroup.status.in_([Status.vulnerable, Status.testing, Status.fixed]))
    return _recalculate_group_status(groups)


def recalc_group_status():
    return _recalculate_group_status(CVEGroup.query)


def _recalculate_group_status(groups):
    updated = []
    for group in groups:
        packages = [package.pkgname for package in group.packages]
        new_status = group_status(status_to_affected(group.status), packages, group.fixed, group.status)
        if group.status is not new_status:
            updated.append(dict(group=group, old_status=group.status))
        group.status = new_status
    db.session.commit()
    return updated


def recalc_group_severity():
    updated = []
    entries = (db.session.query(CVEGroup, CVE)
               .join(CVEGroup.issues).join(CVEGroupEntry.cve)).all()
    issues_by_group = defaultdict(set)
    for group, issue in entries:
        issues_by_group[group].add(issue)
    for group, issues in issues_by_group.items():
        new_severity = highest_severity([issue.severity for issue in issues])
        if group.severity is not new_severity:
            updated.append(dict(group=group, old_severity=group.severity))
        group.severity = new_severity
    db.session.commit()
    return updated


def update_package_cache():
    print('  -> Querying alpm database...', end='', flush=True)
    previous_repos = {repo for repo, in db.session.query(Package.database).distinct()}
    packages = search('', filter_duplicate_packages=False, sort_results=False, force_fresh_handle=True,
                      required_repositories=previous_repos)
    if not packages:
        raise ValueError('Package refresh returned no packages; keeping the existing cache.')
    print('done')

    print('  -> Updating database cache...', end='', flush=True)
    new_packages = []
    for package in packages:
        row = {
            'name': package.name,
            'base': package.base if package.base else package.name,
            'version': package.version,
            'description': package.desc,
            'url': package.url,
            'arch': package.arch,
            'database': package.db.name,
            'filename': package.filename,
            'sha256sum': package.sha256sum,
            'builddate': package.builddate
        }
        required = ('name', 'base', 'version', 'arch', 'database', 'filename', 'sha256sum')
        if any(not row[field] for field in required) or row['description'] is None or row['builddate'] is None:
            raise ValueError('Incomplete package {}; keeping the existing cache.'.format(package.name))
        new_packages.append(row)
    latest = max(packages, key=lambda pkg: pkg.builddate)
    print('  -> Latest package: {} {} {}'.format(
        latest.name, latest.version, datetime.fromtimestamp(latest.builddate).strftime('%c')))
    try:
        Package.query.delete()
        db.session.bulk_insert_mappings(Package, new_packages)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        raise
    print('done')
