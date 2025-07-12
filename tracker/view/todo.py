from collections import OrderedDict
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from operator import attrgetter
from random import randint

from flask import render_template
from pyalpm import vercmp
from sqlalchemy import and_
from sqlalchemy import func
from sqlalchemy import or_

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
from tracker.model.enum import Severity
from tracker.model.enum import Status
from tracker.model.package import filter_duplicate_packages
from tracker.symbol import smileys_happy
from tracker.user import user_can_edit_group
from tracker.user import user_can_edit_issue
from tracker.user import user_can_handle_advisory
from tracker.util import cmp_to_key
from tracker.util import json_response


def get_todo_data():
    incomplete_advisories = (db.session.query(Advisory, CVEGroupPackage, CVEGroup)
                             .join(CVEGroupPackage, Advisory.group_package)
                             .join(CVEGroup, CVEGroupPackage.group)
                             .filter(and_(
                                 Advisory.publication == Publication.published,
                                 or_(Advisory.content == '', Advisory.content.is_(None),
                                     Advisory.reference == '', Advisory.reference.is_(None))))
                             .group_by(CVEGroupPackage.id)
                             .order_by(Advisory.created.desc())).all()

    scheduled_advisories = (db.session.query(Advisory, CVEGroupPackage, CVEGroup)
                            .join(CVEGroupPackage, Advisory.group_package)
                            .join(CVEGroup, CVEGroupPackage.group)
                            .filter(Advisory.publication == Publication.scheduled)
                            .group_by(CVEGroupPackage.id)
                            .order_by(Advisory.created.desc())).all()

    unhandled_advisories = (db.session.query(CVEGroup, Package)
                            .join(CVEGroupPackage, CVEGroup.packages)
                            .join(Package, Package.name == CVEGroupPackage.pkgname)
                            .outerjoin(Advisory)
                            .filter(CVEGroup.advisory_qualified)
                            .filter(CVEGroup.status == Status.fixed)
                            .group_by(CVEGroup.id)
                            .group_by(CVEGroupPackage.id)
                            .having(func.count(Advisory.id) == 0)
                            .order_by(CVEGroup.id)).all()
    unhandled_advisories_data = defaultdict(list)
    for group, package in unhandled_advisories:
        unhandled_advisories_data[group].append(package)
    unhandled_advisories = [(group, packages) for group, packages in unhandled_advisories_data.items()]
    unhandled_advisories = sorted(unhandled_advisories, key=lambda item: item[0].id)
    unhandled_advisories = sorted(unhandled_advisories, key=lambda item: item[0].severity)

    unknown_issues = (db.session.query(CVE)
                      .filter(or_(CVE.remote == Remote.unknown,
                                  CVE.severity == Severity.unknown,
                                  CVE.description.is_(None),
                                  CVE.description == '',
                                  CVE.issue_type.is_(None),
                                  CVE.issue_type == 'unknown'))
                      .order_by(CVE.id.desc())).all()

    unknown_groups = CVEGroup.query.filter(CVEGroup.status == Status.unknown).all()
    unknown_groups = (db.session.query(CVEGroup, Package)
                        .join(CVEGroupPackage, CVEGroup.packages)
                        .join(Package, Package.name == CVEGroupPackage.pkgname)
                        .filter(CVEGroup.status == Status.unknown)
                        .group_by(CVEGroupPackage.id)
                        .order_by(CVEGroup.created.desc())).all()

    unknown_groups_data = defaultdict(list)
    for group, package in unknown_groups:
        unknown_groups_data[group].append(package)
    unknown_groups = []
    for group, packages in unknown_groups_data.items():
        unknown_groups.append((group, packages))
    unknown_groups = sorted(unknown_groups, key=lambda item: item[0].id)

    vulnerable_groups = (db.session.query(CVEGroup, Package)
                         .join(CVEGroupPackage, CVEGroup.packages)
                         .join(Package, Package.name == CVEGroupPackage.pkgname)
                         .filter(CVEGroup.status == Status.vulnerable)
                         .filter(or_(CVEGroup.fixed.is_(None), CVEGroup.fixed == ''))
                         .group_by(CVEGroup.id).group_by(Package.name, Package.version)
                         .order_by(CVEGroup.created.desc())).all()

    vulnerable_group_data = defaultdict(list)
    for group, package in vulnerable_groups:
        vulnerable_group_data[group].append(package)

    bumped_groups = []
    for group, packages in vulnerable_group_data.items():
        packages = sorted(packages, key=cmp_to_key(vercmp, attrgetter('version')), reverse=True)
        if vercmp(packages[0].version, group.affected) <= 0:
            continue
        versions = filter_duplicate_packages(packages, filter_arch=True)
        pkgnames = set([pkg.name for pkg in packages])
        bumped_groups.append((group, pkgnames, versions))
    bumped_groups = sorted(bumped_groups, key=lambda item: item[0].id, reverse=True)
    bumped_groups = sorted(bumped_groups, key=lambda item: item[0].severity)

    orphan_issues = (db.session.query(CVE)
                       .outerjoin(CVEGroupEntry)
                       .group_by(CVE.id)
                       .having(func.count(CVEGroupEntry.id) == 0)
                       .order_by(CVE.id)).all()

    stale_groups, counterpart_suggestions = get_review_suggestions()
    return {
        'stale_groups': stale_groups,
        'counterpart_suggestions': counterpart_suggestions,
        'scheduled_advisories': scheduled_advisories,
        'incomplete_advisories': incomplete_advisories,
        'unhandled_advisories': unhandled_advisories,
        'unknown_issues': unknown_issues,
        'unknown_groups': unknown_groups,
        'bumped_groups': bumped_groups,
        'orphan_issues': orphan_issues
    }


def get_review_suggestions():
    rows = (db.session.query(CVEGroup, CVEGroupEntry.cve_id, CVEGroupPackage.pkgname)
            .join(CVEGroupEntry).join(CVEGroupPackage).all())
    groups = {}
    covered = {(cve_id, name) for group, cve_id, name in rows}
    for group, cve_id, name in rows:
        item = groups.setdefault(group.id, {'group': group, 'issues': set(), 'packages': set()})
        item['issues'].add(cve_id)
        item['packages'].add(name)
    versions = defaultdict(list)
    for package in Package.query.all():
        versions[package.name].append(package)

    stale, counterparts = [], []
    cutoff = datetime.utcnow() - timedelta(days=90)
    for item in groups.values():
        group = item['group']
        names = sorted(item['packages'])
        available = [package for name in names for package in versions[name]]
        if group.status.open() and group.changed < cutoff:
            reason = 'No edits for 90 days'
            if not available:
                reason += '; all packages are removed'
            elif any(vercmp(package.version, group.affected) > 0 for package in available):
                reason += '; repository versions are newer than the recorded affected version'
            stale.append({'name': group.name, 'packages': names, 'last_changed': group.changed.isoformat(),
                          'reason': reason})
        for name in names:
            counterpart = name[6:] if name.startswith('lib32-') else 'lib32-' + name
            missing = sorted(cve_id for cve_id in item['issues'] if (cve_id, counterpart) not in covered)
            if versions[counterpart] and missing:
                counterparts.append({'group': group.name, 'package': name, 'counterpart': counterpart,
                                     'issues': missing})
    return sorted(stale, key=lambda item: item['last_changed']), counterparts


@tracker.route('/todo', methods=['GET'])
def todo():
    entries = get_todo_data()
    return render_template('todo.html',
                           title='Todo Lists',
                           entries=entries,
                           smiley=smileys_happy[randint(0, len(smileys_happy) - 1)],
                           can_handle_advisory=user_can_handle_advisory(),
                           can_edit_group=user_can_edit_group(),
                           can_edit_issue=user_can_edit_issue())


def advisory_json(data):
    advisory, package, group = data
    entry = OrderedDict()
    entry['name'] = advisory.id
    entry['date'] = advisory.created.strftime('%Y-%m-%d')
    entry['type'] = advisory.advisory_type
    entry['severity'] = advisory.group_package.group.severity.label
    entry['affected'] = group.affected
    entry['fixed'] = group.fixed
    entry['package'] = package.pkgname
    return entry


def group_packages_json(item):
    group, packages = item
    entry = OrderedDict()
    entry['name'] = group.name
    entry['status'] = group.status.label
    entry['severity'] = group.severity.label
    entry['affected'] = group.affected
    entry['packages'] = [pkg.name for pkg in packages]
    return entry


def bumped_groups_json(item):
    group, pkgnames, versions = item
    entry = OrderedDict()
    entry['name'] = group.name
    entry['status'] = group.status.label
    entry['severity'] = group.severity.label
    entry['affected'] = group.affected
    entry['versions'] = [{'version': pkg.version, 'database': pkg.database} for pkg in versions]
    entry['packages'] = list(pkgnames)
    return entry


def cve_json(cve):
    entry = OrderedDict()
    entry['name'] = cve.id
    entry['type'] = cve.issue_type
    entry['severity'] = cve.severity.label
    entry['vector'] = cve.remote.label
    entry['description'] = cve.description
    return entry


@tracker.route('/todo<regex("[./]json"):postfix>', methods=['GET'])
@json_response
def todo_json(postfix=None):
    data = get_todo_data()

    json_data = OrderedDict()
    json_data['advisories'] = {
        'scheduled': [advisory_json(d) for d in data['scheduled_advisories']],
        'incomplete': [advisory_json(d) for d in data['incomplete_advisories']],
        'unhandled': [group_packages_json(d) for d in data['unhandled_advisories']]
    }

    json_data['groups'] = {
        'unknown': [group_packages_json(g) for g in data['unknown_groups']],
        'bumped': [bumped_groups_json(g) for g in data['bumped_groups']],
        'stale': data['stale_groups'],
        'counterparts': data['counterpart_suggestions']
    }

    json_data['issues'] = {
        'orphan': [cve_json(cve) for cve in data['orphan_issues']],
        'unknown': [cve_json(cve) for cve in data['unknown_issues']]
    }

    return json_data
