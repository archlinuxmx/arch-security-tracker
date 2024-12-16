from collections import OrderedDict
from re import fullmatch

from flask import abort
from flask import render_template
from flask import request
from sqlalchemy import and_
from sqlalchemy import case
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
from tracker.model.enum import Severity
from tracker.model.enum import Status
from tracker.util import json_response
from tracker.util import page_number


def get_index_data(only_vulnerable=False, only_in_repo=True, group_ids=None):
    select = (db.session.query(CVEGroup, CVE, func.group_concat(CVEGroupPackage.pkgname, ' '),
                               func.group_concat(Advisory.id, ' '))
                        .join(CVEGroupEntry, CVEGroup.issues)
                        .join(CVE, CVEGroupEntry.cve)
                        .join(CVEGroupPackage, CVEGroup.packages)
                        .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                                  Advisory.publication == Publication.published)))
    if group_ids is not None:
        select = select.filter(CVEGroup.id.in_(group_ids))
    if only_vulnerable:
        select = select.filter(CVEGroup.status.in_([Status.unknown, Status.vulnerable, Status.testing]))
    if only_in_repo:
        select = select.join(Package, Package.name == CVEGroupPackage.pkgname)

    entries = (select.group_by(CVEGroup.id).group_by(CVE.id)
                     .order_by(CVEGroup.status.desc())
                     .order_by(CVEGroup.changed.desc())).all()

    groups = {}
    for group, cve, pkgs, advisories in entries:
        group_entry = groups.setdefault(group.id, {})
        group_entry['group'] = group
        group_entry['pkgs'] = sorted(set(pkgs.split(' ')))
        group_entry['advisories'] = sorted(set(advisories.split(' '))) if advisories else []
        group_entry.setdefault('issues', []).append(cve)

    for group in groups.values():
        group['issues'] = sorted(group['issues'], reverse=True)
        group['types'] = sorted({issue.issue_type or 'unknown' for issue in group['issues']})

    groups = groups.values()
    groups = sorted(groups, key=lambda item: item['group'].changed, reverse=True)
    groups = sorted(groups, key=lambda item: item['group'].severity)
    groups = sorted(groups, key=lambda item: item['group'].status)
    return groups


@tracker.route('/', defaults={'only_vulnerable': True}, methods=['GET'])
def index(only_vulnerable=True):
    page = page_number(request.args.get('page', 1), 50)
    sort = request.args.get('sort', 'priority')
    if sort not in ('priority', 'created', 'changed'):
        abort(400)
    query = (CVEGroup.query.join(CVEGroupEntry).join(CVEGroupPackage)
             .join(Package, Package.name == CVEGroupPackage.pkgname))
    if only_vulnerable:
        query = query.filter(CVEGroup.status.in_([Status.unknown, Status.vulnerable, Status.testing]))
    if sort == 'priority':
        query = query.order_by(case({status.name: status.order for status in Status}, value=CVEGroup.status),
                               case({severity.name: severity.order for severity in Severity},
                                    value=CVEGroup.severity), CVEGroup.changed.desc())
    else:
        query = query.order_by(getattr(CVEGroup, sort).desc())
    pagination = query.group_by(CVEGroup.id).order_by(CVEGroup.id.desc()).paginate(
        page=page, per_page=50, error_out=True)
    group_ids = [group.id for group in pagination.items]
    groups = {entry['group'].id: entry for entry in get_index_data(only_vulnerable, group_ids=group_ids)}
    return render_template('index.html',
                           title='Issues' if not only_vulnerable else 'Vulnerable issues',
                           entries=[groups[group_id] for group_id in group_ids],
                           pagination=pagination, sort=sort,
                           only_vulnerable=only_vulnerable)


@tracker.route('/issues', methods=['GET'])
@tracker.route('/issues/open', methods=['GET'])
@tracker.route('/issues/vulnerable', methods=['GET'])
def index_vulnerable():
    return index(only_vulnerable=True)


@tracker.route('/all', methods=['GET'])
@tracker.route('/issues/all', methods=['GET'])
def index_all():
    return index(only_vulnerable=False)


# TODO: temporarily keep /json this way until tools adopted new endpoint
@tracker.route('/json', defaults={'only_vulnerable': False}, methods=['GET'])
@tracker.route('/all.json', defaults={'only_vulnerable': False}, methods=['GET'])
@tracker.route('/issues.json', defaults={'only_vulnerable': False}, methods=['GET'])
@tracker.route('/issues/all.json', defaults={'only_vulnerable': False}, methods=['GET'])
@json_response
def index_json(only_vulnerable=False):
    entries = get_index_data(only_vulnerable)
    json_data = []
    for entry in entries:
        group = entry['group']
        types = entry['types']

        json_entry = OrderedDict()
        json_entry['name'] = group.name
        json_entry['packages'] = entry['pkgs']
        json_entry['status'] = group.status.label
        json_entry['severity'] = group.severity.label
        json_entry['type'] = 'multiple issues' if len(types) > 1 else types[0]
        json_entry['types'] = types
        json_entry['affected'] = group.affected
        json_entry['fixed'] = group.fixed if group.fixed else None
        json_entry['ticket'] = group.bug_ticket if group.bug_ticket else None
        json_entry['issues'] = [str(cve) for cve in entry['issues']]
        json_entry['advisories'] = entry['advisories']
        json_data.append(json_entry)
    return json_data


@tracker.route('/issues.json', methods=['GET'])
@tracker.route('/issues/open.json', methods=['GET'])
@tracker.route('/issues/vulnerable.json', methods=['GET'])
def index_vulnerable_json():
    return index_json(only_vulnerable=True)


@tracker.route('/search', methods=['GET'])
def search():
    term = request.args.get('q', '').strip()
    if len(term) > 256:
        abort(400)
    issues, groups, packages = [], [], []
    if term:
        def contains(column):
            return func.lower(column).contains(term.lower(), autoescape=True)

        issues = (CVE.query.filter(or_(contains(CVE.id), contains(CVE.description), contains(CVE.notes)))
                  .order_by(CVE.id.desc()).limit(50).all())
        group_id = int(term[4:]) if fullmatch(r'AVG-[0-9]{1,18}', term) else None
        groups = (CVEGroup.query.outerjoin(CVEGroupPackage)
                  .filter(or_(CVEGroup.id == group_id, contains(CVEGroup.notes),
                              contains(CVEGroupPackage.pkgname)))
                  .group_by(CVEGroup.id).order_by(CVEGroup.id.desc()).limit(50).all())
        packages = (db.session.query(Package.name).filter(or_(contains(Package.name), contains(Package.description)))
                    .distinct().order_by(Package.name).limit(50).all())
    return render_template('search.html', title='Search', term=term, issues=issues, groups=groups, packages=packages)
