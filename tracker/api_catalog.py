"""Public package, group and advisory catalogues."""

import re

from flask import jsonify
from flask import request
from sqlalchemy import func
from sqlalchemy import or_
from sqlalchemy.orm import selectinload
from sqlalchemy_continuum import version_class
from sqlalchemy_continuum import versioning_manager
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import NotFound

from tracker import db
from tracker.api import api
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model.enum import Publication
from tracker.model.enum import Status
from tracker.model.enum import status_to_affected


def page_parameters(allowed=()):
    if (set(request.args) - {'limit', 'after'} - set(allowed)
            or any(len(values) != 1 for key, values in request.args.lists())):
        raise BadRequest('Unknown or repeated query parameter.')
    raw_limit = request.args.get('limit', '50')
    if not re.fullmatch(r'[0-9]{1,3}', raw_limit) or not 1 <= int(raw_limit) <= 100:
        raise BadRequest('limit must be an integer between 1 and 100.')
    return int(raw_limit), request.args.get('after')


def numeric_cursor(value):
    if value is None:
        return 0
    if not re.fullmatch(r'[0-9]{1,18}', value):
        raise BadRequest('after must be a non-negative integer cursor.')
    return int(value)


@api.route('/packages', methods=['GET'])
def list_packages():
    limit, after = page_parameters({'name', 'base', 'repository', 'architecture', 'q'})
    query = Package.query.filter(Package.id > numeric_cursor(after)).order_by(Package.id)
    for field, column in [('name', Package.name), ('base', Package.base),
                          ('repository', Package.database), ('architecture', Package.arch)]:
        if field in request.args:
            query = query.filter(column == request.args[field])
    if 'q' in request.args:
        term = request.args['q']
        query = query.filter(or_(Package.name.contains(term, autoescape=True),
                                 Package.base.contains(term, autoescape=True),
                                 Package.url.contains(term, autoescape=True)))
    rows = query.limit(limit + 1).all()
    return jsonify(items=[{
        'name': package.name, 'base': package.base, 'version': package.version,
        'repository': package.database, 'architecture': package.arch,
        'description': package.description, 'upstream_url': package.url,
    } for package in rows[:limit]], next_cursor=str(rows[limit - 1].id) if len(rows) > limit else None)


def timestamp(value):
    return value.isoformat(timespec='microseconds') + 'Z'


def serialize_group(group):
    return {
        'name': group.name, 'cves': sorted(entry.cve_id for entry in group.issues),
        'packages': sorted(package.pkgname for package in group.packages),
        'affected': group.affected, 'fixed': group.fixed, 'status': group.status.name,
        'assessment': status_to_affected(group.status).name, 'severity': group.severity.name,
        'references': group.reference.splitlines() if group.reference else [],
        'notes': group.notes or '', 'bug_ticket': group.bug_ticket or '',
        'advisory_qualified': group.advisory_qualified,
        'created': timestamp(group.created), 'updated': timestamp(group.changed),
    }


@api.route('/groups', methods=['GET'])
def list_groups():
    limit, after = page_parameters({'package', 'cve', 'status'})
    query = (CVEGroup.query.options(selectinload(CVEGroup.issues), selectinload(CVEGroup.packages))
             .filter(CVEGroup.id > numeric_cursor(after)).order_by(CVEGroup.id))
    if 'package' in request.args:
        query = query.filter(CVEGroup.packages.any(CVEGroupPackage.pkgname == request.args['package']))
    if 'cve' in request.args:
        query = query.filter(CVEGroup.issues.any(CVEGroupEntry.cve_id == request.args['cve']))
    if 'status' in request.args:
        if request.args['status'] not in Status.__members__:
            raise BadRequest('Unknown group status.')
        query = query.filter(CVEGroup.status == Status[request.args['status']])
    rows = query.limit(limit + 1).all()
    return jsonify(items=[serialize_group(group) for group in rows[:limit]],
                   next_cursor=str(rows[limit - 1].id) if len(rows) > limit else None)


@api.route('/groups/<name>', methods=['GET'])
def get_group(name):
    group = None
    if re.fullmatch(r'AVG-[0-9]{1,18}', name):
        group = CVEGroup.query.filter_by(id=int(name[4:])).first()
    if group is None:
        raise NotFound('Group not found.')
    return jsonify(serialize_group(group))


def serialize_advisory(advisory):
    package = advisory.group_package
    group = package.group
    return {
        'name': advisory.id, 'type': advisory.advisory_type, 'package': package.pkgname,
        'group': group.name, 'cves': sorted(entry.cve_id for entry in group.issues),
        'affected': group.affected, 'fixed': group.fixed, 'severity': group.severity.name,
        'workaround': advisory.workaround or '', 'impact': advisory.impact or '',
        'content': advisory.content or '',
        'references': list(dict.fromkeys(([advisory.reference] if advisory.reference else [])
                                        + (group.reference.splitlines() if group.reference else []))),
        'created': timestamp(advisory.created), 'updated': timestamp(advisory.changed),
    }


def published_advisories():
    return (Advisory.query.filter(Advisory.publication == Publication.published)
            .options(selectinload(Advisory.group_package).selectinload(CVEGroupPackage.group)
                     .selectinload(CVEGroup.issues)))


@api.route('/advisories', methods=['GET'])
def list_advisories():
    limit, after = page_parameters({'package'})
    query = published_advisories().order_by(Advisory.id)
    if after is not None:
        if not re.fullmatch(r'ASA-[0-9]{6}-[0-9]{1,8}', after):
            raise BadRequest('after must be an ASA identifier.')
        query = query.filter(Advisory.id > after)
    if 'package' in request.args:
        query = query.filter(Advisory.group_package.has(CVEGroupPackage.pkgname == request.args['package']))
    rows = query.limit(limit + 1).all()
    return jsonify(items=[serialize_advisory(advisory) for advisory in rows[:limit]],
                   next_cursor=rows[limit - 1].id if len(rows) > limit else None)


@api.route('/advisories/<name>', methods=['GET'])
def get_advisory(name):
    advisory = published_advisories().filter(Advisory.id == name).first()
    if advisory is None:
        raise NotFound('Published advisory not found.')
    return jsonify(serialize_advisory(advisory))


@api.route('/changes', methods=['GET'])
def list_changes():
    """Invalidate current resources from audited transactions, not changed dates."""
    limit, after = page_parameters()
    transaction = versioning_manager.transaction_cls
    latest = db.session.query(func.max(transaction.id)).scalar() or 0
    if after is None:
        return jsonify(items=[], next_cursor=str(latest), has_more=False)
    cursor = numeric_cursor(after)
    if cursor > latest:
        raise BadRequest('Cursor is ahead of this database; start a fresh synchronization.')
    transactions = (db.session.query(transaction.id).filter(transaction.id > cursor)
                    .order_by(transaction.id).limit(limit + 1).all())
    if not transactions:
        return jsonify(items=[], next_cursor=str(cursor), has_more=False)
    end = transactions[min(len(transactions), limit) - 1][0]
    versions = {}
    for model in (CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage, Advisory):
        history = version_class(model)
        versions[model] = (db.session.query(history).filter(history.transaction_id > cursor,
                                                          history.transaction_id <= end).all())
    cves = {row.id for row in versions[CVE]}
    groups = {row.id for row in versions[CVEGroup]}
    groups.update(row.group_id for row in versions[CVEGroupEntry] + versions[CVEGroupPackage])
    cves.update(row.cve_id for row in versions[CVEGroupEntry])

    # Historical links also cover deleted/replaced associations and cascades.
    entry_history = version_class(CVEGroupEntry)
    if cves:
        groups.update(row[0] for row in db.session.query(entry_history.group_id)
                      .filter(entry_history.cve_id.in_(cves)).distinct())
    if groups:
        cves.update(row[0] for row in db.session.query(entry_history.cve_id)
                    .filter(entry_history.group_id.in_(groups)).distinct())

    advisory_history = version_class(Advisory)
    advisories = {row.id for row in versions[Advisory]}
    if groups:
        package_history = version_class(CVEGroupPackage)
        package_ids = db.session.query(package_history.id).filter(package_history.group_id.in_(groups))
        advisories.update(row[0] for row in db.session.query(advisory_history.id)
                          .filter(advisory_history.group_package_id.in_(package_ids)).distinct())
    # Never reveal a draft identifier. An earlier published advisory can be
    # withdrawn or deleted, in which case clients must remove their cached copy.
    advisories = {row[0] for row in db.session.query(advisory_history.id)
                  .filter(advisory_history.id.in_(advisories),
                          advisory_history.publication == Publication.published).distinct()}
    current_cves = {row[0] for row in db.session.query(CVE.id).filter(CVE.id.in_(cves))}
    current_groups = {row[0] for row in db.session.query(CVEGroup.id).filter(CVEGroup.id.in_(groups))}
    current_advisories = {row[0] for row in db.session.query(Advisory.id)
                         .filter(Advisory.id.in_(advisories), Advisory.publication == Publication.published)}
    items = ([{'resource': 'cves', 'name': name, 'deleted': name not in current_cves} for name in sorted(cves)]
             + [{'resource': 'groups', 'name': 'AVG-{}'.format(name), 'deleted': name not in current_groups}
                for name in sorted(groups)]
             + [{'resource': 'advisories', 'name': name, 'deleted': name not in current_advisories}
                for name in sorted(advisories)])
    return jsonify(items=items, next_cursor=str(end), has_more=len(transactions) > limit)
