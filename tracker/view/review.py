from functools import wraps

from flask import abort
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_login import current_user
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy_continuum import version_class
from werkzeug.exceptions import HTTPException
from werkzeug.exceptions import NotFound

from tracker import db
from tracker import tracker
from tracker.form.review import AssessmentForm
from tracker.form.review import IntakeDecisionForm
from tracker.form.review import IntakeForm
from tracker.form.review import IntakePromoteForm
from tracker.form.review import MergeForm
from tracker.form.review import RevertForm
from tracker.form.review import ReviewLookupForm
from tracker.form.review import SignoffForm
from tracker.model import CVE
from tracker.model import CVEGroup
from tracker.model.review import IntakeCandidate
from tracker.model.review import ReviewEvent
from tracker.review import assessment_for
from tracker.review import content_revision
from tracker.review import expect_revision
from tracker.review import lock_record
from tracker.review import merge_groups
from tracker.review import merged_destination
from tracker.review import record_event
from tracker.review import revert_record
from tracker.review import review_revision
from tracker.review import review_target
from tracker.review import target_name
from tracker.user import reporter_required
from tracker.util import page_number
from tracker.view.error import handle_error


def private_review(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        try:
            if not current_user.active:
                abort(403)
            response = make_response(func(*args, **kwargs))
        except HTTPException as error:
            db.session.rollback()
            response = handle_error(error.description, error.code)
        except StaleDataError:
            db.session.rollback()
            response = handle_error('The record changed. Reload before submitting.', 409)
        except SQLAlchemyError:
            db.session.rollback()
            raise
        response.headers['Cache-Control'] = 'no-store'
        return response
    return reporter_required(wrapped)


@tracker.route('/review', methods=['GET', 'POST'])
@private_review
def review_index():
    form = ReviewLookupForm()
    if form.validate_on_submit():
        record = review_target(form.target.data)
        return redirect(url_for('tracker.review_record', name=target_name(record)))
    latest = db.session.query(func.max(ReviewEvent.id)).filter(
        ReviewEvent.action.in_(('required', 'reviewed'))).group_by(ReviewEvent.target)
    events = ReviewEvent.query.filter(ReviewEvent.id.in_(latest)).order_by(ReviewEvent.id.desc()).limit(100).all()
    assessments = []
    for event in events:
        try:
            record = review_target(event.target)
        except NotFound:
            continue
        stale = event.action == 'reviewed' and event.revision != content_revision(record)
        assessments.append((event, stale))
    return render_template('review/index.html', title='Review', form=form, assessments=assessments,
                           retired=ReviewEvent.query.filter_by(action='merged').order_by(ReviewEvent.id.desc()).limit(100).all()), 400 if request.method == 'POST' else 200


@tracker.route('/review/<name>', methods=['GET', 'POST'])
@private_review
def review_record(name):
    record = review_target(name)
    name = target_name(record)
    form = AssessmentForm()
    if form.validate_on_submit():
        expect_revision(record, form.revision.data)
        record_event(record, 'required' if form.required.data else 'reviewed', form.rationale.data)
        db.session.commit()
        return redirect(url_for('tracker.review_record', name=name))
    assessment = assessment_for(record)
    stale = assessment is not None and assessment.revision != content_revision(record)
    revision = review_revision(record)
    if request.method == 'GET':
        form.revision.data = revision
        form.required.data = not assessment or assessment.action == 'required' or stale
        form.rationale.data = assessment.rationale if assessment else ''
    events = ReviewEvent.query.filter_by(target=name).order_by(ReviewEvent.id.desc()).all()
    signoff_form = SignoffForm(formdata=None, revision=revision)
    return render_template('review/record.html', title='Review ' + name, name=name, form=form,
                           events=events, assessment=assessment, signoff_form=signoff_form,
                           revision=revision, stale=stale), 400 if request.method == 'POST' else 200


@tracker.route('/review/<name>/signoff', methods=['POST'])
@private_review
def review_signoff(name):
    record = review_target(name)
    name = target_name(record)
    form = SignoffForm()
    if not form.validate_on_submit():
        abort(400, 'A revision, comment, and valid CSRF token are required.')
    expect_revision(record, form.revision.data)
    assessment = assessment_for(record)
    if not assessment or assessment.action != 'reviewed' or assessment.revision != content_revision(record):
        abort(409, 'Save a current assessment with no further review required before signing off.')
    existing = ReviewEvent.query.filter_by(target=name, action='signoff', user_id=current_user.id,
                                          revision=form.revision.data).first()
    if existing:
        abort(409, 'You already signed off this revision.')
    record_event(record, 'signoff', form.rationale.data, revision=form.revision.data)
    db.session.commit()
    return redirect(url_for('tracker.review_record', name=name))


@tracker.route('/review/intake', methods=['GET', 'POST'])
@private_review
def review_intake():
    form = IntakeForm()
    if form.validate_on_submit():
        candidate = IntakeCandidate(title=form.title.data, source=form.source.data,
                                    cve_name=form.cve_name.data or None, evidence=form.evidence.data,
                                    description=form.description.data, reference=form.reference.data)
        db.session.add(candidate)
        db.session.flush()
        db.session.add(ReviewEvent(target='INTAKE-{}'.format(candidate.id), action='intake-added',
                                   rationale='Added for review', revision=str(candidate.revision), user_id=current_user.id))
        db.session.commit()
        return redirect(url_for('tracker.review_intake_detail', candidate_id=candidate.id))
    state = request.args.get('state', 'pending')
    if state not in ('pending', 'approved', 'rejected'):
        abort(400, 'Unknown queue state.')
    page = page_number(request.args.get('page', 1), 50)
    candidates = IntakeCandidate.query.filter_by(state=state).order_by(IntakeCandidate.id.desc()).paginate(page=page, per_page=50, error_out=True)
    return render_template('review/intake.html', title='Disclosure intake', form=form,
                           candidates=candidates, state=state), 400 if request.method == 'POST' else 200


def lock_candidate(candidate, revision):
    table = IntakeCandidate.__table__
    result = db.session.execute(table.update().where(table.c.id == candidate.id).values(revision=table.c.revision))
    if result.rowcount != 1:
        abort(409, 'The candidate was removed. Reload before submitting.')
    db.session.expire_all()
    if candidate.revision != revision or candidate.promoted_cve:
        abort(409, 'The candidate changed or was already promoted. Reload before submitting.')


@tracker.route('/review/intake/<regex("[0-9]{1,18}"):candidate_id>', methods=['GET', 'POST'])
@private_review
def review_intake_detail(candidate_id):
    candidate = IntakeCandidate.query.get_or_404(int(candidate_id))
    form = IntakeDecisionForm()
    if form.validate_on_submit():
        lock_candidate(candidate, form.revision.data)
        candidate.state = form.state.data
        candidate.cve_name = form.cve_name.data or None
        # Record even repeated decisions as distinct, conflict-checked revisions.
        candidate.revision += 1
        db.session.add(ReviewEvent(target='INTAKE-{}'.format(candidate.id), action='intake-' + candidate.state,
                                   rationale=form.rationale.data, revision=str(candidate.revision), user_id=current_user.id))
        db.session.commit()
        return redirect(url_for('tracker.review_intake_detail', candidate_id=candidate.id))
    if request.method == 'GET':
        form.revision.data = candidate.revision
        form.state.data = candidate.state
        form.cve_name.data = candidate.cve_name
    events = ReviewEvent.query.filter_by(target='INTAKE-{}'.format(candidate.id)).order_by(ReviewEvent.id).all()
    return render_template('review/intake_detail.html', title=candidate.title, candidate=candidate, form=form,
                           promote_form=IntakePromoteForm(formdata=None, revision=candidate.revision),
                           events=events), 400 if request.method == 'POST' else 200


@tracker.route('/review/intake/<regex("[0-9]{1,18}"):candidate_id>/promote', methods=['POST'])
@private_review
def review_intake_promote(candidate_id):
    candidate = IntakeCandidate.query.get_or_404(int(candidate_id))
    form = IntakePromoteForm()
    if not form.validate_on_submit():
        abort(400, 'A revision and valid CSRF token are required.')
    lock_candidate(candidate, form.revision.data)
    if candidate.state != 'approved' or not candidate.cve_name:
        abort(409, 'Approve the candidate and assign a CVE identifier first.')
    if CVE.query.get(candidate.cve_name):
        abort(409, 'This CVE already exists. Review it directly; existing records are never overwritten.')
    record = CVE.new(candidate.cve_name)
    record.description = candidate.description
    record.reference = candidate.reference
    db.session.add(record)
    candidate.promoted_cve = record.id
    db.session.flush()
    record_event(record, 'required', 'Created from a reviewed disclosure; evaluate applicability.')
    db.session.add(ReviewEvent(target='INTAKE-{}'.format(candidate.id), action='intake-promoted',
                               rationale='Created ' + record.id, revision=str(candidate.revision), user_id=current_user.id))
    db.session.commit()
    return redirect(url_for('tracker.review_record', name=record.id))


@tracker.route('/review/merge', methods=['GET', 'POST'])
@private_review
def review_merge():
    form = MergeForm()
    source = destination = None
    if request.method == 'GET':
        form.source.data = request.args.get('source', '')
        form.destination.data = request.args.get('destination', '')
        if form.source.data and form.destination.data:
            source = review_target(form.source.data)
            destination = review_target(form.destination.data)
            if not isinstance(source, CVEGroup) or not isinstance(destination, CVEGroup):
                abort(400, 'Only AVG records can be merged.')
            form.source_revision.data = review_revision(source)
            form.destination_revision.data = review_revision(destination)
    elif form.validate_on_submit():
        source = review_target(form.source.data)
        destination = review_target(form.destination.data)
        for record in sorted((source, destination), key=lambda item: item.id):
            lock_record(record)
        if review_revision(source) != form.source_revision.data or review_revision(destination) != form.destination_revision.data:
            abort(409, 'A group or its assessment changed. Reload the preview.')
        merge_groups(source, destination, form.rationale.data)
        db.session.commit()
        return redirect(url_for('tracker.review_record', name=destination.name))
    return render_template('review/merge.html', title='Merge groups', form=form, source=source,
                           destination=destination), 400 if request.method == 'POST' else 200


@tracker.before_app_request
def redirect_merged_group():
    if request.endpoint not in ('tracker.show_group', 'tracker.show_group_json', 'tracker.show_group_log'):
        return None
    name = request.view_args['avg']
    destination = merged_destination(name)
    if destination and destination != name:
        return redirect(url_for(request.endpoint, avg=destination), code=301)
    return None


@tracker.route('/review/retired/<name>', methods=['GET'])
@private_review
def review_retired(name):
    event = ReviewEvent.query.filter_by(target=name, action='merged').first_or_404()
    versions = version_class(CVEGroup).query.filter_by(id=int(name[4:])).order_by(
        version_class(CVEGroup).transaction_id.desc()).all()
    events = ReviewEvent.query.filter_by(target=name).order_by(ReviewEvent.id.desc()).all()
    return render_template('review/retired.html', title='Retired ' + name, versions=versions,
                           events=events, destination=merged_destination(event.target))


@tracker.route('/review/<name>/revert', methods=['GET', 'POST'])
@private_review
def review_revert(name):
    record = review_target(name)
    name = target_name(record)
    model = version_class(type(record))
    versions = model.query.filter_by(id=record.id).filter(model.operation_type != 2).order_by(model.transaction_id.desc()).all()
    form = RevertForm()
    form.transaction_id.choices = [(version.transaction_id, '{}: {}'.format(version.transaction_id, version.changed))
                                   for version in versions]
    if form.validate_on_submit():
        expect_revision(record, form.revision.data)
        revert_record(record, form.transaction_id.data, form.rationale.data)
        db.session.commit()
        return redirect(url_for('tracker.review_record', name=name))
    if request.method == 'GET':
        form.revision.data = review_revision(record)
    return render_template('review/revert.html', title='Restore ' + name, name=name, form=form,
                           versions=versions), 400 if request.method == 'POST' else 200
