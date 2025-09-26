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
from werkzeug.exceptions import HTTPException

from tracker import db
from tracker import tracker
from tracker.form.review import AssessmentForm
from tracker.form.review import ReviewLookupForm
from tracker.form.review import SignoffForm
from tracker.model.review import ReviewEvent
from tracker.review import assessment_for
from tracker.review import content_revision
from tracker.review import expect_revision
from tracker.review import record_event
from tracker.review import review_revision
from tracker.review import review_target
from tracker.review import target_name
from tracker.user import reporter_required
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
    return render_template('review/index.html', title='Review', form=form, events=events), 400 if request.method == 'POST' else 200


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
