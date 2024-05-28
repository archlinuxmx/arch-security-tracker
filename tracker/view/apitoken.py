from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_login import current_user

from tracker import db
from tracker import tracker
from tracker.form.apitoken import ApiTokenForm
from tracker.form.apitoken import ApiTokenRevokeForm
from tracker.model.apitoken import ApiToken
from tracker.user import reporter_required

from .error import bad_request
from .error import forbidden


def token_response(response, status=200):
    response = make_response(response, status)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


@tracker.route('/tokens', methods=['GET', 'POST'])
@reporter_required
def manage_api_tokens():
    if not current_user.active:
        return forbidden()

    form = ApiTokenForm()
    secret = None
    status = 200
    if form.validate_on_submit():
        token, secret = ApiToken.issue(current_user._get_current_object(), form.name.data)
        db.session.add(token)
        db.session.commit()
        form = ApiTokenForm(formdata=None)
    elif request.method == 'POST':
        status = 400

    tokens = ApiToken.query.filter_by(user_id=current_user.id).order_by(
        ApiToken.created.desc(), ApiToken.id.desc()).all()
    return token_response(render_template('form/apitoken.html', title='API tokens',
                                         form=form, revoke_form=ApiTokenRevokeForm(),
                                         tokens=tokens, secret=secret), status)


@tracker.route('/tokens/<regex("[0-9]{1,18}"):token_id>/revoke', methods=['POST'])
@reporter_required
def revoke_api_token(token_id):
    if not current_user.active:
        return forbidden()

    token = ApiToken.query.filter_by(id=int(token_id), user_id=current_user.id).first_or_404()
    form = ApiTokenRevokeForm()
    if not form.validate_on_submit():
        return bad_request()

    db.session.delete(token)
    db.session.commit()
    return token_response(redirect(url_for('tracker.manage_api_tokens')), 302)
