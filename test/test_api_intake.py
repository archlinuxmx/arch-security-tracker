from tracker.model import CVE
from tracker.model.apitoken import ApiToken
from tracker.model.enum import UserRole
from tracker.model.review import IntakeCandidate
from tracker.model.review import ReviewEvent
from tracker.model.user import User

from .conftest import create_user
from .conftest import logged_in


@create_user(username='ingestor', role=UserRole.reporter)
@logged_in(role=UserRole.reporter)
def test_private_intake_is_scoped_and_retryable(db, client):
    user = User.query.filter_by(name='ingestor').one()
    token, secret = ApiToken.issue(user, 'Mail intake', 'intake:create')
    public_token, public_secret = ApiToken.issue(user, 'Public CVEs')
    db.session.add_all([token, public_token])
    db.session.commit()
    headers = {'Authorization': 'Bearer ' + secret, 'Idempotency-Key': 'mail-123'}
    data = {'title': 'Possible issue', 'source': 'private-message-id', 'evidence': 'private-evidence-marker',
            'description': 'Proposed public description', 'references': ['https://example.org/advisory']}
    assert client.post('/api/v1/intake', json=data).status_code == 401
    assert client.post('/api/v1/intake', json=data, headers=dict(headers, Authorization='Bearer ' + public_secret)).status_code == 403
    assert client.post('/api/v1/intake', json=data, headers={'Authorization': headers['Authorization']}).status_code == 400
    assert client.post('/api/v1/intake', json=dict(data, state='approved'), headers=headers).status_code == 422
    assert client.post('/api/v1/intake', json=dict(data, references=['ftp://example.org/private']), headers=headers).status_code == 422
    response = client.post('/api/v1/intake', json=data, headers=headers)
    assert response.status_code == 201
    assert response.headers['Cache-Control'] == 'no-store'
    candidate = IntakeCandidate.query.one()
    assert candidate.state == 'pending'
    assert candidate.evidence == data['evidence']
    assert candidate.source == data['source']
    assert response.headers['Location'] == '/review/intake/{}'.format(candidate.id)
    assert response.get_json()['review_url'] == response.headers['Location']
    assert 'evidence' not in response.get_json()
    assert 'source' not in response.get_json()
    assert ReviewEvent.query.one().user_id == user.id
    assert CVE.query.count() == 0
    assert client.get('/api/v1/cves').get_json()['items'] == []
    assert client.get('/api/v1/changes').get_json()['items'] == []
    assert client.post('/api/v1/cves', json={'name': 'CVE-2026-1234'}, headers=headers).status_code == 403

    retry = client.post('/api/v1/intake', json=data, headers=headers)
    assert retry.status_code == 200
    assert retry.get_json()['id'] == candidate.id
    assert IntakeCandidate.query.count() == ReviewEvent.query.count() == 1
    assert client.post('/api/v1/intake', json=dict(data, evidence='Different evidence'), headers=headers).status_code == 409
    candidate.state = 'approved'
    candidate.cve_name = 'CVE-2026-1234'
    db.session.commit()
    retry = client.post('/api/v1/intake', json=data, headers=headers)
    assert retry.status_code == 200
    assert retry.get_json()['state'] == 'approved'
    assert retry.get_json()['cve_name'] == candidate.cve_name
    assert candidate.promoted_cve is None
    assert IntakeCandidate.query.count() == ReviewEvent.query.count() == 1
    user.active = False
    db.session.commit()
    assert client.post('/api/v1/intake', json=data, headers=headers).status_code == 403

    old_id = user.id
    db.session.delete(user)
    db.session.commit()
    replacement = User(id=old_id, name='replacement', email='replacement@example.org',
                       salt='unused', password='unused', role=UserRole.reporter)
    db.session.add(replacement)
    db.session.flush()
    token, secret = ApiToken.issue(replacement, 'New account', 'intake:create')
    db.session.add(token)
    db.session.commit()
    response = client.post('/api/v1/intake', json=data, headers=dict(headers, Authorization='Bearer ' + secret))
    assert response.status_code == 201
    assert response.get_json()['id'] != candidate.id
    assert IntakeCandidate.query.count() == 2
