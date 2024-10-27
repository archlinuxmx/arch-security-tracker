from datetime import datetime

from sqlalchemy import event
from sqlalchemy.orm import Session

from .advisory import Advisory
from .apitoken import ApiToken
from .cve import CVE
from .cvegroup import CVEGroup
from .cvegroupentry import CVEGroupEntry
from .cvegrouppackage import CVEGroupPackage
from .package import Package
from .user import User


@event.listens_for(Session, 'before_flush')
def touch_edited_records(session, flush_context, instances):
    for record in session.dirty:
        if isinstance(record, (CVE, CVEGroup, Advisory)) and session.is_modified(record):
            record.changed = datetime.utcnow()
