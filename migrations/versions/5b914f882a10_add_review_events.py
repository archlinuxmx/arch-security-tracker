"""add private review events

Revision ID: 5b914f882a10
Revises: 4ce37a85d102
"""
import sqlalchemy as sa
from alembic import op

revision = '5b914f882a10'
down_revision = '4ce37a85d102'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('review_event',
                    sa.Column('id', sa.Integer(), primary_key=True),
                    sa.Column('target', sa.String(64), nullable=False),
                    sa.Column('action', sa.String(32), nullable=False),
                    sa.Column('revision', sa.String(64), nullable=False),
                    sa.Column('rationale', sa.String(4096), nullable=False),
                    sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id', ondelete='SET NULL')),
                    sa.Column('created', sa.DateTime(), nullable=False))
    op.create_index('ix_review_event_target', 'review_event', ['target'])


def downgrade():
    op.drop_table('review_event')
