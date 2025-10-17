"""add private disclosure intake

Revision ID: 7e913b50c214
Revises: 5b914f882a10
"""
import sqlalchemy as sa
from alembic import op

revision = '7e913b50c214'
down_revision = '5b914f882a10'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('intake_candidate',
                    sa.Column('id', sa.Integer(), primary_key=True),
                    sa.Column('title', sa.String(255), nullable=False),
                    sa.Column('source', sa.String(2048), nullable=False),
                    sa.Column('cve_name', sa.String(64)),
                    sa.Column('evidence', sa.Text(), nullable=False),
                    sa.Column('description', sa.String(4096), nullable=False),
                    sa.Column('reference', sa.String(4096), nullable=False),
                    sa.Column('state', sa.String(16), nullable=False),
                    sa.Column('promoted_cve', sa.String(64)),
                    sa.Column('revision', sa.Integer(), nullable=False),
                    sa.Column('created', sa.DateTime(), nullable=False))
    op.create_index('ix_intake_candidate_state', 'intake_candidate', ['state'])


def downgrade():
    op.drop_table('intake_candidate')
