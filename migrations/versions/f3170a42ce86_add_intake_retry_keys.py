"""Deduplicate private intake submissions."""
import sqlalchemy as sa
from alembic import op

revision = 'f3170a42ce86'
down_revision = 'c9a612d7084e'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('intake_candidate') as batch:
        batch.add_column(sa.Column('ingestion_user_id', sa.Integer()))
        batch.add_column(sa.Column('ingestion_key', sa.String(64)))
        batch.add_column(sa.Column('ingestion_hash', sa.String(64)))
        batch.create_foreign_key('fk_intake_ingestion_user', 'user', ['ingestion_user_id'], ['id'], ondelete='SET NULL')
        batch.create_index('ix_intake_candidate_ingestion', ['ingestion_user_id', 'ingestion_key'], unique=True)


def downgrade():
    with op.batch_alter_table('intake_candidate') as batch:
        batch.drop_index('ix_intake_candidate_ingestion')
        batch.drop_constraint('fk_intake_ingestion_user', type_='foreignkey')
        batch.drop_column('ingestion_hash')
        batch.drop_column('ingestion_key')
        batch.drop_column('ingestion_user_id')
