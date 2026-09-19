"""Allow multiple scopes without changing existing token credentials."""
import sqlalchemy as sa
from alembic import op

revision = 'a73d04b17c62'
down_revision = 'f3170a42ce86'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('api_token') as batch:
        batch.alter_column('scope', existing_type=sa.String(32), type_=sa.String(255),
                           existing_nullable=False)


def downgrade():
    tokens = sa.table('api_token', sa.column('scope', sa.String(255)))
    scopes = op.get_bind().execute(sa.select(tokens.c.scope)).scalars()
    if any(len(scope.split()) != 1 or len(scope) > 32 for scope in scopes):
        raise RuntimeError('Revoke tokens with multiple scopes before downgrading.')
    with op.batch_alter_table('api_token') as batch:
        batch.alter_column('scope', existing_type=sa.String(255), type_=sa.String(32),
                           existing_nullable=False)
