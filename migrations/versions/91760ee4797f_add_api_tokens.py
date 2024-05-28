"""add API tokens

Revision ID: 91760ee4797f
Revises: d0b4cb352ca1

"""
import sqlalchemy as sa
from alembic import op

revision = '91760ee4797f'
down_revision = 'd0b4cb352ca1'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('api_token',
                    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
                    sa.Column('user_id', sa.Integer(), nullable=False),
                    sa.Column('name', sa.String(length=64), nullable=False),
                    sa.Column('token_hash', sa.String(length=64), nullable=False),
                    sa.Column('scope', sa.String(length=32), nullable=False),
                    sa.Column('created', sa.DateTime(), nullable=False),
                    sa.Column('expires_at', sa.DateTime(), nullable=False),
                    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_api_token_user_id', 'api_token', ['user_id'], unique=False)
    op.create_index('ix_api_token_token_hash', 'api_token', ['token_hash'], unique=True)


def downgrade():
    op.drop_index('ix_api_token_token_hash', table_name='api_token')
    op.drop_index('ix_api_token_user_id', table_name='api_token')
    op.drop_table('api_token')
