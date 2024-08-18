"""Add is_admin column to User model

Revision ID: dd6ea3917a4f
Revises: 854d6a63ab43
Create Date: 2024-07-27 11:38:58.232571

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dd6ea3917a4f'
down_revision = '854d6a63ab43'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('user', sa.Column('is_admin', sa.Boolean(), nullable=True))


def downgrade():
    op.drop_column('user', 'is_admin')

    # ### end Alembic commands ###
