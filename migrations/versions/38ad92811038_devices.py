"""devices

Revision ID: 38ad92811038
Revises: 
Create Date: 2020-03-09 14:47:19.120511

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '38ad92811038'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('devices',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ip', sa.String(length=15), nullable=True),
    sa.Column('host', sa.String(length=120), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_devices_host'), 'devices', ['host'], unique=False)
    op.create_index(op.f('ix_devices_ip'), 'devices', ['ip'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_devices_ip'), table_name='devices')
    op.drop_index(op.f('ix_devices_host'), table_name='devices')
    op.drop_table('devices')
    # ### end Alembic commands ###
