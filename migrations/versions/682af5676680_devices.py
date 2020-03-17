"""devices

Revision ID: 682af5676680
Revises: 7b8fad355f33
Create Date: 2020-03-11 15:18:52.825745

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '682af5676680'
down_revision = '7b8fad355f33'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('devices', sa.Column('mac', sa.String(length=20), nullable=True))
    op.add_column('devices', sa.Column('tcp', sa.String(length=200), nullable=True))
    op.add_column('devices', sa.Column('udp', sa.String(length=200), nullable=True))
    op.create_unique_constraint(None, 'devices', ['ip'])
    op.create_unique_constraint(None, 'devices', ['mac'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'devices', type_='unique')
    op.drop_constraint(None, 'devices', type_='unique')
    op.drop_column('devices', 'udp')
    op.drop_column('devices', 'tcp')
    op.drop_column('devices', 'mac')
    # ### end Alembic commands ###
