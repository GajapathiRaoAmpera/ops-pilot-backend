"""integration secrets

Revision ID: 9c1e4a7b2d10
Revises: 6d32349ab86e
"""
import sqlalchemy as sa
from alembic import op

revision = "9c1e4a7b2d10"
down_revision = "6d32349ab86e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("integrations", sa.Column("secret_ciphertext", sa.Text(), nullable=True), schema="opspilot")
    op.add_column("integrations", sa.Column("updated_by", sa.Uuid(), nullable=True), schema="opspilot")
    op.add_column("integrations", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True), schema="opspilot")


def downgrade() -> None:
    op.drop_column("integrations", "updated_at", schema="opspilot")
    op.drop_column("integrations", "updated_by", schema="opspilot")
    op.drop_column("integrations", "secret_ciphertext", schema="opspilot")
