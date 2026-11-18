"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-11-17 20:25:10

Creates all tables. UTC timestamps are stored as naive UTC datetimes. The audit_logs and
security_events tables are made append-only with triggers that reject UPDATE and DELETE.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('audit_logs',
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('actor_sub', sa.String(length=255), nullable=False),
    sa.Column('actor_role', sa.String(length=50), nullable=False),
    sa.Column('action', sa.String(length=100), nullable=False),
    sa.Column('resource_type', sa.String(length=50), nullable=False),
    sa.Column('resource_id', sa.String(length=128), nullable=True),
    sa.Column('request_id', sa.String(length=128), nullable=True),
    sa.Column('correlation_id', sa.String(length=128), nullable=True),
    sa.Column('outcome', sa.String(length=50), nullable=False),
    sa.Column('metadata', sa.JSON(), nullable=False),
    sa.Column('prev_hash', sa.String(length=64), nullable=False),
    sa.Column('row_hash', sa.String(length=64), nullable=False),
    sa.Column('occurred_at', sa.DateTime(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_logs'))
    )
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.create_index('ix_audit_logs_actor_occurred_at', ['actor_sub', 'occurred_at'], unique=False)
        batch_op.create_index('ix_audit_logs_occurred_at', ['occurred_at'], unique=False)
        batch_op.create_index('ix_audit_logs_resource', ['resource_type', 'resource_id'], unique=False)
        batch_op.create_index('uq_audit_logs_seq', ['seq'], unique=True)

    op.create_table('llm_models',
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('provider', sa.String(length=100), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('deleted_at', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_llm_models'))
    )
    with op.batch_alter_table('llm_models', schema=None) as batch_op:
        batch_op.create_index('uq_llm_models_name_active', ['name'], unique=True, sqlite_where=sa.text('deleted_at IS NULL'))

    op.create_table('projects',
    sa.Column('project_key', sa.String(length=64), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('team', sa.String(length=100), nullable=False),
    sa.Column('status', sa.Enum('active', 'suspended', name='project_status', native_enum=False, create_constraint=True, length=32), nullable=False),
    sa.Column('deleted_at', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_projects'))
    )
    with op.batch_alter_table('projects', schema=None) as batch_op:
        batch_op.create_index('ix_projects_team', ['team'], unique=False)
        batch_op.create_index('uq_projects_project_key_active', ['project_key'], unique=True, sqlite_where=sa.text('deleted_at IS NULL'))

    op.create_table('quotas',
    sa.Column('scope_type', sa.Enum('caller', 'team', 'project', 'task', name='quota_scope', native_enum=False, create_constraint=True, length=32), nullable=False),
    sa.Column('scope_ref', sa.String(length=255), nullable=False),
    sa.Column('kind', sa.Enum('rate', 'quota', name='quota_kind', native_enum=False, create_constraint=True, length=32), nullable=False),
    sa.Column('limit_value', sa.Integer(), nullable=False),
    sa.Column('window_seconds', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint('limit_value > 0', name=op.f('ck_quotas_limit_positive')),
    sa.CheckConstraint('window_seconds > 0', name=op.f('ck_quotas_window_positive')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_quotas'))
    )
    with op.batch_alter_table('quotas', schema=None) as batch_op:
        batch_op.create_index('uq_quotas_scope_kind', ['scope_type', 'scope_ref', 'kind'], unique=True)

    op.create_table('rate_counters',
    sa.Column('key', sa.String(length=300), nullable=False),
    sa.Column('window_start', sa.Integer(), nullable=False),
    sa.Column('hits', sa.Integer(), nullable=False),
    sa.Column('expires_at', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('key', 'window_start', name=op.f('pk_rate_counters'))
    )
    with op.batch_alter_table('rate_counters', schema=None) as batch_op:
        batch_op.create_index('ix_rate_counters_expires_at', ['expires_at'], unique=False)

    op.create_table('tasks',
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('max_payload_bytes', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('deleted_at', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint('max_payload_bytes > 0', name=op.f('ck_tasks_max_payload_positive')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tasks'))
    )
    with op.batch_alter_table('tasks', schema=None) as batch_op:
        batch_op.create_index('uq_tasks_name_active', ['name'], unique=True, sqlite_where=sa.text('deleted_at IS NULL'))

    op.create_table('policies',
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('kind', sa.Enum('prompt_injection', 'request_rule', 'response_schema', 'content_security', name='policy_kind', native_enum=False, create_constraint=True, length=32), nullable=False),
    sa.Column('scope_task_id', sa.Uuid(), nullable=True),
    sa.Column('definition', sa.JSON(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint('version > 0', name=op.f('ck_policies_version_positive')),
    sa.ForeignKeyConstraint(['scope_task_id'], ['tasks.id'], name=op.f('fk_policies_scope_task_id_tasks'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_policies'))
    )
    with op.batch_alter_table('policies', schema=None) as batch_op:
        batch_op.create_index('ix_policies_kind_scope_enabled', ['kind', 'scope_task_id', 'enabled'], unique=False)
        batch_op.create_index('uq_policies_name', ['name'], unique=True)

    op.create_table('project_models',
    sa.Column('project_id', sa.Uuid(), nullable=False),
    sa.Column('model_id', sa.Uuid(), nullable=False),
    sa.Column('granted_by', sa.String(length=255), nullable=False),
    sa.Column('granted_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['model_id'], ['llm_models.id'], name=op.f('fk_project_models_model_id_llm_models'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_project_models_project_id_projects'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('project_id', 'model_id', name=op.f('pk_project_models'))
    )
    with op.batch_alter_table('project_models', schema=None) as batch_op:
        batch_op.create_index('ix_project_models_model_id', ['model_id'], unique=False)

    op.create_table('project_tasks',
    sa.Column('project_id', sa.Uuid(), nullable=False),
    sa.Column('task_id', sa.Uuid(), nullable=False),
    sa.Column('granted_by', sa.String(length=255), nullable=False),
    sa.Column('granted_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_project_tasks_project_id_projects'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['task_id'], ['tasks.id'], name=op.f('fk_project_tasks_task_id_tasks'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('project_id', 'task_id', name=op.f('pk_project_tasks'))
    )
    with op.batch_alter_table('project_tasks', schema=None) as batch_op:
        batch_op.create_index('ix_project_tasks_task_id', ['task_id'], unique=False)

    op.create_table('service_identities',
    sa.Column('project_id', sa.Uuid(), nullable=False),
    sa.Column('client_id', sa.String(length=255), nullable=False),
    sa.Column('display_name', sa.String(length=200), nullable=False),
    sa.Column('roles', sa.JSON(), nullable=False),
    sa.Column('status', sa.Enum('pending', 'approved', 'revoked', name='identity_status', native_enum=False, create_constraint=True, length=32), nullable=False),
    sa.Column('approved_by', sa.String(length=255), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_by', sa.String(length=255), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('revocation_reason', sa.String(length=500), nullable=True),
    sa.Column('deleted_at', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_service_identities_project_id_projects')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_service_identities'))
    )
    with op.batch_alter_table('service_identities', schema=None) as batch_op:
        batch_op.create_index('ix_service_identities_project_id_status', ['project_id', 'status'], unique=False)
        batch_op.create_index('uq_service_identities_client_id_active', ['client_id'], unique=True, sqlite_where=sa.text('deleted_at IS NULL'))

    op.create_table('llm_requests',
    sa.Column('project_id', sa.Uuid(), nullable=False),
    sa.Column('service_identity_id', sa.Uuid(), nullable=False),
    sa.Column('request_id', sa.String(length=128), nullable=False),
    sa.Column('correlation_id', sa.String(length=128), nullable=False),
    sa.Column('task_name', sa.String(length=100), nullable=False),
    sa.Column('task_id', sa.Uuid(), nullable=True),
    sa.Column('model_name', sa.String(length=100), nullable=False),
    sa.Column('model_id', sa.Uuid(), nullable=True),
    sa.Column('status', sa.Enum('received', 'rejected', 'succeeded', 'provider_error', 'timeout', 'response_invalid', name='llm_request_status', native_enum=False, create_constraint=True, length=32), nullable=False),
    sa.Column('request_bytes', sa.Integer(), nullable=False),
    sa.Column('response_bytes', sa.Integer(), nullable=True),
    sa.Column('request_sha256', sa.String(length=64), nullable=False),
    sa.Column('response_sha256', sa.String(length=64), nullable=True),
    sa.Column('error_code', sa.String(length=100), nullable=True),
    sa.Column('latency_ms', sa.Integer(), nullable=True),
    sa.Column('provider_attempts', sa.Integer(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['model_id'], ['llm_models.id'], name=op.f('fk_llm_requests_model_id_llm_models')),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_llm_requests_project_id_projects')),
    sa.ForeignKeyConstraint(['service_identity_id'], ['service_identities.id'], name=op.f('fk_llm_requests_service_identity_id_service_identities')),
    sa.ForeignKeyConstraint(['task_id'], ['tasks.id'], name=op.f('fk_llm_requests_task_id_tasks')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_llm_requests'))
    )
    with op.batch_alter_table('llm_requests', schema=None) as batch_op:
        batch_op.create_index('ix_llm_requests_created_at', ['created_at'], unique=False)
        batch_op.create_index('ix_llm_requests_status', ['status'], unique=False)
        batch_op.create_index('uq_llm_requests_project_request', ['project_id', 'request_id'], unique=True)

    op.create_table('security_events',
    sa.Column('event_type', sa.Enum('auth_failed', 'access_denied', 'invalid_request', 'payload_too_large', 'prompt_injection', 'identity_override', 'duplicate_request', 'rate_limited', 'quota_exceeded', 'response_invalid', 'provider_failure', 'dependency_unavailable', name='security_event_type', native_enum=False, create_constraint=True, length=32), nullable=False),
    sa.Column('severity', sa.Enum('info', 'warning', 'critical', name='security_severity', native_enum=False, create_constraint=True, length=32), nullable=False),
    sa.Column('request_id', sa.String(length=128), nullable=True),
    sa.Column('correlation_id', sa.String(length=128), nullable=True),
    sa.Column('llm_request_id', sa.Uuid(), nullable=True),
    sa.Column('project_id', sa.Uuid(), nullable=True),
    sa.Column('service_identity_id', sa.Uuid(), nullable=True),
    sa.Column('caller_sub', sa.String(length=255), nullable=True),
    sa.Column('source_ip', sa.String(length=64), nullable=True),
    sa.Column('details', sa.JSON(), nullable=False),
    sa.Column('occurred_at', sa.DateTime(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['llm_request_id'], ['llm_requests.id'], name=op.f('fk_security_events_llm_request_id_llm_requests')),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_security_events_project_id_projects')),
    sa.ForeignKeyConstraint(['service_identity_id'], ['service_identities.id'], name=op.f('fk_security_events_service_identity_id_service_identities')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_security_events'))
    )
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.create_index('ix_security_events_occurred_at', ['occurred_at'], unique=False)
        batch_op.create_index('ix_security_events_project_occurred_at', ['project_id', 'occurred_at'], unique=False)
        batch_op.create_index('ix_security_events_request_id', ['request_id'], unique=False)
        batch_op.create_index('ix_security_events_type_occurred_at', ['event_type', 'occurred_at'], unique=False)


    for statement in (
        "CREATE TRIGGER trg_audit_logs_no_update BEFORE UPDATE ON audit_logs "
        "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
        "CREATE TRIGGER trg_audit_logs_no_delete BEFORE DELETE ON audit_logs "
        "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
    ):
        op.execute(statement)
    for statement in (
        "CREATE TRIGGER trg_security_events_no_update BEFORE UPDATE ON security_events "
        "BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END",
        "CREATE TRIGGER trg_security_events_no_delete BEFORE DELETE ON security_events "
        "BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END",
    ):
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_update")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_security_events_no_update")
    op.execute("DROP TRIGGER IF EXISTS trg_security_events_no_delete")
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.drop_index('ix_security_events_type_occurred_at')
        batch_op.drop_index('ix_security_events_request_id')
        batch_op.drop_index('ix_security_events_project_occurred_at')
        batch_op.drop_index('ix_security_events_occurred_at')

    op.drop_table('security_events')
    with op.batch_alter_table('llm_requests', schema=None) as batch_op:
        batch_op.drop_index('uq_llm_requests_project_request')
        batch_op.drop_index('ix_llm_requests_status')
        batch_op.drop_index('ix_llm_requests_created_at')

    op.drop_table('llm_requests')
    with op.batch_alter_table('service_identities', schema=None) as batch_op:
        batch_op.drop_index('uq_service_identities_client_id_active', sqlite_where=sa.text('deleted_at IS NULL'))
        batch_op.drop_index('ix_service_identities_project_id_status')

    op.drop_table('service_identities')
    with op.batch_alter_table('project_tasks', schema=None) as batch_op:
        batch_op.drop_index('ix_project_tasks_task_id')

    op.drop_table('project_tasks')
    with op.batch_alter_table('project_models', schema=None) as batch_op:
        batch_op.drop_index('ix_project_models_model_id')

    op.drop_table('project_models')
    with op.batch_alter_table('policies', schema=None) as batch_op:
        batch_op.drop_index('uq_policies_name')
        batch_op.drop_index('ix_policies_kind_scope_enabled')

    op.drop_table('policies')
    with op.batch_alter_table('tasks', schema=None) as batch_op:
        batch_op.drop_index('uq_tasks_name_active', sqlite_where=sa.text('deleted_at IS NULL'))

    op.drop_table('tasks')
    with op.batch_alter_table('rate_counters', schema=None) as batch_op:
        batch_op.drop_index('ix_rate_counters_expires_at')

    op.drop_table('rate_counters')
    with op.batch_alter_table('quotas', schema=None) as batch_op:
        batch_op.drop_index('uq_quotas_scope_kind')

    op.drop_table('quotas')
    with op.batch_alter_table('projects', schema=None) as batch_op:
        batch_op.drop_index('uq_projects_project_key_active', sqlite_where=sa.text('deleted_at IS NULL'))
        batch_op.drop_index('ix_projects_team')

    op.drop_table('projects')
    with op.batch_alter_table('llm_models', schema=None) as batch_op:
        batch_op.drop_index('uq_llm_models_name_active', sqlite_where=sa.text('deleted_at IS NULL'))

    op.drop_table('llm_models')
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_index('uq_audit_logs_seq')
        batch_op.drop_index('ix_audit_logs_resource')
        batch_op.drop_index('ix_audit_logs_occurred_at')
        batch_op.drop_index('ix_audit_logs_actor_occurred_at')

    op.drop_table('audit_logs')
