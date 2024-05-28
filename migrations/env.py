import logging
from logging.config import fileConfig

from alembic import context
from flask import current_app
from sqlalchemy import engine_from_config
from sqlalchemy import event
from sqlalchemy import pool

config = context.config

fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')


def set_sqlite_pragma(dbapi_connection, connection_record):
    isolation_level = dbapi_connection.isolation_level
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=OFF")
    cursor.close()
    dbapi_connection.isolation_level = isolation_level


config.set_main_option('sqlalchemy.url',
                       current_app.extensions['migrate'].db.engine.url.render_as_string(hide_password=False)
                       .replace('%', '%%'))
target_metadata = current_app.extensions['migrate'].db.metadata


def run_migrations_offline():
    """Write migration SQL without opening a database connection."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Apply migrations using a dedicated connection."""

    def process_revision_directives(context, revision, directives):
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info('No changes in schema detected.')

    engine = engine_from_config(config.get_section(config.config_ini_section),
                                prefix='sqlalchemy.',
                                poolclass=pool.NullPool)
    event.listen(engine, 'connect', set_sqlite_pragma)

    connection = engine.connect()
    context.configure(connection=connection,
                      target_metadata=target_metadata,
                      process_revision_directives=process_revision_directives,
                      **current_app.extensions['migrate'].configure_args)

    try:
        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.close()
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
