
from typing import TYPE_CHECKING

import click

from anchore_security_data_collider.deployment import DeploymentEnvironment
from anchore_security_data_collider.identifiers.store import SecurityIdentifiersStore, SecurityIdentifiersStoreConfig

if TYPE_CHECKING:
    from anchore_security_data_collider.cli.config import Application


@click.group(name="security-identifiers")
@click.pass_obj
def group(_: Application):
    pass

@group.command(name="refresh", help="Pull down the latest Anchore Security Identifiers dataset")
@click.option(
    "--environment",
    type=click.Choice(DeploymentEnvironment, case_sensitive=False),
    help="Deployment environment",
    required=True,
)
@click.pass_obj
def refresh_security_identifiers(cfg: Application, environment: DeploymentEnvironment) -> None:
    store = SecurityIdentifiersStore(
        state_dir=cfg.state_dir,
        config=SecurityIdentifiersStoreConfig(
            pull_format_string="ghcr.io/anchore/data/{environment}/security-identifiers/sqlite/v0:latest",
        ),
    )
    store.fetch(environment)
