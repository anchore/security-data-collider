
from typing import TYPE_CHECKING

import click

from anchore_security_data_collider.control_set import ControlSetGenerator, ControlSetGeneratorConfig, CVE5SnapshotConfig
from anchore_security_data_collider.deployment import DeploymentEnvironment

if TYPE_CHECKING:
    from anchore_security_data_collider.cli.config import Application


@click.group(name="control")
@click.pass_obj
def group(_: Application):
    pass

@group.command(name="generate", help="Generate the control dataset from the various upstream security data snapshots")
@click.option("--repo-root", help="Path to the root of the collider control set git repo", required=True)
@click.option("--cve5-repo-root", help="Path to the root of the CVE5 upstream snapshot git repo", required=True)
@click.option(
    "--environment",
    type=click.Choice(DeploymentEnvironment, case_sensitive=False),
    help="Deployment environment",
    required=True,
)
@click.pass_obj
def generate_control_set(cfg: Application, repo_root: str, cve5_repo_root: str, environment: DeploymentEnvironment) -> None:
    ControlSetGenerator(
        config=ControlSetGeneratorConfig(
            repo_root=repo_root,
            cve5=CVE5SnapshotConfig(
                repo_root=cve5_repo_root,
            ),
            environment=environment,
        ),
    ).generate()
