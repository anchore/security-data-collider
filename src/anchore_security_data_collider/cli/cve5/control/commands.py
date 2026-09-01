
from typing import TYPE_CHECKING

import click

from anchore_security_data_collider.providers.cve5.control import ControlSetGenerator, ControlSetGeneratorConfig

if TYPE_CHECKING:
    from anchore_security_data_collider.cli.config import Application


@click.group(name="control")
@click.pass_obj
def group(_: Application):
    pass

@group.command(name="generate", help="Generate the CVE5 security data collider control dataset from the latest snapshot")
@click.option("--repo-root", help="Path to the root of the CVE5 security data collider control set git repo", required=True)
@click.option("--snapshot-repo-root", help="Path to the root of the CVE5 upstream snapshot git repo", required=True)
@click.pass_obj
def generate_control_set(cfg: Application, repo_root: str, snapshot_repo_root: str) -> None:
    ControlSetGenerator(
        config=ControlSetGeneratorConfig(
            control_repo_root=repo_root,
            snapshot_repo_root=snapshot_repo_root,
        ),
    ).generate()
