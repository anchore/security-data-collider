from typing import TYPE_CHECKING

import click

from anchore_security_data_collider.cli.cve5.control.commands import group as control_group
from anchore_security_data_collider.cli.cve5.enriched.commands import group as enriched_group
from anchore_security_data_collider.cli.cve5.snapshot.commands import group as snapshot_group

if TYPE_CHECKING:
    from anchore_security_data_collider.cli.config import Application


@click.group(name="cve5")
@click.pass_obj
def group(_: Application):
    pass

group.add_command(control_group)
group.add_command(enriched_group)
group.add_command(snapshot_group)
