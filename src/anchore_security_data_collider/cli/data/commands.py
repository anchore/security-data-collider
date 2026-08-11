from typing import TYPE_CHECKING

import click

from anchore_security_data_collider.cli.data.control.commands import group as control_group

if TYPE_CHECKING:
    from anchore_security_data_collider.cli.config import Application


@click.group(name="data")
@click.pass_obj
def group(_: Application):
    pass

group.add_command(control_group)
