from typing import TYPE_CHECKING

import click

from anchore_security_data_collider.cli.data.control.commands import group as control_group
from anchore_security_data_collider.cli.data.security_identifiers.commands import group as security_identifiers_group

if TYPE_CHECKING:
    from anchore_security_data_collider.cli.config import Application


@click.group(name="data")
@click.pass_obj
def group(_: Application):
    pass

group.add_command(control_group)
group.add_command(security_identifiers_group)
