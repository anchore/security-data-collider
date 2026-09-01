from typing import TYPE_CHECKING

import click

from anchore_security_data_collider.providers.cve5.snapshot import CVE5Snapshotter

if TYPE_CHECKING:
    from anchore_security_data_collider.cli.config import Application


@click.group(name="snapshot")
@click.pass_obj
def group(_: Application):
    pass


@group.command(name="capture", help="Capture snapshot of the upstream CVE5 data at a specific point in time")
@click.option("--repo-root", help="Path to the root of the existing CVE5 snapshot git repo", required=True)
@click.option("--commit", help="Specific upstream commit to capture, otherwise latest if not provided", required=False)
@click.pass_obj
def cve5_snapshot_capture(cfg: Application, repo_root: str, commit: str | None) -> None:
    CVE5Snapshotter(repo_root).process(commit=commit)
