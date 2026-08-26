from typing import TYPE_CHECKING

import click

from anchore_security_data_collider.enriched.spec_files_importer import SpecFilesImporter, SpecFilesImporterConfig

if TYPE_CHECKING:
    from anchore_security_data_collider.cli.config import Application


@click.group(name="enriched")
@click.pass_obj
def group(_: Application):
    pass

@group.command(name="import-from-specs", help="Import curation data from Anchore Vulnerability Index Spec Files into the enriched dataset")
@click.option("--repo-root", help="Path to the root of the collider enriched data git repo", required=True)
@click.option("--spec-files-repo-root", help="Path to the root of the Anchore Vulnerability Index Spec Files git repo", required=True)
@click.option("--anchore-ids", nargs="+", help="Specific ANCHORE- ids to import enrichment data for", required=False)
@click.option("--cves", nargs="+", help="Specific CVEs to import enrichment data for", required=False)
@click.option("--batch-size", help="Import batch size", type=int, required=False)
@click.pass_obj
def import_from_specs(  # noqa: PLR0913
    cfg: Application,
    repo_root: str,
    spec_files_repo_root: str,
    anchore_ids: list[str] | None,
    cves: list[str] | None,
    batch_size: int,
) -> None:
    SpecFilesImporter(
        config=SpecFilesImporterConfig(
            state_dir=cfg.state_dir,
            repo_root=repo_root,
            spec_files_repo_root=spec_files_repo_root,
        ),
    ).import_(None, None, batch_size=batch_size)
