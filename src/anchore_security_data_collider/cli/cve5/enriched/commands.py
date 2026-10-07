from typing import TYPE_CHECKING

import click

from anchore_security_data_collider.providers.cve5.enriched.renderer import (
    Renderer,
    RendererConfig,
)
from anchore_security_data_collider.providers.cve5.enriched.spec_files_importer import (
    SpecFilesImporter,
    SpecFilesImporterConfig,
    SpecFilesImporterOptions,
)
from anchore_security_data_collider.providers.cve5.enriched.versions.transformer import VersionTransformer, VersionTransformerConfig

if TYPE_CHECKING:
    from anchore_security_data_collider.cli.config import Application


@click.group(name="enriched")
@click.pass_obj
def group(_: Application):
    pass

@group.command(name="import-from-specs", help="Import curation data from Anchore Vulnerability Index Spec Files into the enriched CVE5 dataset")
@click.option("--repo-root", help="Path to the root of the collider enriched data git repo", required=True)
@click.option("--spec-files-repo-root", help="Path to the root of the Anchore Vulnerability Index Spec Files git repo", required=True)
@click.option("--anchore-id", multiple=True, help="Specific ANCHORE- ids to import enrichment data for", required=False)
@click.option("--cve", multiple=True, help="Specific CVEs to import enrichment data for", required=False)
@click.option("--assigner", multiple=True, help="Specific CVE assigners (CNAs) tom import data for", required=False)
@click.option("--batch-size", help="Import batch size", type=int, required=False)
@click.pass_obj
def import_from_specs(  # noqa: PLR0913, PLR0917
    cfg: Application,
    repo_root: str,
    spec_files_repo_root: str,
    anchore_id: list[str] | None = None,
    cve: list[str] | None = None,
    assigner: list[str] | None = None,
    batch_size: int | None = None,
) -> None:
    SpecFilesImporter(
        config=SpecFilesImporterConfig(
            enriched_repo_root=repo_root,
            spec_files_repo_root=spec_files_repo_root,
        ),
    ).import_(options=SpecFilesImporterOptions(
            cves=cve,
            anchore_ids=anchore_id,
            assigners=assigner,
            batch_size=batch_size,
        ),
    )

@group.command(name="transform-versions", help="Attempts to transform and normalize the versions from product entries on CVE5 records")
@click.option("--repo-root", help="Path to the root of the collider enriched data git repo", required=True)
@click.option("--cves", nargs="+", help="Specific CVEs to import enrichment data for", required=False)
@click.option("--batch-size", help="Import batch size", type=int, required=False)
@click.pass_obj
def transform_versions(  # noqa: PLR0913, PLR0917
    cfg: Application,
    repo_root: str,
    cves: list[str] | None,
    batch_size: int,
) -> None:
    VersionTransformer(
        config=VersionTransformerConfig(
            enriched_repo_root=repo_root,
        ),
    ).process(None, batch_size=batch_size)

@group.command(name="render", help="Render the full CVE5 documents with an Anchore ADP section containing our enriched entries and calculated cpeApplicability statements")  # noqa: E501
@click.option("--repo-root", help="Path to the root of the collider enriched data git repo", required=True)
@click.option("--control-repo-root", help="Path to the root of the control data git repo", required=True)
@click.option("--snapshot-repo-root", help="Path to the root of the upstream snapshot data git repo", required=True)
@click.option("--results-dir", help="The directory in which to render results", required=True)
@click.pass_obj
def render(  # noqa: PLR0913, PLR0917
    cfg: Application,
    repo_root: str,
    control_repo_root: str,
    snapshot_repo_root: str,
    results_dir: str,
) -> None:
    Renderer(
        config=RendererConfig(
            enriched_repo_root=repo_root,
            control_repo_root=control_repo_root,
            snapshot_repo_root=snapshot_repo_root,
            results_directory=results_dir,
        ),
    ).render()
