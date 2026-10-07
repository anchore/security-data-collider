import json
import logging
import os
import shutil
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from glob import iglob
from typing import Any

from anchore_security_data_collider.providers.cve5.enriched.adp import ANCHORE_ADP
from anchore_security_data_collider.providers.cve5.enriched.config import EnrichedDatasetConfig
from anchore_security_data_collider.providers.cve5.enriched.cpe import construct_cpe_applicability_statement
from anchore_security_data_collider.providers.cve5.identifier import CVEIdentifier, parse_identifier
from anchore_security_data_collider.providers.cve5.models import CNAEnrichmentFragment
from anchore_security_data_collider.utils import timer


@dataclass(frozen=True, slots=True)
class RendererConfig(EnrichedDatasetConfig):
    control_repo_root: str
    snapshot_repo_root: str
    results_directory: str

class Renderer:
    def __init__(self, config: RendererConfig):
        self._logger = logging.getLogger("cve5-enriched-renderer")
        self._config = config
        self._enriched_data_path = os.path.join(self._config.enriched_repo_root, "data")
        self._control_data_path = os.path.join(self._config.control_repo_root, "data")
        self._snapshot_data_path = os.path.join(self._config.snapshot_repo_root, "data")
        self._results_data_path = os.path.join(self._config.results_directory, "data")

    def _ready(self) -> bool:
        return os.path.exists(self._enriched_data_path) and os.path.exists(self._control_data_path) and os.path.exists(self._snapshot_data_path)

    def _fetch_enriched_fragment(self, identifier: CVEIdentifier) -> Any:
        path = identifier.filename(self._enriched_data_path, "json")
        if not os.path.exists(path):
            return None

        with open(path) as f:
            data = json.load(f)

        cna = data.get("containers", {}).get("cna")
        if not cna:
            return None

        return CNAEnrichmentFragment.from_json(cna)

    def _fetch_control_fragment(self, identifier: CVEIdentifier) -> Any:
        path = identifier.filename(self._control_data_path, "json")
        if not os.path.exists(path):
            return None

        with open(path) as f:
            data = json.load(f)

        cna = data.get("containers", {}).get("cna")
        if not cna:
            return None

        return CNAEnrichmentFragment.from_json(cna)

    def _construct_anchore_adp_section(self, control: CNAEnrichmentFragment, enriched: CNAEnrichmentFragment) -> dict:
        anchore = CNAEnrichmentFragment()

        cpe_applicability = None
        if control.affected != enriched.affected:
            anchore.affected = enriched.affected
            cpe_applicability = construct_cpe_applicability_statement(anchore)

        if control.title != enriched.title:
            anchore.title = enriched.title

        if control.descriptions != enriched.descriptions:
            anchore.descriptions = enriched.descriptions

        if control.references != enriched.references:
            anchore.references = enriched.references

        if control.tags != enriched.tags:
            anchore.tags = enriched.tags

        if control.rejected_reasons != enriched.rejected_reasons:
            anchore.rejected_reasons = enriched.rejected_reasons

        if control.replaced_by != enriched.replaced_by:
            anchore.replaced_by = enriched.replaced_by

        anchore_adp = anchore.to_json()
        if cpe_applicability:
            anchore_adp["cpeApplicability"] = cpe_applicability

        if anchore_adp:
            anchore_adp["providerMetadata"] = deepcopy(ANCHORE_ADP)
            anchore_adp["providerMetadata"]["dateUpdated"] = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
            return anchore_adp

        return None

    def _render_from_upstream_snapshot_file(self, upstream_snapshot_file_path: str) -> tuple[CVEIdentifier, Any]:
        try:
            with open(upstream_snapshot_file_path) as f:
                upstream_snapshot = json.load(f)

            cve_id = upstream_snapshot.get("cveMetadata", {}).get("cveId")
            parsed_cve_id = parse_identifier(cve_id)
            if not parsed_cve_id:
                raise ValueError(f"Unable to extract valid cve identifier from {upstream_snapshot_file_path}")

            rendered = deepcopy(upstream_snapshot)
            control = self._fetch_control_fragment(parsed_cve_id)
            enriched = self._fetch_enriched_fragment(parsed_cve_id)

            if not control or not enriched or control == enriched:
                pass
            else:
                anchore_adp = self._construct_anchore_adp_section(control, enriched)
                if anchore_adp:
                    if "adp" in rendered["containers"]:
                        rendered["containers"]["adp"].append(anchore_adp)
                    else:
                        rendered["containers"]["adp"] = [anchore_adp]

            return parsed_cve_id, rendered
        except Exception as ex:
            self._logger.error(f"unable to render CVE5 document for {upstream_snapshot_file_path}")
            raise ex

    def _prepare_results_directory(self):
        if not os.path.exists(self._results_data_path):
            os.makedirs(self._results_data_path)
        else:
            shutil.rmtree(self._results_data_path)

    def render(self):
        if not self._ready():
            raise ValueError("Input data is not ready")

        self._prepare_results_directory()

        with timer("rendering Anchore enriched CVE5 files"):
            for file in iglob(os.path.join(self._snapshot_data_path, "**/CVE-*.json"), recursive=True):
                self._logger.trace(f"start rendering {file}")
                parsed_cve_id, rendered = self._render_from_upstream_snapshot_file(file)
                output_path = parsed_cve_id.filename(self._results_data_path, "json")
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, "w") as f:
                    json.dump(rendered, f, ensure_ascii=False, indent=2, sort_keys=True)
                self._logger.trace(f"finish rendering {file}")

