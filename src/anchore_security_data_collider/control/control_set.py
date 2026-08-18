import json
import logging
import os
import shutil
from dataclasses import dataclass
from glob import iglob
from typing import TYPE_CHECKING

from anchore_security_data_collider.identifiers.store import SecurityIdentifiersStore, SecurityIdentifiersStoreConfig
from anchore_security_data_collider.utils import execute_command, timer

if TYPE_CHECKING:
    from anchore_security_data_collider.identifiers.anchore_id import AnchoreId
    from anchore_security_data_collider.snapshot.config import SnapshotConfig


@dataclass(frozen=True, slots=True)
class ControlSetGeneratorConfig:
    state_dir: str
    repo_root: str
    cve5: SnapshotConfig

class ControlSetGenerator:
    def __init__(self, config: ControlSetGeneratorConfig):
        self._logger = logging.getLogger("control-set-generator")
        self._config = config
        self._security_identifiers = SecurityIdentifiersStore(
            config.state_dir,
            config=SecurityIdentifiersStoreConfig(
                pull_format_string="ghcr.io/anchore/data/{environment}/security-identifiers/sqlite/v0:latest",
            ),
        )

    def _ready(self) -> bool:
        if not self._security_identifiers.ready():
            return False

        if not os.path.exists(self._config.repo_root):
            return False

        return os.path.exists(self._config.cve5.repo_root)

    def _get_security_identifier_base_path(self, anchore_id: AnchoreId) -> str:
        return os.path.join(self._config.repo_root, "data", str(anchore_id.year), str(anchore_id.index//1000), str(anchore_id))

    def _process_cve5_snapshot(self) -> str:
        snapshot_commit = execute_command("git rev-parse HEAD", cwd=self._config.cve5.repo_root)
        if not snapshot_commit:
            raise ValueError(f"Unable to determine current git commit at {self._config.cve5.repo_root}")

        for cve_file in iglob(os.path.join(self._config.cve5.repo_root, "cves/**/CVE-*.json"), recursive=True):
            with open(cve_file) as fp:
                cve_data = json.load(fp)

            cve_metadata = cve_data.get("cveMetadata")
            if not cve_metadata:
                self._logger.warning(f"Skipping {cve_file} due to missing cveMetadata")
                continue

            # Exclude the update date to avoid unnecessary changes to every record
            # since we only care about tracking a small subset of properties from the upstream
            # record
            if "dateUpdated" in cve_metadata:
                del cve_metadata["dateUpdated"]

            cve_id = cve_metadata.get("cveId")
            if not cve_id:
                self._logger.warning(f"Skipping {cve_file} due to missing cveId")
                continue

            anchore_id = self._security_identifiers.lookup(cve_id)
            if not anchore_id:
                self._logger.warning(f"Skipping {cve_file} due to missing ANCHORE security identifier for {cve_id}")
                continue

            cna = cve_data.get("containers", {}).get("cna", {})
            fragments = {
                "dataType": cve_data.get("dataType"),
                "dataVersion": cve_data.get("dataVersion"),
                "cveMetadata": cve_metadata,
                "containers": {
                    "cna": {
                        "affected": cna.get("affected", []),
                        "descriptions": cna.get("descriptions", []),
                        "references": cna.get("references", []),
                        "tags": cna.get("tags", []),
                    },
                },
            }

            rejected_reasons = cna.get("rejectedReasons")
            if rejected_reasons:
                fragments["containers"]["cna"]["rejectedReasons"] = rejected_reasons

            replaced_by = cna.get("replacedBy")
            if replaced_by:
                fragments["containers"]["cna"]["replacedBy"] = replaced_by

            fragment_dir = os.path.join(self._get_security_identifier_base_path(anchore_id), "cve5")
            os.makedirs(fragment_dir, exist_ok=True)
            fragment_path = os.path.join(fragment_dir, f"{cve_id}.json")
            with open(fragment_path, "w") as fp:
                json.dump(fragments, fp, ensure_ascii=False, indent=2, sort_keys=True)

        return snapshot_commit.strip()

    def generate(self):
        if not self._ready():
            raise ValueError("Input data is not ready")

        with timer("generating collider control set"):
            control_set_data_path = os.path.join(self._config.repo_root, "data")
            if os.path.exists(control_set_data_path):
                shutil.rmtree(control_set_data_path)
            cve5_snapshot_commit = self._process_cve5_snapshot()

            with open(os.path.join(self._config.repo_root, "snapshot.json"), "w") as f:
                json.dump({
                    "snapshots": {
                        "cve5": {
                            "repo": "https://github.com/anchore/dataset-security-cve5-upstream",
                            "commit": cve5_snapshot_commit,
                        },
                    },
                }, f, ensure_ascii=False, indent=2, sort_keys=True)
