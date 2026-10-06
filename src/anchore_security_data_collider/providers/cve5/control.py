import json
import logging
import os
import shutil
from dataclasses import dataclass
from glob import iglob

from anchore_security_data_collider.providers.cve5.identifier import parse_identifier
from anchore_security_data_collider.utils import execute_command, timer


@dataclass(frozen=True, slots=True)
class ControlSetGeneratorConfig:
    control_repo_root: str
    snapshot_repo_root: str


class ControlSetGenerator:
    def __init__(self, config: ControlSetGeneratorConfig):
        self._logger = logging.getLogger("cve5-control-set-generator")
        self._config = config
        self._data_path = os.path.join(self._config.control_repo_root, "data")

    def _ready(self) -> bool:
        if not os.path.exists(self._config.control_repo_root):
            return False

        return os.path.exists(self._config.snapshot_repo_root)

    def _process_cve5_snapshot(self) -> str:
        snapshot_commit = execute_command("git rev-parse HEAD", cwd=self._config.snapshot_repo_root)
        if not snapshot_commit:
            raise ValueError(f"Unable to determine current git commit at {self._config.snapshot_repo_root}")

        for cve_file in iglob(os.path.join(self._config.snapshot_repo_root, "data/**/CVE-*.json"), recursive=True):
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

            cve_id_string = cve_metadata.get("cveId")
            if not cve_id_string:
                self._logger.warning(f"Skipping {cve_file} due to missing cveId")
                continue

            cve_id = parse_identifier(cve_id_string)
            if not cve_id:
                self._logger.warning(f"Skipping {cve_file} due to error parsing identifier {cve_id_string}")
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

            title = cna.get("title")
            if title:
                fragments["containers"]["cna"]["title"] = title

            rejected_reasons = cna.get("rejectedReasons")
            if rejected_reasons:
                fragments["containers"]["cna"]["rejectedReasons"] = rejected_reasons

            replaced_by = cna.get("replacedBy")
            if replaced_by:
                fragments["containers"]["cna"]["replacedBy"] = replaced_by

            output_path = cve_id.filename(self._data_path)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w") as fp:
                json.dump(fragments, fp, ensure_ascii=False, indent=2, sort_keys=True)

        return snapshot_commit.strip()

    def generate(self):
        if not self._ready():
            raise ValueError("CVE5 input data is not ready")

        with timer("generating CVE5 collider control set"):
            control_set_data_path = os.path.join(self._config.control_repo_root, "data")
            if os.path.exists(control_set_data_path):
                shutil.rmtree(control_set_data_path)
            cve5_snapshot_commit = self._process_cve5_snapshot()

            with open(os.path.join(self._config.control_repo_root, "index.json"), "w") as f:
                json.dump(
                    {
                        "snapshots": [
                            {
                                "repo": "https://github.com/anchore/dataset-security-cve5-upstream",
                                "commit": cve5_snapshot_commit,
                            },
                        ],
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
