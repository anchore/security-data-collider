import json
import logging
import os
import re
from copy import deepcopy
from dataclasses import dataclass
from glob import iglob
from typing import Any

from anchore_security_data_collider.providers.cve5.enriched.normalization import normalize
from anchore_security_data_collider.utils import timer

ALL_VERSIONS: str = "*"

def clean_version(version: str | None) -> str | None:
    if not version:
        return version

    version = version.lower().removeprefix("version").strip()
    version = version.lstrip("=").strip()
    version = version.removeprefix("version ").removeprefix("ver ").removeprefix("ver.").removeprefix("v").strip()

    if version == "0.0":
        version = "0"

    return version

@dataclass(frozen=False, slots=True)
class VersionQualifier:
    scheme: str
    version: str
    less_than_or_equal: str | None = None
    less_than: str | None = None

    @classmethod
    def parse_version_scheme(
        cls,
        v: dict[str, Any],
        assigner: str | None = None,
    ) -> str:
        version_scheme = normalize(v.get("versionType"))
        if not version_scheme:
            return "unknown"

        match version_scheme.lower():
            case "git":
                if assigner in {"concretecms", "zabbix"}:
                    return "semver"
            case "release bundle":
                if assigner in {"wolfssl"}:
                    return "semver"
            case "semantic":
                return "semver"
            case "pypi":
                return "python"

        return version_scheme

    @classmethod
    def parse(  # noqa: C901, PLR0912, PLR0915
        cls,
        v: dict[str, Any],
        assigner: str | None = None,
        solutions: set[str] | None = None,
    ) -> VersionQualifier | None:
        version = normalize(v.get("version"))
        less_than = normalize(v.get("lessThan"))
        less_than_or_equal = normalize(v.get("lessThanOrEqual"))
        version_scheme = VersionQualifier.parse_version_scheme(v, assigner)

        # TODO: for now don't do anything with unknown type schemes
        if version_scheme == "unknown":
            return None

        if version and (not less_than and not less_than_or_equal):
            components = version.split(",")
            if len(components) <= 2:
                for c in components:
                    c = normalize(c)
                    if not c:
                        break

                    if c.startswith(">="):
                        version = normalize(c.removeprefix(">="))
                    elif c.startswith("<="):
                        less_than_or_equal = normalize(c.removeprefix("<="))
                    elif c.endswith(" and earlier"):
                        less_than_or_equal = normalize(c.removesuffix(" and earlier"))
                    elif c.startswith("<"):
                        less_than = normalize(c.removeprefix("<"))
                    elif c.startswith("prior to "):
                        less_than = normalize(c.removeprefix("prior to "))
                    elif c.startswith("versions prior to "):
                        less_than = normalize(c.removeprefix("versions prior to "))
                    elif c.startswith("all versions prior to "):
                        less_than = normalize(c.removeprefix("all versions prior to "))
                    elif c.startswith("all versions up to cuda toolkit "):
                        less_than = normalize(c.removeprefix("all versions up to cuda toolkit "))
                    elif c.startswith("all versions up to "):
                        less_than = normalize(c.removeprefix("all versions up to "))
                if version and ((
                    less_than_or_equal
                    and (version.startswith("<=") or version.endswith(" and earlier"))
                ) or (
                    less_than
                    and (
                        version.startswith(
                            ("<", "prior to ", "versions prior to ", "all versions prior to ", "all versions up to cuda toolkit ", "all versions up to "))  # noqa: E501
                    )
                )):
                    version = None

        if version and (
            (less_than and version == less_than)
            or (less_than_or_equal and version == less_than_or_equal)
        ):
            version = None

        if version:
            version = clean_version(version)

        if less_than:
            less_than = clean_version(less_than.removeprefix("<"))

        if less_than_or_equal:
            less_than_or_equal = clean_version(less_than_or_equal.removeprefix("<="))

        if solutions and (less_than_or_equal and not less_than):
            for s in solutions:
                fix_version = re.search(
                    r"Update to\s(.*)\sor a higher version.", s, re.IGNORECASE,
                )

                if fix_version:
                    less_than = fix_version.group(1)
                    less_than_or_equal = None
                    break

        if version and "," in version:
            logging.warning(f"unable to handle parsing for version: {version}")
            return None

        if less_than and "," in less_than:
            logging.warning(f"unable to handle parsing for less_than: {less_than}")
            return None

        if less_than_or_equal and "," in less_than_or_equal:
            logging.warning(f"unable to handle parsing for less_than_or_equal: {less_than_or_equal}")
            return None

        if (not version or version == ALL_VERSIONS) and (less_than or less_than_or_equal):
            version = "0"

        if version and version == ALL_VERSIONS and not less_than_or_equal and not less_than:
            less_than_or_equal = "*"

        # For consistency prefer <= * rather than < * for ranges with no upper bound
        if less_than and less_than == ALL_VERSIONS:
            less_than = None
            less_than_or_equal = ALL_VERSIONS

        if not version:
            return None

        return VersionQualifier(
            scheme=version_scheme,
            version=version,
            less_than=less_than,
            less_than_or_equal=less_than_or_equal,
        )

@dataclass(frozen=False, slots=True)
class VersionStatusChange:
    at: str
    status: str

@dataclass(frozen=False, slots=True)
class VersionNode:
    qualifier: VersionQualifier
    status: str
    changes: list[VersionStatusChange] | None = None

    def to_cve5_json(self) -> Any:
        result = {
            "status": self.status,
            "version": self.qualifier.version,
            "versionType": self.qualifier.scheme,
        }

        if self.qualifier.less_than:
            result["lessThan"] = self.qualifier.less_than
        elif self.qualifier.less_than_or_equal:
            result["lessThanOrEqual"] = self.qualifier.less_than_or_equal

        if self.changes:
            result["changes"] = []

            for c in self.changes:
                result["changes"].append({
                    "at": c.at,
                    "status": c.status,
                })

        return result

    @classmethod
    def parse(
        cls,
        v: dict[str, Any],
        default_status: str,
        assigner: str | None = None,
        solutions: set[str] | None = None,
    ) -> VersionNode:
        status = v.get("status", default_status).lower()
        qualifier = VersionQualifier.parse(v, assigner, solutions)
        if not qualifier:
            logging.warning(f"unable to handle parsing for version node: {json.dumps(v, indent=2)}")
            return None
        raw_changes = v.get("changes")
        status_change_set = set()
        changes = None

        if raw_changes:
            changes = []
            for c in raw_changes:
                at = c.get("at")
                c_status = c.get("status")

                if not at or not status:
                    logging.warning(f"unable to handle parsing for version node: {json.dumps(v, indent=2)}")
                    return None

                status_change = VersionStatusChange(at=at, status=c_status)
                status_change_string = str(status_change)
                if status_change_string not in status_change_set:
                    status_change_set.add(status_change_string)
                    changes.append(status_change)

        # TODO: Don't make any assumptions about remediations based on < just yet
        # if status == "affected" and qualifier.less_than and qualifier.less_than != ALL_VERSIONS:
        #     status_change = VersionStatusChange(at=qualifier.less_than, status="unaffected")
        #     status_change_string = str(status_change)
        #     if status_change_string not in status_change_set:
        #         if changes is None:
        #             changes = []
        #         status_change_set.add(status_change_string)
        #         changes.append(status_change)

        return VersionNode(qualifier=qualifier, status=status, changes=changes)


@dataclass(frozen=True, slots=True)
class VersionTransformerConfig:
    enriched_repo_root: str

class VersionTransformer:
    def __init__(self, config: VersionTransformerConfig):
        self._logger = logging.getLogger("cve5-version-transformer")
        self._config = config

    def _ready(self) -> bool:
        return os.path.exists(self._config.enriched_repo_root)

    def _process_cve_file(self, cve_file: str) -> bool:
        try:
            with open(cve_file) as f:
                cve = json.load(f)

            cve_id = cve.get("cveMetadata", {}).get("cveId")
            assigner = cve.get("cveMetadata", {}).get("assignerShortName")
            cna = cve.get("containers", {}).get("cna")
            if not cna:
                return False

            # TODO: we don't extract the solutions array in the control set yet, but
            # it is optional in all of the parsing calls anyways so is fine for now.
            # It mostly only added additional remediation information for wordpress plugins
            # which are less important to focus on for the moment.
            solutions = cna.get("solutions")
            affected = cna.get("affected")

            if not affected:
                return False

            original_affected = deepcopy(affected)
            for a in affected:
                default_status = a.get("defaultStatus", "unknown")
                for i, v in enumerate(a.get("versions", [])):
                    version_node = VersionNode.parse(v=v, default_status=default_status, assigner=assigner, solutions=solutions)
                    if not version_node:
                        raise ValueError(f"{cve_id}: unable to parse version node {json.dumps(v, indent=2)}")

                    a["versions"][i] = version_node.to_cve5_json()

            if affected == original_affected:
                return False

            with open(cve_file, "w") as fp:
                json.dump(cve, fp, ensure_ascii=False, indent=2, sort_keys=True)

            return True
        except Exception:
            self._logger.warning(f"skipping processing {cve_file}", exc_info=True)
            return False

    def _process(self, cves: list[str] | None, batch_size: int | None):
        # TODO: implement logic to filter by cve id and/or anchore id
        batched_changes = 0
        for cve_file in iglob(os.path.join(self._config.enriched_repo_root, "data/**/CVE-*.json"), recursive=True):
            updated = self._process_cve_file(cve_file)
            if updated:
                batched_changes += 1

            if batch_size and batched_changes >= batch_size:
                self._logger.warning(f"Stopping for now as the update batch size of {batch_size} has been reached")
                break

    def process(self, cves: list[str] | None, batch_size: int | None):
        if not self._ready():
            raise ValueError("Input data is not ready")

        with timer("processing CVE5 data product versions"):
            self._process(cves, batch_size)
