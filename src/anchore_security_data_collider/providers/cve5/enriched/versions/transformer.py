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
VERSION_ALLOWED_PATTERN = r"[a-zA-Z0-9_+\.\-\s\*\(\)\#\~]"
VERSION_ALLOWED_REGEX = re.compile(
    rf"^{VERSION_ALLOWED_PATTERN}+$",
    re.IGNORECASE,
)
VERSION_EQ_PREFIX = re.compile(
    rf"^\s*(\=+\s*|equals?\s+)(?P<eq>{VERSION_ALLOWED_PATTERN}+?)\s*$",
    re.IGNORECASE,
)
VERSION_GTE_PREFIX = re.compile(
    rf"^\s*(\>\=\s*|((all?\s+)?versions?\s+)?greater\s+than\s+or\s+equal\s+)(?P<gte>{VERSION_ALLOWED_PATTERN}+?)\s*$",
    re.IGNORECASE,
)
VERSION_LTE_PREFIX = re.compile(
    rf"^\s*(\<\=\s*|((all?\s+)?versions?\s+)?less\s+than\s+or\s+equal\s+)(?P<lte>{VERSION_ALLOWED_PATTERN}+?)\s*$",
    re.IGNORECASE,
)
VERSION_LTE_SUFFIX = re.compile(
    rf"^\s*(?P<lte>{VERSION_ALLOWED_PATTERN}+?)\s+and\s+earlier\s*$",
    re.IGNORECASE,
)
VERSION_LT_PREFIX = re.compile(
    rf"^\s*(\<\s*|((all?\s+)?versions?\s+)?(less\s+than\s+|prior\s+to\s+|up\s+to\s+(cuda\s+toolkit\s+)?))(?P<lt>{VERSION_ALLOWED_PATTERN}+?)\s*$",
    re.IGNORECASE,
)
VERSION_PREFIX = re.compile(
    rf"^(version|ver\.?)\s+(?P<suffix>{VERSION_ALLOWED_PATTERN}+?)\s*$",
    re.IGNORECASE,
)

def clean_version(version: str | None) -> str | None:
    if not version:
        return version

    m = VERSION_PREFIX.match(version)
    if m:
        version = m.group("suffix").strip()

    version = version.removeprefix("= ")
    version = version.removeprefix(">= ")
    version = version.removeprefix("<= ")
    version = version.removeprefix("< ")
    version = version.strip()

    if version == "0.0":
        version = "0"

    return version

def normalize_version_constraint_chunk(constraint: str) -> str | None:  # noqa: C901
    constraint = normalize(constraint)
    if not constraint:
        return None

    m = VERSION_EQ_PREFIX.match(constraint)
    if m:
        version = clean_version(normalize(m.group("eq")))
        if version:
            return f"= {version}"

    m = VERSION_GTE_PREFIX.match(constraint)
    if m:
        version = clean_version(normalize(m.group("gte")))
        if version:
            return f">= {version}"

    m = VERSION_LTE_PREFIX.match(constraint)
    if not m:
        m = VERSION_LTE_SUFFIX.match(constraint)

    if m:
        version = clean_version(normalize(m.group("lte")))
        if version:
            return f"<= {version}"

    m = VERSION_LT_PREFIX.match(constraint)
    if m:
        version = clean_version(normalize(m.group("lt")))
        if version:
            return f"< {version}"

    return constraint

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
    def parse(  # noqa: C901, PLR0911, PLR0912, PLR0915
        cls,
        v: dict[str, Any],
        assigner: str | None = None,
        solutions: set[str] | None = None,
    ) -> VersionQualifier | None:
        raw_version = v.get("version")
        raw_less_than = v.get("lessThan")
        raw_less_than_or_equal = v.get("lessThanOrEqual")

        version = normalize(raw_version)
        less_than = normalize(raw_less_than)
        less_than_or_equal = normalize(raw_less_than_or_equal)

        if raw_less_than and not less_than:
            logging.warning(f"unable to handle parsing for version: {version}")
            return None

        if raw_less_than_or_equal and not less_than_or_equal:
            logging.warning(f"unable to handle parsing for version: {version}")
            return None

        version_scheme = VersionQualifier.parse_version_scheme(v, assigner)

        # TODO: for now don't do anything with unknown type schemes
        if version_scheme == "unknown":
            logging.warning(f"unable to handle parsing for version: {version}")
            return None

        if version and (not less_than and not less_than_or_equal):
            components = version.split(",")
            if len(components) <= 2:
                for c in components:
                    c = normalize(c)
                    if not c:
                        logging.warning(f"unable to handle parsing for version: {version}")
                        return None

                    c = normalize_version_constraint_chunk(c)
                    if not c:
                        logging.warning(f"unable to handle parsing for version: {version}")
                        return None

                    if c.startswith((">= ", "= ")):
                        version = c
                    elif c.startswith("<= "):
                        less_than_or_equal = c
                    elif c.startswith("< "):
                        less_than = c
                if version and (less_than_or_equal or less_than) and not version.startswith(("= ", ">=")):
                    version = None

        if version and (
            (less_than and version == less_than)
            or (less_than_or_equal and version == less_than_or_equal)
        ):
            #version = None
            logging.warning(f"unable to handle parsing for version: {version}")
            return None

        if less_than:
            less_than = normalize(clean_version(less_than))

            if not less_than:
                logging.warning(f"unable to handle parsing for version: {version}")
                return None

        if less_than_or_equal:
            less_than_or_equal = normalize(clean_version(less_than_or_equal))

            if not less_than_or_equal:
                logging.warning(f"unable to handle parsing for version: {version}")
                return None

        if solutions and (less_than_or_equal and not less_than):
            for s in solutions:
                fix_version = re.search(
                    r"Update to\s(.*)\sor a higher version.", s, re.IGNORECASE,
                )

                if fix_version:
                    less_than = fix_version.group(1)
                    less_than_or_equal = None
                    break

        if version:
            if version.startswith(">= ") and not less_than and not less_than_or_equal:
                less_than_or_equal = ALL_VERSIONS

            version = clean_version(version)

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
            version = "0"

        # For consistency prefer <= * rather than < * for ranges with no upper bound
        # if less_than and less_than == ALL_VERSIONS:
        #     less_than = None
        #     less_than_or_equal = ALL_VERSIONS

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
