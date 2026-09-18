import json
import logging
import os
import tomllib
from copy import deepcopy
from dataclasses import dataclass
from glob import iglob
from typing import Any
from urllib.parse import quote

from packaging.utils import canonicalize_name

from anchore_security_data_collider.providers.cve5.enriched.config import EnrichedDatasetConfig
from anchore_security_data_collider.providers.cve5.identifier import parse_identifier
from anchore_security_data_collider.utils import timer

# CNAs that will have data that isn't currently worth trying to automate imports
# Will currently print out a warning with the proposed change instead
manually_reconciled_cnas: set[str] = {
    "redhat",
}

@dataclass(frozen=True, slots=True)
class SpecFilesImporterConfig(EnrichedDatasetConfig):
    spec_files_repo_root: str

@dataclass(frozen=False, slots=True)
class CVEReferenceIndex:
    url: str
    index: int
    value: dict

def _construct_cpe(cpe: dict[str, str]) -> str:
    part = cpe.get("part", "a")
    vendor = cpe.get("vendor", "*")
    product = cpe.get("product", "*")
    edition = cpe.get("edition", "*")
    language = cpe.get("language", "*")
    software_edition = cpe.get("software_edition", "*")
    target_software = cpe.get("target_software", "*")
    target_hardware = cpe.get("target_hardware", "*")
    other = cpe.get("other", "*")
    return f"cpe:2.3:{part}:{vendor}:{product}:*:*:{edition}:{language}:{software_edition}:{target_software}:{target_hardware}:{other}"

class SpecFilesImporter:
    def __init__(self, config: SpecFilesImporterConfig):
        self._logger = logging.getLogger("spec-files-importer")
        self._config = config
        self._data_path = os.path.join(self._config.enriched_repo_root, "data")

    def _ready(self) -> bool:
        if not os.path.exists(self._config.enriched_repo_root):
            return False

        return os.path.exists(self._config.spec_files_repo_root)

    def _process_nvd_spec(self, spec_path: str, nvd_spec: Any) -> bool:  # noqa: C901, PLR0911, PLR0912, PLR0915
        cve_id_string = nvd_spec.get("id")
        if not cve_id_string:
            return False

        cve_id = parse_identifier(cve_id_string)
        if not cve_id:
            self._logger.warning(f"Skipping {cve_id_string} in {spec_path} due to error while parsing identifier")
            return False

        cve5_fragment_path = cve_id.filename(self._data_path)
        if not os.path.exists(cve5_fragment_path):
            self._logger.warning(f"{cve_id!s}: Skipping because no base fragment found at {cve5_fragment_path}.  Ensure you have synced the control data first and merged to the enriched dataset")
            return False

        with open(cve5_fragment_path) as fp:
            original_cve_record = json.load(fp)

        cve_metadata = original_cve_record.get("cveMetadata")
        if not cve_metadata:
            self._logger.warning(f"{cve_id!s}: Skipping because no cveMetadata section found at {cve5_fragment_path}")
            return False

        cna: str = cve_metadata.get("assignerShortName")
        if not cna:
            self._logger.warning(f"{cve_id!s}: Skipping because assignerShortName not present in cveMetadata section for {cve5_fragment_path}")
            return False

        revised_cve_record = deepcopy(original_cve_record)
        cna_container = revised_cve_record.get("containers", {}).get("cna")
        if not cna_container:
            self._logger.warning(f"{cve_id!s}: Skipping because no cna container section found for {cve5_fragment_path}")
            return False

        # TODO: Figure out if there is a place for the disputed reasons per vendor
        # in CVE5 or BCP-5 or create an extension for this
        disputed = cna_container.get("disputed")
        if disputed:
            mark_disputed = disputed.get("override", False)
            if mark_disputed and "disputed" not in cna_container["tags"]:
                cna_container["tags"].append("disputed")

        # TODO: Figure out how to handle rejections that aren't rejected upstream
        # rejected = cve.vuln.get("rejection")
        # if rejected:
        #     date = rejected.get("date")
        #     reason = rejected.get("reason")

        #     if date or reason:
        #         cve5["additionalMetadata"]["rejection"] = {}

        #     if date:
        #         cve5["additionalMetadata"]["rejection"]["date"] = date.isoformat()

        #     if reason:
        #         cve5["additionalMetadata"]["rejection"]["reason"] = reason

        # TODO: Figure out how to suppress
        # suppression = cve.vuln.get("suppression")
        # if suppression:
        #     ignore = suppression["override"]
        #     if ignore:
        #         cve5["additionalMetadata"]["ignore"] = True

        # TODO: eventually we will need to resolve the entire set of references from the aggregate view once we have that
        # so that we can process drop, override, etc.  For now we expect everything to be merge (previously add), so will
        # only consider those keys.
        references = nvd_spec.get("references", {}).get("merge")
        if not references:
            references = nvd_spec.get("references", {}).get("add")

        cve5_references = []
        if references:
            for r in references:
                cve5_references.append(
                    {
                        "url": r["url"],
                    },
                )

        cve5_affected: list[dict[str, Any]] = []
        # TODO: eventually need to support all of the new add/remove logic
        overrides = nvd_spec.get("products", {}).get("override", {})
        patch_references: set[str] = set()
        if overrides:
            for record_type, records in overrides.items():
                for r in records:
                    p = {
                        "_index": r.get("_index", 999_999_999),
                    }
                    cve5_affected.append(p)
                    collection_url = r.get("collection_url")
                    if collection_url:
                        p["collectionURL"] = collection_url

                    vendor = r.get("vendor")
                    if vendor:
                        p["vendor"] = vendor

                    product = r.get("product")
                    if product:
                        p["product"] = product

                    p["defaultStatus"] = "unaffected"

                    match record_type:
                        case "docker":
                            package_name = r.get("package_name")
                            if not package_name:
                                self._logger.warning(f"Unable to import from {cve_id} due to missing packageName")
                                return False
                            if not collection_url or "docker.com" in collection_url or "docker.io" in collection_url:
                                p["packageURL"] = f"pkg:docker/{package_name}"
                                if collection_url:
                                    p["collectionURL"] = "https://hub.docker.com"
                            else:
                                p["packageURL"] = f"pkg:docker/{package_name}?repository_url={quote(collection_url)}"
                                p["collectionURL"] = collection_url

                            p["packageName"] = package_name
                        case "jenkins-plugin":
                            group_id = r.get("group_id")
                            if not group_id:
                                self._logger.warning(f"Unable to import from {cve_id} due to missing group_id")
                                return False
                            artifact_id = r.get("artifact_id")
                            if not artifact_id:
                                self._logger.warning(f"Unable to import from {cve_id} due to missing artifact_id")
                                return False
                            repository_url = collection_url
                            if collection_url == "https://plugins.jenkins.io":
                                repository_url = "https://repo.jenkins-ci.org/artifactory/releases"
                                p["collectionURL"] = repository_url
                            p["packageName"] = f"{group_id}:{artifact_id}"
                            p["packageURL"] = f"pkg:maven/{group_id}/{artifact_id}?repository_url={quote(repository_url)}"
                        case "maven":
                            group_id = r.get("group_id")
                            if not group_id:
                                self._logger.warning(f"Unable to import from {cve_id} due to missing group_id")
                                return False
                            artifact_id = r.get("artifact_id")
                            if not artifact_id:
                                self._logger.warning(f"Unable to import from {cve_id} due to missing artifact_id")
                                return False
                            if not collection_url or collection_url.startswith("https://repo.maven.apache.org/maven2"):
                                p["packageURL"] = f"pkg:maven/{group_id}/{artifact_id}"
                            else:
                                p["packageURL"] = f"pkg:maven/{group_id}/{artifact_id}?repository_url={quote(collection_url)}"
                            p["packageName"] = f"{group_id}:{artifact_id}"
                        case "npm":
                            package_name = r.get("package_name")
                            if not package_name:
                                self._logger.warning(f"Unable to import from {cve_id} due to missing packageName")
                                return False
                            npmjs_repo = "://registry.npmjs.org" in collection_url or "://www.npmjs.com/" in collection_url or "://npmjs.com/" in collection_url
                            purl_package_name = quote(package_name)
                            if not collection_url or npmjs_repo:
                                p["packageURL"] = f"pkg:npm/{purl_package_name}"

                                if npmjs_repo:
                                    p["collectionURL"] = "https://registry.npmjs.org"
                            else:
                                p["packageURL"] = f"pkg:npm/{purl_package_name}?repository_url={quote(collection_url)}"
                                p["collectionURL"] = collection_url
                            p["packageName"] = package_name
                        case "python":
                            package_name = r.get("package_name")
                            if package_name:
                                package_name = canonicalize_name(package_name)
                            if not package_name:
                                self._logger.warning(f"Unable to import from {cve_id} due to missing packageName")
                                return False
                            if not collection_url or "://pypi.org" in collection_url:
                                p["packageURL"] = f"pkg:pypi/{package_name}"

                                if "://pypi.org" in collection_url:
                                    p["collectionURL"] = "https://pypi.org"
                            else:
                                p["packageURL"] = f"pkg:pypi/{package_name}?repository_url={quote(collection_url)}"
                                p["collectionURL"] = collection_url

                            p["packageName"] = package_name
                        case "vscode-extension":
                            publisher = r["publisher"]
                            extension_name = r["extension_name"]
                            collection_url = r["collection_url"]

                            if not collection_url or "://marketplace.visualstudio.com" in collection_url:
                                p["packageURL"] = f"pkg:vscode-extension/{publisher}/{extension_name}"

                                if collection_url:
                                    p["collectionURL"] = collection_url
                            else:
                                p["packageURL"] = f"pkg:vscode-extension/{publisher}/{extension_name}?repository_url={quote(collection_url)}"
                                p["collectionURL"] = collection_url

                            p["packageName"] = f"{publisher}.{extension_name}"
                            p["collectionURL"] = r["collection_url"]
                        case _:
                            # TODO: Handle other package types
                            return False
                            #package_name = r.get("package_name")
                            #if package_name:
                            #    p["packageName"] = package_name

                    source = r.get("source")
                    github_repo: str | None = None
                    if source:
                        p["repo"] = source[0]["url"]

                        for s in source:
                            s_url = s["url"]
                            if s_url.startswith("https://github.com"):
                                github_repo = s_url.strip("/")
                                break


                    platforms = r.get("platforms")
                    if platforms:
                        p["platforms"] = platforms

                    modules = r.get("modules")
                    if modules:
                        p["modules"] = modules

                    program_files = r.get("program_files")
                    if program_files:
                        p["programFiles"] = program_files

                    program_routines = r.get("program_routines")
                    if program_routines:
                        p["programRoutines"] = program_routines

                    cpes = r.get("cpe")
                    if cpes:
                        p["cpes"] = []
                        for cpe in cpes:
                            p["cpes"].append(_construct_cpe(cpe))

                    versions: list[dict[str, Any]] = []
                    affected = r.get("affected", [])

                    if affected:
                        for affected_record in affected:
                            a = affected_record["version"]
                            v = {
                                "status": "affected",
                            }
                            less_than = a.get("less_than")
                            less_than_or_equal = a.get("less_than_or_equal")
                            start_inclusive = a.get("greater_than_or_equal")
                            version = a.get("equals")
                            scheme = a.get("scheme")

                            # TODO: add an unaffected package entry for each remediation
                            if less_than:
                                v["lessThan"] = less_than

                            if less_than_or_equal:
                                v["lessThanOrEqual"] = less_than_or_equal

                            if start_inclusive:
                                v["version"] = start_inclusive

                            if version:
                                v["version"] = version

                            if (less_than_or_equal or less_than) and not start_inclusive:
                                v["version"] = "0"

                            if start_inclusive and not less_than_or_equal and not less_than:
                                v["lessThanOrEqual"] = "*"

                            if scheme:
                                v["versionType"] = scheme

                            versions.append(v)

                            for remediation in affected_record.get("remediation", []):
                                remediated_version = remediation.get("version")
                                if remediated_version:
                                    if "changes" not in v:
                                        v["changes"] = []

                                    v["changes"].append({
                                        "at": remediated_version,
                                        "status": "unaffected",
                                    })

                                for patch in remediation.get("patch", []):
                                    commit = patch.get("commit")
                                    if commit:
                                        if commit.startswith("https://"):
                                            patch_references.add(commit)
                                        # TODO: support rendering of URLs for other sources (once we have any data populated for them)
                                        elif github_repo:
                                            patch_references.add(f"{github_repo}/commit/{commit}")

                                    pr = patch.get("pr")
                                    if pr:
                                        if pr.startswith("https://"):
                                            patch_references.add(pr)
                                        # TODO: support rendering of URLs for other sources (once we have any data populated for them)
                                        elif github_repo:
                                            patch_references.add(f"{github_repo}/pull/{pr}")

                    unaffected = r.get("unaffected", [])
                    if unaffected:
                        for a in unaffected:
                            a = a["version"]
                            v = {
                                "status": "unaffected",
                            }
                            less_than = a.get("less_than")
                            less_than_or_equal = a.get("less_than_or_equal")
                            start_inclusive = a.get("greater_than_or_equal")
                            version = a.get("equals")
                            scheme = a.get("scheme")

                            if less_than:
                                v["lessThan"] = less_than

                            if less_than_or_equal:
                                v["lessThanOrEqual"] = less_than_or_equal

                            if start_inclusive:
                                v["version"] = start_inclusive

                            if version:
                                v["version"] = version

                            if (less_than_or_equal or less_than) and not start_inclusive:
                                v["version"] = "0"

                            if start_inclusive and not less_than_or_equal and not less_than:
                                v["lessThanOrEqual"] = "*"

                            if scheme:
                                v["versionType"] = scheme

                            versions.append(v)

                    investigating = r.get("investigating", [])
                    if investigating:
                        for a in investigating:
                            a = a["version"]
                            v = {
                                "status": "unknown",
                            }
                            less_than = a.get("less_than")
                            less_than_or_equal = a.get("less_than_or_equal")
                            start_inclusive = a.get("greater_than_or_equal")
                            version = a.get("equals")
                            scheme = a.get("scheme")

                            if less_than:
                                v["lessThan"] = less_than

                            if less_than_or_equal:
                                v["lessThanOrEqual"] = less_than_or_equal

                            if start_inclusive:
                                v["version"] = start_inclusive

                            if version:
                                v["version"] = version

                            if (less_than_or_equal or less_than) and not start_inclusive:
                                v["version"] = "0"

                            if start_inclusive and not less_than_or_equal and not less_than:
                                v["lessThanOrEqual"] = "*"

                            if scheme:
                                v["versionType"] = scheme

                            versions.append(v)

                    if versions:
                        p["versions"] = versions

                    # Create the additional jenkins-plugin registry record
                    if record_type == "jenkins-plugin":
                        p2 = deepcopy(p)
                        p2["collectionURL"] = r["registry"]
                        p2["packageName"] = r["plugin_name"]
                        if "packageURL" in p2:
                            del p2["packageURL"]
                        cve5_affected.append(p2)

        for patch_ref in patch_references:
            cve5_references.append(
                {
                    "url": patch_ref,
                    "tags": ["patch"],
                },
            )

        next_index = 0
        if cve5_references:
            existing: dict[str, CVEReferenceIndex] = {}
            for index, ref in enumerate(cna_container.get("references", [])):
                url = ref["url"]
                if url not in existing:
                    existing[url] = CVEReferenceIndex(url=url, index=index, value=ref)
                elif "tags" not in existing[url].value:
                    existing[url].value["tags"] = ref.get("tags", [])
                else:
                    for t in ref.get("tags", []):
                        if t not in existing[url].value["tags"]:
                            existing[url].value["tags"].append(t)
                next_index += 1

            for ref in cve5_references:
                url = ref["url"]
                ex = existing.get(url)
                if not ex:
                    existing[url] = CVEReferenceIndex(url=url, index=next_index, value=ref)
                    next_index += 1
                elif "tags" not in existing[url].value:
                    existing[url].value["tags"] = ref.get("tags", [])
                else:
                    for t in ref.get("tags", []):
                        if t not in existing[url].value["tags"]:
                            existing[url].value["tags"].append(t)

            ordered = []
            for ref in sorted(existing.values(), key=lambda r: r.index):
                ordered.append(ref.value)

            revised_cve_record["containers"]["cna"]["references"] = ordered

        if cve5_affected:
            cve5_affected = sorted(cve5_affected, key=lambda a: a["_index"])
            for affected in cve5_affected:
                del affected["_index"]
            revised_cve_record["containers"]["cna"]["affected"] = cve5_affected

        if original_cve_record == revised_cve_record:
            return False

        if cna in manually_reconciled_cnas:
            self._logger.warning(f"{cve_id!s}: Manual reconciliation needed for {cve_id}, cna: {cna}")
            self._logger.warning(json.dumps(revised_cve_record, ensure_ascii=False, indent=2, sort_keys=True))
            return False

        with open(cve5_fragment_path, "w") as fp:
            json.dump(revised_cve_record, fp, ensure_ascii=False, indent=2, sort_keys=True)
        return True

    def _process_spec_file(self, spec_file: str) -> int:
        try:
            with open(spec_file, "rb") as fp:
                enriched = tomllib.load(fp)

            vuln = enriched.get("vuln")
            if not vuln:
                logging.warning(f"Skipping {spec_file}.  No vulnerability data section found.")
                return 0

            nvd_vuln = vuln.get("providers", {}).get("nvd", [])
            if not nvd_vuln:
                logging.warning(f"Skipping {spec_file}.  No vuln.providers.nvd data section found.")
                return 0

            updated_count = 0
            for n in nvd_vuln:
                updated = self._process_nvd_spec(spec_file, n)
                if updated:
                    updated_count += 1

            return updated_count
        except Exception:
            self._logger.exception(f"Error processing {spec_file}")
            raise

    def _process_import(self, cves: list[str] | None, anchore_ids: list[str] | None, batch_size: int | None):
        # TODO: implement logic to filter by cve id and/or anchore id
        batched_changes = 0
        for spec_file in iglob(os.path.join(self._config.spec_files_repo_root, "data/**/ANCHORE-*.toml"), recursive=True):
            updated_count = self._process_spec_file(spec_file)
            batched_changes += updated_count

            if batch_size and batched_changes >= batch_size:
                self._logger.warning(f"Stopping for now as the update batch size of {batch_size} has been reached")
                break

    def import_(self, cves: list[str] | None, anchore_ids: list[str] | None, batch_size: int | None):
        if not self._ready():
            raise ValueError("Input data is not ready")

        with timer("importing improvements from vulnerability index spec files"):
            self._process_import(cves, anchore_ids, batch_size)
