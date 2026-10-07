import json
from typing import TYPE_CHECKING, Any

from cpe import CPE
from cpe.comp.cpecomp2_3_fs import CPEComponent2_3_FS

if TYPE_CHECKING:
    from anchore_security_data_collider.providers.cve5.models import CNAEnrichmentFragment

platform_to_cpe_lookup = {
    "android": "cpe:2.3:o:google:android:-:*:*:*:*:*:*:*",
    "ios": "cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*",
    "macos": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*",
    "windows":  "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
    "linux": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
    "gentoo": "cpe:2.3:o:gentoo:linux:-:*:*:*:*:*:*:*",
    "debian": "cpe:2.3:o:debian:debian_linux:-:*:*:*:*:*:*:*",
}

# Exclude versions schemes that contain data that is useless for CPE-based comparisons
excluded_version_schemes = ["date", "git"]

# TODO: this was essentially a copy/paste of the existing logic from
# https://github.com/anchore/nvd-data-overrides/blob/main/scripts/generate.py and should likely be
# re-evaluated eventually.
def construct_cpe_applicability_statement(cna: CNAEnrichmentFragment) -> Any:  # noqa: C901, PLR0912, PLR0915
    if not cna.affected:
        return None

    cpe_applicability = []
    encountered_configs = set()

    for affected in cna.affected:
        cpes = affected.get("cpes")
        if not cpes:
            continue

        versions = affected.get("versions")
        if not versions:
            continue

        configuration = {"nodes": []}

        for cpe in cpes:
            node = {"cpeMatch": [], "negate": False, "operator": "OR"}

            for version in versions:
                version_type = version.get("versionType")
                if version_type in excluded_version_schemes:
                    continue

                cpe_match = {
                    "criteria": cpe,
                    "vulnerable": version["status"] == "affected",
                }

                less_than = version.get("lessThan")
                less_than_or_equal = version.get("lessThanOrEqual")
                v = version["version"].strip().replace("(", "\\(").replace(")", "\\)").replace("+", "\\+").replace("#", "\\#")

                if not less_than and not less_than_or_equal:
                    # This is a single affected version so set the version component in the CPE
                    c = CPE(cpe)

                    if c.is_application():
                        c.get("app")[0]["version"] = CPEComponent2_3_FS(
                            v, "version",
                        )
                        cpe_match["criteria"] = c.as_fs()
                    elif c.is_operating_system():
                        c.get("os")[0]["version"] = CPEComponent2_3_FS(
                            v, "version",
                        )
                        cpe_match["criteria"] = c.as_fs()
                    elif c.is_hardware():
                        c.get("hw")[0]["version"] = CPEComponent2_3_FS(
                            v, "version",
                        )
                        cpe_match["criteria"] = c.as_fs()
                elif v != "0":
                    cpe_match["versionStartIncluding"] = v

                if less_than and less_than.strip() != "*":
                    cpe_match["versionEndExcluding"] = less_than.strip()
                elif less_than_or_equal and less_than_or_equal.strip() != "*":
                    cpe_match["versionEndIncluding"] = (
                        less_than_or_equal.strip()
                    )

                node["cpeMatch"].append(cpe_match)

            if node["cpeMatch"]:
                configuration["nodes"].append(node)

        # Handle creating platform cpe config for specific cases.  This won't handle multi-node configs,
        # but that isn't necessary for the current dataset and we can always expand it later if needed.
        platforms = affected.get("platforms", [])
        if platforms:
            platform_matches = []
            for platform in platforms:
                platform = platform.lower()
                platform_cpe = platform_to_cpe_lookup.get(platform)
                if not platform_cpe:
                    continue

                platform_cpe_match_criteria = {
                    "vulnerable": False,
                    "criteria": platform_cpe,
                }
                platform_matches.append(platform_cpe_match_criteria)

            if platform_matches:
                configuration["operator"] = "AND"
                configuration["nodes"].append(
                    {
                        "cpeMatch": platform_matches,
                        "negate": False,
                        "operator": "OR",
                    },
                )

        if len(configuration["nodes"]) > 0:
            config_dump = json.dumps(configuration, ensure_ascii=False, sort_keys=True)
            if config_dump not in encountered_configs:
                cpe_applicability.append(configuration)
                encountered_configs.add(config_dump)

    return cpe_applicability
