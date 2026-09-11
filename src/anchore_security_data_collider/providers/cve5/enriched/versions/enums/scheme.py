import logging

from anchore_security_data_collider.enums import NormalizingStrEnum


class VersionScheme(NormalizingStrEnum):
    SEMVER = "semver"
    DEB = "deb"
    GIT = "git"
    MAVEN = "maven"
    PYTHON = "python"
    DATE = "date"
    RPM = "rpm"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

    @classmethod
    def _resolve_no_match(cls, original: str | None, normalized: str | None):  # noqa: PLR0911
        if original is None:
            return cls.UNKNOWN

        match normalized:
            case "semantic":
                return cls.SEMVER
            case "git":
                return cls.GIT
            case "pypi":
                return cls.PYTHON
            case "unknown", "":
                return cls.UNKNOWN
            case _:
                logging.warning(f"Returning `unknown` as fallthrough normalized version scheme for {original}")
                return cls.UNKNOWN
