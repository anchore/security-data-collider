import os
from dataclasses import dataclass
from functools import total_ordering

PREFIX = "CVE"

@dataclass(frozen=True, slots=True)
@total_ordering
class CVEIdentifier:  # noqa: PLW1641
    year: int
    index: int

    def __str__(self) -> str:
        return f"{PREFIX}-{self.year}-{self.index:04}"

    def __eq__(self, other):
        return ((self.year, self.index) == (other.year, other.index))

    def __lt__(self, other):
        return ((self.year, self.index) < (other.year, other.index))

    def __gt__(self, other):
        return ((self.year, self.index) > (other.year, other.index))

    def filename(self, root: str, extension: str="json") -> str:
        return os.path.join(root, str(self.year), str(self.index // 1000), f"{self!s}.{extension}")


def parse_identifier(cve_id: str) -> CVEIdentifier | None:
    if not cve_id:
        return None

    if not cve_id.startswith("CVE-"):
        return None

    components = cve_id.split("-")
    if len(components) != 3:
        return None

    return CVEIdentifier(
        year=int(components[1]),
        index=int(components[2]),
    )
