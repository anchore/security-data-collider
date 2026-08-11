from dataclasses import dataclass
from functools import total_ordering

PREFIX = "ANCHORE"


@dataclass(frozen=True, slots=True)
@total_ordering
class AnchoreId:  # noqa: PLW1641
    year: int
    index: int

    def __str__(self) -> str:
        return f"{PREFIX}-{self.year}-{self.index}"

    def __eq__(self, other):
        return ((self.year, self.index) == (other.year, other.index))

    def __lt__(self, other):
        return ((self.year, self.index) < (other.year, other.index))

    def __gt__(self, other):
        return ((self.year, self.index) > (other.year, other.index))


class InvalidAnchoreIdError(ValueError):
    def __init__(self, identifier: str):
        super().__init__(f"{identifier} is an invalid Anchore id")


def parse(anchore_id: str) -> AnchoreId:
    components = anchore_id.split("-")
    if len(components) != 3:
        raise InvalidAnchoreIdError(anchore_id)

    if components[0] != PREFIX:
        raise InvalidAnchoreIdError(anchore_id)

    try:
        year = int(components[1])
        index = int(components[2])
        return AnchoreId(year=year, index=index)
    except Exception as e:
        raise InvalidAnchoreIdError(anchore_id) from e
