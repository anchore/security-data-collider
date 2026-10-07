from dataclasses import dataclass
from typing import Any


@dataclass(frozen=False, slots=True)
class CNAEnrichmentFragment:
    affected: list[Any] | None = None
    title: str | None = None
    descriptions: list[Any] | None = None
    references: list[Any] | None = None
    tags: list[str] | None = None
    rejected_reasons: list[Any] | None = None
    replaced_by: list[Any] | None = None

    @classmethod
    def from_json(cls, json: Any) -> CNAEnrichmentFragment:
        return CNAEnrichmentFragment(
            affected = json.get("affected"),
            title = json.get("title"),
            descriptions = json.get("descriptions"),
            references = json.get("references"),
            tags = json.get("tags"),
            rejected_reasons = json.get("rejectedReasons"),
            replaced_by = json.get("replacedBy"),
        )

    def to_json(self) -> Any:
        json = {}

        if self.affected:
            json["affected"] = self.affected

        if self.title:
            json["title"] = self.title

        if self.descriptions:
            json["descriptions"] = self.descriptions

        if self.references:
            json["references"] = self.references

        if self.tags:
            json["tags"] = self.tags

        if self.rejected_reasons:
            json["rejectedReasons"] = self.rejected_reasons

        if self.replaced_by:
            json["replacedBy"] = self.replaced_by

        return json
