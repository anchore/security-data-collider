from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EnrichedDatasetConfig:
    enriched_repo_root: str
