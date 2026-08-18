from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SnapshotConfig:
    repo_root: str
