from enum import StrEnum


class NormalizingStrEnum(StrEnum):
    @classmethod
    def _normalize(cls, value: str | None) -> str | None:
        if value is None:
            return None

        return value.lower().strip()

    @classmethod
    def _resolve_no_match(cls, original: str | None, normalized: str | None) -> str | None:  # noqa: ARG003
        return None

    @classmethod
    def _missing_(cls, value):
        normalized = cls._normalize(value)
        if normalized is not None:
            for member in cls:
                if member.value == normalized:
                    return member

        return cls._resolve_no_match(value, normalized)
